#!/usr/bin/env python3
"""Generate WireGuard Ansible config from a topology YAML.

Idempotent: key material persists in <topology-dir>/state/ (override with
--state-dir). Existing keys in the ansible inventory are also read as a
first-run fallback. Use --rotate <network> (repeatable) to force
regeneration of a network's key material.

Output layout under the -i/--inventory root:
  <root>/inventory/host_vars/<host>/*.yml   ansible host_vars
  <root>/netplan/<host>/*.yaml              netplan drop-ins
  <root>/wireguard/<host>/<iface>.conf      ready-to-use wg-quick confs
  <root>/networkmanager/<host>/<iface>.nmconnection
                                            NetworkManager keyfiles (the
                                            GNOME/Ubuntu Settings VPN GUI)

Usage:
  ./gen_wireguard.py -i out -t topology.yml
  ./gen_wireguard.py -i out -t topology.yml --rotate exit-egress-node

Vault files must be decrypted before running; re-encrypt afterwards.
"""
import argparse
import io
import ipaddress
import os
import subprocess
import sys
import uuid
from itertools import combinations
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import DoubleQuotedScalarString as DQ


# ---------- wg helpers ----------

def wg(*args, stdin=None):
    try:
        r = subprocess.run(["wg", *args], input=stdin,
                           capture_output=True, text=True, check=True)
    except FileNotFoundError:
        sys.exit("wg(8) not found in PATH; install wireguard-tools")
    except subprocess.CalledProcessError as e:
        sys.exit(f"`wg {args[0]}` failed: {e.stderr.strip()}")
    return r.stdout.strip()


def gen_keypair():
    priv = wg("genkey")
    pub = wg("pubkey", stdin=priv + "\n")
    return priv, pub


def gen_psk():
    return wg("genpsk")


# ---------- topology helpers ----------

def san(name: str) -> str:
    """Sanitize a name for use inside an Ansible variable identifier."""
    return name.replace("-", "_")


def pair_key(a: str, b: str) -> frozenset:
    return frozenset({a, b})


def participants(network: dict) -> list:
    if network["type"] == "mesh":
        return list(network["members"])
    if network["type"] == "hub":
        return [network["hub"]] + list(network.get("clients", []))
    sys.exit(f"unknown network type: {network['type']}")


def host_address(network: dict, host: str, topology: dict) -> str:
    subnet = ipaddress.ip_network(network["subnet"])
    if network["type"] == "mesh":
        idx = network["members"].index(host)
        return str(subnet.network_address + 1 + idx)
    if host == network["hub"]:
        return str(subnet.network_address + 1)
    octet = topology["clients"][host]["octet"]
    return str(subnet.network_address + octet)


def prefix_len(network: dict) -> int:
    return ipaddress.ip_network(network["subnet"]).prefixlen


def peer_endpoint(topology: dict, host: str, net_name: str, port: int) -> str:
    """Endpoint for a host on a specific network.

    hosts.<name>.endpoint is the default. hosts.<name>.endpoints.<network>
    can override it when several WireGuard listeners share one public IP and
    need distinct DNAT ports.
    """
    host_cfg = topology["hosts"][host]
    ep = (host_cfg.get("endpoints") or {}).get(net_name, host_cfg["endpoint"])
    return _with_port(str(ep), port)


def _with_port(ep: str, port: int) -> str:
    """Append `:port` unless `ep` already carries one.

    Accepts hostnames, IPv4 addresses, bracketed IPv6 ("[2001:db8::1]") and
    bare IPv6 ("2001:db8::1", which gets brackets so the port is unambiguous).
    """
    if ep.startswith("["):
        return ep if "]:" in ep else f"{ep}:{port}"
    colons = ep.count(":")
    if colons == 0:
        return f"{ep}:{port}"
    if colons == 1:
        return ep                      # host:port or ipv4:port
    return f"[{ep}]:{port}"            # bare IPv6 literal


def local_networks(topology: dict, host: str) -> list:
    """Networks `host` reaches without any tunnel (hosts.<name>.local_networks).

    Typically the host's own LAN, plus whatever its LAN gateway routes. Only
    `hosts` entries can carry this; clients never do.
    """
    nets = []
    for cidr in (topology["hosts"].get(host) or {}).get("local_networks") or []:
        try:
            nets.append(ipaddress.ip_network(str(cidr), strict=False))
        except ValueError:
            sys.exit(f"hosts.{host}.local_networks: invalid network {cidr!r}")
    return nets


def is_local_route(route: str, local_nets: list) -> bool:
    """True if `route` lies inside (or equals) one of `local_nets`."""
    r = ipaddress.ip_network(str(route), strict=False)
    return any(r.version == n.version and r.subnet_of(n) for n in local_nets)


def tunnel_routes(host: str, net: dict, topology: dict) -> list:
    """Routes beyond the tunnel subnet that `host` sends into this network."""
    if net["type"] == "mesh":
        routes = []
        for other in participants(net):
            if other != host:
                routes += list((net.get("member_routes") or {}).get(other, []))
        return routes
    if host == net["hub"]:
        return []
    if net.get("default_route"):
        return ["0.0.0.0/0", "::/0"]
    return list(net.get("extra_routes", []))


def route_plan(host: str, net_name: str, net: dict, topology: dict) -> tuple:
    """Split `host`'s tunnel routes into (installed, suppressed).

    A route inside one of the host's local_networks is suppressed: it stays in
    the peer's AllowedIPs, so traffic arriving through the tunnel from those
    networks is still accepted, but no kernel route is installed for it, so
    the host keeps answering those networks over its own LAN. Without this, a
    host that sits inside a LAN which another member advertises would send
    its replies to that LAN into the tunnel, where the far end drops them.
    """
    local = local_networks(topology, host)
    installed, suppressed = [], []
    for r in tunnel_routes(host, net, topology):
        (suppressed if local and is_local_route(r, local) else installed).append(r)
    if suppressed and "0.0.0.0/0" in installed:
        sys.exit(f"{host}: local_networks cannot be combined with a default "
                 f"route on network {net_name!r}")
    return installed, suppressed


def table_off_post_up(installed: list) -> list:
    """PostUp commands that re-add only the wanted routes under Table = off."""
    return [f"ip route add {r} dev %i" for r in installed]


IFNAMSIZ = 15  # Linux kernel interface name limit (IFNAMSIZ - 1)


def iface_name(net_name: str, net: dict) -> str:
    """Kernel interface name for a network; override with `iface:` in topology."""
    name = net.get("iface") or net_name
    if len(name) > IFNAMSIZ:
        sys.exit(f"interface name {name!r} exceeds {IFNAMSIZ} chars; "
                 f"set `iface:` on network {net_name!r} in topology")
    return name


def validate_topology(topology: dict) -> None:
    """Reject topologies that would silently render wrong configs.

    Every check here corresponds to output that would otherwise be produced
    without error and be wrong: addresses outside the subnet, a client
    colliding with the hub, a host with no `hosts:` entry, duplicate
    interface names, or a peer with no endpoint to dial.
    """
    hosts = topology.get("hosts") or {}
    clients = topology.get("clients") or {}
    networks = topology.get("networks") or {}
    if not networks:
        sys.exit("topology defines no networks")

    seen_ifaces: dict = {}
    for net_name, net in networks.items():
        net_type = net.get("type")
        if net_type not in ("mesh", "hub"):
            sys.exit(f"network {net_name!r}: type must be 'mesh' or 'hub', "
                     f"got {net_type!r}")
        if "subnet" not in net:
            sys.exit(f"network {net_name!r}: missing `subnet`")
        if "port" not in net:
            sys.exit(f"network {net_name!r}: missing `port`")
        try:
            subnet = ipaddress.ip_network(net["subnet"])
        except ValueError as e:
            sys.exit(f"network {net_name!r}: bad subnet {net['subnet']!r}: {e}")
        if subnet.version != 4:
            sys.exit(f"network {net_name!r}: only IPv4 subnets are supported")
        # usable host addresses are network+1 .. broadcast-1
        last_usable = subnet.num_addresses - 2

        if net_type == "hub" and not net.get("hub"):
            sys.exit(f"network {net_name!r}: hub network needs `hub:`")
        # clients live under `clients:`; every other participant under `hosts:`
        for host in participants(net):
            if net_type == "hub" and host != net["hub"]:
                continue
            if host not in hosts:
                sys.exit(f"network {net_name!r} uses host {host!r}, which has "
                         f"no entry under `hosts:`")

        iface = iface_name(net_name, net)
        if iface in seen_ifaces:
            sys.exit(f"networks {seen_ifaces[iface]!r} and {net_name!r} both "
                     f"use interface name {iface!r}; set `iface:` on one")
        seen_ifaces[iface] = net_name

        if net_type == "mesh":
            members = list(net.get("members") or [])
            if len(members) != len(set(members)):
                sys.exit(f"network {net_name!r}: duplicate members")
            if len(members) > last_usable:
                sys.exit(f"network {net_name!r}: {len(members)} members do not "
                         f"fit in {subnet} (max {last_usable})")
            needs_endpoint = members
        else:
            hub = net["hub"]
            used_octets: dict = {}
            for client in net.get("clients") or []:
                if client == hub:
                    sys.exit(f"network {net_name!r}: {client!r} is both hub and client")
                if client not in clients or "octet" not in clients[client]:
                    sys.exit(f"client {client!r} needs `clients: {{{client}: {{octet: N}}}}`")
                octet = clients[client]["octet"]
                if not isinstance(octet, int) or not 2 <= octet <= last_usable:
                    sys.exit(f"client {client!r}: octet {octet!r} must be an "
                             f"integer in 2..{last_usable} (1 is the hub)")
                if octet in used_octets:
                    sys.exit(f"network {net_name!r}: clients {used_octets[octet]!r} "
                             f"and {client!r} share octet {octet}")
                used_octets[octet] = client
            needs_endpoint = [hub] if net.get("clients") else []

        for host in needs_endpoint:
            host_cfg = hosts[host] or {}
            if not (host_cfg.get("endpoint")
                    or (host_cfg.get("endpoints") or {}).get(net_name)):
                sys.exit(f"host {host!r} needs `endpoint:` (peers dial it on "
                         f"network {net_name!r})")


# ---------- state ----------

class State:
    def __init__(self):
        self.priv: dict = {}   # (host, network) -> privkey
        self.pub: dict = {}    # (host, network) -> pubkey
        self.psk: dict = {}    # (network, frozenset({a,b})) -> psk

    def drop_network(self, net: str):
        self.priv = {k: v for k, v in self.priv.items() if k[1] != net}
        self.pub = {k: v for k, v in self.pub.items() if k[1] != net}
        self.psk = {k: v for k, v in self.psk.items() if k[0] != net}


def load_state(yaml: YAML, root: Path, topology: dict) -> State:
    state = State()
    all_hosts = set()
    for net in topology["networks"].values():
        all_hosts.update(participants(net))

    for host in all_hosts:
        pub_file = root / "inventory" / "host_vars" / host / "wireguard.yml"
        if pub_file.exists():
            doc = yaml.load(pub_file.read_text()) or {}
            for net_name, pub in (doc.get("wireguard_public_keys") or {}).items():
                state.pub[(host, net_name)] = str(pub)

        for net_name, net in topology["networks"].items():
            vault_file = root / "inventory" / "host_vars" / host / f"wireguard_vault_{net_name}.yml"
            if not vault_file.exists():
                continue
            doc = yaml.load(vault_file.read_text()) or {}
            priv_var = f"vault_wireguard_{san(net_name)}_private_key"
            if priv_var in doc:
                state.priv[(host, net_name)] = str(doc[priv_var])
            psk_prefix = f"vault_wg_psk_{san(net_name)}_"
            for var, val in doc.items():
                if not var.startswith(psk_prefix):
                    continue
                peer_san = var[len(psk_prefix):]
                for other in participants(net):
                    if other != host and san(other) == peer_san:
                        state.psk[(net_name, pair_key(host, other))] = str(val)
                        break
    return state


STATE_PRIV = "private_keys.yml"
STATE_PUB = "public_keys.yml"
STATE_PSK = "preshared_keys.yml"


def load_state_from_dir(yaml: YAML, state_root: Path) -> State:
    """Load keys from a standalone state/ dir (authoritative, survives out/ wipes)."""
    state = State()
    priv_file = state_root / STATE_PRIV
    if priv_file.exists():
        doc = yaml.load(priv_file.read_text()) or {}
        for host, nets in doc.items():
            for net_name, key in (nets or {}).items():
                state.priv[(host, net_name)] = str(key)
    pub_file = state_root / STATE_PUB
    if pub_file.exists():
        doc = yaml.load(pub_file.read_text()) or {}
        for host, nets in doc.items():
            for net_name, key in (nets or {}).items():
                state.pub[(host, net_name)] = str(key)
    psk_file = state_root / STATE_PSK
    if psk_file.exists():
        doc = yaml.load(psk_file.read_text()) or {}
        for net_name, pairs in doc.items():
            for pair_str, psk in (pairs or {}).items():
                a, b = pair_str.split("__", 1)
                state.psk[(net_name, pair_key(a, b))] = str(psk)
    return state


def save_state_to_dir(yaml: YAML, state_root: Path, state: State) -> None:
    """Persist all key material to state/ dir (0600 for private/psk files)."""
    # iterate in sorted order: insertion order can come from set iteration
    # (hash-seed dependent), and the state files should not churn between runs
    priv_doc: dict = {}
    for (host, net_name), key in sorted(state.priv.items()):
        priv_doc.setdefault(host, {})[net_name] = DQ(key)
    pub_doc: dict = {}
    for (host, net_name), key in sorted(state.pub.items()):
        pub_doc.setdefault(host, {})[net_name] = DQ(key)
    psk_doc: dict = {}
    for (net_name, pair), psk in sorted(
            state.psk.items(), key=lambda kv: (kv[0][0], sorted(kv[0][1]))):
        a, b = sorted(pair)
        psk_doc.setdefault(net_name, {})[f"{a}__{b}"] = DQ(psk)

    state_root.mkdir(parents=True, exist_ok=True)
    write_yaml_secure(yaml, state_root / STATE_PRIV, priv_doc)
    write_yaml(yaml, state_root / STATE_PUB, pub_doc)
    write_yaml_secure(yaml, state_root / STATE_PSK, psk_doc)


def merge_state(base: State, other: State) -> None:
    """Fill missing entries in `base` from `other`; never overwrite."""
    for k, v in other.priv.items():
        base.priv.setdefault(k, v)
    for k, v in other.pub.items():
        base.pub.setdefault(k, v)
    for k, v in other.psk.items():
        base.psk.setdefault(k, v)


def generate_missing(state: State, topology: dict):
    for net_name, net in topology["networks"].items():
        for host in participants(net):
            if (host, net_name) not in state.priv:
                priv, pub = gen_keypair()
                state.priv[(host, net_name)] = priv
                state.pub[(host, net_name)] = pub
        for a, b in combinations(participants(net), 2):
            if (net_name, pair_key(a, b)) not in state.psk:
                state.psk[(net_name, pair_key(a, b))] = gen_psk()


# ---------- doc builders ----------

def peer_list_for(host: str, net_name: str, net: dict,
                  topology: dict, state: State) -> list:
    peers = []
    net_type = net["type"]
    for other in participants(net):
        if other == host:
            continue
        # clients don't peer with other clients in a hub network
        if net_type == "hub" and host != net["hub"] and other != net["hub"]:
            continue

        peer = {
            "name": DQ(other),
            "public_key": DQ(state.pub[(other, net_name)]),
            "preshared_key": DQ("{{ vault_wg_psk_" + san(net_name) + "_" + san(other) + " }}"),
        }

        if net_type == "mesh":
            other_addr = host_address(net, other, topology)
            allowed = [f"{other_addr}/32"]
            member_routes = net.get("member_routes") or {}
            allowed += list(member_routes.get(other, []))
            peer["allowed_ips"] = [DQ(x) for x in allowed]
            peer["endpoint"] = DQ(peer_endpoint(topology, other, net_name, net["port"]))
            peer["persistent_keepalive"] = 25
        elif host == net["hub"]:
            client_addr = host_address(net, other, topology)
            peer["allowed_ips"] = [DQ(f"{client_addr}/32")]
            # no endpoint: client initiates
        else:
            if net.get("default_route"):
                peer["allowed_ips"] = [DQ("0.0.0.0/0"), DQ("::/0")]
            else:
                hub_addr = host_address(net, other, topology)
                allowed = [f"{hub_addr}/32"] + list(net.get("extra_routes", []))
                peer["allowed_ips"] = [DQ(x) for x in allowed]
            peer["endpoint"] = DQ(peer_endpoint(topology, other, net_name, net["port"]))
            peer["persistent_keepalive"] = 25

        peers.append(peer)
    return peers


def build_host_doc(host: str, topology: dict, state: State) -> dict:
    public_keys = {}
    instances = []

    for net_name, net in topology["networks"].items():
        if host not in participants(net):
            continue
        public_keys[net_name] = DQ(state.pub[(host, net_name)])

        addr = host_address(net, host, topology)
        plen = prefix_len(net)
        is_client = net["type"] == "hub" and host != net["hub"]

        inst = {
            "name": DQ(iface_name(net_name, net)),
            "address": [DQ(f"{addr}/{plen}")],
            "private_key": DQ("{{ vault_wireguard_" + san(net_name) + "_private_key }}"),
            "peers": peer_list_for(host, net_name, net, topology, state),
        }
        if not is_client:
            inst["listen_port"] = net["port"]
        if is_client and net.get("dns"):
            inst["dns"] = [DQ(x) for x in net["dns"]]
        installed, suppressed = route_plan(host, net_name, net, topology)
        if suppressed:
            inst["table"] = DQ("off")
            if installed:
                inst["post_up"] = [DQ(c) for c in table_off_post_up(installed)]
        instances.append(inst)

    return {
        "wireguard_public_keys": public_keys,
        "wireguard_instances": instances,
    }


def build_firewall_doc(host: str, topology: dict) -> dict:
    """Build ansible-enterprise firewall-role vars for a host.

    Emits:
      firewall_accept:     UDP accept for every wg listener (mesh member or hub)
      firewall_masquerade: SNAT for exit-hub subnets, out the host's wan_iface
    """
    host_cfg = topology["hosts"].get(host, {}) or {}
    wan = host_cfg.get("wan_iface", "eth0")
    accepts, masquerades = [], []
    for net_name, net in topology["networks"].items():
        if host not in participants(net):
            continue
        is_listener = net["type"] == "mesh" or host == net.get("hub")
        if is_listener:
            accepts.append({
                "proto": "udp",
                "port": net["port"],
                "comment": DQ(net_name),
            })
        # SNAT whenever the hub forwards beyond itself: a default-route exit
        # (egress to the internet) OR a split tunnel with extra_routes (egress to
        # the routed RFC1918 nets). Without this the routed hosts have no return
        # path for the tunnel subnet.
        if (net["type"] == "hub" and host == net.get("hub")
                and (net.get("default_route") or net.get("extra_routes"))):
            masquerades.append({
                "saddr": DQ(net["subnet"]),
                "oif": DQ(wan),
                "comment": DQ(f"{net_name} egress"),
            })
    return {
        "firewall_accept": accepts,
        "firewall_masquerade": masquerades,
    }


def build_vault_doc(host: str, net_name: str, net: dict, state: State) -> dict:
    doc = {
        f"vault_wireguard_{san(net_name)}_private_key": DQ(state.priv[(host, net_name)]),
    }
    for other in participants(net):
        if other == host:
            continue
        psk = state.psk[(net_name, pair_key(host, other))]
        doc[f"vault_wg_psk_{san(net_name)}_{san(other)}"] = DQ(psk)
    return doc


# ---------- netplan rendering ----------

def build_netplan_doc(host: str, topology: dict, state: State) -> dict:
    """Build a netplan document with one tunnel per WG network the host is on."""
    tunnels = {}
    for net_name, net in topology["networks"].items():
        if host not in participants(net):
            continue

        iface = iface_name(net_name, net)
        addr = host_address(net, host, topology)
        plen = prefix_len(net)
        is_client = net["type"] == "hub" and host != net["hub"]
        net_type = net["type"]

        tunnel = {
            "mode": "wireguard",
            "addresses": [DQ(f"{addr}/{plen}")],
            "key": DQ(state.priv[(host, net_name)]),
        }
        if not is_client:
            tunnel["port"] = net["port"]

        peers = []
        for other in participants(net):
            if other == host:
                continue
            if net_type == "hub" and host != net["hub"] and other != net["hub"]:
                continue

            peer = {
                "keys": {
                    "public": DQ(state.pub[(other, net_name)]),
                    "shared": DQ(state.psk[(net_name, pair_key(host, other))]),
                },
            }

            if net_type == "mesh":
                allowed = [f"{host_address(net, other, topology)}/32"]
                allowed += list((net.get("member_routes") or {}).get(other, []))
                peer["allowed-ips"] = [DQ(x) for x in allowed]
                peer["endpoint"] = DQ(peer_endpoint(topology, other, net_name, net["port"]))
                peer["keepalive"] = 25
            elif host == net["hub"]:
                peer["allowed-ips"] = [DQ(f"{host_address(net, other, topology)}/32")]
            else:
                if net.get("default_route"):
                    peer["allowed-ips"] = [DQ("0.0.0.0/0"), DQ("::/0")]
                else:
                    allowed = [f"{host_address(net, other, topology)}/32"]
                    allowed += list(net.get("extra_routes", []))
                    peer["allowed-ips"] = [DQ(x) for x in allowed]
                peer["endpoint"] = DQ(peer_endpoint(topology, other, net_name, net["port"]))
                peer["keepalive"] = 25

            peers.append(peer)
        tunnel["peers"] = peers

        routes = []
        _, suppressed = route_plan(host, net_name, net, topology)
        if is_client:
            hub_addr = host_address(net, net["hub"], topology)
            if net.get("default_route"):
                routes.append({"to": "default", "via": DQ(hub_addr)})
            else:
                for r in net.get("extra_routes", []):
                    if r not in suppressed:
                        routes.append({"to": DQ(r), "via": DQ(hub_addr)})
        elif net_type == "mesh":
            for other in participants(net):
                if other == host:
                    continue
                other_addr = host_address(net, other, topology)
                for r in (net.get("member_routes") or {}).get(other, []):
                    if r not in suppressed:
                        routes.append({"to": DQ(r), "via": DQ(other_addr)})
        if routes:
            tunnel["routes"] = routes

        if is_client and net.get("dns"):
            tunnel["nameservers"] = {"addresses": [DQ(x) for x in net["dns"]]}

        tunnels[iface] = tunnel

    return {
        "network": {
            "version": 2,
            "tunnels": tunnels,
        },
    }


# ---------- wg-quick conf rendering ----------

def peer_is_visible(host: str, other: str, net: dict) -> bool:
    """Whether `other` appears as a peer in `host`'s config for this network.

    Clients in a hub network peer only with the hub, never with each other.
    """
    if other == host:
        return False
    return not (net["type"] == "hub"
                and host != net["hub"]
                and other != net["hub"])


def peer_allowed_ips(host: str, other: str, net: dict, topology: dict) -> list:
    """AllowedIPs for peer `other`, as seen from `host`, in one network."""
    if net["type"] == "mesh":
        return ([f"{host_address(net, other, topology)}/32"]
                + list((net.get("member_routes") or {}).get(other, [])))
    if host == net["hub"]:
        return [f"{host_address(net, other, topology)}/32"]
    if net.get("default_route"):
        return ["0.0.0.0/0", "::/0"]
    return ([f"{host_address(net, other, topology)}/32"]
            + list(net.get("extra_routes", [])))


def render_wg_conf(host: str, net_name: str, net: dict,
                   topology: dict, state: State) -> str:
    """Render a ready-to-use wg-quick .conf file (secrets inlined)."""
    iface = iface_name(net_name, net)
    lines = [f"# {iface} on {host} - generated by gen_wireguard.py",
             "# DO NOT EDIT; regenerate via gen_wireguard.py",
             "",
             "[Interface]",
             f"PrivateKey = {state.priv[(host, net_name)]}",
             f"Address = {host_address(net, host, topology)}/{prefix_len(net)}"]

    is_client = net["type"] == "hub" and host != net["hub"]
    if not is_client:
        lines.append(f"ListenPort = {net['port']}")
    if is_client and net.get("dns"):
        lines.append(f"DNS = {', '.join(net['dns'])}")
    installed, suppressed = route_plan(host, net_name, net, topology)
    if suppressed:
        lines += [f"# local_networks: not routed into the tunnel: {', '.join(suppressed)}",
                  "Table = off"]
        lines += [f"PostUp = {c}" for c in table_off_post_up(installed)]

    for other in participants(net):
        if not peer_is_visible(host, other, net):
            continue

        lines += ["", f"# {other}", "[Peer]",
                  f"PublicKey = {state.pub[(other, net_name)]}",
                  f"PresharedKey = {state.psk[(net_name, pair_key(host, other))]}",
                  f"AllowedIPs = {', '.join(peer_allowed_ips(host, other, net, topology))}"]

        # the hub never dials a client; the client initiates
        if net["type"] == "mesh" or host != net["hub"]:
            lines.append(f"Endpoint = {peer_endpoint(topology, other, net_name, net['port'])}")
            lines.append("PersistentKeepalive = 25")

    return "\n".join(lines) + "\n"


# ---------- NetworkManager rendering ----------

def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def render_nm_keyfile(host: str, net_name: str, net: dict,
                      topology: dict, state: State) -> str:
    """Render a NetworkManager keyfile (.nmconnection) for one WG network.

    The GNOME/Ubuntu Settings VPN GUI is a NetworkManager front-end: it does
    not read /etc/wireguard at all, it stores connections as keyfiles under
    /etc/NetworkManager/system-connections/. Same key material as the
    wg-quick conf, different on-disk format.
    """
    iface = iface_name(net_name, net)
    is_client = net["type"] == "hub" and host != net["hub"]
    # Deterministic UUID: re-running the generator must update the existing
    # connection in place. A random one each run would leave NM holding a
    # pile of duplicates that all claim the same interface name.
    conn_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"wg://{host}/{iface}")

    lines = [f"# {iface} on {host} - generated by gen_wireguard.py",
             "# DO NOT EDIT; regenerate via gen_wireguard.py",
             "# install as root:root 0600 in /etc/NetworkManager/system-connections/",
             "# then: nmcli connection reload",
             "",
             "[connection]",
             f"id={iface}",
             f"uuid={conn_uuid}",
             "type=wireguard",
             f"interface-name={iface}",
             # these are on-demand tunnels; bringing them up is a deliberate act
             "autoconnect=false",
             "",
             "[wireguard]",
             f"private-key={state.priv[(host, net_name)]}",
             "private-key-flags=0"]
    if not is_client:
        lines.append(f"listen-port={net['port']}")
    installed, suppressed = route_plan(host, net_name, net, topology)
    if suppressed:
        # NM installs a route per allowed-ip by default; take over explicitly
        lines.append("peer-routes=false")

    for other in participants(net):
        if not peer_is_visible(host, other, net):
            continue
        allowed = peer_allowed_ips(host, other, net, topology)
        # the peer's public key is part of the section name in this format
        lines += ["", f"# {other}",
                  f"[wireguard-peer.{state.pub[(other, net_name)]}]",
                  f"preshared-key={state.psk[(net_name, pair_key(host, other))]}",
                  # without an explicit flags=0 NM treats the PSK as not-stored
                  # and silently brings the tunnel up without it
                  "preshared-key-flags=0",
                  f"allowed-ips={';'.join(allowed)};"]
        if net["type"] == "mesh" or host != net["hub"]:
            lines.append(
                f"endpoint={peer_endpoint(topology, other, net_name, net['port'])}")
            lines.append("persistent-keepalive=25")

    lines += ["",
              "[ipv4]",
              "method=manual",
              f"address1={host_address(net, host, topology)}/{prefix_len(net)}"]
    if is_client and net.get("dns"):
        # wg-quick's DNS= mixes both; NM splits them into two keys
        servers = [d for d in net["dns"] if _is_ip_literal(d)]
        domains = [d for d in net["dns"] if not _is_ip_literal(d)]
        if servers:
            lines.append(f"dns={';'.join(servers)};")
        if domains:
            lines.append(f"dns-search={';'.join(domains)};")
    if is_client and not net.get("default_route"):
        # split tunnel: never let this connection install a default route
        lines.append("never-default=true")
    if suppressed:
        lines += [f"route{i}={r}" for i, r in enumerate(installed, start=1)]

    # no v6 address is assigned on any of these tunnels
    lines += ["", "[ipv6]", "addr-gen-mode=default", "method=disabled"]

    return "\n".join(lines) + "\n"


# ---------- io ----------

def _write_private(path: Path, text: str) -> None:
    """Write `text` to `path` with mode 0600 from the moment the file exists.

    Creating the file with default permissions and chmod-ing afterwards leaves
    a window where secrets are world-readable, so the mode is set at open().
    os.open() ignores `mode` for an existing file, hence the explicit chmod.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    path.chmod(0o600)


def _dump_yaml(yaml: YAML, data: dict) -> str:
    buf = io.StringIO()
    buf.write("---\n")
    yaml.dump(data, buf)
    return buf.getvalue()


def write_yaml(yaml: YAML, path: Path, data: dict):
    """Write a public YAML document (mode left to the umask)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_dump_yaml(yaml, data))


def write_conf(path: Path, content: str):
    """Write a wg-quick / NetworkManager file that contains inlined secrets."""
    _write_private(path, content)


def write_yaml_secure(yaml: YAML, path: Path, data: dict):
    """Like write_yaml, but mode 0600 (use for files with secrets)."""
    _write_private(path, _dump_yaml(yaml, data))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--inventory", required=True,
                    help="inventory root (contains host_vars/)")
    ap.add_argument("-t", "--topology", required=True,
                    help="topology YAML file")
    ap.add_argument("--rotate", action="append", default=[],
                    help="network name to force-rotate (repeatable)")
    ap.add_argument("--state-dir",
                    help="persistent key store (default: <topology-dir>/state)")
    args = ap.parse_args()

    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)

    topology_path = Path(args.topology)
    topology = yaml.load(topology_path.read_text())
    validate_topology(topology)
    root = Path(args.inventory)
    state_root = Path(args.state_dir) if args.state_dir else topology_path.parent / "state"

    # state/ is authoritative; fall back to inventory for first-time migration
    state = load_state_from_dir(yaml, state_root)
    merge_state(state, load_state(yaml, root, topology))
    for net in args.rotate:
        if net not in topology["networks"]:
            sys.exit(f"unknown network in --rotate: {net}")
        state.drop_network(net)
    generate_missing(state, topology)

    all_hosts = set()
    for net in topology["networks"].values():
        all_hosts.update(participants(net))

    for host in sorted(all_hosts):
        host_cfg = topology["hosts"].get(host, {}) or {}
        emit_inventory = host_cfg.get("emit_inventory", True)
        emit_wg_conf = host_cfg.get("emit_wg_conf", True)
        emit_netplan = host_cfg.get("emit_netplan", True)
        emit_nm = host_cfg.get("emit_nm", True)

        if emit_inventory:
            write_yaml(yaml,
                       root / "inventory" / "host_vars" / host / "wireguard.yml",
                       build_host_doc(host, topology, state))
            write_yaml(yaml,
                       root / "inventory" / "host_vars" / host / "wireguard_firewall.yml",
                       build_firewall_doc(host, topology))
        if emit_netplan:
            write_yaml_secure(yaml,
                              root / "netplan" / host / "90-wireguard.yaml",
                              build_netplan_doc(host, topology, state))
        for net_name, net in topology["networks"].items():
            if host not in participants(net):
                continue
            if emit_inventory:
                write_yaml_secure(yaml,
                           root / "inventory" / "host_vars" / host / f"wireguard_vault_{net_name}.yml",
                           build_vault_doc(host, net_name, net, state))
            if emit_wg_conf:
                write_conf(root / "wireguard" / host / f"{iface_name(net_name, net)}.conf",
                           render_wg_conf(host, net_name, net, topology, state))
            if emit_nm:
                write_conf(root / "networkmanager" / host
                           / f"{iface_name(net_name, net)}.nmconnection",
                           render_nm_keyfile(host, net_name, net, topology, state))

    save_state_to_dir(yaml, state_root, state)

    print(f"wrote configs for {len(all_hosts)} hosts across "
          f"{len(topology['networks'])} networks"
          + (f"; rotated: {', '.join(args.rotate)}" if args.rotate else ""))
    print(f"ansible inventory:           {root / 'inventory'}")
    print(f"netplan drop-ins:            {root / 'netplan'}")
    print(f"ready-to-use wg-quick confs: {root / 'wireguard'}")
    print(f"NetworkManager keyfiles:     {root / 'networkmanager'}")
    print(f"persistent key state:        {state_root}")


if __name__ == "__main__":
    main()
