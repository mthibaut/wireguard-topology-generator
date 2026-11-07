import os
import stat
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def write_fake_wg(bin_dir: Path) -> None:
    wg = bin_dir / "wg"
    wg.write_text(
        """#!/usr/bin/env python3
import base64
import hashlib
from pathlib import Path
import sys

def key(label):
    digest = hashlib.sha256(label.encode()).digest()
    return base64.b64encode(digest).decode()[:43] + "="

if sys.argv[1:] == ["genkey"]:
    state = Path(__file__).with_name(".counter")
    n = int(state.read_text()) if state.exists() else 0
    state.write_text(str(n + 1))
    print(key(f"private-{n}"))
elif sys.argv[1:] == ["pubkey"]:
    private = sys.stdin.read().strip()
    print(key(f"public-{private}"))
elif sys.argv[1:] == ["genpsk"]:
    state = Path(__file__).with_name(".counter")
    n = int(state.read_text()) if state.exists() else 0
    state.write_text(str(n + 1))
    print(key(f"psk-{n}"))
else:
    raise SystemExit(f"unexpected wg args: {sys.argv[1:]}")
"""
    )
    wg.chmod(wg.stat().st_mode | stat.S_IXUSR)


def run_generator(tmp_path: Path, *extra_args: str,
                  topology_path: Path | None = None) -> subprocess.CompletedProcess:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    write_fake_wg(bin_dir)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"

    return subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "gen_wireguard.py"),
            "-i",
            str(tmp_path / "out"),
            "-t",
            str(topology_path or REPO_ROOT / "topology.yml.example"),
            "--state-dir",
            str(tmp_path / "state"),
            *extra_args,
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )


def test_example_topology_generates_expected_outputs(tmp_path):
    result = run_generator(tmp_path)

    assert "wrote configs for 3 hosts across 3 networks" in result.stdout
    assert (tmp_path / "out/inventory/host_vars/node-a/wireguard.yml").exists()
    assert (tmp_path / "out/inventory/host_vars/client-1/wireguard_vault_home.yml").exists()
    assert (tmp_path / "out/netplan/client-1/90-wireguard.yaml").exists()
    assert (tmp_path / "out/wireguard/client-1/home.conf").exists()
    assert (tmp_path / "state/private_keys.yml").exists()


def test_networkmanager_keyfiles_are_emitted(tmp_path):
    run_generator(tmp_path)

    # iface naming is in flux, so glob rather than hard-code a filename
    keyfiles = sorted((tmp_path / "out/networkmanager/client-1").glob("*.nmconnection"))
    assert keyfiles, "no NetworkManager keyfiles emitted for client-1"

    text = keyfiles[0].read_text()
    assert "type=wireguard" in text
    # the peer's public key is carried in the section header in this format
    assert "[wireguard-peer." in text
    # without explicit flags=0 NetworkManager treats the secrets as not-stored
    assert "private-key-flags=0" in text
    assert "preshared-key-flags=0" in text
    # keyfile lists are semicolon-separated and semicolon-terminated
    for line in text.splitlines():
        if line.startswith("allowed-ips="):
            assert line.endswith(";")
    # secrets inlined -> must not be world-readable
    assert stat.S_IMODE(keyfiles[0].stat().st_mode) == 0o600


def test_networkmanager_uuid_is_stable_across_runs(tmp_path):
    """A fresh UUID each run would leave NetworkManager holding duplicates."""
    def uuids():
        return sorted(
            line
            for f in sorted((tmp_path / "out/networkmanager").rglob("*.nmconnection"))
            for line in f.read_text().splitlines()
            if line.startswith("uuid=")
        )

    run_generator(tmp_path)
    first = uuids()
    run_generator(tmp_path)

    assert first and first == uuids()


def test_generation_is_idempotent_with_persistent_state(tmp_path):
    run_generator(tmp_path)
    first_conf = (tmp_path / "out/wireguard/client-1/home.conf").read_text()
    first_state = (tmp_path / "state/private_keys.yml").read_text()

    run_generator(tmp_path)

    assert (tmp_path / "out/wireguard/client-1/home.conf").read_text() == first_conf
    assert (tmp_path / "state/private_keys.yml").read_text() == first_state


def test_rotation_changes_only_selected_network_state(tmp_path):
    run_generator(tmp_path)
    before = (tmp_path / "state/private_keys.yml").read_text()

    run_generator(tmp_path, "--rotate", "home")
    after = (tmp_path / "state/private_keys.yml").read_text()

    assert before != after
    assert "core:" in after
    assert "home:" in after


def test_iface_name_defaults_to_network_name_unless_overridden(tmp_path):
    """Default interface name is the bare network name; `iface:` overrides it.

    `exit-egress-node` is 17 chars and would exceed IFNAMSIZ, hence the
    explicit `iface: wg-exit-b` in the example topology.
    """
    run_generator(tmp_path)

    assert (tmp_path / "out/wireguard/client-1/home.conf").exists()
    assert (tmp_path / "out/wireguard/client-1/wg-exit-b.conf").exists()
    assert not (tmp_path / "out/wireguard/client-1/exit-egress-node.conf").exists()


def test_per_network_endpoint_override_only_affects_that_network(tmp_path):
    topology = tmp_path / "topology.yml"
    topology.write_text(
        (REPO_ROOT / "topology.yml.example").read_text().replace(
            "  node-b:\n"
            "    endpoint: vpn.example.org\n",
            "  node-b:\n"
            "    endpoint: vpn.example.org\n"
            "    endpoints:\n"
            "      core: vpn.example.org:40010\n",
        )
    )

    run_generator(tmp_path, topology_path=topology)

    core_conf = (tmp_path / "out/wireguard/node-a/core.conf").read_text()
    exit_conf = (tmp_path / "out/wireguard/client-1/wg-exit-b.conf").read_text()
    assert "Endpoint = vpn.example.org:40010" in core_conf
    assert "Endpoint = vpn.example.org:40003" in exit_conf


# ---------- local_networks: host inside a LAN another member advertises ----------

def _local_networks_topology(tmp_path: Path) -> Path:
    """Example topology where node-b sits inside the LAN that node-a
    advertises on core, and node-a also
    advertises a second, non-local network."""
    topology = tmp_path / "topology.yml"
    text = (REPO_ROOT / "topology.yml.example").read_text()
    text = text.replace(
        "  node-b:\n"
        "    endpoint: vpn.example.org\n",
        "  node-b:\n"
        "    endpoint: vpn.example.org\n"
        "    local_networks: [ \"10.10.0.0/16\" ]\n",
    )
    text = text.replace(
        'node-a: [ "10.10.0.0/16" ]',
        'node-a: [ "10.10.0.0/16", "10.30.0.0/16" ]',
    )
    topology.write_text(text)
    return topology


def _load(path: Path):
    from ruamel.yaml import YAML
    return YAML(typ="safe").load(path.read_text())


def test_local_networks_suppress_route_but_keep_allowed_ips(tmp_path):
    run_generator(tmp_path, topology_path=_local_networks_topology(tmp_path))
    out = tmp_path / "out"

    # wg-quick: take over routing, re-add only the non-local route
    conf = (out / "wireguard/node-b/core.conf").read_text()
    assert "Table = off" in conf
    assert "PostUp = ip route add 10.30.0.0/16 dev %i" in conf
    assert "ip route add 10.10.0.0/16" not in conf
    allowed = [l for l in conf.splitlines() if l.startswith("AllowedIPs")]
    assert any("10.10.0.0/16" in l for l in allowed), "must still accept LAN sources"

    # ansible inventory: same, via the role's table/post_up keys
    doc = _load(out / "inventory/host_vars/node-b/wireguard.yml")
    core = next(i for i in doc["wireguard_instances"] if i["name"] == "core")
    assert core["table"] == "off"
    assert core["post_up"] == ["ip route add 10.30.0.0/16 dev %i"]
    peer = next(p for p in core["peers"] if p["name"] == "node-a")
    assert "10.10.0.0/16" in peer["allowed_ips"]

    # netplan: the local route is simply not listed
    np = _load(out / "netplan/node-b/90-wireguard.yaml")
    routes = [r["to"] for r in np["network"]["tunnels"]["core"]["routes"]]
    assert routes == ["10.30.0.0/16"]

    # NetworkManager: no automatic peer routes, explicit route for the rest
    nm = (out / "networkmanager/node-b/core.nmconnection").read_text()
    assert "peer-routes=false" in nm
    assert "route1=10.30.0.0/16" in nm
    assert "10.10.0.0/16;" in nm  # still in allowed-ips

    # the advertising member is unaffected
    assert "Table" not in (out / "wireguard/node-a/core.conf").read_text()


def test_local_networks_cover_subnets_and_ignore_unrelated_routes():
    import ipaddress
    sys.path.insert(0, str(REPO_ROOT))
    import gen_wireguard as g

    lan = [ipaddress.ip_network("10.10.0.0/16")]
    assert g.is_local_route("10.10.0.0/16", lan)
    assert g.is_local_route("10.10.30.0/24", lan)
    assert not g.is_local_route("10.0.0.0/8", lan)
    assert not g.is_local_route("0.0.0.0/0", lan)   # a supernet is not local
    assert not g.is_local_route("::/0", lan)        # other address family


def test_hosts_without_local_networks_keep_wg_quick_routing(tmp_path):
    """Regression: the feature must not change output for anyone not using it."""
    run_generator(tmp_path)
    out = tmp_path / "out"
    for conf in (out / "wireguard").rglob("*.conf"):
        assert "Table" not in conf.read_text(), conf
    for nm in (out / "networkmanager").rglob("*.nmconnection"):
        assert "peer-routes" not in nm.read_text(), nm
    for doc_path in (out / "inventory/host_vars").glob("*/wireguard.yml"):
        for inst in _load(doc_path)["wireguard_instances"]:
            assert "table" not in inst and "post_up" not in inst, doc_path


def test_invalid_local_network_is_rejected(tmp_path):
    topology = tmp_path / "topology.yml"
    topology.write_text((REPO_ROOT / "topology.yml.example").read_text().replace(
        "  node-b:\n    endpoint: vpn.example.org\n",
        "  node-b:\n    endpoint: vpn.example.org\n"
        "    local_networks: [ \"10.10.0.0/33\" ]\n"))
    try:
        run_generator(tmp_path, topology_path=topology)
    except subprocess.CalledProcessError as e:
        assert "local_networks: invalid network" in e.stderr
    else:
        raise AssertionError("invalid CIDR was accepted")


# ---------- helpers for cross-checking the rendered outputs ----------

def _gen():
    sys.path.insert(0, str(REPO_ROOT))
    import gen_wireguard as g
    return g


def _iface(topo: dict, net_name: str) -> str:
    return topo["networks"][net_name].get("iface") or net_name


def _parse_conf(text: str):
    """Return (interface_dict, [peer_dict, ...]) from a wg-quick conf."""
    iface, peers, cur = {}, [], None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[Interface]":
            cur = iface
        elif line == "[Peer]":
            cur = {}
            peers.append(cur)
        else:
            key, _, value = line.partition(" = ")
            cur[key] = value
    return iface, peers


def _conf(out: Path, host: str, net_name: str, topo: dict):
    return _parse_conf(
        (out / "wireguard" / host / f"{_iface(topo, net_name)}.conf").read_text())


def _pub(out: Path, host: str, net_name: str) -> str:
    return _load(out / "inventory/host_vars" / host / "wireguard.yml")[
        "wireguard_public_keys"][net_name]


def _vault(out: Path, host: str, net_name: str) -> dict:
    return _load(out / "inventory/host_vars" / host / f"wireguard_vault_{net_name}.yml")


def _is_default_client(net: dict, host: str) -> bool:
    return (net["type"] == "hub" and host != net["hub"]
            and bool(net.get("default_route")))


def _write_topology(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "topology.yml"
    path.write_text(text)
    return path


def _expect_rejected(tmp_path: Path, text: str, message: str) -> None:
    try:
        run_generator(tmp_path, topology_path=_write_topology(tmp_path, text))
    except subprocess.CalledProcessError as e:
        assert message in e.stderr, e.stderr
    else:
        raise AssertionError(f"topology was accepted; expected: {message}")


# ---------- cross-checks: the outputs must agree with each other ----------

def test_every_peer_pair_agrees_on_keys_psk_endpoint_and_routes(tmp_path):
    """For every visible pair (a, b): a's config and b's config must name each
    other's current public key, share one PSK, and route each other's tunnel
    address (unless the client is on a default route, where AllowedIPs is 0/0)."""
    run_generator(tmp_path)
    out = tmp_path / "out"
    topo = _load(REPO_ROOT / "topology.yml.example")
    g = _gen()
    checked = 0
    for net_name, net in topo["networks"].items():
        parts = g.participants(net)
        for a in parts:
            for b in parts:
                if a == b or not g.peer_is_visible(a, b, net):
                    continue
                checked += 1
                _, peers_a = _conf(out, a, net_name, topo)
                _, peers_b = _conf(out, b, net_name, topo)
                peer_a = next(p for p in peers_a if p["PublicKey"] == _pub(out, b, net_name))
                peer_b = next(p for p in peers_b if p["PublicKey"] == _pub(out, a, net_name))

                psk_a = _vault(out, a, net_name)[f"vault_wg_psk_{g.san(net_name)}_{g.san(b)}"]
                psk_b = _vault(out, b, net_name)[f"vault_wg_psk_{g.san(net_name)}_{g.san(a)}"]
                assert peer_a["PresharedKey"] == psk_a == psk_b, (net_name, a, b)
                assert peer_b["PresharedKey"] == psk_a, (net_name, a, b)

                if not _is_default_client(net, a):
                    assert f"{g.host_address(net, b, topo)}/32" in peer_a["AllowedIPs"].split(", ")
                if not _is_default_client(net, b):
                    assert f"{g.host_address(net, a, topo)}/32" in peer_b["AllowedIPs"].split(", ")

                # who dials whom: the hub never sets an Endpoint for a client
                a_dials = net["type"] == "mesh" or a != net["hub"]
                b_dials = net["type"] == "mesh" or b != net["hub"]
                assert ("Endpoint" in peer_a) == a_dials, (net_name, a, b)
                assert ("Endpoint" in peer_b) == b_dials, (net_name, b, a)
    assert checked == 6  # core: 2 directions; home and exit-egress-node: 2 each


def test_wg_conf_netplan_and_networkmanager_agree_per_peer(tmp_path):
    """The three renderings of one tunnel must describe the same peers,
    AllowedIPs and endpoints. They are written by separate code paths."""
    run_generator(tmp_path)
    out = tmp_path / "out"
    topo = _load(REPO_ROOT / "topology.yml.example")
    g = _gen()
    for host in ("node-a", "node-b", "client-1"):
        netplan = _load(out / "netplan" / host / "90-wireguard.yaml")["network"]["tunnels"]
        for net_name, net in topo["networks"].items():
            if host not in g.participants(net):
                continue
            iface = _iface(topo, net_name)
            _, conf_peers = _conf(out, host, net_name, topo)
            conf = {p["PublicKey"]: p for p in conf_peers}

            np_peers = {p["keys"]["public"]: p for p in netplan[iface]["peers"]}
            nm_text = (out / "networkmanager" / host / f"{iface}.nmconnection").read_text()
            nm = _nm_peers(nm_text)

            assert set(conf) == set(np_peers) == set(nm), (host, net_name)
            for key, cp in conf.items():
                want_allowed = set(cp["AllowedIPs"].split(", "))
                assert set(np_peers[key]["allowed-ips"]) == want_allowed, (host, net_name)
                assert set(nm[key]["allowed-ips"].rstrip(";").split(";")) == want_allowed, (host, net_name)
                want_ep = cp.get("Endpoint")
                assert np_peers[key].get("endpoint") == want_ep, (host, net_name)
                assert nm[key].get("endpoint") == want_ep, (host, net_name)


def _nm_peers(text: str) -> dict:
    peers, cur = {}, None
    for line in text.splitlines():
        if line.startswith("[wireguard-peer."):
            cur = line[len("[wireguard-peer."):-1]
            peers[cur] = {}
        elif line.startswith("["):
            cur = None
        elif cur is not None and "=" in line:
            key, _, value = line.partition("=")
            peers[cur][key] = value
    return peers


def test_firewall_rules_match_listeners_and_egress(tmp_path):
    run_generator(tmp_path)
    fw = lambda h: _load(tmp_path / "out/inventory/host_vars" / h / "wireguard_firewall.yml")

    node_a = fw("node-a")
    assert {"proto": "udp", "port": 40001, "comment": "core"} in node_a["firewall_accept"]
    assert {"proto": "udp", "port": 40002, "comment": "home"} in node_a["firewall_accept"]
    # no wan_iface set for node-a in the example -> documented default eth0
    assert node_a["firewall_masquerade"] == [
        {"saddr": "10.100.1.0/24", "oif": "eth0", "comment": "home egress"}]

    strange = fw("node-b")
    ports = {r["comment"]: r["port"] for r in strange["firewall_accept"]}
    assert ports == {"core": 40001, "exit-egress-node": 40003}
    assert strange["firewall_masquerade"] == [
        {"saddr": "10.100.2.0/24", "oif": "ens3", "comment": "exit-egress-node egress"}]

    # a pure client listens on nothing and masquerades nothing
    assert fw("client-1")["firewall_accept"] == []
    assert fw("client-1")["firewall_masquerade"] == []


def test_default_route_client_routes_everything_through_the_hub(tmp_path):
    run_generator(tmp_path)
    out = tmp_path / "out"
    topo = _load(REPO_ROOT / "topology.yml.example")

    iface, peers = _conf(out, "client-1", "exit-egress-node", topo)
    assert peers[0]["AllowedIPs"] == "0.0.0.0/0, ::/0"
    assert iface["DNS"] == "1.1.1.1"
    assert "Table" not in iface

    np = _load(out / "netplan/client-1/90-wireguard.yaml")["network"]["tunnels"]["wg-exit-b"]
    assert np["routes"] == [{"to": "default", "via": "10.100.2.1"}]
    assert np["nameservers"] == {"addresses": ["1.1.1.1"]}

    nm = (out / "networkmanager/client-1/wg-exit-b.nmconnection").read_text()
    assert "never-default=true" not in nm   # default route is the point of this tunnel
    assert "dns=1.1.1.1;" in nm


def test_nm_splits_dns_servers_from_search_domains(tmp_path):
    topo = (REPO_ROOT / "topology.yml.example").read_text().replace(
        'dns: [ "1.1.1.1" ]', 'dns: [ "1.1.1.1", "corp.example" ]')
    run_generator(tmp_path, topology_path=_write_topology(tmp_path, topo))
    nm = (tmp_path / "out/networkmanager/client-1/wg-exit-b.nmconnection").read_text()
    assert "dns=1.1.1.1;" in nm
    assert "dns-search=corp.example;" in nm
    conf = (tmp_path / "out/wireguard/client-1/wg-exit-b.conf").read_text()
    assert "DNS = 1.1.1.1, corp.example" in conf


def test_first_run_imports_keys_from_inventory_when_state_is_missing(tmp_path):
    """Migration path: with state/ gone, keys come back from the inventory."""
    run_generator(tmp_path)
    before_priv = (tmp_path / "state/private_keys.yml").read_text()
    before_psk = (tmp_path / "state/preshared_keys.yml").read_text()
    before_pub = (tmp_path / "state/public_keys.yml").read_text()

    for f in (tmp_path / "state").glob("*.yml"):
        f.unlink()
    run_generator(tmp_path)

    assert (tmp_path / "state/private_keys.yml").read_text() == before_priv
    assert (tmp_path / "state/preshared_keys.yml").read_text() == before_psk
    assert (tmp_path / "state/public_keys.yml").read_text() == before_pub


def test_secret_bearing_files_are_private_from_creation(tmp_path):
    run_generator(tmp_path)
    out = tmp_path / "out"
    secret_files = [
        *(out / "inventory/host_vars").glob("*/wireguard_vault_*.yml"),
        *(out / "netplan").rglob("*.yaml"),
        *(out / "wireguard").rglob("*.conf"),
        *(out / "networkmanager").rglob("*.nmconnection"),
        tmp_path / "state/private_keys.yml",
        tmp_path / "state/preshared_keys.yml",
    ]
    assert secret_files
    for f in secret_files:
        assert stat.S_IMODE(f.stat().st_mode) == 0o600, f


# ---------- validation: wrong output must be refused, not rendered ----------

def test_mesh_with_more_members_than_subnet_holds_is_rejected(tmp_path):
    _expect_rejected(tmp_path, """
hosts:
  a: {endpoint: 10.200.0.1}
  b: {endpoint: 10.200.0.2}
  c: {endpoint: 10.200.0.3}
networks:
  core: {type: mesh, port: 40001, subnet: 10.100.0.0/30, members: [a, b, c]}
""", "do not fit")


def test_client_octet_colliding_with_hub_is_rejected(tmp_path):
    _expect_rejected(tmp_path, """
hosts:
  hub1: {endpoint: 10.200.0.1}
clients:
  client-1: {octet: 1}
networks:
  home: {type: hub, port: 40002, subnet: 10.100.1.0/24, hub: hub1, clients: [client-1]}
""", "1 is the hub")


def test_two_clients_sharing_an_octet_is_rejected(tmp_path):
    _expect_rejected(tmp_path, """
hosts:
  hub1: {endpoint: 10.200.0.1}
clients:
  client-1: {octet: 50}
  phone: {octet: 50}
networks:
  home: {type: hub, port: 40002, subnet: 10.100.1.0/24, hub: hub1, clients: [client-1, phone]}
""", "share octet 50")


def test_network_member_missing_from_hosts_is_rejected(tmp_path):
    _expect_rejected(tmp_path, """
hosts:
  a: {endpoint: 10.200.0.1}
networks:
  core: {type: mesh, port: 40001, subnet: 10.100.0.0/28, members: [a, ghost]}
""", "no entry under `hosts:`")


def test_mesh_member_without_endpoint_is_rejected(tmp_path):
    _expect_rejected(tmp_path, """
hosts:
  a: {endpoint: 10.200.0.1}
  b: {}
networks:
  core: {type: mesh, port: 40001, subnet: 10.100.0.0/28, members: [a, b]}
""", "needs `endpoint:`")


def test_duplicate_interface_names_are_rejected(tmp_path):
    _expect_rejected(tmp_path, """
hosts:
  a: {endpoint: 10.200.0.1}
  b: {endpoint: 10.200.0.2}
networks:
  core: {type: mesh, port: 40001, subnet: 10.100.0.0/28, members: [a, b], iface: wg0}
  other: {type: mesh, port: 40002, subnet: 10.100.3.0/28, members: [a, b], iface: wg0}
""", "both use interface name")


def test_missing_wg_binary_gives_a_clear_error(tmp_path):
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "gen_wireguard.py"),
         "-i", str(tmp_path / "out"), "-t", str(REPO_ROOT / "topology.yml.example"),
         "--state-dir", str(tmp_path / "state")],
        env={"PATH": ""}, capture_output=True, text=True)
    assert result.returncode != 0
    assert "wg(8) not found" in result.stderr
    assert "Traceback" not in result.stderr


def test_bare_ipv6_endpoints_get_brackets_and_a_port():
    g = _gen()
    assert g._with_port("vpn.example.org", 40001) == "vpn.example.org:40001"
    assert g._with_port("10.200.0.1", 40001) == "10.200.0.1:40001"
    assert g._with_port("10.200.0.1:40099", 40001) == "10.200.0.1:40099"
    assert g._with_port("2001:db8::1", 40001) == "[2001:db8::1]:40001"
    assert g._with_port("[2001:db8::1]", 40001) == "[2001:db8::1]:40001"
    assert g._with_port("[2001:db8::1]:40099", 40001) == "[2001:db8::1]:40099"
