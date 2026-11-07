# Wireguard config generator

[![CI](https://github.com/mthibaut/wireguard-topology-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/mthibaut/wireguard-topology-generator/actions/workflows/ci.yml)

Topology-driven WireGuard config generator that emits Ansible `host_vars`,
ready-to-use `wg-quick` interface configs, and netplan tunnel drop-ins.

Given a declarative `topology.yml` describing hosts, networks, and clients, the
generator renders per-host configs for four deployment styles:

- Ansible roles can use the inventory fragments
- Systems using `wg-quick@<iface>` can drop the generated `.conf` files
  directly in `/etc/wireguard`
- Netplan configs for `/etc/netplan`
- NetworkManager keyfiles for `/etc/NetworkManager/system-connections/` —
  what the GNOME/Ubuntu **Settings → Network → VPN** GUI actually reads. It
  does not look at `/etc/wireguard` at all, so a tunnel configured there is
  invisible to the GUI (and vice versa). Install as `root:root` mode `0600`,
  then `nmcli connection reload`. Disable per host with `emit_nm: false`.

The generator preserves keys whenever the topology is modified (inside the
state directory).

Designed for a **split-purpose, multi-interface** setup: don't cram all
WireGuard traffic into one interface but separate tunnel networks for
server↔server traffic, remote-LAN access, and exit-node use.

## Contents

- [`gen_wireguard.py`](gen_wireguard.py) — the generator. Idempotent; reads
  existing key material and only creates what's missing.
- [`topology.yml.example`](topology.yml.example) — worked example with a
  two-server mesh, one roaming client-1, and three networks. Copy to
  `topology.yml` and adapt.
- `state/` — persistent key store containing the symmetric keys (PSKs) and public/private WireGuard keys (gitignored).

## Quick start

Install from a checkout:

```sh
python3 -m pip install .
```

Or run the script directly after installing the one Python dependency:

```sh
python3 -m pip install ruamel.yaml           # only dependency beyond stdlib + wg(8)
cp topology.yml.example topology.yml
./gen_wireguard.py -i out -t topology.yml
```

If installed as a package, use the console command:

```sh
gen-wireguard -i out -t topology.yml
```

Rotate one network's keys (everything else is preserved):

```sh
./gen_wireguard.py -i out -t topology.yml --rotate exit-egress-node
```

After generating, encrypt the vault files:

```sh
ansible-vault encrypt out/inventory/host_vars/*/wireguard_vault_*.yml
```

## Design

### Per-interface compartmentalization

Each logical use case gets its **own** WireGuard interface using its own
address space:

| Interface | Purpose | Routes |
|---|---|---|
| `wg-core`   | always-on server↔server mesh | just the other servers' /32s (+ any advertised LANs) |
| `wg-home`   | remote access to home LAN via a gateway host | `10.10.x.0/24` only — no default-route hijack |
| `wg-exit-*` | exit-node tunnels (your VPN exit nodes) | `0.0.0.0/0, ::/0` — default route, DNS pinned |

Machines in multiple networks reuse the final octet in the IP address.

Benefits over a single interface:

- Explicit routing per use case
- `wg-home` and any `wg-exit-*` can coexist: connect to your home network
  or your private exit server at will
- Manipulate the tunnels separately without impacting the other ones

### Key handling

All keys are reused:

- `state/` is the authoritative store — delete the generator's `-i` output
  directory and rerun.
- Keys are **never** rotated implicitly. Use `--rotate <network>` to
  regenerate if needed
- First-run migration: if there is no `state/`, keys from the ansible
  inventory are imported if present

Pairwise PSKs per network: each unordered pair `{a, b}` of participants shares
one PSK. Count per network: `N·(N−1)/2` for mesh, `N` for hub (one per
client).

### Output layout

Under the `-i/--inventory` root (e.g. `out/`):

```
<root>/inventory/host_vars/<host>/
├── wireguard.yml                 # public: pubkeys + wireguard_instances[]
├── wireguard_firewall.yml        # firewall_accept + firewall_masquerade lists
├── wireguard_vault_core.yml      # secret: private key + PSKs for this network
├── wireguard_vault_home.yml
└── wireguard_vault_<net>.yml     # one per network the host participates in

<root>/netplan/<host>/
└── 90-wireguard.yaml             # netplan drop-in (systemd-networkd / NM)

<root>/wireguard/<host>/
└── <iface>.conf                  # ready-to-use wg-quick confs (secrets inlined)
```

`wireguard.yml` is merged across all networks for the host
(`wireguard_instances` is a list of per-interface dicts). Vault files are
split per network so one network's secrets can be rotated and re-encrypted
independently.

### Hosts inside a routed LAN (`local_networks`)

A mesh member that advertises a LAN (`member_routes: { gw: [10.10.0.0/16] }`)
makes every other member route that LAN into the tunnel. That is right for
members out on the internet, and wrong for a member that **sits inside** that
LAN: it then answers LAN clients outside its own subnet (VPN clients, other
VLANs) through the tunnel, the far end drops the reply because its source is
not in that peer's AllowedIPs, and those clients simply time out.

Declare what such a host already reaches without a tunnel:

```yaml
hosts:
  lan-server:
    local_networks: [ "10.10.0.0/16" ]   # own LAN + whatever its gateway routes
```

Any tunnel route inside (or equal to) a local network is then **kept in
AllowedIPs** — so traffic forwarded to the host through the tunnel from those
networks is still accepted — but **not installed as a route**:

- wg-quick / ansible inventory: `Table = off` plus `PostUp = ip route add <r>
  dev %i` for the remaining routes (inventory keys `table` / `post_up`)
- netplan: the route is omitted from `routes`
- NetworkManager: `peer-routes=false` plus explicit `routeN=` entries

Hosts without `local_networks` are unaffected. It cannot be combined with a
default-route network on the same host.

### Firewall rule emission

For each host participating in the topology, the generator writes a
`wireguard_firewall.yml` host_var consumable by an ansible firewall role:

- `firewall_accept` — one UDP accept per WireGuard listener (mesh member
  or hub).
- `firewall_masquerade` — SNAT for each exit-hub subnet out the host's
  `wan_iface` (defaults to `eth0`).

DNAT (for split hubs where a frontline firewall forwards UDP to a back-of-house 
WG server) and forward-chain rules between WG interfaces and local LANs are
not created.

### Per-host emit flags

Set on entries under `hosts:` in `topology.yml`. All default to `true`.

- `emit_wg_conf: false` — skip wg-quick `.conf` generation for this host
  (useful when the host is configured via an ansible role that consumes the
  host_vars instead).
- `emit_inventory: false` — skip ansible host_vars (including firewall-rule)
  emission (useful for hosts not managed by ansible).
- `emit_netplan: false` — skip netplan drop-in generation (useful for hosts
  not running netplan, e.g. FreeBSD, Alpine, Arch).

## Example

Look at `topology.yml.example` for a worked-out example. After running the 
generator the resulting ansible host_vars look like this:

```yaml
wireguard_instances:
  - name: wg-core                             # also used as wg-quick@<name>
    listen_port: 40001                        # OPTIONAL — omit on roaming clients
    address: ["10.100.0.1/28"]
    private_key: "{{ vault_wireguard_core_private_key }}"
    dns: ["1.1.1.1"]                          # OPTIONAL — set for default-route interfaces
    peers:
      - name: node-b                    # OPTIONAL — emitted as `# node-b` comment
        public_key: "..."
        preshared_key: "{{ vault_wg_psk_core_node_b }}"  # OPTIONAL but always emitted
        allowed_ips: ["10.100.0.2/32"]
        endpoint: "node-b.example.com:40001"  # OPTIONAL — omitted for hub→client peers
        persistent_keepalive: 25              # OPTIONAL
```

## Caveats

- No IPv6 interface addressing yet; default-route peers still include ::/0.
- A client's `octet:` is reused across every hub network it joins (so `client-1`
  is `.50` in every `/24`).
- The gateway gets `network_address + 1`. Member `i` gets
  `network_address + 1 + i`. A `/28` fits 14 members, a `/30` fits 2. No
  collision checking.
- **Endpoints.** `hosts[x].endpoint` is the default hostname or IP, with the
  network port appended automatically. Use `hosts[x].endpoints.<network>` to
  override a specific peer endpoint, including the port, when DNAT or split
  public addresses require it.
- **Name sanitization collisions.** Host and network names are sanitized
  (hyphens → underscores) for use in Ansible variable names. Two names that
  sanitize to the same string (e.g., `exit-us` and `exit_us`) will collide.
- **Interface name length (IFNAMSIZ = 15).** The Linux kernel caps network
  interface names at 15 chars. You can use `iface:` to override the generated
  `wg_network` name if it gets too long. 


## License

MIT — see [LICENSE](LICENSE).
