# DoU

DoU means **DNS-over-USTPS**.

This project uses the current `USTP-Secure` transport base and tunnels DNS packets over `USTPS`.

## Architecture

- `server.py`
  - accepts USTPS clients
  - receives DNS queries over USTPS
  - resolves them directly in Python
  - returns the raw DNS response over USTPS

- `client.py`
  - connects to the DoU server over USTPS
  - exposes a local UDP DNS socket
  - receives local DNS queries from the OS or applications
  - forwards each one over USTPS
  - returns the raw DNS reply locally

## Current scope

- Python DoU server/client included
- native OpenWrt client package source included
- no TCP tunnel
- raw DNS packets over USTPS
- TOFU supported like USTP-Secure
- optional USTPS cleartext mode also supported if you explicitly ask for it
- optional DNS64 mode is supported on the server
- DNS64 stays off by default; on manual startup the server can ask whether you want to enable it

## Transport notes

- DoU reuses the `USTPS` handshake:
  - X25519 session key derivation
  - TOFU server key verification
  - optional `USTPS Congestion`
  - optional cleartext + HMAC mode
- DNS requests are multiplexed with a DoU-level `request_id`
- transport itself is still unordered
- request/response matching happens at the DoU layer, not by arrival order

## Server

Example:

```bash
python3 server.py \
  --bind-port 4053 \
  --dns64 off
```

Without `--start`, this configures the service and exits.

To actually run the server in the foreground:

```bash
python3 server.py --start
```

Enable DNS64:

```bash
python3 server.py \
  --bind-port 4053 \
  --dns64 on \
  --dns64-prefix 64:ff9b::/96
```

DNS64 behavior:

- if a domain already has real `AAAA` records, the server returns them normally
- if a domain only has `A` records, the server synthesizes `AAAA` records using the configured prefix
- the default DNS64 prefix is the RFC well-known NAT64 prefix:
  - `64:ff9b::/96`
- on manual interactive startup, if DNS64 is still `off`, the server asks whether you want to enable it
- if you enable DNS64 there, the generated `systemd` unit also keeps that choice

## Client

Example:

```bash
python3 client.py \
  --server <SERVER_IP_OR_DOMAIN> \
  --local-dns-port 4333
```

Without `--start`, this configures the client service and exits.

To actually run the client in the foreground:

```bash
python3 client.py --start --server <SERVER_IP_OR_DOMAIN>
```

Then point your local resolver or app to:

```text
::1:4333
```

If you start the client manually without `--server`, it will ask you for the DoU server first.

Accepted formats:

```text
x1co.com.br
x1co.com.br:4053
1.2.3.4
1.2.3.4:4053
[2001:db8::1]
[2001:db8::1]:4053
```

## OpenWrt

The `DoU` repo keeps the Python-oriented OpenWrt bootstrap path:

- `openwrt/`
  - quick Python-based bootstrap for larger devices

The native package source tree was split out into the separate `DoU-OpenWrt` repo/directory so the router-specific packaging can evolve independently.

Files:
- `openwrt/dou.uci`
- `openwrt/dou.init`
- `openwrt/apply_uci.sh`

What it does:
- installs a UCI config for DoU
- installs an OpenWrt init/procd service for the DoU client
- can automatically point `dnsmasq` to the local DoU listener

Important:
- it still needs the real server values before it can work
- especially:
  - `server`
  - optional `peer_port`
  - cipher / cleartext / congestion settings if you want different ones

Suggested OpenWrt flow:

```sh
cd /root/DoU
sh ./openwrt/apply_uci.sh
uci set dou.main.server='YOUR_SERVER_IP_OR_DOMAIN'
uci set dou.main.enabled='1'
uci commit dou
/etc/init.d/dou restart
/etc/init.d/dnsmasq restart
```

Local DNS target on OpenWrt:
- default local listener: `::1:4333`
- the native client now accepts IPv4 or IPv6 listener addresses

The init script runs:
- `python3 /root/DoU/client.py ...`

If you want another project path on OpenWrt, edit:
- `openwrt/dou.init`

## Native OpenWrt Package

The native OpenWrt package now lives in the separate `DoU-OpenWrt` directory/repo.

That split keeps:
- `DoU`
  - Python server
  - Python client
  - Python-based OpenWrt bootstrap
- `DoU-OpenWrt`
  - native `.ipk` packaging
  - native `C` client
  - small-router footprint tuning

## Systemd

The Python DoU server now installs its `systemd` unit automatically when:

- `systemd` is available
- the process is running as `root`
- the generated unit needs to be installed or updated

The generated server unit keeps only the necessary flags:

- `--start`
- `--bind-port`
- `--dns64`
- `--dns64-prefix` only when different from the default

The generated client unit keeps only the necessary flags:

- `--start`
- `--server`
- `--local-dns-port` only when different from the default

The Python DoU client now also installs its `systemd` unit automatically when:

- `systemd` is available
- the process is running as `root`
- the generated unit needs to be installed or updated

The client configures `dnsmasq` automatically:

- it writes `no-resolv`
- it writes a plain `server=::1#4333` line into `/etc/dnsmasq.conf`

```text
/etc/dnsmasq.conf
no-resolv
server=::1#4333
```

## Recovery

- if the network drops temporarily, the client now keeps running and keeps trying to rebuild the USTPS transport
- local DNS requests may still time out or return `SERVFAIL` while the uplink is down
- once connectivity comes back, the client reconnects without needing a manual restart

For the client, the installed service automatically stores the chosen DoU server in:

```text
--server <HOST_OR_IP[:PORT]>
```

So after that, the service does not need to prompt again.
