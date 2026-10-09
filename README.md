# self-hosted-vpn

[![CI](https://github.com/yorick1125/self-hosted-vpn/actions/workflows/ci.yml/badge.svg)](https://github.com/yorick1125/self-hosted-vpn/actions/workflows/ci.yml)

A self-hosted WireGuard VPN managed by **`wgm`**, a small Go CLI that runs on the VPN server
itself. One static binary, no dependencies beyond `wireguard-tools`, no web UI to attack.

```console
$ sudo wgm init --endpoint vpn.example.com
Server ready on wg0 (UDP 51820), subnet 10.8.0.0/24, NAT via eth0.

$ sudo wgm add laptop --qr          # scan with the WireGuard phone app, or:
$ sudo wgm add laptop > laptop.conf

$ sudo wgm list
NAME    IP        STATUS   LAST HANDSHAKE  RX       TX       ENDPOINT
laptop  10.8.0.2  online   12s ago         4.2 MiB  1.1 MiB  198.51.100.4:41000
phone   10.8.0.3  offline  never           0 B      0 B      -

$ sudo wgm revoke laptop            # access cut immediately
```

Bash scripts in `scripts/` handle the rest of the server: UFW firewall and SSH hardening.

## Security design

| Decision | Why |
|---|---|
| Keys generated in-process (Go `crypto/ecdh`, X25519) | Private keys never pass through another process, pipe or argv |
| Every client gets a preshared key | Adds a symmetric layer on top of Curve25519 (post-quantum hedge) |
| Client names restricted to `[A-Za-z0-9_-]`, max 32 | Blocks path traversal (`../`) and config injection via newlines |
| Endpoint, DNS and interface names validated | A bad value can't inject `PostUp =` commands into a config that runs as root |
| Config files `0600`, directories `0700` | Only root can read keys |
| Atomic writes (temp file + `fsync` + rename) | A crash or full disk never leaves a half-written `wg0.conf` |
| Exclusive file lock on every change | Two concurrent `wgm add` can't hand out the same IP (tested with 20 in parallel) |
| Live changes via `wg syncconf` | Adding or revoking a client never drops other users' connections |
| Clients route `0.0.0.0/0, ::/0` | All DNS goes through the tunnel; IPv6 is blackholed rather than leaked |
| `init` refuses to overwrite | Re-running it can't rotate the server key and silently break every client |
| `--dry-run` on every command | Preview exactly what would change on a production server |

## Install

```bash
# On the server (Debian/Ubuntu)
sudo apt install wireguard-tools qrencode
go install github.com/yorick1125/self-hosted-vpn/cmd/wgm@latest   # or download from CI artifacts
sudo cp ~/go/bin/wgm /usr/local/bin/

git clone https://github.com/yorick1125/self-hosted-vpn.git && cd self-hosted-vpn/scripts
sudo ./02-configure-firewall.sh                     # allow SSH + WireGuard only
sudo wgm init --endpoint <your-server-ip-or-domain>
sudo CONFIRM_SSH_HARDENING=yes ./03-harden-server.sh
sudo wgm add laptop --qr
```

## Commands

```
wgm init   [--address 10.8.0.1/24] [--port 51820] [--endpoint HOST] [--dns IPs] [--wan-iface IF]
wgm add    <name> [--qr]       create a client and print its config
wgm list   [--json]            clients with live status (alias: ls)
wgm show   <name> [--qr]       print an existing client's config
wgm revoke <name>              remove a client and cut its access (alias: rm)

Every command: --dir (default /etc/wireguard), --iface (default wg0), --dry-run
```

Status messages go to stderr, so `wgm add x > x.conf` captures only the config and
`wgm list --json` pipes cleanly into `jq`.

`wgm` reads and writes the same `# BEGIN client-<name>` layout as the original Bash scripts,
so a server set up with `scripts/add-client.sh` can be taken over by `wgm` with no migration.

## Testing

```bash
go test -race ./...                   # unit + CLI tests, any OS
sudo ./tests/integration-wgm.sh       # real WireGuard: live sync and an actual handshake
./tests/run-tests.sh                  # Bash script suite
```

The integration test brings up a real server interface, provisions clients with `wgm`,
completes a WireGuard handshake from a second interface, then revokes the client and checks
the peer is gone from the running interface. CI runs all three, plus `go vet`, `gofmt`,
`govulncheck` and `shellcheck`, and cross-compiles `amd64`/`arm64` binaries.

More on the script-level tests and verifying a real deployment: [docs/TESTING.md](docs/TESTING.md).
DNS leak details: [docs/DNS-LEAK-PREVENTION.md](docs/DNS-LEAK-PREVENTION.md).

## Layout

```
cmd/wgm/               CLI entry point and end-to-end CLI tests
internal/wgkey/        X25519 key generation (stdlib only, RFC 7748 test vector)
internal/wgconf/       server/client config parsing, rendering, IP allocation
internal/manager/      init/add/revoke/list, locking, atomic writes, live sync
scripts/               firewall + SSH hardening (and the original Bash client tools)
tests/                 Bash suite and the live WireGuard integration test
docs/                  setup guide, DNS leak prevention, testing
```
