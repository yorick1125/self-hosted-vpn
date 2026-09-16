# Setup guide

End-to-end deployment of the WireGuard VPN on a fresh Ubuntu/Debian VPS.

## Prerequisites

- A cloud VPS (DigitalOcean, Linode, Hetzner, etc.) running Ubuntu 22.04+ or Debian 11+
- Root or sudo access over SSH
- An SSH key already installed for your user — `scripts/03-harden-server.sh` disables
  password login, so confirm key-based login works before running it

## 1. Install WireGuard

```bash
git clone https://github.com/yorick1125/self-hosted-vpn.git
cd self-hosted-vpn/scripts
chmod +x *.sh
sudo ./01-install-wireguard.sh
```

Installs `wireguard`/`wireguard-tools`/`qrencode`, generates the server keypair,
writes `/etc/wireguard/wg0.conf`, enables IPv4 forwarding, and starts `wg-quick@wg0`.

## 2. Configure the firewall

```bash
sudo ./02-configure-firewall.sh
```

Enables UFW, allows inbound SSH and the WireGuard UDP port, and denies everything
else inbound by default.

## 3. Harden the server

```bash
sudo CONFIRM_SSH_HARDENING=yes ./03-harden-server.sh
```

Disables SSH password auth and root login, installs `fail2ban` for SSH brute-force
protection, and enables unattended security updates. Requires the explicit
`CONFIRM_SSH_HARDENING=yes` flag as a safeguard against lockout.

## 4. Provision a client

```bash
sudo ./add-client.sh laptop
```

Generates a client keypair and preshared key, appends a `[Peer]` block to the
server config, writes `/etc/wireguard/clients/laptop.conf`, hot-reloads WireGuard
via `wg syncconf` (no restart needed), and prints a QR code for mobile clients.

Import the `.conf` file into the WireGuard app on desktop, or scan the QR code
on iOS/Android.

## 5. Revoke a client

```bash
sudo ./revoke-client.sh laptop
```

Removes the peer from the server and deletes the client's config file.

## Verifying the tunnel

From a connected client:

```bash
curl ifconfig.me        # should print the VPS's public IP
```

See [DNS-LEAK-PREVENTION.md](DNS-LEAK-PREVENTION.md) to confirm DNS queries are
also routed through the tunnel.

## Configuration knobs

All scripts source `scripts/00-config.sh`, which reads overrides from the
environment: `WG_INTERFACE`, `WG_PORT`, `WG_SUBNET_V4`, `WG_SERVER_IP_V4`,
`CLIENT_DNS`, `SSH_PORT`, `WG_PUBLIC_IP`. Example: run on a non-default port with
`WG_PORT=51821 sudo ./01-install-wireguard.sh`.
