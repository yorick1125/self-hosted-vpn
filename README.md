# self-hosted-vpn
Self-hosted WireGuard VPN deployed on a cloud VPS — covers server hardening, firewall configuration, encrypted tunneling, and automated client provisioning.

This project documents the end-to-end setup of a self-hosted VPN server using WireGuard on a cloud-based Linux VPS. It covers server provisioning, network interface configuration, firewall rules with UFW, DNS leak prevention, and a Bash script for generating client configs. Built to demonstrate practical skills in Linux administration, cloud infrastructure, and network security.

## Quick start

```bash
git clone https://github.com/yorick1125/self-hosted-vpn.git
cd self-hosted-vpn/scripts
chmod +x *.sh
sudo ./01-install-wireguard.sh
sudo ./02-configure-firewall.sh
sudo CONFIRM_SSH_HARDENING=yes ./03-harden-server.sh
sudo ./add-client.sh laptop
```

Full walkthrough: [docs/SETUP.md](docs/SETUP.md). DNS leak details: [docs/DNS-LEAK-PREVENTION.md](docs/DNS-LEAK-PREVENTION.md).

## Layout

```
scripts/
  00-config.sh              shared variables, sourced by the rest
  01-install-wireguard.sh   installs WireGuard, generates server keys, brings up wg0
  02-configure-firewall.sh  UFW rules: allow SSH + WireGuard, deny everything else inbound
  03-harden-server.sh       key-only SSH, fail2ban, unattended security updates
  add-client.sh             provisions a client: keys, peer entry, config, QR code
  revoke-client.sh          removes a client's peer entry and config
configs/
  wg0.conf.example          annotated example of the generated server config
  client.conf.example       annotated example of a generated client config
docs/
  SETUP.md                  step-by-step deployment guide
  DNS-LEAK-PREVENTION.md    why the default config doesn't leak DNS, and how to verify
```
