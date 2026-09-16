#!/usr/bin/env bash
# Installs WireGuard, generates the server keypair, and brings up the interface.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/00-config.sh"

require_root

if ! command -v wg >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y wireguard wireguard-tools qrencode
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y wireguard-tools qrencode
  else
    echo "Unsupported package manager. Install WireGuard manually and re-run." >&2
    exit 1
  fi
fi

mkdir -p "$WG_DIR" "$CLIENTS_DIR"
chmod 700 "$WG_DIR" "$CLIENTS_DIR"

if [[ ! -f "$WG_DIR/server_private.key" ]]; then
  umask 077
  wg genkey | tee "$WG_DIR/server_private.key" | wg pubkey > "$WG_DIR/server_public.key"
fi

SERVER_PRIVATE_KEY="$(cat "$WG_DIR/server_private.key")"
DEFAULT_IFACE="$(detect_default_iface)"
PUBLIC_IP="${WG_PUBLIC_IP:-$(detect_public_ip)}"

if [[ ! -f "$WG_DIR/$WG_INTERFACE.conf" ]]; then
  umask 077
  cat > "$WG_DIR/$WG_INTERFACE.conf" <<EOF
[Interface]
Address = $WG_SERVER_IP_V4/24
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIVATE_KEY
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $DEFAULT_IFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $DEFAULT_IFACE -j MASQUERADE
EOF
  chmod 600 "$WG_DIR/$WG_INTERFACE.conf"
fi

echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf
sysctl -p /etc/sysctl.d/99-wireguard.conf >/dev/null

systemctl enable --now "wg-quick@$WG_INTERFACE"

echo "WireGuard is up on $WG_INTERFACE (UDP $WG_PORT)."
echo "Public IP: ${PUBLIC_IP:-<could not detect, set WG_PUBLIC_IP manually>}"
echo "Server public key: $(cat "$WG_DIR/server_public.key")"
echo "Next: sudo ./02-configure-firewall.sh, then sudo ./03-harden-server.sh"
