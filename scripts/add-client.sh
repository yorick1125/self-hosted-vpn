#!/usr/bin/env bash
# Provisions a new WireGuard client: keypair, server peer entry, client config, QR code.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/00-config.sh"

require_root

CLIENT_NAME="${1:?Usage: $0 <client-name>}"
CLIENT_CONF="$CLIENTS_DIR/$CLIENT_NAME.conf"

if [[ -f "$CLIENT_CONF" ]]; then
  echo "Client '$CLIENT_NAME' already exists at $CLIENT_CONF" >&2
  exit 1
fi

SUBNET_PREFIX="${WG_SERVER_IP_V4%.*}"
LAST_OCTET=$(grep -oP "(?<=AllowedIPs = ${SUBNET_PREFIX//./\\.}\.)\d+(?=/32)" "$WG_DIR/$WG_INTERFACE.conf" 2>/dev/null | sort -n | tail -1)
NEXT_OCTET=$(( ${LAST_OCTET:-1} + 1 ))
CLIENT_IP="$SUBNET_PREFIX.$NEXT_OCTET"

umask 077
CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
PRESHARED_KEY=$(wg genpsk)
SERVER_PUBLIC_KEY=$(cat "$WG_DIR/server_public.key")
PUBLIC_IP="${WG_PUBLIC_IP:-$(detect_public_ip)}"

cat >> "$WG_DIR/$WG_INTERFACE.conf" <<EOF

# BEGIN client-$CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = $CLIENT_IP/32
# END client-$CLIENT_NAME
EOF

cat > "$CLIENT_CONF" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP/24
DNS = $CLIENT_DNS

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
Endpoint = $PUBLIC_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
chmod 600 "$CLIENT_CONF"

wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE")

echo "Client '$CLIENT_NAME' added with IP $CLIENT_IP"
echo "Config saved to $CLIENT_CONF"
if command -v qrencode >/dev/null 2>&1; then
  qrencode -t ansiutf8 < "$CLIENT_CONF"
fi
