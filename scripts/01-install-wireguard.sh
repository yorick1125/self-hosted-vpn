#!/usr/bin/env bash
# Installs WireGuard, generates the server keypair, and brings up the interface.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/00-config.sh"

require_root

if ! command -v wg >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    run apt-get update
    run apt-get install -y wireguard wireguard-tools qrencode
  elif command -v dnf >/dev/null 2>&1; then
    run dnf install -y wireguard-tools qrencode
  elif [[ -n "$DRY_RUN" ]]; then
    # Dry-run is for previewing from a workstation, which may not be the same
    # OS as the target. Report the intent instead of refusing.
    log "  [dry-run] no apt-get/dnf on this host; the target would install wireguard wireguard-tools qrencode"
  else
    echo "Unsupported package manager. Install WireGuard manually and re-run." >&2
    exit 1
  fi
fi

if [[ -n "$DRY_RUN" ]]; then
  log "  [dry-run] would create $WG_DIR and $CLIENTS_DIR (mode 700)"
else
  mkdir -p "$WG_DIR" "$CLIENTS_DIR"
  chmod 700 "$WG_DIR" "$CLIENTS_DIR"
fi

if [[ -n "$DRY_RUN" ]]; then
  log "  [dry-run] would generate a server keypair in $WG_DIR"
  SERVER_PRIVATE_KEY="<generated at run time>"
elif [[ ! -f "$WG_DIR/server_private.key" ]]; then
  umask 077
  wg genkey | tee "$WG_DIR/server_private.key" | wg pubkey > "$WG_DIR/server_public.key"
  SERVER_PRIVATE_KEY="$(cat "$WG_DIR/server_private.key")"
else
  SERVER_PRIVATE_KEY="$(cat "$WG_DIR/server_private.key")"
fi

DEFAULT_IFACE="$(detect_default_iface 2>/dev/null || true)"
PUBLIC_IP="${WG_PUBLIC_IP:-$(detect_public_ip)}"

if [[ -z "$DEFAULT_IFACE" ]]; then
  if [[ -n "$DRY_RUN" ]]; then
    DEFAULT_IFACE="<default route interface>"
  else
    # An empty interface here silently produces a malformed MASQUERADE rule,
    # and the tunnel comes up but routes nothing.
    echo "Could not determine the default network interface. Set WG_DEFAULT_IFACE and re-run." >&2
    exit 1
  fi
fi

if [[ -n "$DRY_RUN" ]]; then
  log "  [dry-run] would write $WG_DIR/$WG_INTERFACE.conf:"
  log "            Address = $WG_SERVER_IP_V4/24, ListenPort = $WG_PORT"
  log "            MASQUERADE via $DEFAULT_IFACE"
elif [[ ! -f "$WG_DIR/$WG_INTERFACE.conf" ]]; then
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

SYSCTL_CONF="${SYSCTL_CONF:-/etc/sysctl.d/99-wireguard.conf}"
if [[ -z "$DRY_RUN" ]]; then
  mkdir -p "$(dirname "$SYSCTL_CONF")"
  echo "net.ipv4.ip_forward=1" > "$SYSCTL_CONF"
fi
run sysctl -p "$SYSCTL_CONF"

run systemctl enable --now "wg-quick@$WG_INTERFACE"

if [[ -n "$DRY_RUN" ]]; then
  echo
  echo "Dry run complete. Nothing was installed, written, or started."
  exit 0
fi

echo "WireGuard is up on $WG_INTERFACE (UDP $WG_PORT)."
echo "Public IP: ${PUBLIC_IP:-<could not detect, set WG_PUBLIC_IP manually>}"
echo "Server public key: $(cat "$WG_DIR/server_public.key")"
echo "Next: sudo ./02-configure-firewall.sh, then sudo ./03-harden-server.sh"
