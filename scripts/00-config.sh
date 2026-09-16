#!/usr/bin/env bash
# Shared config sourced by the other scripts in this directory.
set -euo pipefail

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_PORT="${WG_PORT:-51820}"
WG_DIR="${WG_DIR:-/etc/wireguard}"
WG_SUBNET_V4="${WG_SUBNET_V4:-10.8.0.0/24}"
WG_SERVER_IP_V4="${WG_SERVER_IP_V4:-10.8.0.1}"
CLIENTS_DIR="${CLIENTS_DIR:-$WG_DIR/clients}"
CLIENT_DNS="${CLIENT_DNS:-1.1.1.1,1.0.0.1}"

detect_public_ip() {
  curl -fsSL4 https://ifconfig.me 2>/dev/null || curl -fsSL4 https://api.ipify.org 2>/dev/null || true
}

detect_default_iface() {
  ip -4 route ls | awk '/^default/ {print $5; exit}'
}

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
  fi
}
