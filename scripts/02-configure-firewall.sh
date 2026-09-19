#!/usr/bin/env bash
# Locks the server down to just SSH and the WireGuard port via UFW.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/00-config.sh"

require_root

if ! command -v ufw >/dev/null 2>&1; then
  run apt-get update
  run apt-get install -y ufw
fi

SSH_PORT="${SSH_PORT:-22}"

run ufw allow "$SSH_PORT"/tcp comment 'SSH'
run ufw allow "$WG_PORT"/udp comment 'WireGuard'
run ufw default deny incoming
run ufw default allow outgoing
run ufw --force enable

echo "Firewall active: inbound limited to SSH ($SSH_PORT/tcp) and WireGuard ($WG_PORT/udp)."
echo "Next: sudo ./03-harden-server.sh"
