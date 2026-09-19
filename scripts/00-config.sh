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

# ---------------------------------------------------------------------------
# Execution modes
#
# DRY_RUN=1   Print every system-changing command instead of running it. Nothing
#             is installed, no service is touched, no firewall rule applied.
#             Use it to review what a script would do before pointing it at a
#             real server.
#
# WG_TEST=1   Set by the test suite. Same root bypass as DRY_RUN, but commands
#             still run, so tests can assert on the files actually generated.
#             Tests point WG_DIR at a temp directory and put fake binaries on
#             PATH, so nothing touches the real system.
# ---------------------------------------------------------------------------
DRY_RUN="${DRY_RUN:-}"
WG_TEST="${WG_TEST:-}"

# Log to stderr so it never contaminates a value being captured by $(...).
log() {
  printf '%s\n' "$*" >&2
}

# Wrap anything that changes system state: package installs, systemctl, ufw,
# sysctl, wg syncconf. Under DRY_RUN the command is printed and skipped.
run() {
  if [[ -n "$DRY_RUN" ]]; then
    printf '  [dry-run] %s\n' "$*" >&2
    return 0
  fi
  "$@"
}

require_root() {
  # Neither mode changes the real system, so neither needs privileges.
  if [[ -n "$DRY_RUN" || -n "$WG_TEST" ]]; then
    return 0
  fi
  if [[ "$EUID" -ne 0 ]]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
  fi
}

detect_public_ip() {
  curl -fsSL4 https://ifconfig.me 2>/dev/null || curl -fsSL4 https://api.ipify.org 2>/dev/null || true
}

detect_default_iface() {
  ip -4 route ls | awk '/^default/ {print $5; exit}'
}

# Next free host address in the WireGuard subnet, derived from the peers already
# in the server config. Prints the address, or fails if the /24 is exhausted.
next_client_ip() {
  local conf="$1" prefix last next
  prefix="${WG_SERVER_IP_V4%.*}"
  last="$(grep -oE "AllowedIPs = ${prefix//./\\.}\.[0-9]+/32" "$conf" 2>/dev/null \
          | sed -E 's|.*\.([0-9]+)/32$|\1|' | sort -n | tail -1)"
  next=$(( ${last:-1} + 1 ))
  if (( next > 254 )); then
    echo "No addresses left in $prefix.0/24 (last allocated: ${last:-1})." >&2
    return 1
  fi
  printf '%s.%s\n' "$prefix" "$next"
}
