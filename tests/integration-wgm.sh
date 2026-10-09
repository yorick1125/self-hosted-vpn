#!/usr/bin/env bash
# Live test of the Go CLI against real WireGuard: brings up a server
# interface, provisions clients with wgm, completes a real handshake from a
# second interface on the same host, then revokes it.
#
# Needs root, wireguard-tools and iproute2. Uses kernel WireGuard when
# available, otherwise wireguard-go. Runs in CI; safe on a dev VM, not on a
# production VPN server (it creates wgmtest0/wgmtest1).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
SRV=wgmtest0 CLI=wgmtest1 PORT=51999
D="$WORK/wireguard"
W="$WORK/wgm"

cleanup() {
  ip link del "$SRV" 2>/dev/null || true
  ip link del "$CLI" 2>/dev/null || true
  pkill -f "wireguard-go -f wgmtest" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

up_iface() {
  if ip link add "$1" type wireguard 2>/dev/null; then return; fi
  command -v wireguard-go >/dev/null || fail "no kernel WireGuard and no wireguard-go"
  setsid wireguard-go -f "$1" >/dev/null 2>&1 &
  for _ in $(seq 50); do ip link show "$1" >/dev/null 2>&1 && return; sleep 0.1; done
  fail "wireguard-go did not create $1"
}

# init's service steps are faked; the WireGuard interfaces are real.
mkdir -p "$WORK/bin"
for b in systemctl sysctl; do printf '#!/bin/sh\nexit 0\n' > "$WORK/bin/$b"; chmod +x "$WORK/bin/$b"; done
export PATH="$WORK/bin:$PATH" SYSCTL_CONF="$WORK/sysctl.conf"

(cd "$ROOT" && go build -o "$W" ./cmd/wgm)

"$W" init --dir "$D" --iface "$SRV" --port "$PORT" --endpoint 127.0.0.1 --wan-iface lo 2>/dev/null
up_iface "$SRV"
wg setconf "$SRV" <(wg-quick strip "$D/$SRV.conf")
ip addr add 10.8.0.1/24 dev "$SRV"
ip link set "$SRV" up

"$W" add laptop --dir "$D" --iface "$SRV" > "$WORK/laptop.conf" 2>/dev/null
"$W" add phone  --dir "$D" --iface "$SRV" > /dev/null 2>&1
[[ "$(wg show "$SRV" peers | wc -l)" == 2 ]] || fail "peers not applied to the live interface"

# Client side: wg setconf doesn't understand Address/DNS (wg-quick fields).
up_iface "$CLI"
grep -vE '^(Address|DNS)' "$WORK/laptop.conf" > "$WORK/laptop-wg.conf"
wg setconf "$CLI" "$WORK/laptop-wg.conf"
ip link set "$CLI" up

for _ in $(seq 50); do
  "$W" list --dir "$D" --iface "$SRV" | grep -q '^laptop .*online' && break
  sleep 0.2
done
"$W" list --dir "$D" --iface "$SRV"
"$W" list --dir "$D" --iface "$SRV" | grep -q '^laptop .*online' || fail "no handshake from laptop"

"$W" revoke laptop --dir "$D" --iface "$SRV" 2>/dev/null
[[ "$(wg show "$SRV" peers | wc -l)" == 1 ]] || fail "revoked peer still on the live interface"
[[ ! -e "$D/clients/laptop.conf" ]] || fail "revoked client config still on disk"

echo "PASS: init, live add, real handshake, live revoke"
