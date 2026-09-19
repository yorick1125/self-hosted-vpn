#!/usr/bin/env bash
# 01-install-wireguard.sh: key generation, server config, service bring-up.
set -uo pipefail

source "$TESTS_DIR/lib/harness.sh"

setup_sandbox
trap teardown_sandbox EXIT

OUT="$("$SCRIPTS_DIR/01-install-wireguard.sh" 2>&1)"
CONF="$WG_DIR/$WG_INTERFACE.conf"

it "generates a server private key"
assert_file_exists "$WG_DIR/server_private.key"

it "generates a server public key"
assert_file_exists "$WG_DIR/server_public.key"

it "writes the interface config"
assert_file_exists "$CONF"

it "config listens on the configured port"
assert_contains "$(cat "$CONF")" "ListenPort = 51820"

it "config uses the configured server address"
assert_contains "$(cat "$CONF")" "Address = 10.8.0.1/24"

it "config embeds the generated private key"
assert_contains "$(cat "$CONF")" "PrivateKey = PRIV"

it "NAT rule targets the detected default interface, not an empty string"
assert_contains "$(cat "$CONF")" "POSTROUTING -o eth0 -j MASQUERADE"

it "enables the wg-quick service"
assert_contains "$(mock_calls)" "systemctl enable --now wg-quick@wg0"

it "enables IP forwarding"
assert_contains "$(mock_calls)" "sysctl -p"

it "reports the server public key to the operator"
assert_contains "$OUT" "PUBL"

# --- idempotency: a second run must not rotate keys or duplicate config ------
KEY_BEFORE="$(cat "$WG_DIR/server_private.key")"
CONF_BEFORE="$(cat "$CONF")"
"$SCRIPTS_DIR/01-install-wireguard.sh" >/dev/null 2>&1

it "re-running does not rotate the server key"
assert_eq "$(cat "$WG_DIR/server_private.key")" "$KEY_BEFORE"

it "re-running does not rewrite the interface config"
assert_eq "$(cat "$CONF")" "$CONF_BEFORE"

summary
