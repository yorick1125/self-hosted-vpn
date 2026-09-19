#!/usr/bin/env bash
# add-client.sh / revoke-client.sh: address allocation, config contents, cleanup.
set -uo pipefail

source "$TESTS_DIR/lib/harness.sh"

setup_sandbox
trap teardown_sandbox EXIT

"$SCRIPTS_DIR/01-install-wireguard.sh" >/dev/null 2>&1
CONF="$WG_DIR/$WG_INTERFACE.conf"

# --- first client ------------------------------------------------------------
OUT="$("$SCRIPTS_DIR/add-client.sh" laptop 2>&1)"

it "writes a client config"
assert_file_exists "$CLIENTS_DIR/laptop.conf"

it "first client gets .2 (the server holds .1)"
assert_contains "$OUT" "10.8.0.2"

it "adds a peer block to the server config"
assert_contains "$(cat "$CONF")" "# BEGIN client-laptop"

it "peer entry is scoped to a single address"
assert_contains "$(cat "$CONF")" "AllowedIPs = 10.8.0.2/32"

it "client config routes all traffic through the tunnel"
assert_contains "$(cat "$CLIENTS_DIR/laptop.conf")" "AllowedIPs = 0.0.0.0/0"

it "client config sets DNS, so queries don't leak to the local resolver"
assert_contains "$(cat "$CLIENTS_DIR/laptop.conf")" "DNS = 1.1.1.1,1.0.0.1"

it "client config points at the server endpoint"
assert_contains "$(cat "$CLIENTS_DIR/laptop.conf")" "Endpoint = 203.0.113.10:51820"

it "client and server share a preshared key"
assert_contains "$(cat "$CLIENTS_DIR/laptop.conf")" "PresharedKey = PSK0"

it "client config holds the client's private key, never the server's"
assert_not_contains "$(cat "$CLIENTS_DIR/laptop.conf")" "$(cat "$WG_DIR/server_private.key")"

it "reloads the interface without dropping it"
assert_contains "$(mock_calls)" "wg syncconf wg0"

# --- second client: allocation must advance ----------------------------------
OUT2="$("$SCRIPTS_DIR/add-client.sh" phone 2>&1)"

it "second client gets the next free address"
assert_contains "$OUT2" "10.8.0.3"

it "both peers are present"
assert_eq "$(grep -c '^\[Peer\]' "$CONF")" "2"

# --- duplicates are refused ---------------------------------------------------
it "refuses to re-add an existing client"
assert_fails "already exists" "$SCRIPTS_DIR/add-client.sh" laptop

# --- revocation ---------------------------------------------------------------
"$SCRIPTS_DIR/revoke-client.sh" laptop >/dev/null 2>&1

it "revoking deletes the client config"
assert_file_missing "$CLIENTS_DIR/laptop.conf"

it "revoking removes the peer block"
assert_not_contains "$(cat "$CONF")" "# BEGIN client-laptop"

it "revoking leaves the other client intact"
assert_contains "$(cat "$CONF")" "# BEGIN client-phone"

it "refuses to revoke an unknown client"
assert_fails "No such client" "$SCRIPTS_DIR/revoke-client.sh" nobody

# --- reallocation after revocation --------------------------------------------
OUT3="$("$SCRIPTS_DIR/add-client.sh" tablet 2>&1)"

it "next client allocates above the highest peer, not into the freed gap"
assert_contains "$OUT3" "10.8.0.4"

summary
