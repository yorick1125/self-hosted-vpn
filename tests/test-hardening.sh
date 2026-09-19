#!/usr/bin/env bash
# 02-configure-firewall.sh and 03-harden-server.sh.
set -uo pipefail

source "$TESTS_DIR/lib/harness.sh"

setup_sandbox
trap teardown_sandbox EXIT

# --- firewall ----------------------------------------------------------------
"$SCRIPTS_DIR/02-configure-firewall.sh" >/dev/null 2>&1
CALLS="$(mock_calls)"

it "allows SSH inbound"
assert_contains "$CALLS" "ufw allow 22/tcp"

it "allows the WireGuard port inbound"
assert_contains "$CALLS" "ufw allow 51820/udp"

it "denies everything else inbound"
assert_contains "$CALLS" "ufw default deny incoming"

it "leaves outbound open"
assert_contains "$CALLS" "ufw default allow outgoing"

it "enables the firewall"
assert_contains "$CALLS" "ufw --force enable"

it "opens SSH before denying inbound, so it can't lock you out mid-run"
ALLOW_LINE="$(grep -n 'ufw allow 22/tcp' <<<"$CALLS" | cut -d: -f1)"
DENY_LINE="$(grep -n 'ufw default deny incoming' <<<"$CALLS" | cut -d: -f1)"
if (( ALLOW_LINE < DENY_LINE )); then _pass; else _fail "SSH allowed at line $ALLOW_LINE, deny at $DENY_LINE"; fi

# --- hardening requires explicit confirmation --------------------------------
it "refuses to harden SSH without explicit confirmation"
assert_fails "CONFIRM_SSH_HARDENING=yes" "$SCRIPTS_DIR/03-harden-server.sh"

# --- hardening, confirmed ----------------------------------------------------
# setup_sandbox already seeded a stock sshd_config at $SSHD_CONFIG.
OUT="$(CONFIRM_SSH_HARDENING=yes "$SCRIPTS_DIR/03-harden-server.sh" 2>&1)"
CALLS="$(mock_calls)"

it "disables root login"
assert_contains "$(cat "$SSHD_CONFIG")" "PermitRootLogin no"

it "disables password authentication"
assert_contains "$(cat "$SSHD_CONFIG")" "PasswordAuthentication no"

it "backs up the original sshd_config before editing it"
BACKUPS=( "$SSHD_CONFIG".bak.* )
assert_file_exists "${BACKUPS[0]}"

it "the backup still has the original permissive settings"
assert_contains "$(cat "${BACKUPS[0]}")" "#PasswordAuthentication yes"

it "installs fail2ban"
assert_contains "$CALLS" "apt-get install -y fail2ban"

it "validates sshd_config before restarting the service"
assert_contains "$CALLS" "sshd -t"

it "restarts SSH using the unit name that exists on this distro"
assert_contains "$CALLS" "systemctl restart ssh"

# --- the guard that matters: a broken sshd_config must not reach a restart ----
teardown_sandbox
setup_sandbox
export MOCK_SSHD_INVALID=1

OUT="$(CONFIRM_SSH_HARDENING=yes "$SCRIPTS_DIR/03-harden-server.sh" 2>&1 || true)"
CALLS="$(mock_calls)"

it "aborts when sshd_config fails validation"
assert_contains "$OUT" "failed validation"

it "does NOT restart sshd with a broken config (this is the lockout path)"
assert_not_contains "$CALLS" "systemctl restart"

it "restores the backup when validation fails"
assert_contains "$(cat "$SSHD_CONFIG")" "#PasswordAuthentication yes"

unset MOCK_SSHD_INVALID

summary
