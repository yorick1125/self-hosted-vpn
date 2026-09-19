#!/usr/bin/env bash
# Minimal test harness. No dependencies beyond bash + coreutils, so it runs
# anywhere the scripts themselves do - including Git Bash on Windows.

TESTS_RUN=0
TESTS_FAILED=0
CURRENT_TEST=""

RED=$'\033[31m'; GREEN=$'\033[32m'; DIM=$'\033[2m'; RESET=$'\033[0m'
if [[ ! -t 1 ]]; then RED=""; GREEN=""; DIM=""; RESET=""; fi

it() {
  CURRENT_TEST="$1"
  TESTS_RUN=$((TESTS_RUN + 1))
}

_fail() {
  TESTS_FAILED=$((TESTS_FAILED + 1))
  printf '%s  FAIL%s %s\n' "$RED" "$RESET" "$CURRENT_TEST"
  printf '%s       %s%s\n' "$DIM" "$1" "$RESET"
}

_pass() {
  printf '%s  ok  %s %s\n' "$GREEN" "$RESET" "$CURRENT_TEST"
}

assert_eq() {
  if [[ "$1" == "$2" ]]; then _pass; else _fail "expected '$2', got '$1'"; fi
}

assert_contains() {
  if [[ "$1" == *"$2"* ]]; then _pass; else _fail "expected output to contain '$2'"; fi
}

assert_not_contains() {
  if [[ "$1" != *"$2"* ]]; then _pass; else _fail "expected output NOT to contain '$2'"; fi
}

assert_file_exists() {
  if [[ -f "$1" ]]; then _pass; else _fail "expected file to exist: $1"; fi
}

assert_file_missing() {
  if [[ ! -f "$1" ]]; then _pass; else _fail "expected file to be gone: $1"; fi
}

# assert_fails <expected-substring-of-stderr> <command...>
assert_fails() {
  local want="$1"; shift
  local out rc
  out="$("$@" 2>&1)" && rc=0 || rc=$?
  if (( rc == 0 )); then
    _fail "expected a non-zero exit, got 0"
  elif [[ "$out" != *"$want"* ]]; then
    _fail "exit $rc as expected, but stderr lacked '$want'; got: ${out//$'\n'/ | }"
  else
    _pass
  fi
}

summary() {
  echo
  if (( TESTS_FAILED == 0 )); then
    printf '%s%d passed%s\n' "$GREEN" "$TESTS_RUN" "$RESET"
    return 0
  fi
  printf '%s%d of %d failed%s\n' "$RED" "$TESTS_FAILED" "$TESTS_RUN" "$RESET"
  return 1
}

# ---------------------------------------------------------------------------
# Sandbox: a temp WG_DIR plus fake system binaries on PATH, so the real scripts
# can run end to end without root, WireGuard, or Linux.
# ---------------------------------------------------------------------------
setup_sandbox() {
  SANDBOX="$(mktemp -d)"
  export WG_DIR="$SANDBOX/wireguard"
  export CLIENTS_DIR="$WG_DIR/clients"
  export WG_TEST=1
  export WG_INTERFACE="${WG_INTERFACE:-wg0}"
  export WG_PUBLIC_IP="203.0.113.10"   # TEST-NET-3, safe in docs and tests
  export PATH="$MOCK_BIN:$PATH"
  export MOCK_LOG="$SANDBOX/mock-calls.log"

  # Every path the scripts would otherwise write under /etc, redirected into the
  # sandbox. Without these the scripts abort on the first privileged write.
  export SYSCTL_CONF="$SANDBOX/etc/sysctl.d/99-wireguard.conf"
  export FAIL2BAN_JAIL="$SANDBOX/etc/fail2ban/jail.local"
  export SSHD_CONFIG="$SANDBOX/etc/ssh/sshd_config"

  : > "$MOCK_LOG"
  mkdir -p "$WG_DIR" "$CLIENTS_DIR" "$SANDBOX/etc/ssh" "$SANDBOX/etc/fail2ban" \
           "$SANDBOX/etc/sysctl.d"

  # A plausible stock sshd_config for the hardening script to rewrite.
  cat > "$SSHD_CONFIG" <<'EOF'
#PermitRootLogin prohibit-password
#PasswordAuthentication yes
#ChallengeResponseAuthentication yes
X11Forwarding yes
EOF
}

teardown_sandbox() {
  [[ -n "${SANDBOX:-}" && -d "$SANDBOX" ]] && rm -rf "$SANDBOX"
}

# Everything the mocks were asked to do this run.
mock_calls() {
  cat "$MOCK_LOG" 2>/dev/null || true
}
