#!/usr/bin/env bash
# Runs every test file. Works anywhere bash does, including Git Bash on Windows.
#
#   ./tests/run-tests.sh              all suites
#   ./tests/run-tests.sh install      only tests/test-install.sh
set -uo pipefail

export TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export REPO_DIR="$(cd "$TESTS_DIR/.." && pwd)"
export SCRIPTS_DIR="$REPO_DIR/scripts"
export MOCK_BIN="$TESTS_DIR/mocks/bin"

# Git checkouts on Windows don't preserve the executable bit.
chmod +x "$SCRIPTS_DIR"/*.sh "$MOCK_BIN"/* "$TESTS_DIR"/*.sh 2>/dev/null || true

filter="${1:-}"
failed=0
ran=0

for suite in "$TESTS_DIR"/test-*.sh; do
  name="$(basename "$suite" .sh)"; name="${name#test-}"
  [[ -n "$filter" && "$name" != *"$filter"* ]] && continue
  ran=$((ran + 1))
  printf '\n\033[1m%s\033[0m\n' "$name"
  bash "$suite" || failed=$((failed + 1))
done

if (( ran == 0 )); then
  echo "No suites matched '${filter}'." >&2
  exit 1
fi

echo
if (( failed == 0 )); then
  printf '\033[32mAll %d suite(s) passed.\033[0m\n' "$ran"
else
  printf '\033[31m%d of %d suite(s) failed.\033[0m\n' "$failed" "$ran"
fi
exit $(( failed > 0 ))
