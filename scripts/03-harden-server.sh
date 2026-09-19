#!/usr/bin/env bash
# SSH hardening + fail2ban + unattended security updates.
#
# This disables SSH password auth and root login. Make sure you can already
# log in with an SSH key before running it, or you will lock yourself out.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/00-config.sh"

require_root

if [[ "${CONFIRM_SSH_HARDENING:-}" != "yes" ]]; then
  cat >&2 <<'EOF'
This will set PermitRootLogin=no and PasswordAuthentication=no in sshd_config.
Confirm you can already log in with an SSH key from this machine, then re-run:

  sudo CONFIRM_SSH_HARDENING=yes ./03-harden-server.sh
EOF
  exit 1
fi

SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
SSHD_BACKUP="$SSHD_CONFIG.bak.$(date +%s)"
cp "$SSHD_CONFIG" "$SSHD_BACKUP"
sed -i \
  -e 's/^#\?PermitRootLogin.*/PermitRootLogin no/' \
  -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' \
  -e 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' \
  -e 's/^#\?X11Forwarding.*/X11Forwarding no/' \
  "$SSHD_CONFIG"

if command -v apt-get >/dev/null 2>&1; then
  run apt-get update
  run apt-get install -y fail2ban unattended-upgrades
  run dpkg-reconfigure -f noninteractive unattended-upgrades
fi

FAIL2BAN_JAIL="${FAIL2BAN_JAIL:-/etc/fail2ban/jail.local}"
mkdir -p "$(dirname "$FAIL2BAN_JAIL")"
cat > "$FAIL2BAN_JAIL" <<'EOF'
[sshd]
enabled = true
maxretry = 5
bantime = 1h
findtime = 10m
EOF

# Validate before restarting. A malformed sshd_config plus a restart is how
# you lock yourself out of a remote server permanently.
if command -v sshd >/dev/null 2>&1; then
  if ! run sshd -t; then
    echo "sshd_config failed validation - restoring backup and aborting." >&2
    cp "$SSHD_BACKUP" "$SSHD_CONFIG"
    exit 1
  fi
fi

run systemctl enable --now fail2ban
# The unit is 'ssh' on Debian/Ubuntu and 'sshd' on RHEL derivatives.
if systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
  run systemctl restart sshd
else
  run systemctl restart ssh
fi

echo "Hardening applied: key-only SSH, fail2ban active, unattended security updates enabled."
echo "Backup of the previous sshd_config was saved alongside it."
