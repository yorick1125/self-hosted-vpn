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

SSHD_CONFIG="/etc/ssh/sshd_config"
cp "$SSHD_CONFIG" "$SSHD_CONFIG.bak.$(date +%s)"
sed -i \
  -e 's/^#\?PermitRootLogin.*/PermitRootLogin no/' \
  -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' \
  -e 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' \
  -e 's/^#\?X11Forwarding.*/X11Forwarding no/' \
  "$SSHD_CONFIG"

if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y fail2ban unattended-upgrades
  dpkg-reconfigure -f noninteractive unattended-upgrades
fi

cat > /etc/fail2ban/jail.local <<'EOF'
[sshd]
enabled = true
maxretry = 5
bantime = 1h
findtime = 10m
EOF

systemctl enable --now fail2ban
systemctl restart sshd

echo "Hardening applied: key-only SSH, fail2ban active, unattended security updates enabled."
echo "Backup of the previous sshd_config was saved alongside it."
