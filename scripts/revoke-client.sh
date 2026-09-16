#!/usr/bin/env bash
# Removes a client's peer entry from the server and deletes its config.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/00-config.sh"

require_root

CLIENT_NAME="${1:?Usage: $0 <client-name>}"
CLIENT_CONF="$CLIENTS_DIR/$CLIENT_NAME.conf"

if ! grep -q "# BEGIN client-$CLIENT_NAME" "$WG_DIR/$WG_INTERFACE.conf"; then
  echo "No such client: $CLIENT_NAME" >&2
  exit 1
fi

sed -i "/# BEGIN client-$CLIENT_NAME/,/# END client-$CLIENT_NAME/d" "$WG_DIR/$WG_INTERFACE.conf"
rm -f "$CLIENT_CONF"

wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE")

echo "Client '$CLIENT_NAME' revoked."
