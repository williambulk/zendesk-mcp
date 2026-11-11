#!/bin/bash
set -euo pipefail

# Run interactively on the MacBook. The iMac password is entered into SSH,
# never into chat, source files, environment variables, or command arguments.
imac_host="${1:-${IMAC_HOST:?Usage: IMAC_HOST=<host> IMAC_USER=<user> $0}}"
imac_user="${2:-${IMAC_USER:?Usage: IMAC_HOST=<host> IMAC_USER=<user> $0}}"
imac_key="$HOME/.ssh/zendesk_imac_ed25519"

mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
if [[ ! -f "$imac_key" ]]; then
  ssh-keygen -t ed25519 -f "$imac_key" -N '' -C 'Zendesk MCP MacBook to homelab iMac'
fi
chmod 600 "$imac_key"
if [[ ! -f "$imac_key.pub" ]]; then
  ssh-keygen -y -f "$imac_key" > "$imac_key.pub"
fi

echo 'Authorize this dedicated key on the iMac. Enter the iMac account password when SSH asks.'
ssh-copy-id -i "$imac_key.pub" -o StrictHostKeyChecking=yes "$imac_user@$imac_host"
ssh -T -i "$imac_key" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes "$imac_user@$imac_host" 'uname -sm && id -un'
echo 'SSH access is ready. Return to the Zendesk setup conversation to continue.'
