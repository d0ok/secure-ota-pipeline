#!/usr/bin/env bash
# Sign firmware with a GPG key.
# Usage: sign_firmware.sh <firmware.bin> <key-id>
# Produces <firmware.bin>.sig (detached, armored) and <firmware.bin>.sha256.
set -euo pipefail

FW="${1:?firmware file required}"
KEY_ID="${2:?GPG key id required}"

sha256sum "$FW" | awk '{print $1}' > "$FW.sha256"
rm -f "$FW.sig"
gpg --batch --yes --pinentry-mode loopback \
    ${GPG_PASSPHRASE:+--passphrase "$GPG_PASSPHRASE"} \
    --local-user "$KEY_ID" --armor --detach-sign --output "$FW.sig" "$FW"

echo "Signed $FW with key $KEY_ID"
