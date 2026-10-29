#!/usr/bin/env bash
# Verify a detached signature using only the given public key (isolated keyring).
# Usage: verify_signature.sh <firmware.bin> <public-key.asc>
set -euo pipefail

FW="${1:?firmware required}"
PUB="${2:?public key required}"

GH="$(mktemp -d)"
trap 'rm -rf "$GH"' EXIT
chmod 700 "$GH"
gpg --homedir "$GH" --batch --quiet --import "$PUB"
gpg --homedir "$GH" --batch --status-fd 1 --verify "$FW.sig" "$FW" | grep -q 'GOODSIG' \
  && echo "Signature OK: $FW" \
  || { echo "Signature INVALID: $FW" >&2; exit 1; }
