#!/usr/bin/env bash
# Negative tests: the backend must reject (a) a modified firmware and
# (b) a package signed by an untrusted key.
# Usage: tamper_test.sh <good-package.tar.gz> <backend-url>
set -euo pipefail

PKG="$(realpath "${1:?package required}")"
URL="${2:?backend url required}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

expect_reject() {
  local name="$1" pkg="$2"
  local code
  code=$(curl -s -o "$WORK/resp.json" -w '%{http_code}' -X POST -F "package=@$pkg" \
    ${BACKEND_TOKEN:+-H "Authorization: Bearer $BACKEND_TOKEN"} "$URL/api/v1/updates")
  if [ "$code" = "201" ]; then
    echo "FAIL: $name was ACCEPTED" >&2; exit 1
  fi
  echo "PASS: $name rejected (HTTP $code): $(cat "$WORK/resp.json")"
}

# (a) flip a byte in the firmware, keep original signature and manifest
mkdir "$WORK/a"; tar -C "$WORK/a" -xzf "$PKG"
printf 'X' | dd of="$WORK/a/firmware.bin" bs=1 seek=0 conv=notrunc 2>/dev/null
sed -i 's/"version": "\([^"]*\)"/"version": "\1-tampered"/' "$WORK/a/manifest.json"
tar -C "$WORK/a" -czf "$WORK/tampered.tar.gz" firmware.bin firmware.bin.sig firmware.bin.sha256 sbom.cdx.json manifest.json
expect_reject "tampered firmware" "$WORK/tampered.tar.gz"

# (b) re-sign with a throwaway, untrusted key and fix up hash/manifest/SBOM consistently
mkdir "$WORK/b" "$WORK/gh"; chmod 700 "$WORK/gh"; tar -C "$WORK/b" -xzf "$PKG"
gpg --homedir "$WORK/gh" --batch --quiet --passphrase '' --quick-generate-key "attacker@example.invalid" ed25519 sign never
printf 'Y' >> "$WORK/b/firmware.bin"
NEW=$(sha256sum "$WORK/b/firmware.bin" | awk '{print $1}')
echo "$NEW" > "$WORK/b/firmware.bin.sha256"
sed -i "s/\"sha256\": \"[0-9a-f]*\"/\"sha256\": \"$NEW\"/; s/\"version\": \"\([^\"]*\)\"/\"version\": \"\1-evil\"/" "$WORK/b/manifest.json"
python3 - "$WORK/b/sbom.cdx.json" "$NEW" <<'PY'
import json, sys
p, h = sys.argv[1:3]
d = json.load(open(p)); d["metadata"]["component"]["hashes"][0]["content"] = h
json.dump(d, open(p, "w"))
PY
rm -f "$WORK/b/firmware.bin.sig"
gpg --homedir "$WORK/gh" --batch --yes --armor --detach-sign --output "$WORK/b/firmware.bin.sig" "$WORK/b/firmware.bin"
tar -C "$WORK/b" -czf "$WORK/untrusted.tar.gz" firmware.bin firmware.bin.sig firmware.bin.sha256 sbom.cdx.json manifest.json
expect_reject "package signed by untrusted key" "$WORK/untrusted.tar.gz"
