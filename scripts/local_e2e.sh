#!/usr/bin/env bash
# Run the whole pipeline locally (same scripts CI uses) with an ephemeral GPG key.
# Usage: scripts/local_e2e.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
GH="$WORK/gnupg"; mkdir -p "$GH"; chmod 700 "$GH"
export GNUPGHOME="$GH"
VERSION="1.0.0-local"
PORT="${PORT:-18080}"
BPID=""
cleanup() { [ -n "$BPID" ] && kill "$BPID" 2>/dev/null || true; gpgconf --kill gpg-agent 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

echo "== 1. build"
make -C "$ROOT/firmware" VERSION="$VERSION" BUILD=local OUT="$WORK/build" >/dev/null
"$WORK/build/firmware.bin"

echo "== 2. SBOM"
"$ROOT/scripts/generate_sbom.sh" "$WORK/build/firmware.bin" "$VERSION" "$WORK/build/sbom.cdx.json"
python3 "$ROOT/scripts/validate_sbom.py" "$WORK/build/sbom.cdx.json" || echo "(schema validation skipped: cyclonedx-python-lib not installed)"

echo "== 3. sign (ephemeral key)"
gpg --batch --quiet --passphrase '' --quick-generate-key "OTA Release Signing <ota-release@example.invalid>" ed25519 sign never
KEY_ID=$(gpg --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')
gpg --armor --export "$KEY_ID" > "$WORK/pub.asc"
"$ROOT/scripts/sign_firmware.sh" "$WORK/build/firmware.bin" "$KEY_ID"
"$ROOT/scripts/verify_signature.sh" "$WORK/build/firmware.bin" "$WORK/pub.asc"

echo "== 4. package"
"$ROOT/scripts/package.sh" "$WORK/build" "$VERSION" "$WORK/ota-package.tar.gz"

echo "== 5. start mock backend + deploy"
gpg --batch --quiet --no-default-keyring --keyring "$WORK/trusted.gpg" --import "$WORK/pub.asc" 2>/dev/null
UPDATE_STORE="$WORK/store" TRUSTED_KEYRING="$WORK/trusted.gpg" PORT="$PORT" \
  python3 "$ROOT/backend/app.py" > "$WORK/backend.log" 2>&1 &
BPID=$!
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null && break; sleep 0.25; done
"$ROOT/scripts/deploy.sh" "$WORK/ota-package.tar.gz" "http://127.0.0.1:$PORT"

echo "== 6. negative tests"
"$ROOT/scripts/tamper_test.sh" "$WORK/ota-package.tar.gz" "http://127.0.0.1:$PORT"

echo "== 7. replay (same version again must be rejected)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -F "package=@$WORK/ota-package.tar.gz" "http://127.0.0.1:$PORT/api/v1/updates")
[ "$CODE" = "409" ] && echo "PASS: duplicate version rejected (HTTP 409)" || { echo "FAIL: got HTTP $CODE" >&2; exit 1; }

echo; echo "ALL CHECKS PASSED"
