#!/usr/bin/env bash
# End-to-end test of the vehicle-side client against the mock backend.
# Uses an ephemeral GPG key; the vehicle is provisioned with that key's PUBLIC half only.
# Usage: scripts/vehicle_e2e.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
GH="$WORK/gnupg"; mkdir -p "$GH"; chmod 700 "$GH"
export GNUPGHOME="$GH"
PORT="${PORT:-18081}"
URL="http://127.0.0.1:$PORT"
ECU="$WORK/ecu"
BPID=""
cleanup() { [ -n "$BPID" ] && kill "$BPID" 2>/dev/null || true; gpgconf --kill gpg-agent 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

ecu() { python3 "$ROOT/vehicle/ecu_updater.py" --state "$ECU" "$@"; }

expect_code() {  # expect_code <exit-code> <name> <command...>
  local want="$1" name="$2"; shift 2
  local out rc
  set +e; out=$("$@" 2>&1); rc=$?; set -e
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL: $name (exit $rc, wanted $want)"; echo "$out"; exit 1
  fi
  echo "PASS: $name -> $(echo "$out" | tail -1)"
}

installed_version() { ecu status | python3 -c 'import json,sys; print(json.load(sys.stdin)["installed_version"])'; }
expect_installed() {
  local got; got="$(installed_version)"
  [ "$got" = "$1" ] && echo "PASS: installed version is $1" || { echo "FAIL: installed $got, wanted $1"; exit 1; }
}

echo "== setup: ephemeral release key, backend trusts it, vehicle pins it"
gpg --batch --quiet --passphrase '' --quick-generate-key "OTA Release Signing <ota-release@example.invalid>" ed25519 sign never 2>/dev/null
KEY_ID=$(gpg --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')
gpg --armor --export "$KEY_ID" > "$WORK/pub.asc"
gpg --batch --quiet --no-default-keyring --keyring "$WORK/trusted.gpg" --import "$WORK/pub.asc" 2>/dev/null

mkpkg() {  # mkpkg <version> <out.tar.gz> : build, SBOM, sign, package with the real scripts
  local v="$1" out="$2" d="$WORK/build-$1"
  mkdir -p "$d"
  make -C "$ROOT/firmware" VERSION="$v" BUILD=e2e OUT="$d" >/dev/null
  "$ROOT/scripts/generate_sbom.sh" "$d/firmware.bin" "$v" "$d/sbom.cdx.json" >/dev/null
  "$ROOT/scripts/sign_firmware.sh" "$d/firmware.bin" "$KEY_ID" >/dev/null 2>&1
  "$ROOT/scripts/package.sh" "$d" "$v" "$out" >/dev/null
}
repack() {  # repack <dir> <out.tar.gz>
  tar -C "$1" -czf "$2" firmware.bin firmware.bin.sig firmware.bin.sha256 sbom.cdx.json manifest.json
}

mkpkg 1.0.1 "$WORK/p101.tar.gz"
mkpkg 1.0.2 "$WORK/p102.tar.gz"
mkpkg 1.0.3 "$WORK/p103.tar.gz"

UPDATE_STORE="$WORK/store" TRUSTED_KEYRING="$WORK/trusted.gpg" PORT="$PORT" \
  python3 "$ROOT/backend/app.py" > "$WORK/backend.log" 2>&1 &
BPID=$!
for _ in $(seq 1 40); do curl -sf "$URL/healthz" >/dev/null && break; sleep 0.25; done
"$ROOT/scripts/deploy.sh" "$WORK/p101.tar.gz" "$URL" >/dev/null
"$ROOT/scripts/deploy.sh" "$WORK/p102.tar.gz" "$URL" >/dev/null

ecu provision --pubkey "$WORK/pub.asc"
expect_installed 0.0.0

echo "== 1. normal install from a local package"
expect_code 0 "install 1.0.1" ecu update --package "$WORK/p101.tar.gz"
expect_installed 1.0.1

echo "== 2. anti-rollback"
expect_code 1 "replay of 1.0.1 refused" ecu update --package "$WORK/p101.tar.gz"
expect_installed 1.0.1

echo "== 3. failed self-test rolls back to the previous slot"
expect_code 3 "1.0.2 with failing self-test rolled back" ecu update --package "$WORK/p102.tar.gz" --simulate-selftest-failure
expect_installed 1.0.1

echo "== 4. fetch newest from the backend (vehicle downloads the full package)"
expect_code 0 "install newest from backend" ecu update --backend "$URL"
expect_installed 1.0.2
expect_code 0 "already up to date" ecu update --backend "$URL"

echo "== 5. downgrade refused even though the old package is validly signed"
expect_code 1 "downgrade to 1.0.1 refused" ecu update --package "$WORK/p101.tar.gz"
expect_installed 1.0.2

echo "== 6. attacks: the vehicle must reject these WITHOUT any help from the backend"
# 6a flipped firmware byte, everything else untouched
mkdir "$WORK/a"; tar -C "$WORK/a" -xzf "$WORK/p103.tar.gz"
printf 'X' | dd of="$WORK/a/firmware.bin" bs=1 seek=0 conv=notrunc 2>/dev/null
repack "$WORK/a" "$WORK/a.tar.gz"
expect_code 1 "flipped firmware byte" ecu update --package "$WORK/a.tar.gz"

# 6b attacker also fixes manifest, .sha256 and SBOM hashes, but keeps the original signature
mkdir "$WORK/b"; tar -C "$WORK/b" -xzf "$WORK/p103.tar.gz"
printf 'Y' >> "$WORK/b/firmware.bin"
NEW=$(sha256sum "$WORK/b/firmware.bin" | awk '{print $1}')
echo "$NEW" > "$WORK/b/firmware.bin.sha256"
python3 - "$WORK/b" "$NEW" <<'PY'
import json, sys
d, h = sys.argv[1:3]
m = json.load(open(f"{d}/manifest.json")); m["sha256"] = h; json.dump(m, open(f"{d}/manifest.json", "w"))
s = json.load(open(f"{d}/sbom.cdx.json")); s["metadata"]["component"]["hashes"][0]["content"] = h; json.dump(s, open(f"{d}/sbom.cdx.json", "w"))
PY
repack "$WORK/b" "$WORK/b.tar.gz"
expect_code 1 "consistent hashes but original signature (signature invalid)" ecu update --package "$WORK/b.tar.gz"

# 6c attacker re-signs the modified firmware with their own key
mkdir "$WORK/c" "$WORK/cgh"; chmod 700 "$WORK/cgh"; tar -C "$WORK/c" -xzf "$WORK/b.tar.gz"
gpg --homedir "$WORK/cgh" --batch --quiet --passphrase '' --quick-generate-key "attacker@example.invalid" ed25519 sign never 2>/dev/null
rm -f "$WORK/c/firmware.bin.sig"
gpg --homedir "$WORK/cgh" --batch --yes --armor --detach-sign --output "$WORK/c/firmware.bin.sig" "$WORK/c/firmware.bin" 2>/dev/null
repack "$WORK/c" "$WORK/c.tar.gz"
expect_code 1 "re-signed by an untrusted key" ecu update --package "$WORK/c.tar.gz"

# 6d genuine signed firmware 1.0.3 but the SBOM of a different release swapped in
mkdir "$WORK/d" "$WORK/d2"; tar -C "$WORK/d" -xzf "$WORK/p103.tar.gz"; tar -C "$WORK/d2" -xzf "$WORK/p102.tar.gz"
cp "$WORK/d2/sbom.cdx.json" "$WORK/d/sbom.cdx.json"
repack "$WORK/d" "$WORK/d.tar.gz"
expect_code 1 "valid signature but SBOM of another release" ecu update --package "$WORK/d.tar.gz"

# 6e not a package at all
head -c 2000 /dev/urandom > "$WORK/junk.bin"
expect_code 1 "garbage input" ecu update --package "$WORK/junk.bin"

expect_installed 1.0.2

echo "== 7. the genuine, never-seen 1.0.3 still installs after all the failed attacks"
expect_code 0 "install genuine 1.0.3" ecu update --package "$WORK/p103.tar.gz"
expect_installed 1.0.3

echo "== audit log (last entries)"
tail -n 4 "$ECU/update.log"
echo; echo "VEHICLE CHECKS PASSED"
