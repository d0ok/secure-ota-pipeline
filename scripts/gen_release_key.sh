#!/usr/bin/env bash
# Generate a release signing key for this pipeline (run once, on a trusted machine).
# Writes the PUBLIC key to keys/release-signing.pub.asc (commit this).
# Prints the PRIVATE key and fingerprint for you to store as GitHub secrets/variables.
# Nothing private is written inside the repo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GH="$(mktemp -d)"; chmod 700 "$GH"
export GNUPGHOME="$GH"
trap 'gpgconf --kill gpg-agent 2>/dev/null || true; rm -rf "$GH"' EXIT

read -r -s -p "Passphrase for the new signing key: " PASS; echo
gpg --batch --quiet --pinentry-mode loopback --passphrase "$PASS" \
    --quick-generate-key "OTA Release Signing <ota-release@example.invalid>" ed25519 sign 2y
FPR=$(gpg --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')

mkdir -p "$ROOT/keys"
gpg --armor --export "$FPR" > "$ROOT/keys/release-signing.pub.asc"

echo
echo "Public key written to keys/release-signing.pub.asc (commit it)."
echo "Fingerprint (GitHub variable GPG_KEY_ID): $FPR"
echo
echo "Private key (GitHub secret GPG_PRIVATE_KEY). Copy it now, it is not saved anywhere:"
gpg --batch --pinentry-mode loopback --passphrase "$PASS" --armor --export-secret-keys "$FPR"
echo
echo "Also store the passphrase as GitHub secret GPG_PASSPHRASE."
