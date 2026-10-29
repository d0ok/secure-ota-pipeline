#!/usr/bin/env bash
# Bundle firmware, signature, hash, SBOM and manifest into one update package.
# Usage: package.sh <build_dir> <version> <output.tar.gz>
set -euo pipefail

DIR="${1:?build dir required}"
VERSION="${2:?version required}"
OUT="${3:?output package required}"

cat > "$DIR/manifest.json" <<EOF
{
  "name": "ecu-firmware",
  "version": "$VERSION",
  "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "firmware": "firmware.bin",
  "signature": "firmware.bin.sig",
  "sha256": "$(cat "$DIR/firmware.bin.sha256")",
  "sbom": "sbom.cdx.json"
}
EOF

tar -C "$DIR" -czf "$OUT" firmware.bin firmware.bin.sig firmware.bin.sha256 sbom.cdx.json manifest.json
echo "Package created: $OUT"
