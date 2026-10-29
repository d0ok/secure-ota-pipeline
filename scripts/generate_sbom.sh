#!/usr/bin/env bash
# Generate a CycloneDX SBOM for the firmware release.
# Usage: generate_sbom.sh <firmware.bin> <version> <output.json>
# Components come from sbom/components.json (hand-maintained inventory of
# third-party code linked into the firmware) plus the firmware itself with its hash.
set -euo pipefail

FW="${1:?firmware file required}"
VERSION="${2:?version required}"
OUT="${3:?output path required}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

python3 - "$FW" "$VERSION" "$OUT" "$HERE/sbom/components.json" <<'PY'
import hashlib, json, sys, uuid, datetime
fw, version, out, comps_path = sys.argv[1:5]
sha256 = hashlib.sha256(open(fw, "rb").read()).hexdigest()
components = json.load(open(comps_path))
bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
    "version": 1,
    "metadata": {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tools": {"components": [{"type": "application", "name": "generate_sbom.sh", "version": "1.0"}]},
        "component": {
            "type": "firmware",
            "bom-ref": "ecu-firmware",
            "name": "ecu-firmware",
            "version": version,
            "hashes": [{"alg": "SHA-256", "content": sha256}],
        },
    },
    "components": components,
    "dependencies": [
        {"ref": "ecu-firmware", "dependsOn": [c["bom-ref"] for c in components]}
    ],
}
json.dump(bom, open(out, "w"), indent=2)
print(f"SBOM written to {out} ({len(components)} components)")
PY
