#!/usr/bin/env bash
# Generate a CycloneDX SBOM for the firmware release.
# Usage: generate_sbom.sh <firmware.bin> <version> <output.json>
#
# Components come from two sources, tagged in each component's properties:
#   detected  shared libraries the binary really links against, found with ldd,
#             resolved to the distro package that owns each file (dpkg), with
#             the library file's SHA-256.
#   declared  vendored or statically linked code that tools cannot see,
#             listed by hand in sbom/components.json.
# Plus the firmware itself (with its hash) and the compiler used for the build.
set -euo pipefail

FW="${1:?firmware file required}"
VERSION="${2:?version required}"
OUT="${3:?output path required}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

python3 - "$FW" "$VERSION" "$OUT" "$HERE/sbom/components.json" <<'PY'
import datetime, hashlib, json, os, re, subprocess, sys, uuid

fw, version, out, declared_path = sys.argv[1:5]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def distro():
    try:
        kv = dict(l.strip().split("=", 1) for l in open("/etc/os-release") if "=" in l)
        return kv.get("ID", "linux").strip('"')
    except OSError:
        return "linux"


def prop(name, value):
    return {"name": name, "value": value}


def detect_linked_libraries(binary):
    """Return CycloneDX components for shared libraries linked by the binary."""
    code, text = run(["ldd", binary])
    if code != 0:  # static binary: nothing to detect
        return []
    ns = distro()
    arch_code, arch = run(["dpkg", "--print-architecture"])
    comps, seen = [], set()
    for line in text.splitlines():
        m = re.search(r"(\S+)\s+=>\s+(/\S+)", line) or re.match(r"\s*(/\S+)\s+\(", line)
        if not m:
            continue  # linux-vdso etc. have no file on disk
        soname = m.group(1) if m.lastindex == 2 else os.path.basename(m.group(1))
        path = os.path.realpath(m.group(m.lastindex))
        if not os.path.isfile(path):
            continue
        file_hash = sha256_file(path)
        owner_code, owner = run(["dpkg", "-S", path])
        pkg = owner.split(":")[0] if owner_code == 0 and owner else None
        if pkg is None:
            # also try the pre-usrmerge spelling of the path
            for alt in (m.group(m.lastindex), "/usr" + path if not path.startswith("/usr") else path[4:]):
                owner_code, owner = run(["dpkg", "-S", alt])
                if owner_code == 0 and owner:
                    pkg = owner.split(":")[0]
                    break
        if pkg:
            _, info = run(["dpkg-query", "-W", "-f=${Version}\t${Maintainer}", pkg])
            ver, _, maint = info.partition("\t")
            purl = f"pkg:deb/{ns}/{pkg}@{ver}" + (f"?arch={arch}" if arch_code == 0 else "")
            comp = {
                "type": "library",
                "bom-ref": purl,
                "name": pkg,
                "version": ver,
                "purl": purl,
                "publisher": maint or None,
                "hashes": [{"alg": "SHA-256", "content": file_hash}],
                "properties": [prop("ota:source", "detected"),
                               prop("ota:linked-file", soname)],
            }
            comp = {k: v for k, v in comp.items() if v is not None}
        else:
            ref = f"file:{soname}"
            comp = {
                "type": "library",
                "bom-ref": ref,
                "name": soname,
                "version": "unknown",
                "hashes": [{"alg": "SHA-256", "content": file_hash}],
                "properties": [prop("ota:source", "detected"),
                               prop("ota:note", "no owning package found")],
            }
        if comp["bom-ref"] not in seen:
            seen.add(comp["bom-ref"])
            comps.append(comp)
    return comps


def compiler_tool():
    code, text = run(["gcc", "--version"])
    if code != 0:
        return []
    first = text.splitlines()[0]
    m = re.search(r"(\d+\.\d+\.\d+)", first)
    return [{"type": "application", "name": "gcc", "version": m.group(1) if m else first}]


detected = detect_linked_libraries(fw)
declared = json.load(open(declared_path))
for c in declared:
    c.setdefault("properties", []).append(prop("ota:source", "declared"))

components = detected + [c for c in declared if c["bom-ref"] not in {d["bom-ref"] for d in detected}]

bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
    "version": 1,
    "metadata": {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tools": {"components": [
            {"type": "application", "name": "generate_sbom.sh", "version": "2.0"},
            *compiler_tool(),
        ]},
        "component": {
            "type": "firmware",
            "bom-ref": "ecu-firmware",
            "name": "ecu-firmware",
            "version": version,
            "hashes": [{"alg": "SHA-256", "content": sha256_file(fw)}],
        },
    },
    "components": components,
    "dependencies": [
        {"ref": "ecu-firmware", "dependsOn": [c["bom-ref"] for c in components]}
    ],
}
json.dump(bom, open(out, "w"), indent=2)
print(f"SBOM written to {out}: {len(detected)} detected + "
      f"{len(components) - len(detected)} declared components")
PY
