#!/usr/bin/env python3
"""Simulated vehicle-side update client (ECU / gateway).

The backend already verifies packages, but a vehicle must not rely on that:
it re-verifies everything itself, with its own pinned trust anchor, before it
touches flash. This client demonstrates the checks a real ECU would make.

Commands
  provision --pubkey FILE     "factory" step: pin the release public key
  update --package FILE       install a package from a local file
  update --backend URL        fetch the newest package from the backend
  status                      show installed version, slots and anti-rollback floor

Checks before anything is written (any failure rejects the package):
  1. package contains exactly the expected files (no path tricks)
  2. SHA-256 of firmware matches the manifest
  3. detached GPG signature is valid and made by the PINNED key fingerprint
  4. SBOM is CycloneDX and describes this exact firmware (hash and version)
  5. version is strictly newer than anything ever installed (anti-rollback)

Install is A/B: the new image goes to the inactive slot, is re-hashed from
storage, activated, then self-tested. A failed self-test switches back to the
previous slot. The anti-rollback floor only moves after a successful commit.

Exit codes: 0 installed or up to date, 1 rejected, 2 error, 3 rolled back.

This is a simulation: real ECUs verify in a bootloader or HSM, with keys and
the rollback counter held in protected hardware, and do not execute the image
on the host.
"""
import argparse
import datetime
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

REQUIRED = {"firmware.bin", "firmware.bin.sig", "firmware.bin.sha256",
            "sbom.cdx.json", "manifest.json"}
MAX_PACKAGE_BYTES = 50 * 1024 * 1024
VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.]+)?$")
INITIAL_VERSION = "0.0.0"


class Rejected(Exception):
    """Package failed a check; nothing was installed."""


class RolledBack(Exception):
    """Install was attempted, the self-test failed, the old slot is active again."""


def parse_version(v):
    """Compare on major.minor.patch only; any suffix is ignored for ordering."""
    m = VERSION_RE.match(v if isinstance(v, str) else "")
    if not m:
        raise Rejected(f"invalid version string: {v!r}")
    return tuple(int(x) for x in m.groups())


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write_json(path, obj):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class Ecu:
    def __init__(self, state_dir):
        self.dir = Path(state_dir)
        self.state_file = self.dir / "state.json"
        self.log_file = self.dir / "update.log"
        self.trust_dir = self.dir / "trust"

    def load(self):
        if not self.state_file.exists():
            raise SystemExit("ECU is not provisioned. Run: provision --pubkey FILE")
        return json.loads(self.state_file.read_text())

    def save(self, st):
        atomic_write_json(self.state_file, st)

    def log(self, result, **kw):
        entry = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 "result": result, **kw}
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def active_version(self, st):
        return st["slots"][st["active_slot"]]["version"]


# ---------------------------------------------------------------- provisioning

def gpg_primary_fingerprint(pubkey_path):
    with tempfile.TemporaryDirectory() as gh:
        os.chmod(gh, 0o700)
        r = subprocess.run(["gpg", "--homedir", gh, "--batch", "--show-keys",
                            "--with-colons", str(pubkey_path)],
                           capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"cannot read public key: {r.stderr.strip()}")
    fprs, expect_fpr = [], False
    for line in r.stdout.splitlines():
        kind = line.split(":")[0]
        if kind == "pub":
            expect_fpr = True
        elif kind == "fpr" and expect_fpr:
            fprs.append(line.split(":")[9].upper())
            expect_fpr = False
    if len(fprs) != 1:
        raise SystemExit(f"expected exactly one public key, found {len(fprs)}")
    return fprs[0]


def provision(ecu, pubkey):
    if ecu.state_file.exists():
        raise SystemExit("ECU is already provisioned; the pinned key cannot be replaced")
    fpr = gpg_primary_fingerprint(pubkey)
    ecu.trust_dir.mkdir(parents=True)
    shutil.copy(pubkey, ecu.trust_dir / "pinned.pub.asc")
    (ecu.trust_dir / "fingerprint.txt").write_text(fpr + "\n")
    for slot in ("A", "B"):
        (ecu.dir / f"slot_{slot}").mkdir()
    ecu.save({"active_slot": "A",
              "rollback_floor": INITIAL_VERSION,
              "slots": {"A": {"version": INITIAL_VERSION, "sha256": None, "state": "committed"},
                        "B": {"version": None, "sha256": None, "state": "empty"}}})
    ecu.log("provisioned", pinned_fingerprint=fpr)
    print(f"Provisioned. Pinned signing key fingerprint: {fpr}")


# ----------------------------------------------------------------- verification

def safe_extract(data, dest):
    if len(data) > MAX_PACKAGE_BYTES:
        raise Rejected("package too large")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            names = [m.name for m in tf.getmembers()]
            for m in tf.getmembers():
                if not m.isfile() or m.name not in REQUIRED:
                    raise Rejected(f"unexpected archive member: {m.name}")
            if len(names) != len(set(names)):
                raise Rejected("duplicate archive members")
            tf.extractall(dest, filter="data")
    except tarfile.TarError as e:
        raise Rejected(f"not a valid package archive: {e}")
    missing = REQUIRED - {p.name for p in Path(dest).iterdir()}
    if missing:
        raise Rejected(f"missing files: {sorted(missing)}")


def verify_signature(trust_dir, fw, sig):
    pinned = (trust_dir / "fingerprint.txt").read_text().strip().upper()
    with tempfile.TemporaryDirectory() as gh:
        os.chmod(gh, 0o700)
        imp = subprocess.run(["gpg", "--homedir", gh, "--batch", "--quiet", "--import",
                              str(trust_dir / "pinned.pub.asc")],
                             capture_output=True, text=True)
        if imp.returncode != 0:
            raise Rejected("pinned key could not be loaded")
        r = subprocess.run(["gpg", "--homedir", gh, "--batch", "--status-fd", "1",
                            "--verify", str(sig), str(fw)],
                           capture_output=True, text=True)
    if r.returncode != 0 or "[GNUPG:] GOODSIG" not in r.stdout:
        raise Rejected("signature invalid, or made by a key that is not the pinned key")
    for line in r.stdout.splitlines():
        if line.startswith("[GNUPG:] VALIDSIG"):
            parts = line.split()
            primary = (parts[-1] if len(parts) >= 11 else parts[2]).upper()
            if primary != pinned:
                raise Rejected("signed by a different key than the pinned fingerprint")
            return primary
    raise Rejected("no valid signature status from gpg")


def verify_package(ecu, data, work):
    """Return the verified manifest. Raises Rejected on any failure."""
    safe_extract(data, work)
    try:
        manifest = json.loads((work / "manifest.json").read_text())
        version = manifest["version"]
        expected_sha = manifest["sha256"]
    except (json.JSONDecodeError, KeyError, TypeError):
        raise Rejected("manifest is malformed")
    parse_version(version)

    fw_sha = sha256_file(work / "firmware.bin")
    if fw_sha != expected_sha:
        raise Rejected("firmware hash does not match manifest")
    manifest["_signer"] = verify_signature(ecu.trust_dir, work / "firmware.bin",
                                           work / "firmware.bin.sig")
    try:
        sbom = json.loads((work / "sbom.cdx.json").read_text())
        comp = sbom["metadata"]["component"]
        sbom_hashes = {h["alg"]: h["content"] for h in comp.get("hashes", [])}
    except (json.JSONDecodeError, KeyError, TypeError):
        raise Rejected("SBOM is malformed")
    if sbom.get("bomFormat") != "CycloneDX":
        raise Rejected("SBOM is not CycloneDX")
    if sbom_hashes.get("SHA-256") != fw_sha:
        raise Rejected("SBOM does not describe this firmware (hash mismatch)")
    if comp.get("version") != version:
        raise Rejected("SBOM version does not match manifest version")
    manifest["_sha256"] = fw_sha
    return manifest


# ---------------------------------------------------------------------- install

def self_test(binary, version, simulate_failure):
    if simulate_failure:
        return False, "simulated self-test failure"
    r = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        return False, f"image exited with code {r.returncode}"
    if version not in r.stdout:
        return False, "image does not report the expected version"
    return True, r.stdout.strip()


def install(ecu, data, simulate_failure=False):
    st = ecu.load()
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        manifest = verify_package(ecu, data, work)
        version = manifest["version"]

        floor = parse_version(st["rollback_floor"])
        if parse_version(version) <= floor:
            raise Rejected(f"version {version} is not newer than {st['rollback_floor']} "
                           "(anti-rollback)")
        if parse_version(version) <= parse_version(ecu.active_version(st)):
            raise Rejected(f"version {version} is not newer than the installed "
                           f"{ecu.active_version(st)}")

        prev, new = st["active_slot"], ("B" if st["active_slot"] == "A" else "A")
        target = ecu.dir / f"slot_{new}" / "firmware.bin"
        shutil.copyfile(work / "firmware.bin", target)
        os.chmod(target, 0o755)
        with open(target, "rb") as f:
            os.fsync(f.fileno())
        if sha256_file(target) != manifest["_sha256"]:
            raise Rejected("image written to flash does not match the verified hash")

        st["slots"][new] = {"version": version, "sha256": manifest["_sha256"], "state": "pending"}
        st["active_slot"] = new
        ecu.save(st)

        ok, detail = self_test(target, version, simulate_failure)
        if not ok:
            st["active_slot"] = prev
            st["slots"][new]["state"] = "failed"
            ecu.save(st)
            ecu.log("rolled_back", version=version, reason=detail, restored=ecu.active_version(st))
            raise RolledBack(f"self-test failed ({detail}); restored version "
                             f"{ecu.active_version(st)} in slot {prev}")

        st["slots"][new]["state"] = "committed"
        st["rollback_floor"] = version
        ecu.save(st)
        ecu.log("installed", version=version, slot=new, signer=manifest["_signer"],
                sha256=manifest["_sha256"])
        return version, new


def fetch_latest(ecu, url):
    base = url.rstrip("/")
    with urllib.request.urlopen(f"{base}/api/v1/updates", timeout=15) as r:
        available = json.load(r).get("available", [])
    candidates = []
    for v in available:
        try:
            candidates.append((parse_version(v), v))
        except Rejected:
            continue
    if not candidates:
        return None, None
    _, latest = max(candidates)
    with urllib.request.urlopen(f"{base}/api/v1/updates/{latest}/package", timeout=30) as r:
        data = r.read(MAX_PACKAGE_BYTES + 1)
    return latest, data


# --------------------------------------------------------------------------- CLI

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--state", default="./ecu-state", help="ECU storage directory")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("provision")
    p.add_argument("--pubkey", required=True)
    u = sub.add_parser("update")
    g = u.add_mutually_exclusive_group(required=True)
    g.add_argument("--package")
    g.add_argument("--backend")
    u.add_argument("--simulate-selftest-failure", action="store_true",
                   help="demo: force the post-install self-test to fail")
    sub.add_parser("status")
    args = ap.parse_args()
    ecu = Ecu(args.state)

    try:
        if args.cmd == "provision":
            provision(ecu, args.pubkey)
        elif args.cmd == "status":
            st = ecu.load()
            print(json.dumps({"active_slot": st["active_slot"],
                              "installed_version": ecu.active_version(st),
                              "rollback_floor": st["rollback_floor"],
                              "slots": st["slots"]}, indent=2))
        else:
            if args.package:
                data = Path(args.package).read_bytes()
            else:
                latest, data = fetch_latest(ecu, args.backend)
                if latest is None:
                    print("Backend offers no updates.")
                    return 0
                st = ecu.load()
                if parse_version(latest) <= parse_version(ecu.active_version(st)):
                    print(f"Up to date (installed {ecu.active_version(st)}, "
                          f"newest offered {latest}).")
                    return 0
            try:
                version, slot = install(ecu, data, args.simulate_selftest_failure)
            except Rejected as e:
                ecu.log("rejected", reason=str(e))
                raise
            print(f"INSTALLED version {version} into slot {slot} (committed).")
    except Rejected as e:
        print(f"REJECTED: {e}", file=sys.stderr)
        return 1
    except RolledBack as e:
        print(f"ROLLED BACK: {e}", file=sys.stderr)
        return 3
    except (OSError, subprocess.SubprocessError, urllib.error.URLError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
