"""Mock vehicle update backend.

Accepts an update package, verifies it before accepting:
  1. package structure and manifest
  2. SHA-256 of the firmware matches the manifest
  3. detached GPG signature is valid and made by a trusted key
  4. SBOM is valid CycloneDX JSON and describes this exact firmware (hash match)
Only then is the update stored and made available to vehicles.
"""
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

from flask import Flask, jsonify, request, send_file

app = Flask(__name__)

STORE = Path(os.environ.get("UPDATE_STORE", "./store"))
TRUSTED_KEYRING = os.environ.get("TRUSTED_KEYRING", "./trusted.gpg")
REQUIRED = {"firmware.bin", "firmware.bin.sig", "firmware.bin.sha256",
            "sbom.cdx.json", "manifest.json"}
MAX_PACKAGE_BYTES = 50 * 1024 * 1024


def reject(reason, code=400):
    return jsonify({"status": "rejected", "reason": reason}), code


def safe_extract(data: bytes, dest: Path):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile() or m.name not in REQUIRED:
                raise ValueError(f"unexpected archive member: {m.name}")
        tf.extractall(dest, filter="data")


def verify_signature(fw: Path, sig: Path) -> str:
    """Verify detached signature against the trusted keyring only."""
    with tempfile.TemporaryDirectory() as gh:
        os.chmod(gh, 0o700)
        proc = subprocess.run(
            ["gpg", "--homedir", gh, "--no-default-keyring",
             "--keyring", os.path.abspath(TRUSTED_KEYRING),
             "--status-fd", "1", "--verify", str(sig), str(fw)],
            capture_output=True, text=True)
    if proc.returncode != 0 or "[GNUPG:] GOODSIG" not in proc.stdout:
        raise ValueError("GPG signature verification failed")
    for line in proc.stdout.splitlines():
        if line.startswith("[GNUPG:] VALIDSIG"):
            return line.split()[2]  # signing key fingerprint
    raise ValueError("no VALIDSIG status from gpg")


def check_sbom(sbom_path: Path, fw_sha: str):
    sbom = json.loads(sbom_path.read_text())
    if sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM is not CycloneDX")
    comp = sbom.get("metadata", {}).get("component", {})
    hashes = {h["alg"]: h["content"] for h in comp.get("hashes", [])}
    if hashes.get("SHA-256") != fw_sha:
        raise ValueError("SBOM does not describe this firmware (hash mismatch)")
    return len(sbom.get("components", []))


@app.post("/api/v1/updates")
def upload():
    expected = os.environ.get("BACKEND_TOKEN")
    if expected and request.headers.get("Authorization") != f"Bearer {expected}":
        return reject("unauthorized", 401)

    f = request.files.get("package")
    if f is None:
        return reject("missing 'package' upload")
    data = f.read(MAX_PACKAGE_BYTES + 1)
    if len(data) > MAX_PACKAGE_BYTES:
        return reject("package too large", 413)

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        try:
            safe_extract(data, td)
            missing = REQUIRED - {p.name for p in td.iterdir()}
            if missing:
                return reject(f"missing files: {sorted(missing)}")
            manifest = json.loads((td / "manifest.json").read_text())
            fw_sha = hashlib.sha256((td / "firmware.bin").read_bytes()).hexdigest()
            if fw_sha != manifest.get("sha256"):
                return reject("firmware hash does not match manifest")
            fingerprint = verify_signature(td / "firmware.bin", td / "firmware.bin.sig")
            n_components = check_sbom(td / "sbom.cdx.json", fw_sha)
        except (ValueError, tarfile.TarError, json.JSONDecodeError, KeyError) as e:
            return reject(str(e))

        version = manifest["version"]
        if not version.replace(".", "").replace("-", "").isalnum():
            return reject("invalid version string")
        dest = STORE / version
        if dest.exists():
            return reject(f"version {version} already published", 409)
        dest.mkdir(parents=True)
        for p in td.iterdir():
            (dest / p.name).write_bytes(p.read_bytes())
        # keep the exact signed package so vehicles can fetch and verify it themselves
        (dest / "package.tar.gz").write_bytes(data)
        (dest / "verification.json").write_text(json.dumps({
            "signer_fingerprint": fingerprint,
            "firmware_sha256": fw_sha,
            "sbom_components": n_components}, indent=2))

    app.logger.info("accepted %s signed by %s", version, fingerprint)
    return jsonify({"status": "accepted", "version": version,
                    "signer": fingerprint, "sbom_components": n_components}), 201


@app.get("/api/v1/updates")
def list_updates():
    versions = sorted(p.name for p in STORE.glob("*") if p.is_dir()) if STORE.exists() else []
    return jsonify({"available": versions})


def _version_dir(version):
    d = (STORE / version).resolve()
    if STORE.resolve() not in d.parents or not d.is_dir():
        return None
    return d


@app.get("/api/v1/updates/<version>/package")
def get_package(version):
    """The complete signed package (firmware, signature, SBOM, manifest)."""
    d = _version_dir(version)
    if d is None or not (d / "package.tar.gz").exists():
        return reject("not found", 404)
    return send_file(d / "package.tar.gz", as_attachment=True)


@app.get("/api/v1/updates/<version>/firmware")
def get_firmware(version):
    d = _version_dir(version)
    if d is None:
        return reject("not found", 404)
    return send_file(d / "firmware.bin", as_attachment=True)


@app.get("/healthz")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    STORE.mkdir(parents=True, exist_ok=True)
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 8080)))
