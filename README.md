# Secure Vehicle Update System with SBOM Pipeline
[![Secure OTA pipeline](https://github.com/d0ok/secure-ota-pipeline/actions/workflows/pipeline.yml/badge.svg)](https://github.com/d0ok/secure-ota-pipeline/actions/workflows/pipeline.yml)

A demonstration CI/CD pipeline for over-the-air (OTA) vehicle software updates:

**build firmware → generate CycloneDX SBOM → sign with GPG → package → deploy to a mock vehicle backend that verifies everything before accepting.**

A gap analysis maps the pipeline to UN R156 (software update management): [docs/UN_R156_gap_analysis.md](docs/UN_R156_gap_analysis.md).

![Architecture](docs/architecture.svg)

## What it demonstrates

| Stage | Implementation |
|---|---|
| Build | `firmware/` C program compiled with version and build id injected |
| SBOM | CycloneDX 1.5 JSON via `scripts/generate_sbom.sh`, validated against the official schema in CI |
| Signing | Detached, armored GPG signature, performed in a protected GitHub environment |
| Package | `tar.gz` with firmware, signature, SHA-256, SBOM, manifest |
| Mock backend | Flask service (`backend/app.py`) that checks manifest hash, GPG signature against a trusted keyring, SBOM-to-firmware hash binding, and rejects duplicate versions |
| Negative tests | `scripts/tamper_test.sh`: modified firmware and untrusted signer must be rejected |

## Run it locally

Requirements: `gcc`, `make`, `gpg`, `python3`, `curl`.

```bash
pip install -r backend/requirements.txt "cyclonedx-python-lib[json-validation]"
scripts/local_e2e.sh
```

This uses an ephemeral GPG key and runs the same scripts as CI. It ends with `ALL CHECKS PASSED` when build, SBOM, signing, deployment, tamper rejection and replay rejection all behave.

## Set up the GitHub pipeline

1. Generate the release key once, on a trusted machine:
   ```bash
   scripts/gen_release_key.sh
   ```
   Commit `keys/release-signing.pub.asc`. The private key is only printed to your terminal.
2. In the repo settings:
   - Create an environment named `firmware-signing`, with required reviewers.
   - Add environment secrets `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE`.
   - Add the variable `GPG_KEY_ID` (the fingerprint printed by the script).
3. Push to `main`. The workflow in `.github/workflows/pipeline.yml` runs build, sbom, sign (waits for approval), then deploy-mock-backend.

## Layout

```
firmware/        mock ECU firmware and Makefile
sbom/            component inventory feeding the SBOM
scripts/         build, sign, verify, package, deploy, tests
backend/         mock vehicle backend (Flask)
keys/            public signing key (you add this)
docs/            gap analysis and architecture diagram
.github/         workflow
```

## Limitations

This is a teaching and portfolio project, not a production OTA system. The backend has no TLS, device identity or real persistence; the vehicle side is not implemented; the SBOM component list is hand-maintained; keys are software keys. See the gap analysis for the full list, and do not read it as evidence of R156 compliance.
