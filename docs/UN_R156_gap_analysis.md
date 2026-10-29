# UN R156 Gap Analysis: Secure OTA Pipeline

**Scope:** this repository's CI/CD pipeline (build → SBOM → GPG sign → deploy to mock vehicle backend).
**Standard:** UN Regulation No. 156, software update and software update management system (SUMS).
**Status of this document:** engineering self-assessment for a demonstration project. It is not an audit result and not a statement of compliance.

## 1. How to read this

R156 does not certify a pipeline. It requires the vehicle manufacturer to operate a **certified SUMS** (an organisational process system, assessed by an auditor and re-audited periodically) and to show that vehicles in the approved type can be updated safely. A CI/CD pipeline like this one can supply *technical evidence* for part of that system. Much of R156 sits outside any pipeline: organisational processes, vehicle-side behaviour, type-approval impact assessment and user communication.

Status values:

| Status | Meaning |
|---|---|
| **Covered** | The pipeline implements and demonstrably tests the control. |
| **Partial** | Implemented in a simplified or mock form; needs hardening for production. |
| **Gap** | Not implemented in this repo; needed for an R156-style SUMS. |
| **Out of scope** | Vehicle-side or organisational; cannot be met by a pipeline alone. |

**Paragraph references.** Requirements are mapped by topic. Only section 7.1 (SUMS) and 7.2.1 (RXSWIN identification) are cited by number, because I could confirm those against secondary sources. Check finer paragraph numbers (7.2.2.x, 7.2.3 and so on) against the current consolidated text of R156 (including the 01 series amendments) before using this in an audit file.

## 2. Mapping

| # | R156 requirement area | Pipeline control | Evidence in repo | Status |
|---|---|---|---|---|
| 1 | **Authenticity of updates** — updates must be protected so a vehicle or backend can tell they come from the manufacturer | Detached GPG signature over `firmware.bin`, made in a gated CI job; backend verifies against a trusted keyring and rejects other signers | `scripts/sign_firmware.sh`, `backend/app.py::verify_signature`, `scripts/tamper_test.sh` (untrusted-key case) | **Partial** (backend verifies; the vehicle does not, key handling is software-only) |
| 2 | **Integrity of updates** — modification must be detectable | SHA-256 in manifest and `.sha256`; hash checked by backend; signature covers firmware bytes | `package.sh`, `backend/app.py`, tamper test (flipped byte rejected) | **Covered** for the backend path; **Gap** for on-vehicle check |
| 3 | **Unique software identification** (7.2.1, RXSWIN) | Version in firmware build and manifest; firmware hash in SBOM | `firmware/Makefile`, `manifest.json`, SBOM `metadata.component` | **Gap** — no RXSWIN scheme, no mapping of software versions to regulations (for example RX79) |
| 4 | **Software and hardware configuration records** (7.1: documenting configuration, dependencies, compatibility) | CycloneDX SBOM lists components and the firmware hash | `scripts/generate_sbom.sh`, `sbom/components.json`, schema validation in CI | **Partial** — SBOM is a hand-maintained inventory, no hardware BOM, no ECU interdependency model |
| 5 | **Compatibility check against vehicle configuration before release** (7.1) | None. Backend accepts any validly signed package | — | **Gap** |
| 6 | **Assessment of update impact on type approval and safety** (7.1) | None. Release is automatic from `main` | — | **Gap** (needs a gated release workflow with a recorded impact decision) |
| 7 | **Secure, recorded update process** (traceability) | Immutable CI run, build artifacts, `verification.json` written by backend per accepted update, backend log | `.github/workflows/pipeline.yml`, `backend/app.py` | **Partial** — no per-vehicle update record, no tamper-evident audit log |
| 8 | **Controlled release approval** | `sign` job runs in a protected GitHub environment with required reviewers | `pipeline.yml` (`environment: firmware-signing`) | **Partial** — must be configured in repo settings; no separation of duties evidence |
| 9 | **Protection of signing keys** | Key stored as an environment secret, removed from runner afterwards | `pipeline.yml` | **Partial** — software key. Production should use an HSM or cloud KMS, key ceremony, rotation and revocation |
| 10 | **Replay and downgrade protection** | Backend rejects an already-published version (HTTP 409) | `scripts/local_e2e.sh` step 7 | **Partial** — only duplicate versions; no monotonic version policy, no signed timestamps or expiry |
| 11 | **Supply-chain / supplier control** (third-party software risk) | SBOM lists third-party components with licences and suppliers | `sbom/components.json` | **Partial** — no vulnerability scanning, no VEX, no supplier attestations |
| 12 | **Secure transport and backend access control** | Optional bearer token; the mock listens on localhost over HTTP | `backend/app.py`, `deploy.sh` | **Gap** — no TLS or mutual TLS, no device identity |
| 13 | **Failed or interrupted update: restore previous version or reach a safe state** | None | — | **Out of scope** (vehicle). The pipeline could supply a recovery image and test evidence |
| 14 | **Update only when vehicle conditions allow** (for example sufficient power, safe state) | None | — | **Out of scope** (vehicle) |
| 15 | **Informing the user before an update** (purpose, impact, required actions) | None | — | **Out of scope** (HMI and process) |
| 16 | **Certified SUMS, periodic re-audit, documented processes** | Pipeline is technical evidence only | This document | **Out of scope** (organisational) |
| 17 | **Evidence per release** | Per-release package holds firmware, signature, SBOM and manifest | `package.sh` | **Partial** — no build provenance (for example SLSA attestation), no test or validation report attached |

## 3. Priority gaps

Ordered by how much they undermine the security story:

1. **Verification on the vehicle, not only the backend.** Today only the mock backend checks signatures. A real ECU or gateway must verify authenticity and integrity itself, with a pinned public key in protected storage.
2. **RXSWIN and configuration management (item 3, 5).** Define RXSWINs per regulation, tie them to firmware versions, and block release for vehicles whose configuration is not declared compatible.
3. **Key management (item 9).** Move signing to an HSM or KMS, add rotation and revocation, and record who approved each signature.
4. **Release governance (items 6, 8).** Add a recorded impact assessment and approval step before the `sign` job.
5. **Downgrade, replay and freshness (item 10).** Signed metadata with version floor and expiry.
6. **Transport security (item 12).** TLS with device authentication.
7. **SBOM depth (items 4, 11).** Generate the SBOM from the real build (not a hand-kept list), scan it for vulnerabilities, and keep it with the release record.

## 4. Related frameworks worth aligning with

- **UN R155 / ISO/SAE 21434**: the cybersecurity management system that SUMS sits next to; type approval needs both.
- **ISO 24089**: software update engineering guidance that maps onto R156.
- **Uptane**: a purpose-built secure update framework for vehicles, addressing key compromise, rollback and freeze attacks that a single GPG signature does not.

## 5. Limitations of this demonstration

- The mock backend is a single Flask process with no TLS, authentication beyond an optional token, or persistence guarantees.
- GPG was chosen for clarity, not because it suits embedded verification. Production systems commonly use asymmetric signatures with hardware-backed keys and compact metadata formats.
- Nothing here has been reviewed by an approval authority or technical service.
