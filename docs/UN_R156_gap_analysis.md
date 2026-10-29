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
| 1 | **Authenticity of updates** — updates must be protected so a vehicle or backend can tell they come from the manufacturer | Detached GPG signature over `firmware.bin`, made in a gated CI job; backend verifies against a trusted keyring and rejects other signers | `scripts/sign_firmware.sh`, `backend/app.py::verify_signature`, `scripts/tamper_test.sh` (untrusted-key case); the simulated vehicle (`vehicle/ecu_updater.py`) verifies independently against its own pinned key fingerprint, tested by `scripts/vehicle_e2e.sh` | **Partial** — both backend and simulated vehicle verify, but the simulation runs in user space with a GPG keyring file, not in a bootloader or HSM, and key handling is software-only |
| 2 | **Integrity of updates** — modification must be detectable | SHA-256 in manifest and `.sha256`; hash checked by backend; signature covers firmware bytes | `package.sh`, `backend/app.py`, tamper test (flipped byte rejected) | **Covered** in simulation: backend and simulated vehicle both check hashes, and tampering is rejected in every tested form. Real ECU enforcement is a gap |
| 3 | **Unique software identification** (7.2.1, RXSWIN) | Version in firmware build and manifest; firmware hash in SBOM | `firmware/Makefile`, `manifest.json`, SBOM `metadata.component` | **Gap** — no RXSWIN scheme, no mapping of software versions to regulations (for example RX79) |
| 4 | **Software and hardware configuration records** (7.1: documenting configuration, dependencies, compatibility) | CycloneDX SBOM generated in CI from the real build: shared libraries the binary links (found with `ldd`, resolved to the owning distro package and version, with file hashes), the compiler used, the firmware hash, plus hand-declared vendored code. Each component is tagged `detected` or `declared` | `scripts/generate_sbom.sh`, `sbom/components.json`, schema validation in CI | **Partial** — statically linked or vendored code is only as good as the hand-kept declared list; detection works for dpkg-based systems only; no hardware BOM, no ECU interdependency model |
| 5 | **Compatibility check against vehicle configuration before release** (7.1) | None. Backend accepts any validly signed package | — | **Gap** |
| 6 | **Assessment of update impact on type approval and safety** (7.1) | None. Release is automatic from `main` | — | **Gap** (needs a gated release workflow with a recorded impact decision) |
| 7 | **Secure, recorded update process** (traceability) | Immutable CI run, build artifacts, vulnerability report archived per run, `verification.json` written by backend per accepted update, backend log | `.github/workflows/pipeline.yml`, `backend/app.py` | **Partial** — no per-vehicle update record, no tamper-evident audit log |
| 8 | **Controlled release approval** | `sign` job runs in a protected GitHub environment with required reviewers | `pipeline.yml` (`environment: firmware-signing`) | **Partial** — must be configured in repo settings; no separation of duties evidence |
| 9 | **Protection of signing keys** | Key stored as an environment secret, removed from runner afterwards | `pipeline.yml` | **Partial** — software key. Production should use an HSM or cloud KMS, key ceremony, rotation and revocation |
| 10 | **Replay and downgrade protection** | Backend rejects an already-published version (HTTP 409). The simulated vehicle keeps a monotonic anti-rollback floor and refuses any version not newer than the installed one, even if validly signed | `scripts/local_e2e.sh` step 7, `scripts/vehicle_e2e.sh` steps 2 and 5 | **Partial** — the floor is a JSON file, not a hardware counter; the backend has no version policy; no signed timestamps, expiry or freshness, so a vehicle can be kept on an old version by withholding updates (freeze attack) |
| 11 | **Supply-chain / supplier control** (third-party software risk) | SBOM lists third-party components with versions, hashes and suppliers. The scan step (below, row 18) screens them before release | `sbom/components.json`, `scripts/generate_sbom.sh` | **Partial** — no supplier attestations; declared (hand-listed) components such as the vendored driver use generic identifiers that the scanner cannot match, so they are not screened |
| 12 | **Secure transport and backend access control** | Optional bearer token; the mock listens on localhost over HTTP | `backend/app.py`, `deploy.sh` | **Gap** — no TLS or mutual TLS, no device identity |
| 13 | **Failed or interrupted update: restore previous version or reach a safe state** | Simulated vehicle uses A/B slots: the new image goes to the inactive slot, is re-hashed from storage, activated, self-tested, and the previous slot is restored if the self-test fails. The rollback floor moves only after commit | `vehicle/ecu_updater.py`, `scripts/vehicle_e2e.sh` step 3 | **Partial** — simulation only. Not tested: power loss mid-write (state is saved atomically but no fault injection was done), flash and bootloader behaviour, safe-state handling. The real requirement belongs to the vehicle |
| 14 | **Update only when vehicle conditions allow** (for example sufficient power, safe state) | None | — | **Out of scope** (vehicle) |
| 15 | **Informing the user before an update** (purpose, impact, required actions) | None | — | **Out of scope** (HMI and process) |
| 16 | **Certified SUMS, periodic re-audit, documented processes** | Pipeline is technical evidence only | This document | **Out of scope** (organisational) |
| 17 | **Evidence per release** | Per-release package holds firmware, signature, SBOM and manifest | `package.sh` | **Partial** — no build provenance (for example SLSA attestation), no test or validation report attached. The vulnerability report is archived by CI but is not inside the signed package, so the vehicle backend cannot check that a scan took place |
| 18 | **Known-vulnerability screening before release.** R156 does not prescribe scanning by name; this supports the software risk assessment in the SUMS and the monitoring duties of the cybersecurity management system (R155) | `vuln-scan` job runs before `sign`: pinned, checksum-verified Grype scans the SBOM; policy blocks on any Critical finding or any known-exploited (KEV) finding; other findings are reported only. A scanner self-test on a deliberately vulnerable canary SBOM fails the run if the scanner finds nothing | `.github/workflows/pipeline.yml`, `scripts/vuln_gate.py`, `tests/canary.cdx.json`, `.grype-version` | **Partial** — screening happens at build time only: there is no continuous monitoring of already-shipped versions against new CVEs, no VEX or recorded triage decisions (current findings are judged not applicable by reading CVE descriptions, which is not documented evidence), and the policy follows the distro's severity rating, which can differ from NVD's |

## 3. Priority gaps

Ordered by how much they undermine the security story:

1. **Verification in real vehicle hardware.** The simulated vehicle already verifies independently of the backend (pinned key fingerprint, hashes, SBOM binding, anti-rollback, A/B rollback). What remains is doing this in a bootloader or HSM, with the key and rollback counter in protected storage, and testing power loss during an update.
2. **RXSWIN and configuration management (item 3, 5).** Define RXSWINs per regulation, tie them to firmware versions, and block release for vehicles whose configuration is not declared compatible.
3. **Key management (item 9).** Move signing to an HSM or KMS, add rotation and revocation, and record who approved each signature.
4. **Release governance (items 6, 8).** Add a recorded impact assessment and approval step before the `sign` job.
5. **Downgrade, replay and freshness (item 10).** Signed metadata with version floor and expiry.
6. **Transport security (item 12).** TLS with device authentication.
7. **Vulnerability management after release (items 11, 18).** The build-time gate exists. Still missing: scheduled re-scans of every released SBOM as new CVEs appear, VEX statements recording why a finding does or does not apply, and a way to bind the scan result to the signed package.
8. **SBOM depth (items 4, 11).** The SBOM now comes from the real build, but static and vendored code still depends on a hand-kept list. Add a source-level scanner, a hardware BOM, and sign the SBOM itself (or a build attestation) so it is tamper-evident.

## 4. Lesson from building the scan: a clean result is not evidence

The first vulnerability scans of this project reported "No vulnerabilities found". That was wrong. The SBOM identified the package `libc6` without its release or its source package, but distro security data is keyed by release and by *source* package (`libc6` is built from `glibc`). The scanner could not match anything and said nothing was wrong. Two changes fixed it: the SBOM generator now records the distro release and the upstream source package, and CI runs a self-test that scans a deliberately vulnerable canary SBOM and fails if the scanner finds nothing. Any control that can fail silently needs a test that proves it can still detect something.

## 5. Related frameworks worth aligning with

- **UN R155 / ISO/SAE 21434**: the cybersecurity management system that SUMS sits next to; type approval needs both.
- **ISO 24089**: software update engineering guidance that maps onto R156.
- **Uptane**: a purpose-built secure update framework for vehicles, addressing key compromise, rollback and freeze attacks that a single GPG signature does not.

## 6. Limitations of this demonstration

- The mock backend is a single Flask process with no TLS, authentication beyond an optional token, or persistence guarantees.
- GPG was chosen for clarity, not because it suits embedded verification. Production systems commonly use asymmetric signatures with hardware-backed keys and compact metadata formats.
- Nothing here has been reviewed by an approval authority or technical service.
