# Disclaimer

This project is an educational and portfolio demonstration. Please read this before using or referring to it.

## Not for use in real vehicles

The code is a simulation. It must not be used to update, test on, or connect to real vehicles, ECUs or other safety-relevant systems. The simulated vehicle client runs in user space, keeps its trust key and rollback counter in ordinary files, and has not been tested for power loss, hardware faults or adversarial conditions. The mock backend has no TLS, device authentication or hardening.

## Not a compliance claim

- This project does **not** make any product, process or organisation compliant with UN Regulation No. 156 (software update management), UN R155, ISO/SAE 21434, ISO 24089 or any other standard or law.
- `docs/UN_R156_gap_analysis.md` is the author's own engineering self-assessment. It has not been reviewed by an approval authority, technical service, auditor or lawyer. Paragraph references are limited to those the author could confirm, and the mapping is by topic, so it must be checked against the current official regulation text before being relied on.
- R156 certifies an organisation's software update management system (SUMS), not a code repository. A pipeline can supply technical evidence for part of one, nothing more.

## Not professional advice

Nothing here is legal, regulatory, security or safety advice.

## Security caveats

- Findings reported by the vulnerability scan are a screening result, not a security assessment. A clean scan does not mean the software is free of vulnerabilities (an early version of this project reported "no vulnerabilities" because of a flaw in the SBOM identifiers, see section 4 of the gap analysis). Statements that a finding "does not apply" to the demo firmware are the author's reading of the CVE descriptions, not verified analysis.
- Signing keys in this project are ordinary software keys. The example key identity (`ota-release@example.invalid`) is a placeholder. If you reuse the scripts, generate your own keys, protect them properly and never commit private key material.

## No affiliation

This is an independent project. It is not affiliated with, endorsed by, or sponsored by UNECE, any vehicle manufacturer or supplier, GitHub, Anchore (Grype), the CycloneDX project or the GnuPG project. Names are used only to describe what the code works with. The component "mock-can-driver" and its supplier in the example SBOM are fictional.

## Third-party software

The repository does not bundle third-party code. At run time it uses, and downloads under their own licences: GnuPG, Flask, `cyclonedx-python-lib`, Grype and its vulnerability database, and GitHub Actions. The licences of the libraries your firmware links to are your responsibility.

## No warranty

The software is provided under the MIT licence (see `LICENSE`), without warranty of any kind. The author accepts no liability for any use of it.
