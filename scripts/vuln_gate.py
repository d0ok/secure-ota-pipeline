#!/usr/bin/env python3
"""Apply a release policy to a Grype JSON report.

Usage:
  vuln_gate.py report.json [--fail-on SEVERITY] [--fail-on-kev]
  vuln_gate.py canary.json --expect-findings

Policy mode (default) exits 1 when the report contains a finding at or above
--fail-on severity, or any finding in CISA's Known Exploited Vulnerabilities
catalogue (--fail-on-kev). Everything else is reported but does not block.

--expect-findings is a scanner self-test: it exits 1 if the report is EMPTY.
Run it on a deliberately vulnerable canary SBOM so a scanner that silently
matches nothing (wrong distro, missing source package) cannot pass as clean.
"""
import argparse
import json
import sys

ORDER = ["Unknown", "Negligible", "Low", "Medium", "High", "Critical"]


def rank(sev):
    return ORDER.index(sev) if sev in ORDER else 0


def is_kev(vuln):
    """KEV can sit on the record itself or on a related record (e.g. NVD)."""
    if vuln.get("knownExploited"):
        return True
    return any(r.get("knownExploited") for r in vuln.get("relatedVulnerabilities", []) or [])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--fail-on", default="Critical", choices=ORDER,
                    help="lowest severity that blocks the release (default Critical)")
    ap.add_argument("--fail-on-kev", action="store_true",
                    help="block on any known-exploited vulnerability")
    ap.add_argument("--expect-findings", action="store_true",
                    help="scanner self-test: fail if the report has no matches")
    args = ap.parse_args()

    matches = json.load(open(args.report)).get("matches", []) or []

    if args.expect_findings:
        if not matches:
            print("SELF-TEST FAILED: scanner reported no findings for the canary SBOM. "
                  "Scan results cannot be trusted.", file=sys.stderr)
            return 1
        print(f"Self-test OK: scanner matched {len(matches)} findings on the canary.")
        return 0

    counts = {s: 0 for s in ORDER}
    blockers = []
    for m in matches:
        v = m.get("vulnerability", {})
        sev = v.get("severity", "Unknown")
        counts[sev if sev in counts else "Unknown"] += 1
        kev = is_kev(v)
        why = []
        if rank(sev) >= rank(args.fail_on):
            why.append(f"severity {sev}")
        if args.fail_on_kev and kev:
            why.append("known exploited (KEV)")
        if why:
            art = m.get("artifact", {})
            fixed = ", ".join(v.get("fix", {}).get("versions", []) or []) or "no fix listed"
            blockers.append(f"  {v.get('id')}  {art.get('name')} {art.get('version')}  "
                            f"[{'; '.join(why)}]  fixed in: {fixed}")

    print(f"Findings: {len(matches)} total  " +
          "  ".join(f"{s}={counts[s]}" for s in reversed(ORDER) if counts[s]))
    if blockers:
        print(f"\nRELEASE BLOCKED by policy (fail-on={args.fail_on}"
              f"{', KEV' if args.fail_on_kev else ''}):", file=sys.stderr)
        print("\n".join(blockers), file=sys.stderr)
        return 1
    print("Policy passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
