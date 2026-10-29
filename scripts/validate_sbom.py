#!/usr/bin/env python3
"""Validate a CycloneDX 1.5 JSON SBOM against the official schema."""
import sys

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

path = sys.argv[1]
errors = JsonStrictValidator(SchemaVersion.V1_5).validate_str(open(path).read())
if errors:
    print(f"SBOM INVALID: {errors}", file=sys.stderr)
    sys.exit(1)
print(f"SBOM valid CycloneDX 1.5: {path}")
