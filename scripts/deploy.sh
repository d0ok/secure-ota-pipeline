#!/usr/bin/env bash
# Deploy a signed update package to the vehicle backend.
# Usage: deploy.sh <package.tar.gz> [backend-url]
set -euo pipefail

PKG="${1:?package required}"
URL="${2:-${BACKEND_URL:-http://127.0.0.1:8080}}"

HTTP_CODE=$(curl -sS -o /tmp/deploy_response.json -w '%{http_code}' \
  -X POST -F "package=@${PKG}" \
  ${BACKEND_TOKEN:+-H "Authorization: Bearer $BACKEND_TOKEN"} \
  "$URL/api/v1/updates")

cat /tmp/deploy_response.json; echo
if [ "$HTTP_CODE" != "201" ]; then
  echo "Deployment rejected by backend (HTTP $HTTP_CODE)" >&2
  exit 1
fi
echo "Deployment accepted (HTTP $HTTP_CODE)"
