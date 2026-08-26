#!/bin/bash
# Quick smoke test for the CAPEv2 dev stack started by docker/cape-compose.yml.
# Verifies: container health, REST endpoints maljan calls, and round-trip submit.
#
# Usage:
#   bash docker/cape/smoke-test.sh
#
# Exit codes:
#   0 — all checks passed
#   1 — a check failed (printed in red)

set -uo pipefail

BASE_URL="${CAPE_BASE_URL:-http://localhost:18000}"
# Dev stack ships with token_auth_enabled=no. If you flip CAPE to require
# tokens, export CAPE_API_TOKEN before running this script.
TOKEN="${CAPE_API_TOKEN:-}"
if [[ -n "${TOKEN}" ]]; then
    AUTH_HEADER="Authorization: Token ${TOKEN}"
else
    AUTH_HEADER="X-Empty-Header: 1"
fi

green() { printf "\033[32m%s\033[0m\n" "$1"; }
red()   { printf "\033[31m%s\033[0m\n" "$1"; }
info()  { printf "\033[34m[smoke]\033[0m %s\n" "$1"; }

fail=0
require_200() {
    local label="$1"
    local url="$2"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -H "${AUTH_HEADER}" "${url}")
    if [[ "${code}" == "200" ]]; then
        green "  ${label}: HTTP ${code}"
    else
        red "  ${label}: HTTP ${code} (expected 200)"
        fail=1
    fi
}

info "1. Containers up?"
if ! docker ps --format '{{.Names}}' | grep -q maljan-cape-postgres; then
    red "  maljan-cape-postgres not running"
    fail=1
else
    green "  maljan-cape-postgres up"
fi
if ! docker ps --format '{{.Names}}' | grep -q maljan-cape-web; then
    red "  maljan-cape-web not running"
    fail=1
else
    green "  maljan-cape-web up"
fi

info "2. REST endpoints reachable?"
require_200 "/apiv2/" "${BASE_URL}/apiv2/"
require_200 "/apiv2/cuckoo/status/" "${BASE_URL}/apiv2/cuckoo/status/"
require_200 "/apiv2/machines/list/" "${BASE_URL}/apiv2/machines/list/"
require_200 "/apiv2/tasks/list/" "${BASE_URL}/apiv2/tasks/list/"

info "3. Submit + view round-trip?"
sample=$(mktemp /tmp/maljan-smoke-XXXXXX.bin)
echo -n "MZ\x90\x00This is a smoke-test stub, not real malware." > "${sample}"
resp=$(curl -s -H "${AUTH_HEADER}" -F "file=@${sample}" \
    "${BASE_URL}/apiv2/tasks/create/file/")
rm -f "${sample}"
task_id=$(printf "%s" "${resp}" | python3 -c "import sys, json
d = json.load(sys.stdin)
inner = d.get('data') if isinstance(d.get('data'), dict) else {}
candidates = (d.get('task_id'), (d.get('task_ids') or [None])[0], inner.get('task_id'), (inner.get('task_ids') or [None])[0])
print(next((str(c) for c in candidates if c is not None), ''))" 2>/dev/null)
if [[ -z "${task_id}" ]]; then
    red "  submit failed; response: ${resp}"
    fail=1
else
    green "  submit returned task_id=${task_id}"
    view_resp=$(curl -s -H "${AUTH_HEADER}" "${BASE_URL}/apiv2/tasks/view/${task_id}/")
    status=$(printf "%s" "${view_resp}" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('data', {}).get('status', 'unknown'))" 2>/dev/null)
    green "  view returned status=${status}"
fi

echo
if [[ "${fail}" == "0" ]]; then
    green "All checks passed. Maljan can now point SANDBOX__CAPE2_BASE_URL=${BASE_URL}"
    exit 0
else
    red "Some checks failed. Inspect the CAPE container logs: docker compose -f docker/cape-compose.yml logs cape-web"
    exit 1
fi
