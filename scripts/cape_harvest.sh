#!/usr/bin/env bash
# Pull recovered CAPE reports as they finish, while the network is available.
#
# The instance works through the re-submitted batch at roughly six minutes a
# sample (§3.24), and the operator's link to that network is not guaranteed to
# stay up for the five hours that takes. So this harvests on a loop instead of
# waiting for the end: the fetcher skips what is already archived, enforces the
# duration gate, and verifies each report's sha256, so running it repeatedly is
# idempotent and cannot admit a phantom.
set -uo pipefail
ROOT="${MALJAN_ROOT:-/home/user/Belgeler/kingston/Projects/Maljan}"
cd "$ROOT" || exit 1
LOG="$ROOT/logs/cape-harvest.log"
STOP="$ROOT/logs/cape-harvest.STOP"
LEDGER="$ROOT/tests/evaluation/cape_task_ledger_v2.json"
TARGET="${TARGET:-100}"
INTERVAL="${INTERVAL:-600}"

log() { printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOG"; }
archived() { ls "$ROOT"/data/cape_reports/*.json 2>/dev/null | wc -l; }

log "harvester up: every ${INTERVAL}s until ${TARGET} reports are archived"
while :; do
  [ -f "$STOP" ] && { log "STOP sentinel — exiting"; exit 0; }
  n="$(archived)"
  if [ "$n" -ge "$TARGET" ]; then
    log "archive holds ${n} reports — target reached, exiting"
    exit 0
  fi
  out="$("$ROOT/.venv/bin/python" tests/evaluation/fetch_cape_reports.py --ledger "$LEDGER" 2>&1 | tail -2 | tr '\n' ' ')"
  log "archive ${n} -> $(archived) | ${out}"
  sleep "$INTERVAL"
done
