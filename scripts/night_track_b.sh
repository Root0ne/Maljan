#!/usr/bin/env bash
# Track B — the heavy local track. One job, one model server, guard-supervised.
#
# This is the only thing running tonight that can hurt the machine: the harness
# reloads a 16 GB model server between calls (§3.22), and the desktop stack has
# to keep breathing alongside it. So unlike track A this registers itself with
# the night guard as the killable job and refuses to start while the STOP
# sentinel is down.
#
# Being killed is cheap and by design. ``eval_judge_contribution.py`` checkpoints
# every call to /tmp and only counts *reached* calls as done, so a guard kill
# costs the one call in flight. That is why the guard is allowed to be decisive:
# the alternative — a frozen desktop and a power cycle — costs the whole night.
#
# The loop exists because the failure this run is chasing is intermittent. The
# first attempt lost five of nine calls, and the harness now records *why* each
# one left the reconciliation path instead of filing it as an error. A run that
# stops early because the guard intervened should resume when the pressure
# passes rather than wait for morning.
set -uo pipefail

ROOT="${MALJAN_ROOT:-/home/user/Belgeler/kingston/Projects/Maljan}"
cd "$ROOT" || exit 1
LOG_DIR="$ROOT/logs"
LOG="$LOG_DIR/night-track-b.log"
STATUS="$LOG_DIR/night-track-b.status"
STOP="$LOG_DIR/overnight-watch.STOP"
JOB_PID_FILE="$LOG_DIR/night-job.pid"
CHECKPOINT="/tmp/judge_contribution_checkpoint.jsonl"

MAX_ATTEMPTS="${MAX_ATTEMPTS:-6}"
# 75 minutes per attempt. Five outstanding calls at a 300 s verdict ceiling plus
# a model reload each is ~35 minutes; double it so a slow attempt finishes rather
# than being cut off one call short.
ATTEMPT_TIMEOUT="${ATTEMPT_TIMEOUT:-4500}"
# How long to wait for the guard to lift a STOP before giving up on this attempt.
STOP_WAIT="${STOP_WAIT:-1800}"

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$LOG"; }
status() { printf '%s\n' "$*" >"$STATUS"; }

scored_calls() {
    # Rows without an "error" key are reached calls: reconciled or fallback, both
    # of which are measurements. Counted with grep so this needs no interpreter.
    [ -r "$CHECKPOINT" ] || { echo 0; return; }
    grep -c '"key"' "$CHECKPOINT" 2>/dev/null | head -1
}

wait_for_stop_to_lift() {
    local waited=0
    while [ -e "$STOP" ]; do
        if [ "$waited" -ge "$STOP_WAIT" ]; then
            log "STOP still down after ${waited}s — skipping this attempt"
            return 1
        fi
        [ "$waited" -eq 0 ] && { log "STOP sentinel is down — waiting for the guard to lift it"; status "waiting on STOP"; }
        sleep 30
        waited=$((waited + 30))
    done
    return 0
}

cleanup() {
    # Leave nothing holding memory: a transient unit outlives the harness that
    # started it, and one left running has twice cost 11 GB overnight.
    systemctl --user stop c3-llama.service 2>/dev/null
    systemctl --user reset-failed c3-llama.service 2>/dev/null
    rm -f "$JOB_PID_FILE" "$LOG_DIR/night-job.grace"
}

log "track B up: C3 judge-contribution, both seams instrumented"

attempt=1
while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
    if ! wait_for_stop_to_lift; then
        attempt=$((attempt + 1))
        continue
    fi

    before=$(scored_calls)
    log "=== attempt ${attempt}/${MAX_ATTEMPTS}: ${before} calls already on record ==="
    status "attempt ${attempt} running (${before} calls done)"

    timeout --signal=TERM --kill-after=120 "$ATTEMPT_TIMEOUT" \
        .venv/bin/python -u tests/evaluation/eval_judge_contribution.py >>"$LOG" 2>&1 &
    job=$!
    # Register with the guard only while the job is alive. The guard kills what
    # this file names and nothing else, so a stale PID here is how an unrelated
    # process gets killed later — it is removed on every exit path.
    printf '%s\n' "$job" >"$JOB_PID_FILE"
    wait "$job"
    rc=$?
    rm -f "$JOB_PID_FILE"

    after=$(scored_calls)
    log "attempt ${attempt} exited ${rc}: ${before} -> ${after} calls on record"

    if [ "$rc" -eq 0 ]; then
        log "=== track B complete ==="
        status "complete (${after} calls)"
        cleanup
        exit 0
    fi

    # No progress and no guard intervention means retrying will not help: the
    # failure is in the harness or the model server, not in the machine's load.
    if [ "$after" -le "$before" ] && [ ! -e "$STOP" ]; then
        log "no progress and no STOP — the obstacle is not memory pressure; stopping"
        status "stalled after ${after} calls (rc=${rc})"
        cleanup
        exit 1
    fi

    log "progress made or guard intervened — retrying after a pause"
    cleanup
    sleep 120
    attempt=$((attempt + 1))
done

log "=== track B gave up after ${MAX_ATTEMPTS} attempts ==="
status "gave up after ${MAX_ATTEMPTS} attempts ($(scored_calls) calls)"
cleanup
exit 1
