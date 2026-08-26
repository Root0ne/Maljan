#!/usr/bin/env bash
# Track A — the network arms. Runs unattended while the machine is otherwise idle.
#
# These are hosted-API probes: ~100 MB resident, no model server, no sandbox. They
# cannot starve the desktop, so unlike the heavy track they are not gated on the
# STOP sentinel and are not registered with the night guard as a killable job.
# What they *can* do is stall on a provider's rate limiter, so each arm gets a
# hard wall-clock ceiling and the chain moves on rather than spending the night
# in someone else's queue.
#
# Why these two arms, in this order. ``qwen3.6-35b-a3b`` on DashScope is the same
# model the local server hosts, at the vendor's own precision. Running it with
# ``--no-thinking`` matches the local arm's configuration exactly, which leaves
# **quantisation as the only difference** — the confound the roadmap recorded as
# irreducible. Running it again with thinking on then isolates that one flag on
# identical weights, which §3.31 could only measure on a different model.
#
# Both are resumable: only scored rows count as done, so a ceiling that fires
# mid-arm costs nothing but the calls it had not yet made.
set -uo pipefail

ROOT="${MALJAN_ROOT:-/home/user/Belgeler/kingston/Projects/Maljan}"
cd "$ROOT" || exit 1
LOG_DIR="$ROOT/logs"
LOG="$LOG_DIR/night-track-a.log"
STATUS="$LOG_DIR/night-track-a.status"

# 90 minutes per arm. The two qwen3.6-plus arms took ~33 minutes each for n=25,
# and a3b is a smaller model on the same endpoint, so this is roughly triple the
# expected time — generous enough that only a genuine stall trips it.
ARM_TIMEOUT="${ARM_TIMEOUT:-5400}"
REPEATS="${REPEATS:-5}"

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$LOG"; }
status() { printf '%s\n' "$*" >"$STATUS"; }

run_arm() {
    local arm="$1" label="$2"
    shift 2
    log "=== $label: starting (ceiling ${ARM_TIMEOUT}s) ==="
    status "running $label"
    # ``-u`` because this harness has no flush=True: without it the log stays
    # empty for the whole run and progress is only visible in the checkpoint.
    timeout --signal=TERM --kill-after=60 "$ARM_TIMEOUT" \
        .venv/bin/python -u tests/evaluation/eval_frontier_probe.py \
        --arm "$arm" --repeats "$REPEATS" "$@" >>"$LOG" 2>&1
    local rc=$?
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        log "=== $label: hit the ${ARM_TIMEOUT}s ceiling — partial rows kept, moving on ==="
    elif [ "$rc" -ne 0 ]; then
        log "=== $label: exited $rc — partial rows kept, moving on ==="
    else
        log "=== $label: done ==="
    fi
    return 0
}

log "track A up: qwen35ba3b in both configurations, ${REPEATS} repeats"

# Thinking off first: it is the arm that answers the standing question, so if the
# quota runs out mid-chain the measurement that survives is the one worth having.
run_arm qwen35ba3b "qwen35ba3b/no-thinking" --no-thinking
run_arm qwen35ba3b "qwen35ba3b/thinking"

log "track A complete"
status "complete"
