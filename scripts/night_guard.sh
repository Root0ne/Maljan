#!/usr/bin/env bash
# A watcher that actually intervenes, because the polite one was not enough.
#
# `overnight_watch.sh` deliberately only writes a STOP sentinel and lets heavy
# steps notice it, on the reasoning that killing someone's work while they sleep
# is worse than the problem. On 2026-08-10 the machine froze anyway: two heavy
# jobs ran concurrently (a Ghidra pre-pass whose JVM reaches ~5 GB on large
# binaries, plus periodic container restarts) and the desktop stopped responding.
#
# That changes the trade. Every eval harness here checkpoints per sample, so a
# killed job costs minutes and resumes exactly where it stopped. A frozen desktop
# costs the whole night and a hard reset. So this guard escalates:
#
#   available < WARN_MB  -> lay down the STOP sentinel; heavy steps must not start
#   available < KILL_MB  -> terminate the registered job, gently then firmly
#
# It only ever kills the PID written to the job file, never a process it merely
# recognises: the failure mode of a pattern match is killing the wrong thing, and
# this script exists to prevent damage rather than cause a new kind.
set -uo pipefail

ROOT="${MALJAN_ROOT:-/home/user/Belgeler/kingston/Projects/Maljan}"
LOG_DIR="${LOG_DIR:-$ROOT/logs}"
mkdir -p "$LOG_DIR"

LOG="$LOG_DIR/night-guard.log"
STOP="$LOG_DIR/overnight-watch.STOP"
JOB_PID_FILE="${JOB_PID_FILE:-$LOG_DIR/night-job.pid}"

# 6 GB to warn, 4 GB to act. Today's freeze began while ~5 GB still showed as
# available, so the old 3 GB floor was measuring a cliff the machine had already
# gone over. These leave room for the desktop stack to keep breathing.
WARN_MB="${WARN_MB:-6144}"
KILL_MB="${KILL_MB:-4096}"
INTERVAL="${INTERVAL:-10}"
# Consecutive critical readings required before killing. At INTERVAL=10 this
# tolerates ~30 s of transient pressure — long enough for a model load, far
# short of a run that is genuinely eating the machine.
KILL_STRIKES="${KILL_STRIKES:-3}"
# A job that is about to make a known large allocation (loading a 16 GB model
# between arms) touches this file first and removes it after. While it is
# fresh the guard warns but does not kill: on 2026-08-11 the strike counter
# expired mid-load three times, ending a run for pressure that had already
# passed by the time it was measured. Declared work is not runaway work.
GRACE="$LOG_DIR/night-job.grace"
GRACE_MAX_AGE="${GRACE_MAX_AGE:-180}"

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "$(ts) $*" >>"$LOG"; }

avail_mb() { awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo; }
pswpout()  { awk '/pswpout/{print $2}' /proc/vmstat; }

log "night-guard up: warn<${WARN_MB}MB kill<${KILL_MB}MB every ${INTERVAL}s"
last_swap=$(pswpout)
warned=0
strikes=0

while true; do
    mb=$(avail_mb)
    swap=$(pswpout)
    swap_delta=$((swap - last_swap))
    last_swap=$swap

    # Swap *flow* is the honest pressure signal; a large resident swap stock is
    # harmless once the pages are cold. A sustained outflow means the machine is
    # actively evicting to keep up, which is what preceded the freeze.
    if [ "$swap_delta" -gt 20000 ]; then
        log "WARN swapping hard: ${swap_delta} pages out in ${INTERVAL}s, ${mb}MB available"
    fi

    if [ "$mb" -lt "$KILL_MB" ]; then
        # Sustained pressure is dangerous; a transient is not. Loading a 16 GB
        # model drops MemAvailable by ~3 GB for about ten seconds, and on
        # 2026-08-11 that cost a two-hour paired run its fourth restart — the
        # guard, not the memory, was the thing ending the job. Require the
        # condition to hold across consecutive checks before acting.
        if [ -f "$GRACE" ]; then
            age=$(( $(date +%s) - $(stat -c %Y "$GRACE" 2>/dev/null || echo 0) ))
            if [ "$age" -lt "$GRACE_MAX_AGE" ]; then
                log "CRITICAL ${mb}MB — declared allocation in progress (${age}s), holding"
                touch "$STOP"
                sleep "$INTERVAL"
                continue
            fi
            log "grace marker is ${age}s old (> ${GRACE_MAX_AGE}) — treating as stale"
        fi
        strikes=$((strikes + 1))
        if [ "$strikes" -lt "$KILL_STRIKES" ]; then
            log "CRITICAL ${mb}MB available (<${KILL_MB}) — strike ${strikes}/${KILL_STRIKES}, holding"
            touch "$STOP"
            sleep "$INTERVAL"
            continue
        fi
        log "CRITICAL ${mb}MB available (<${KILL_MB}) for ${strikes} checks — stopping the registered job"
        touch "$STOP"
        if [ -f "$JOB_PID_FILE" ]; then
            pid=$(cat "$JOB_PID_FILE" 2>/dev/null || true)
            if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
                kill -TERM "$pid" 2>/dev/null && log "  SIGTERM -> $pid"
                sleep 15
                if kill -0 "$pid" 2>/dev/null; then
                    kill -KILL "$pid" 2>/dev/null && log "  SIGKILL -> $pid (did not exit)"
                fi
            else
                log "  no live job registered at $JOB_PID_FILE"
            fi
        fi
        sleep 60          # let the machine recover before judging it again
        continue
    fi

    strikes=0

    if [ "$mb" -lt "$WARN_MB" ]; then
        [ "$warned" -eq 0 ] && log "LOW ${mb}MB available (<${WARN_MB}) — STOP sentinel laid"
        touch "$STOP"
        warned=1
    elif [ "$warned" -eq 1 ]; then
        log "recovered: ${mb}MB available — clearing STOP"
        rm -f "$STOP"
        warned=0
    fi

    sleep "$INTERVAL"
done
