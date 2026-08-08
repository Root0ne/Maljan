#!/usr/bin/env bash
# Overnight resource watch — runs while unattended work proceeds.
#
# The machine has a known way to die: llama-server alone holds ~16 GB and an arq
# analysis grows to ~8.5 GB, which together fill 30 GB of RAM. Tonight neither is
# supposed to start at all, so this watch exists to prove that stayed true and to
# stop the work if memory heads the wrong way for any other reason.
#
# It deliberately does NOT kill anything. Terminating processes on someone's
# machine while they sleep is worse than the problem it would solve; instead it
# writes a STOP sentinel that the heavy steps check before starting.
#
# Usage:  scripts/overnight_watch.sh &        (or via Bash run_in_background)
# Stop:   touch logs/overnight-watch.DONE

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$REPO/logs"
LOG="$LOG_DIR/overnight-watch.log"
STOP="$LOG_DIR/overnight-watch.STOP"
DONE="$LOG_DIR/overnight-watch.DONE"
ROADMAP="$REPO/docs/academic-article/paper-roadmap.md"

INTERVAL="${WATCH_INTERVAL:-60}"
# Below this many MB available, declare CRITICAL and lay down the STOP sentinel.
FLOOR_MB="${WATCH_FLOOR_MB:-3072}"
# Below this, warn but keep going.
WARN_MB="${WATCH_WARN_MB:-6144}"

mkdir -p "$LOG_DIR"
rm -f "$STOP" "$DONE"

ts() { date '+%Y-%m-%d %H:%M:%S'; }

log() { printf '%s %s\n' "$(ts)" "$1" >>"$LOG"; }

available_mb() { awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo; }

top_rss() {
    ps -eo rss=,comm= --sort=-rss 2>/dev/null | head -3 |
        awk '{printf "%s(%.1fG) ", $2, $1/1048576}'
}

# Tonight's invariant: no Maljan container and no llama-server. Anything else is
# my own work overrunning, and I want to see it in the log rather than infer it.
maljan_containers() {
    docker ps --format '{{.Names}}' 2>/dev/null | grep -c '^maljan-' || true
}

llama_state() {
    # `is-active` prints the state AND exits non-zero when not running, so a plain
    # `|| echo unknown` appends a second line to a perfectly good answer.
    local state
    state=$(systemctl --user is-active maljan-llama.service 2>/dev/null)
    echo "${state:-unknown}"
}

roadmap_progress() {
    [ -f "$ROADMAP" ] || { echo "-/-"; return; }
    local done total
    done=$(grep -c '^\s*- \[x\]' "$ROADMAP" 2>/dev/null || echo 0)
    total=$(grep -c '^\s*- \[[ x]\]' "$ROADMAP" 2>/dev/null || echo 0)
    echo "$done/$total"
}

log "START watch pid=$$ interval=${INTERVAL}s warn=${WARN_MB}MB floor=${FLOOR_MB}MB"
log "INVARIANT expecting 0 maljan containers and llama-server inactive for this run"

critical_latched=0

while [ ! -f "$DONE" ]; do
    avail=$(available_mb)
    load=$(awk '{print $1}' /proc/loadavg)
    ctrs=$(maljan_containers)
    llama=$(llama_state)
    prog=$(roadmap_progress)

    level="OK"
    if [ "$avail" -lt "$FLOOR_MB" ]; then
        level="CRITICAL"
    elif [ "$avail" -lt "$WARN_MB" ]; then
        level="WARN"
    fi

    log "$level avail=${avail}MB load=${load} maljan_containers=${ctrs} llama=${llama} roadmap=${prog} top=[$(top_rss)]"

    # The invariant is a separate line so a morning grep for ALERT finds it.
    if [ "$ctrs" -ne 0 ] || [ "$llama" = "active" ]; then
        log "ALERT invariant broken — containers=${ctrs} llama=${llama}; heavy services were not supposed to run in this session"
    fi

    if [ "$level" = "CRITICAL" ] && [ "$critical_latched" -eq 0 ]; then
        touch "$STOP"
        critical_latched=1
        log "STOP sentinel written to $STOP — heavy steps must not start; nothing was killed"
    fi

    sleep "$INTERVAL"
done

log "DONE sentinel seen — work reported complete"
log "SUMMARY samples=$(grep -c ' avail=' "$LOG") critical=$(grep -c ' CRITICAL ' "$LOG") warn=$(grep -c ' WARN ' "$LOG") alerts=$(grep -c ' ALERT ' "$LOG") roadmap=$(roadmap_progress)"
log "END watch pid=$$"
