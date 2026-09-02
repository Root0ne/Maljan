#!/usr/bin/env bash
# Start, stop and check the local model server, with the flags that were tuned
# for this host.
#
# Until now this configuration existed in exactly one place: the argv of a
# running process. That is a bad place for it. If the server died the tuning
# died with it, the reproducibility appendix could not name the settings that
# produced the measurements, and the next person to start it by hand would
# start a different server and not know. The regex below is the whole trick —
# it puts blocks 10..39's expert tensors in host memory and leaves everything
# else on the GPU, which is what makes a 35B MoE fit an 8 GB card at all.
#
# Recorded from the process that produced the runs in this repository:
#   -c 131072 -t 16 -fa on -ctk q8_0 -ctv q8_0 -ngl 999 --context-shift on
#
# Run:  scripts/llm_server.sh start | stop | restart | status | wait
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

BIN="${LLAMA_BIN:-/home/user/maljan-llm-build/ik_llama.cpp/build-cuda/bin/llama-server}"
MODEL="${LLAMA_MODEL:-$PWD/models/Qwen3.6-35B-A3B-IQ3_K_R4.gguf}"
PORT="${LLAMA_PORT:-8080}"
# Loopback by default: the server has no authentication and the pipeline sends
# it decompiled code and strings from the sample. Set LLAMA_HOST=0.0.0.0 only
# when containers on another host must reach it.
HOST="${LLAMA_HOST:-127.0.0.1}"
CTX="${LLAMA_CTX:-131072}"
LOG="logs/llama-server.log"
# Blocks 10..39: expert tensors to host memory. Blocks 0..9 and every non-expert
# tensor stay on the card.
OFFLOAD='blk\.([1-3][0-9])\.ffn_(up|gate|down)_exps=CPU'

mkdir -p logs

# Match on the process *name*, then confirm the port from its own argv.
#
# This was `pgrep -f "llama-server .*--port $PORT"`, which matches any process
# whose command line merely contains that text — including a monitoring shell
# that greps for exactly this pattern. On 2026-08-15 one did: `start` found the
# watcher, reported "already running", skipped the launch, and a run proceeded
# against a server that was not there. `pgrep -x` matches comm, which a bash
# script cannot fake, so the whole class of self-match goes with it.
pid_of() {
    local pid
    for pid in $(pgrep -x llama-server 2>/dev/null); do
        if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q -- "--port $PORT"; then
            printf '%s\n' "$pid"
            return 0
        fi
    done
    return 1
}

healthy() { curl -s -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/health" 2>/dev/null | grep -q 200; }

rss_gb() {
    local pid="$1" kb
    kb=$(awk '/^VmRSS/{print $2}' "/proc/$pid/status" 2>/dev/null) || return 1
    [ -n "${kb:-}" ] && awk -v k="$kb" 'BEGIN{printf "%.2f", k/1048576}'
}

case "${1:-status}" in

start)
    pid=$(pid_of)
    if [ -n "${pid:-}" ]; then
        echo "already running (pid $pid)"
        exit 0
    fi
    [ -x "$BIN" ] || { echo "no server binary at $BIN" >&2; exit 1; }
    [ -r "$MODEL" ] || { echo "no model at $MODEL" >&2; exit 1; }
    # A 14 GB load is a declared allocation, not a runaway one. The guard reads
    # this marker and warns instead of killing whatever is registered.
    date +%s > logs/night-job.grace
    nohup "$BIN" \
        -m "$MODEL" \
        -c "$CTX" -t 16 -fa on -ctk q8_0 -ctv q8_0 -ngl 999 \
        -ot "$OFFLOAD" \
        --context-shift on --jinja \
        --alias qwen3.6-35b-a3b \
        --host "$HOST" --port "$PORT" \
        >>"$LOG" 2>&1 &
    echo "starting (pid $!), ctx $CTX, log $LOG"
    ;;

stop)
    pid=$(pid_of)
    [ -n "${pid:-}" ] || { echo "not running"; exit 0; }
    echo "stopping pid $pid (held $(rss_gb "$pid") GB)"
    kill -TERM "$pid" 2>/dev/null
    for _ in $(seq 30); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill -0 "$pid" 2>/dev/null && { echo "  did not exit, SIGKILL"; kill -KILL "$pid"; }
    rm -f logs/night-job.grace
    ;;

restart)
    "$0" stop
    sleep 3
    "$0" start
    "$0" wait
    ;;

wait)
    # The load reads 14 GB off disk. Ten minutes is generous and finite.
    for i in $(seq 120); do
        if healthy; then
            pid=$(pid_of)
            echo "healthy after ${i}0s — pid $pid, $(rss_gb "$pid") GB resident"
            rm -f logs/night-job.grace
            exit 0
        fi
        sleep 10
    done
    echo "not healthy after 20 minutes — see $LOG" >&2
    rm -f logs/night-job.grace
    exit 1
    ;;

status)
    pid=$(pid_of)
    if [ -z "${pid:-}" ]; then
        echo "llama-server: not running"
        exit 3
    fi
    printf 'llama-server: pid %s, %s GB resident, health %s\n' \
        "$pid" "$(rss_gb "$pid")" "$(healthy && echo ok || echo DOWN)"
    awk '/^MemAvailable/{printf "host: %.1f GB available\n", $2/1048576}' /proc/meminfo
    ;;

*)
    echo "usage: $0 {start|stop|restart|status|wait}" >&2
    exit 2
    ;;
esac
