#!/usr/bin/env bash
# Run a checkpointed eval to completion on a host the model server outgrows.
#
# llama-server's resident set climbs with cumulative requests and does not come
# back down: 10.5 GB freshly loaded, 17.5 GB after thirty-five minutes of this
# workload, 18.1 GB after an hour. On a 30 GB host that reaches the memory
# guard's floor long before a 72-row run finishes, and what the guard can kill
# is the eval — the only process in the picture that is not the one growing.
#
# So the run is cycled instead. Work until the server's own footprint is the
# problem, stop cleanly, restart the server, resume from the checkpoint. Every
# harness here writes one line per generation before starting the next, so a
# cycle boundary costs at most the generation in flight.
#
# This is the appendix's own advice applied to itself: "a long paired run must
# restart it between arms". It is not a workaround for a bug in the eval. It is
# the shape a measurement takes when the instrument drifts while you use it.
#
# Run:  scripts/run_with_restarts.sh <checkpoint> <target-rows> <command...>
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

CHECKPOINT="${1:?usage: run_with_restarts.sh <checkpoint> <target-rows> <command...>}"
TARGET="${2:?target row count}"
shift 2
[ "$#" -gt 0 ] || { echo "no command given" >&2; exit 2; }

# Restart the server when the host drops below this. Above the guard's kill
# floor (4 GB) on purpose: the point is to act before the guard has to.
FLOOR_MB="${FLOOR_MB:-6144}"
POLL_S="${POLL_S:-30}"
MAX_CYCLES="${MAX_CYCLES:-12}"

say() { printf '\n\033[1m[%s] %s\033[0m\n' "$(date +%H:%M:%S)" "$1"; }

rows() { wc -l < "$CHECKPOINT" 2>/dev/null || echo 0; }
avail_mb() { awk '/^MemAvailable/{print int($2/1024)}' /proc/meminfo; }

for cycle in $(seq "$MAX_CYCLES"); do
    have=$(rows)
    if [ "$have" -ge "$TARGET" ]; then
        say "done: $have/$TARGET rows"
        exit 0
    fi

    say "cycle $cycle — $have/$TARGET rows, $(avail_mb) MB available"
    # Start every cycle on a freshly loaded server. The first version checked
    # the floor first and started the run anyway, which meant that when the
    # server was already bloated the supervisor launched a run and killed it
    # within one poll — reclaiming nothing and looking like the eval had
    # failed. The headroom has to exist before the work begins, not be tested
    # after it. Forty seconds a cycle buys the whole cycle.
    if ./scripts/llm_server.sh status >/dev/null 2>&1; then
        ./scripts/llm_server.sh restart || exit 1
    else
        ./scripts/llm_server.sh start
        ./scripts/llm_server.sh wait || { echo "the server never came up" >&2; exit 1; }
    fi
    say "server fresh, $(avail_mb) MB available"

    "$@" &
    job=$!
    printf '%s\n' "$job" > logs/night-job.pid

    # Watch the host, not the job. The job is fine; the server underneath it is
    # what runs the machine out of memory.
    while kill -0 "$job" 2>/dev/null; do
        mb=$(avail_mb)
        if [ "$mb" -lt "$FLOOR_MB" ]; then
            say "$mb MB left — pausing the run at $(rows) rows to reclaim the server's growth"
            kill -TERM "$job" 2>/dev/null
            for _ in $(seq 30); do kill -0 "$job" 2>/dev/null || break; sleep 1; done
            kill -KILL "$job" 2>/dev/null
            break
        fi
        sleep "$POLL_S"
    done
    wait "$job" 2>/dev/null
    rm -f logs/night-job.pid

    after=$(rows)
    if [ "$after" -ge "$TARGET" ]; then
        say "done: $after/$TARGET rows"
        exit 0
    fi
    if [ "$after" -le "$have" ]; then
        echo "cycle $cycle added no rows ($have -> $after) — stopping rather than looping" >&2
        exit 1
    fi
    say "cycle $cycle added $((after - have)) rows; restarting the server"
    ./scripts/llm_server.sh restart || exit 1
done

say "gave up after $MAX_CYCLES cycles at $(rows)/$TARGET rows"
exit 1
