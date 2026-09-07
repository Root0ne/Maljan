#!/usr/bin/env bash
# A watcher that actually intervenes, because the polite one was not enough.
#
# An earlier, polite watcher deliberately only wrote a STOP sentinel and let heavy
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
#
# ---------------------------------------------------------------------------
# 2026-08-13: why this file was rewritten
# ---------------------------------------------------------------------------
# The machine froze again and had to be power-cycled. The guard was running and
# it saw the danger — 13:06:01 "LOW 5571MB available — STOP sentinel laid" — and
# then **wrote nothing for six minutes** while llama-server kept working, until
# the log ends mid-line on the power cut. A process that polls every ten seconds
# and goes silent for six minutes was not asleep; it could not be scheduled.
#
# It could not be scheduled because of how it was written. The old polling path
# forked six to eight times a pass — `awk` three times, plus `pgrep`, `date`,
# `stat`, `cat` — and fork+exec is precisely the operation that stops completing
# when a machine is thrashing: it needs page-ins for the binary, the loader and
# the copied address space. **The guard's protection failed in exactly the
# condition it exists to handle,** and it failed because of its implementation
# rather than its policy.
#
# Three changes follow from that:
#
#   1. **The hot path no longer forks.** /proc is read with bash builtins, the
#      timestamp comes from printf's %(...)T, and the log is held open on fd 3.
#      A pass is now a handful of reads and no process creation.
#
#   2. **Starvation is itself the alarm.** If a pass starts much later than the
#      interval promised, the machine already failed the only test that matters —
#      it could not run a ten-line loop on time. That is not a reason to begin
#      counting strikes; it is the finding, and the guard acts immediately.
#
#   3. **Heat is watched too.** Nothing here ever looked at temperature. This is
#      a laptop that idles at 80 °C on the CPU die (k10temp Tctl), and it had
#      been running a 16-thread model server flat out for fourteen hours. Memory
#      was measured, and heat — the thing the operator actually reported — was
#      not measured at all.
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

# A pass that starts this many times later than promised means the guard was
# starved of CPU or blocked on I/O. Four passes (40 s at INTERVAL=10) is far
# beyond any scheduling jitter on an idle machine and far short of the six
# minutes observed before the freeze.
STARVE_FACTOR="${STARVE_FACTOR:-4}"

# CPU die temperature, read from k10temp. 90 °C sustained is not a crash risk on
# its own — the silicon throttles long before it is damaged — but on this
# chassis it is the point where the fans are already at their limit and any
# additional pressure has nowhere to go. Two consecutive readings, so a single
# spike during a model load does not end a run.
THERMAL_MAX="${THERMAL_MAX:-90}"
THERMAL_CLEAR="${THERMAL_CLEAR:-82}"
THERMAL_STRIKES="${THERMAL_STRIKES:-2}"

# A job that is about to make a known large allocation (loading a 16 GB model
# between arms) touches this file first and removes it after. While it is
# fresh the guard warns but does not kill: on 2026-08-11 the strike counter
# expired mid-load three times, ending a run for pressure that had already
# passed by the time it was measured. Declared work is not runaway work.
GRACE="$LOG_DIR/night-job.grace"
GRACE_MAX_AGE="${GRACE_MAX_AGE:-180}"
# A declared allocation excuses low MemAvailable. It does NOT excuse an
# exhausted swap file. On 2026-08-11 the grace window held three times while
# swap ran to 100%, and the desktop session was killed — by the kernel's OOM
# killer, which picks its victim by size and chose the editor. Once swap is
# gone the machine has no headroom to wait in, so grace stops applying and the
# guard acts. Grace is a reason to wait, never a reason to stop looking.
SWAP_FLOOR_MB="${SWAP_FLOOR_MB:-1024}"

# Hold the log open once rather than reopening it on every line: an open() per
# message is another syscall that can block on a saturated disk.
exec 3>>"$LOG"
log() {
    local now
    printf -v now '%(%Y-%m-%d %H:%M:%S)T' -1
    printf '%s %s\n' "$now" "$*" >&3
}

now_epoch() { printf -v EPOCH '%(%s)T' -1; }

# ---------------------------------------------------------------------------
# Fork-free sampling
# ---------------------------------------------------------------------------

# Read the first line of a file into the named variable. Succeeds when it got a
# value, which is the question every caller here is actually asking.
#
# `read` returns non-zero at EOF without a trailing newline, *after* assigning
# what it read. So the idiom this replaces — `read -r x < f || x=fallback` —
# threw away a perfectly good value whenever the writer omitted the newline, and
# the writers are other people's programs and the kernel. Two of the sites were
# load-bearing: stop_job would log "no live job registered" and kill nothing,
# and volunteer_as_oom_victim would leave the job at its default OOM score, so
# the kernel would go back to choosing its victim by size — which on 2026-08-11
# meant the user's editor. A guard that disarms itself over a missing byte is
# worse than no guard, because the log still says it is watching.
slurp() {
    local __var="$1" __val=""
    read -r __val < "$2" 2>/dev/null
    [ -n "$__val" ] || return 1
    printf -v "$__var" '%s' "$__val"
}

# Sets AVAIL_MB and SWAPFREE_MB. One open, one pass, no subprocess.
read_meminfo() {
    local key val rest
    AVAIL_MB=0
    SWAPFREE_MB=0
    while read -r key val rest; do
        case "$key" in
            MemAvailable:) AVAIL_MB=$((val / 1024)) ;;
            SwapFree:) SWAPFREE_MB=$((val / 1024)) ;;
        esac
    done < /proc/meminfo
}

# Sets PSWPOUT — the cumulative count of pages written to swap. Its *rate* is
# the honest pressure signal; a large resident swap stock is harmless once the
# pages are cold.
read_pswpout() {
    local key val
    PSWPOUT=0
    while read -r key val; do
        if [ "$key" = "pswpout" ]; then
            PSWPOUT=$val
            break
        fi
    done < /proc/vmstat
}

# Locate the CPU die temperature once at startup. hwmon numbering is not stable
# across boots, so the path is discovered rather than hard-coded; if it cannot
# be found the guard says so and carries on watching memory, because a missing
# sensor is a reason to lose one signal, not all of them.
TEMP_PATH=""
find_temp_sensor() {
    local h name
    for h in /sys/class/hwmon/hwmon*; do
        [ -r "$h/name" ] || continue
        slurp name "$h/name" || continue
        if [ "$name" = "k10temp" ] && [ -r "$h/temp1_input" ]; then
            TEMP_PATH="$h/temp1_input"   # Tctl
            return 0
        fi
    done
    for h in /sys/class/thermal/thermal_zone*; do
        [ -r "$h/temp" ] && { TEMP_PATH="$h/temp"; return 0; }
    done
    return 1
}

# Sets TEMP_C, or -1 when unreadable.
read_temp() {
    local raw
    TEMP_C=-1
    [ -n "$TEMP_PATH" ] || return 0
    slurp raw "$TEMP_PATH" || return 0
    [ -n "$raw" ] && TEMP_C=$((raw / 1000))
}

# Choose the OOM killer's victim in advance.
#
# Every mechanism above races the kernel: the guard samples every INTERVAL
# seconds, and memory can be exhausted between two samples. When that happens
# the kernel picks a victim by size, which on 2026-08-11 meant the user's
# editor — the largest thing that was not the job actually at fault.
#
# oom_score_adj settles that in advance. Raising a score does not need root
# (only lowering one does), so the heavy jobs volunteer themselves as the first
# to die. This does not prevent the pressure; it makes the consequence land on
# the work rather than on the desktop, which is the only part that is ours to
# lose.
#
# Walks /proc by glob instead of shelling out to pgrep, and only every
# OOM_EVERY passes: the PIDs change when llama-server is restarted between
# samples, which is minutes apart, not seconds.
OOM_EVERY="${OOM_EVERY:-6}"
volunteer_as_oom_victim() {
    local d name pid
    for d in /proc/[0-9]*; do
        [ -r "$d/comm" ] || continue
        slurp name "$d/comm" || continue
        [ "$name" = "llama-server" ] || continue
        echo 1000 >"$d/oom_score_adj" 2>/dev/null
    done
    if [ -r "$JOB_PID_FILE" ]; then
        slurp pid "$JOB_PID_FILE" || return 0
        [ -n "${pid:-}" ] && [ -d "/proc/$pid" ] || return 0
        echo 1000 >"/proc/$pid/oom_score_adj" 2>/dev/null
        for d in /proc/"$pid"/task/*/children; do
            [ -r "$d" ] || continue
            local kids kid
            slurp kids "$d" || continue
            for kid in $kids; do
                echo 1000 >"/proc/$kid/oom_score_adj" 2>/dev/null
            done
        done
    fi
}

stop_job() {
    local why="$1" pid
    : >"$STOP"
    # Every caller of stop_job lays the sentinel, but only the memory branch used
    # to track that it had done so. On 2026-08-14 a resume-from-suspend fired the
    # starvation branch at 23:15:03; it laid STOP with `warned` still 0, so the
    # recovery arm below (`elif [ "$warned" -eq 1 ]`) never ran and **the sentinel
    # stayed on a machine with 21 GB free**. Every heavy step is gated on that
    # file, so the guard had quietly closed the night. Setting the flag here
    # rather than in each branch means a future caller cannot reintroduce this.
    warned=1
    if [ -r "$JOB_PID_FILE" ]; then
        slurp pid "$JOB_PID_FILE" || pid=""
        if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null && log "  SIGTERM -> $pid ($why)"
            sleep 15
            if kill -0 "$pid" 2>/dev/null; then
                kill -KILL "$pid" 2>/dev/null && log "  SIGKILL -> $pid (did not exit)"
            fi
        else
            log "  no live job registered at $JOB_PID_FILE ($why)"
        fi
    fi
}

# What the registered job is actually holding, in MB: its own resident set plus
# its descendants'. Zero when nothing is registered.
#
# The kill rule needs this because MemAvailable is a property of the machine and
# not of the job, and the two get confused the moment something large and
# unmanaged is resident. Depth-limited so a pathological process tree cannot
# spin the guard in the one loop that has to stay cheap.
job_rss_mb() {
    local pid frontier next p d kids pages total=0
    [ -r "$JOB_PID_FILE" ] || { printf 0; return 0; }
    slurp pid "$JOB_PID_FILE" || { printf 0; return 0; }
    [ -n "${pid:-}" ] && [ -d "/proc/$pid" ] || { printf 0; return 0; }
    frontier="$pid"
    for _ in 1 2 3 4 5 6; do
        [ -n "$frontier" ] || break
        next=""
        for p in $frontier; do
            [ -r "/proc/$p/statm" ] || continue
            read -r _ pages _ < "/proc/$p/statm" 2>/dev/null || continue
            total=$((total + pages * 4 / 1024))
            for d in /proc/"$p"/task/*/children; do
                [ -r "$d" ] || continue
                slurp kids "$d" || continue
                next="$next $kids"
            done
        done
        frontier="$next"
    done
    printf '%s' "$total"
}

# The largest resident process on the machine, for the one log line that has to
# say who is actually holding the memory. A guard that reports a shortage
# without naming its owner sends whoever reads the log looking in the wrong
# place — which is the failure this whole branch exists to stop repeating.
# Called only when the guard is about to explain itself, never in the steady
# state.
largest_holder() {
    local d name pages best=0 best_name="?" best_pid="?"
    for d in /proc/[0-9]*; do
        [ -r "$d/statm" ] || continue
        read -r _ pages _ < "$d/statm" 2>/dev/null || continue
        [ "${pages:-0}" -gt "$best" ] 2>/dev/null || continue
        slurp name "$d/comm" || continue
        best=$pages
        best_name=$name
        best_pid=${d#/proc/}
    done
    printf '%s (pid %s, %sMB)' "$best_name" "$best_pid" "$((best * 4 / 1024))"
}

if find_temp_sensor; then
    read_temp
    log "night-guard up: warn<${WARN_MB}MB kill<${KILL_MB}MB thermal>${THERMAL_MAX}C every ${INTERVAL}s (sensor ${TEMP_PATH}, now ${TEMP_C}C)"
else
    log "night-guard up: warn<${WARN_MB}MB kill<${KILL_MB}MB every ${INTERVAL}s — NO temperature sensor found, heat is unwatched"
fi

read_pswpout
last_swap=$PSWPOUT
now_epoch
last_pass=$EPOCH
warned=0
strikes=0
# Set once the guard has explained that the shortage is not the job's, so the
# explanation appears at the start of an episode instead of every pass.
misattributed=0
# Set when a kill was tried and the floor did not come back. Both clear on the
# first pass that recovers, so a genuinely new episode is judged on its own.
kill_ineffective=0
thermal_strikes=0
thermal_hold=0
pass=0

while true; do
    now_epoch
    elapsed=$((EPOCH - last_pass))
    last_pass=$EPOCH
    pass=$((pass + 1))

    # 1. Starvation. A pass that arrives this late is not a measurement of the
    #    machine, it *is* the measurement: the guard could not run on time, so
    #    nothing else can be trusted to either. No strikes, no grace — the one
    #    documented case of this ended in a power cut.
    if [ "$elapsed" -gt $((INTERVAL * STARVE_FACTOR)) ]; then
        log "STARVED: this pass is ${elapsed}s late (interval ${INTERVAL}s) — the machine could not schedule a ten-line loop; stopping the job without waiting"
        stop_job "starvation"
        sleep 60
        now_epoch
        last_pass=$EPOCH
        strikes=0
        continue
    fi

    [ $((pass % OOM_EVERY)) -eq 1 ] && volunteer_as_oom_victim

    read_meminfo
    read_temp
    read_pswpout
    swap_delta=$((PSWPOUT - last_swap))
    last_swap=$PSWPOUT
    mb=$AVAIL_MB

    if [ "$swap_delta" -gt 20000 ]; then
        log "WARN swapping hard: ${swap_delta} pages out in ${elapsed}s, ${mb}MB available, ${TEMP_C}C"
    fi

    # 2. Heat. Acted on before memory, because a machine that is too hot stays
    #    too hot until the load comes off, and no amount of free memory fixes it.
    if [ "$TEMP_C" -ge 0 ] && [ "$TEMP_C" -ge "$THERMAL_MAX" ]; then
        thermal_strikes=$((thermal_strikes + 1))
        if [ "$thermal_strikes" -ge "$THERMAL_STRIKES" ]; then
            if [ "$thermal_hold" -eq 0 ]; then
                log "THERMAL ${TEMP_C}C >= ${THERMAL_MAX}C for ${thermal_strikes} checks — stopping the job and holding until it drops below ${THERMAL_CLEAR}C"
                stop_job "thermal"
                thermal_hold=1
            fi
            : >"$STOP"
            sleep "$INTERVAL"
            continue
        fi
        log "THERMAL ${TEMP_C}C >= ${THERMAL_MAX}C — strike ${thermal_strikes}/${THERMAL_STRIKES}"
    else
        thermal_strikes=0
    fi

    if [ "$thermal_hold" -eq 1 ]; then
        if [ "$TEMP_C" -ge 0 ] && [ "$TEMP_C" -le "$THERMAL_CLEAR" ]; then
            log "thermal recovered: ${TEMP_C}C <= ${THERMAL_CLEAR}C — clearing hold"
            thermal_hold=0
            warned=1     # let the memory branch decide whether STOP still applies
        else
            : >"$STOP"
            sleep "$INTERVAL"
            continue
        fi
    fi

    # 3. Memory, as before.
    if [ "$mb" -lt "$KILL_MB" ]; then
        if [ -r "$GRACE" ]; then
            # The job writes its start epoch into the marker, so the age needs no
            # stat(1). An unparseable marker is treated as fresh-but-unknown and
            # therefore stale, which fails safe.
            grace_at=0
            slurp grace_at "$GRACE" || grace_at=0
            case "$grace_at" in (*[!0-9]* | "") grace_at=0 ;; esac
            if [ "$grace_at" -eq 0 ]; then
                # An older harness that only touch()es the marker. Fall back to
                # the file's mtime — one fork, but only on a pass that is already
                # below the kill floor, and never in the steady state.
                grace_at=$(stat -c %Y "$GRACE" 2>/dev/null || echo 0)
                case "$grace_at" in (*[!0-9]* | "") grace_at=0 ;; esac
            fi
            age=$((EPOCH - grace_at))
            if [ "$grace_at" -gt 0 ] && [ "$age" -lt "$GRACE_MAX_AGE" ] && [ "$SWAPFREE_MB" -ge "$SWAP_FLOOR_MB" ]; then
                log "CRITICAL ${mb}MB — declared allocation in progress (${age}s, swap ${SWAPFREE_MB}MB free), holding"
                : >"$STOP"
                sleep "$INTERVAL"
                continue
            fi
            if [ "$SWAPFREE_MB" -lt "$SWAP_FLOOR_MB" ]; then
                log "grace marker present but swap is down to ${SWAPFREE_MB}MB (<${SWAP_FLOOR_MB}) — grace does not apply"
            fi
        fi
        strikes=$((strikes + 1))
        if [ "$strikes" -lt "$KILL_STRIKES" ]; then
            log "CRITICAL ${mb}MB available (<${KILL_MB}) — strike ${strikes}/${KILL_STRIKES}, holding"
            : >"$STOP"
            sleep "$INTERVAL"
            continue
        fi
        # Attribute before acting. Killing the registered job recovers at most
        # what the job is holding; if that still leaves the machine under the
        # floor, the memory belongs to something the guard does not manage and
        # the kill is pure loss.
        #
        # On 2026-08-15 that loss was 34 minutes of a model run. The guard killed
        # at 3921MB; available then read 3912, 3928, 3920 over the next 90 s,
        # because every page the job gave back was immediately taken by swap-in.
        # It fired again every 90 s for an hour with nothing left to kill. The
        # floor was the model server's 18 GB of dirty anonymous memory — not
        # reclaimable, not the job's, and not the guard's to free.
        #
        # Swap is the exception. Once it is gone the machine has no headroom to
        # wait in and something has to go whether or not it is the culprit; that
        # is the case this guard was written for, and it still kills.
        # The predictive gate above is not enough on its own, and the incident
        # proves it: the job's own resident set was larger than the shortfall,
        # so arithmetic said killing it would clear the floor, and killing it
        # cleared nothing. With ~6 GB sitting in swap, every page the job
        # returned was taken straight back by a swap-in, and MemAvailable did
        # not move. Prediction cannot see that; measurement can. So once a kill
        # has been tried and failed, the guard stops trying, and says why.
        if [ "$kill_ineffective" -eq 1 ] && [ "$SWAPFREE_MB" -ge "$SWAP_FLOOR_MB" ]; then
            : >"$STOP"
            sleep "$INTERVAL"
            continue
        fi

        job_mb=$(job_rss_mb)
        if [ "$SWAPFREE_MB" -ge "$SWAP_FLOOR_MB" ] && [ $((mb + job_mb)) -lt "$KILL_MB" ]; then
            if [ "$misattributed" -eq 0 ]; then
                log "CRITICAL ${mb}MB available (<${KILL_MB}) — the registered job holds ${job_mb}MB, so killing it reaches $((mb + job_mb))MB and is still under the floor. It is not what is holding the memory: $(largest_holder) is. Holding with STOP laid, swap ${SWAPFREE_MB}MB free."
                misattributed=1
            fi
            : >"$STOP"
            sleep "$INTERVAL"
            continue
        fi
        misattributed=0
        log "CRITICAL ${mb}MB available (<${KILL_MB}) for ${strikes} checks — the registered job holds ${job_mb}MB, enough for killing it to clear the floor; stopping it"
        stop_job "memory"
        sleep 60
        # Did it work? A guard that never checks its own remedy will apply it
        # forever, which is how one run became forty pointless kill attempts.
        read_meminfo
        if [ "$AVAIL_MB" -lt "$KILL_MB" ]; then
            kill_ineffective=1
            log "  the kill did not recover the floor: ${mb}MB before, ${AVAIL_MB}MB after. Holding from here — $(largest_holder) is what the machine is short of, and no job this guard manages can give that back."
        fi
        now_epoch
        last_pass=$EPOCH
        strikes=0
        continue
    fi

    strikes=0
    misattributed=0
    kill_ineffective=0

    if [ "$mb" -lt "$WARN_MB" ]; then
        [ "$warned" -eq 0 ] && log "LOW ${mb}MB available (<${WARN_MB}) — STOP sentinel laid"
        : >"$STOP"
        warned=1
    elif [ "$warned" -eq 1 ]; then
        log "recovered: ${mb}MB available, ${TEMP_C}C — clearing STOP"
        rm -f "$STOP"
        warned=0
    fi

    sleep "$INTERVAL"
done
