#!/usr/bin/env bash
# Keeps C4 advancing across memory-guard kills, without arguing with the guard.
#
# The guard exists because the desktop froze on 2026-08-10 and VS Code was killed
# on 2026-08-11; it terminates the registered job when available memory stays
# under its floor. On 2026-08-12 it did exactly that to C4 at 22:33 — correctly,
# and the run then sat dead for an hour because nothing was watching.
#
# So this does not raise the floor, disable the guard, or protect the job from
# it. It waits for the machine to recover and starts the next attempt. Each arm
# is checkpointed, so a kill costs one arm (~40 min) rather than the night, and
# a completed arm is never repeated.
#
# It will not start an attempt while:
#   * the guard's STOP sentinel is down (memory is low),
#   * available memory is under RESUME_MB, or
#   * a previous attempt is still running.
#
# Stop it with:  touch logs/c4-supervisor.STOP
set -uo pipefail

ROOT="${MALJAN_ROOT:-/home/user/Belgeler/kingston/Projects/Maljan}"
cd "$ROOT" || exit 1

LOG_DIR="$ROOT/logs"
LOG="$LOG_DIR/c4-supervisor.log"
STOP="$LOG_DIR/c4-supervisor.STOP"
GUARD_STOP="$LOG_DIR/overnight-watch.STOP"
JOB_PID_FILE="$LOG_DIR/night-job.pid"
CHECKPOINT="$ROOT/tests/evaluation/dynamic_vs_static_checkpoint.jsonl"
PY="$ROOT/.venv/bin/python"
HARNESS="tests/evaluation/eval_dynamic_vs_static.py"

# Start an attempt only with real headroom. The guard kills under 4096 MB; going
# again at 4100 MB would just feed it another victim. 9 GB is roughly llama's
# post-load footprint plus the pipeline's peak plus room for the desktop.
RESUME_MB="${RESUME_MB:-9216}"
POLL="${POLL:-60}"
# Two arms per archived report, derived rather than fixed. It was hard-coded to
# 86 (43 reports x 2) and then the §3.24 recovery started adding reports to the
# archive while the study ran; a fixed target would have declared the study
# finished with a third of the recovered cohort untouched. Re-read each pass, so
# it tracks the archive as the recovery lands.
target_arms() {
  local n
  n="$(ls "$ROOT"/data/cape_reports/*.json 2>/dev/null | wc -l)"
  echo $((n * 2))
}

# Do not start a sixteen-thread model server into a machine that is already hot.
# The guard clears its thermal hold at 82 °C, which is the top of this chassis's
# idle band (measured 76-81 °C on the CPU die at rest); starting work the instant
# the hold lifts would put full load on silicon that has not actually cooled.
# 84 °C leaves a little room above idle without waiting for a temperature this
# laptop does not reach on its own.
RESUME_MAX_C="${RESUME_MAX_C:-84}"

cpu_temp_c() {
  local h name raw
  for h in /sys/class/hwmon/hwmon*; do
    [ -r "$h/name" ] || continue
    read -r name < "$h/name" 2>/dev/null || continue
    if [ "$name" = "k10temp" ] && [ -r "$h/temp1_input" ]; then
      read -r raw < "$h/temp1_input" 2>/dev/null || return 1
      echo $((raw / 1000))
      return 0
    fi
  done
  return 1
}

log() { printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOG"; }

available_mb() { awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo; }

completed_arms() {
  [ -s "$CHECKPOINT" ] || { echo 0; return; }
  "$PY" - "$CHECKPOINT" <<'EOF' 2>/dev/null || echo 0
import json, sys
seen = set()
for line in open(sys.argv[1]):
    try:
        row = json.loads(line)
    except Exception:
        continue
    if "error" not in row and row.get("key"):
        seen.add(row["key"])
print(len(seen))
EOF
}

running() { pgrep -f "eval_dynamic_vs_static\.py" >/dev/null 2>&1; }

# An idle model server is the deadlock this supervisor walked into on its first
# night. After the guard killed the harness at 05:11, llama-server stayed up —
# it is a separate systemd unit — holding 19.4 GB of its 20 GB cap and doing
# nothing. The supervisor then waited three hours for memory that could only be
# released by the harness it was refusing to start.
#
# The harness kills and reloads the server at the start of every sample anyway,
# so stopping an idle one costs a model load and nothing else. Only ever when no
# harness is running, and only on a clear "no work in flight" answer.
reap_idle_llama() {
  running && return 0
  systemctl --user is-active c4-llama.service >/dev/null 2>&1 || return 0
  local health
  health="$(curl -s -m 5 http://localhost:8080/health 2>/dev/null || true)"
  case "$health" in
    *'"slots_processing":0'*)
      local held
      held="$(systemctl --user show c4-llama.service -p MemoryCurrent --value 2>/dev/null)"
      held="$(( ${held:-0} / 1048576 ))"
      log "reaping idle model server holding ${held}MB — the harness reloads it per sample"
      systemctl --user stop c4-llama.service >/dev/null 2>&1
      sleep 5
      ;;
  esac
}

log "supervisor up: resume>${RESUME_MB}MB, poll ${POLL}s, target $(target_arms) arms (2 per archived report)"

attempts=0
while :; do
  if [ -f "$STOP" ]; then
    log "STOP sentinel present — supervisor exiting"
    exit 0
  fi

  done_arms="$(completed_arms)"
  total_arms="$(target_arms)"
  if [ "$done_arms" -ge "$total_arms" ]; then
    log "all $total_arms arms complete — supervisor exiting"
    exit 0
  fi

  if running; then
    sleep "$POLL"
    continue
  fi

  # Before judging the machine short of memory, stop holding it hostage.
  reap_idle_llama

  avail="$(available_mb)"
  if [ -f "$GUARD_STOP" ]; then
    log "holding: guard STOP sentinel is down (${avail}MB available, ${done_arms}/${total_arms} arms)"
    sleep "$POLL"
    continue
  fi
  if [ "$avail" -lt "$RESUME_MB" ]; then
    log "holding: ${avail}MB available < ${RESUME_MB}MB (${done_arms}/${total_arms} arms)"
    sleep "$POLL"
    continue
  fi
  temp="$(cpu_temp_c || echo -1)"
  if [ "$temp" -ge 0 ] && [ "$temp" -ge "$RESUME_MAX_C" ]; then
    log "holding: CPU die at ${temp}C >= ${RESUME_MAX_C}C (${done_arms}/${total_arms} arms)"
    sleep "$POLL"
    continue
  fi

  attempts=$((attempts + 1))
  log "attempt ${attempts}: ${avail}MB available, ${done_arms}/${total_arms} arms done — starting"
  nohup setsid "$PY" "$HARNESS" >>"$LOG_DIR/c4_run.log" 2>&1 &
  sleep 5
  pid="$(pgrep -f "eval_dynamic_vs_static\.py" | head -1)"
  if [ -n "$pid" ]; then
    echo "$pid" >"$JOB_PID_FILE"
    log "attempt ${attempts}: pid ${pid} registered with the guard"
  else
    log "attempt ${attempts}: process did not come up — will retry"
  fi
  sleep "$POLL"
done
