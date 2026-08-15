#!/usr/bin/env bash
# Recover the samples the sandbox lost, and take the cohort to its full size.
#
# Three of the hundred submitted samples never produced a report. They are not
# missing data in the ordinary sense: all three are still marked `reported` by
# the sandbox, at zero seconds, with no report directory — which is the instrument
# failure this paper is about, arriving in its own corpus. Their binaries are on
# disk and their original task ids are in the ledger, so the only thing standing
# between the cohort and its full size is being on the sandbox's network.
#
# This runs the whole recovery: submit, wait, harvest with identity verification,
# re-score the baseline, re-derive every number, rebuild the paper. It refuses
# clearly rather than hanging when the instance is unreachable, because the
# failure a reader of this script will hit most often is being on the wrong
# network, and a timeout is a bad way to be told that.
#
# Nothing here touches the sandbox host or its tunnels. It submits files and
# reads reports through the published API, which is the only interface this
# project has ever used against it.
#
# Run:  make cohort-complete
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

PY=".venv/bin/python"
EVAL="tests/evaluation"
# Each analysis takes about ten minutes on the single guest, and three run in
# series. Twice that is the ceiling before this gives up and says so.
WAIT_BUDGET_S=${WAIT_BUDGET_S:-3600}
POLL_S=${POLL_S:-60}

say() { printf '\n\033[1m%s\033[0m\n' "$1"; }
die() { printf '\033[31m%s\033[0m\n' "$1" >&2; exit 1; }

instance=$("$PY" - <<'INST'
import json
from pathlib import Path
print(json.loads(Path("tests/evaluation/cape_task_ledger_n100.json").read_text())["instance"].split()[0])
INST
)

say "sandbox: $instance"
if ! curl -s -o /dev/null -m 8 "$instance/apiv2/tasks/view/1/"; then
    die "not reachable — this needs the sandbox's network. Nothing was submitted.
     The three binaries are on disk and their task ids are in the ledger, so
     rerunning this from that network is all that is required."
fi

say "submitting the samples that never ran"
"$PY" "$EVAL/submit_cape_missing.py" || die "submission failed"

say "waiting for the analyses (each is roughly ten minutes on one guest)"
deadline=$(( $(date +%s) + WAIT_BUDGET_S ))
while :; do
    remaining=$("$PY" - <<'LEFT'
import json
from pathlib import Path

base = Path("tests/evaluation")
cohort = {s["sha256"] for s in json.loads((base / "dynamic_cohort_n100.json").read_text())["samples"]}
have = {p.stem for p in (Path("data/cape_reports")).glob("*.json")}
print(len(cohort - have))
LEFT
)
    [ "$remaining" -eq 0 ] && { say "all analyses have reports"; break; }
    if [ "$(date +%s)" -ge "$deadline" ]; then
        printf '\033[33m%s\033[0m\n' \
          "still waiting on $remaining after ${WAIT_BUDGET_S}s. The submissions stand;
     rerun this script, or harvest later with:
       $PY $EVAL/fetch_cape_reports.py --ledger $EVAL/cape_task_ledger_v2.json"
        break
    fi
    printf '  %s left, polling again in %ss\n' "$remaining" "$POLL_S"
    sleep "$POLL_S"
    "$PY" "$EVAL/fetch_cape_reports.py" --ledger "$EVAL/cape_task_ledger_v2.json" >/dev/null 2>&1
done

say "re-scoring the no-LLM baseline over whatever the cohort now holds"
"$PY" "$EVAL/eval_cape_baseline.py" || die "baseline scoring failed"

say "re-deriving every number and rebuilding"
"$PY" "$EVAL/reanalyse.py" >/dev/null || die "re-analysis failed"
"$PY" "$EVAL/paper_facts.py" | head -1
"$PY" "$EVAL/make_paper_figures.py" >/dev/null || die "figures failed"
"$PY" docs/academic-article/paper/build_paper.py || die "the paper did not build"

say "cohort size now:"
"$PY" - <<'SIZE'
import json
from pathlib import Path

d = json.loads(Path("tests/evaluation/cape_baseline.json").read_text())
lost = d["skipped"]["no_report"]
print(f"  scored {len(d['per_sample'])}, still without a report {len(lost)}")
if lost:
    print("  " + ", ".join(s[:12] for s in lost))
SIZE

printf '\n\033[33m%s\033[0m\n' \
"Every sentence about the cohort size is derived, so the paper has already
updated itself. What is not automatic: if the three are recovered, Section 5's
account of them changes from permanently lost to recovered on a third attempt,
and the instrument finding — that all three still reported success — stands
either way and should stay."
