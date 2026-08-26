"""Re-submit the cohort samples whose 2026-08-10 analyses never happened.

§3.24: of the 100 tasks submitted on 2026-08-10, 43 produced reports after
186-366 s of analysis and 57 returned in **zero to one second** — 56 of them
marked `reported` by the sandbox, none of them with a report directory. A single
VM stopped detonating mid-batch while the scheduler kept closing tickets, so the
cohort has been n=43 ever since without anything on disk saying so.

The samples themselves are intact: all 57 binaries are in `data/samples`, and a
re-submission of one of them on 2026-08-13 (task 19144) ran **362 s** and
produced a fetchable report on the same instance. So this re-submits the rest.

It writes a **second ledger** rather than editing the first. The original records
what was submitted on 2026-08-10 and what became of it; overwriting it would
erase the evidence for §3.24 in the act of repairing the damage it describes.

Run:  .venv/bin/python tests/evaluation/submit_cape_missing.py [--limit N] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]

LEDGER_V1 = _HERE / "cape_task_ledger_n100.json"
LEDGER_V2 = _HERE / "cape_task_ledger_v2.json"
REPORTS_DIR = _REPO_ROOT / "data" / "cape_reports"
SAMPLES_DIR = _REPO_ROOT / "data" / "samples"

# The instance detonates a PE in 186-366 s. Anything an order of magnitude below
# that did not run, whatever the status field says.
MIN_PLAUSIBLE_SECONDS = 60
SUBMIT_DELAY = 1.0
TIMEOUT = 180

# Matches what the surviving 43 were given, so the recovered samples are not
# analysed under different terms from the ones they will be pooled with.
ANALYSIS_TIMEOUT = 200
PACKAGE = "exe"
PLATFORM = "windows"


def missing_samples(tasks: dict[str, str]) -> list[str]:
    """Cohort members with no archived report, in ledger order."""
    return [sha for sha in tasks if not (REPORTS_DIR / f"{sha}.json").exists()]


def submit(client: httpx.Client, base: str, path: Path) -> tuple[str | None, str]:
    """Returns (task_id, note). A refusal is data, not an exception."""
    try:
        with path.open("rb") as fh:
            resp = client.post(
                f"{base}/apiv2/tasks/create/file/",
                files={"file": (path.name, fh)},
                data={
                    "timeout": str(ANALYSIS_TIMEOUT),
                    "package": PACKAGE,
                    "platform": PLATFORM,
                },
            )
        resp.raise_for_status()
        payload: dict[str, Any] = resp.json()
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {str(exc)[:120]}"

    ids = ((payload.get("data") or {}).get("task_ids")) or []
    if not ids:
        # The instance answers a rate-limit refusal with the same shape as an
        # auth refusal, so the body is kept verbatim rather than summarised.
        return None, f"no task id: {json.dumps(payload)[:160]}"
    return str(ids[0]), "submitted"


def main() -> int:
    ap = argparse.ArgumentParser(description="Re-submit cohort samples that never ran.")
    ap.add_argument("--limit", type=int, default=0, help="Submit at most N (0 = all).")
    ap.add_argument("--dry-run", action="store_true", help="List what would be submitted.")
    args = ap.parse_args()

    v1 = json.loads(LEDGER_V1.read_text())
    base = str(v1["instance"]).split()[0]
    tasks: dict[str, str] = v1["tasks"]

    todo = missing_samples(tasks)
    without_binary = [s for s in todo if not (SAMPLES_DIR / f"{s}.exe").exists()]
    todo = [s for s in todo if (SAMPLES_DIR / f"{s}.exe").exists()]
    if args.limit:
        todo = todo[: args.limit]

    print(f"cohort {len(tasks)} | archived {len(tasks) - len(missing_samples(tasks))}")
    print(
        f"to re-submit {len(todo)}"
        + (f" | {len(without_binary)} lack a local binary" if without_binary else "")
    )
    print(f"instance {base}", flush=True)
    if args.dry_run:
        for sha in todo:
            print(f"  would submit {sha[:12]} (old task {tasks[sha]})")
        return 0

    submitted: dict[str, str] = {}
    refused: dict[str, str] = {}
    if LEDGER_V2.exists():
        prior = json.loads(LEDGER_V2.read_text())
        submitted.update(prior.get("tasks") or {})
        print(f"resuming: {len(submitted)} already re-submitted", flush=True)

    with httpx.Client(timeout=TIMEOUT) as client:
        for i, sha in enumerate(todo, 1):
            if sha in submitted:
                continue
            tid, note = submit(client, base, SAMPLES_DIR / f"{sha}.exe")
            if tid:
                submitted[sha] = tid
                print(f"  [{i}/{len(todo)}] {sha[:12]} -> task {tid}", flush=True)
            else:
                refused[sha] = note
                print(f"  [{i}/{len(todo)}] {sha[:12]} REFUSED — {note}", flush=True)
            LEDGER_V2.write_text(
                json.dumps(
                    {
                        "schema": "cape-task-ledger/v2",
                        "supersedes": LEDGER_V1.name,
                        "why": (
                            "§3.24: 56 of the v1 tasks were marked reported after 0-1 s with no "
                            "report directory. This ledger records the re-submission; v1 is kept "
                            "intact as the evidence for that finding."
                        ),
                        "instance": v1["instance"],
                        "analysis_timeout": ANALYSIS_TIMEOUT,
                        "min_plausible_seconds": MIN_PLAUSIBLE_SECONDS,
                        "tasks": submitted,
                        "refused": refused,
                    },
                    indent=1,
                )
                + "\n"
            )
            time.sleep(SUBMIT_DELAY)

    print(f"\nsubmitted {len(submitted)}, refused {len(refused)}")
    print(f"ledger: {LEDGER_V2.relative_to(_REPO_ROOT)}")
    print(
        "\nFetch when they finish. A task is only done if its analysis lasted at least "
        f"{MIN_PLAUSIBLE_SECONDS}s — the status field alone reported success for analyses "
        "that took zero (§3.24)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
