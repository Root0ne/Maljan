"""Fetch the cohort's CAPE reports into the local archive, verifying each one.

The n=100 cohort was submitted as one batch and its task ids are recorded in
`cape_task_ledger_n100.json`. This pulls each task's JSON report to
`data/cape_reports/<sha256>.json`, which is what `eval_cape_baseline.py` and the
dynamic-path evaluations read.

**Why every report is checked against the ledger's sha, not just its status
code.** This instance answers a rate-limit refusal with a body that is
byte-identical to its auth refusal, and both can arrive as HTTP 200. A fetcher
that trusts the status code writes an error page to `<sha>.json` and every
downstream study then scores a document that is not a report — the same shape as
the load-refused-with-200 defect in §3.14, arriving one layer further out. So a
file is only written when the report's own `target.file.sha256` matches the sha
the ledger asked for. Anything else is recorded as a failure with its reason,
and the archive stays clean.

Resumable: an existing, verified file is skipped, so an interrupted run costs
only the report it was mid-transfer on.

Run:  .venv/bin/python tests/evaluation/fetch_cape_reports.py [--limit N]
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
LEDGER = _HERE / "cape_task_ledger_n100.json"
REPORTS_DIR = _REPO_ROOT / "data" / "cape_reports"
FAILURES = _HERE / "cape_fetch_failures.json"

# One VM, and this is a courtesy rather than a limit we were given.
DELAY_SECONDS = 0.4
TIMEOUT_SECONDS = 120


def report_url(base: str, task_id: str) -> str:
    return f"{base.rstrip('/')}/apiv2/tasks/get/report/{task_id}/json/"


def verify(payload: Any, expected_sha: str) -> str | None:
    """Return None when the payload is the requested report, else why it is not."""
    if not isinstance(payload, dict):
        return f"not a JSON object ({type(payload).__name__})"
    if "error" in payload and payload.get("error"):
        return f"api error: {str(payload.get('error_value') or payload['error'])[:80]}"
    target = payload.get("target")
    if not isinstance(target, dict):
        return "no target block — not an analysis report"
    got = str((target.get("file") or {}).get("sha256") or "")
    if not got:
        return "report carries no target sha256"
    if got.lower() != expected_sha.lower():
        return f"sha mismatch: asked {expected_sha[:12]}, got {got[:12]}"
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch cohort CAPE reports with verification.")
    ap.add_argument("--limit", type=int, default=0, help="Stop after N fetches (0 = all).")
    args = ap.parse_args()

    ledger = json.loads(LEDGER.read_text())
    base = str(ledger["instance"]).split()[0]
    tasks: dict[str, str] = ledger["tasks"]
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    todo = [(sha, tid) for sha, tid in tasks.items() if not (REPORTS_DIR / f"{sha}.json").exists()]
    # Count what is on disk *before* --limit truncates the work list; deriving it
    # from the truncated list reports "already archived 97" for a 3-report trial
    # run, which is the kind of plausible wrong number this project keeps finding.
    already = len(tasks) - len(todo)
    if args.limit:
        todo = todo[: args.limit]
    print(f"ledger {len(tasks)} tasks | archived {already} | fetching {len(todo)}")
    print(f"instance {base}", flush=True)

    failures: dict[str, str] = {}
    fetched = 0
    with httpx.Client(timeout=TIMEOUT_SECONDS) as client:
        for i, (sha, tid) in enumerate(todo, 1):
            try:
                resp = client.get(report_url(base, tid))
                resp.raise_for_status()
                payload = resp.json()
            except Exception as exc:  # noqa: BLE001 — a failed fetch is data
                failures[sha] = f"{type(exc).__name__}: {str(exc)[:100]}"
                print(f"  [{i}/{len(todo)}] {sha[:12]} task {tid}: {failures[sha]}", flush=True)
                time.sleep(DELAY_SECONDS)
                continue

            why = verify(payload, sha)
            if why:
                failures[sha] = why
                print(f"  [{i}/{len(todo)}] {sha[:12]} task {tid}: REJECTED — {why}", flush=True)
                time.sleep(DELAY_SECONDS)
                continue

            (REPORTS_DIR / f"{sha}.json").write_text(json.dumps(payload))
            fetched += 1
            size_mb = len(resp.content) / 1_048_576
            print(
                f"  [{i}/{len(todo)}] {sha[:12]} task {tid}: ok "
                f"({size_mb:.1f} MB, {len(payload.get('signatures') or [])} signatures)",
                flush=True,
            )
            time.sleep(DELAY_SECONDS)

    if failures:
        FAILURES.write_text(json.dumps(failures, indent=1))
    archived = len(list(REPORTS_DIR.glob("*.json")))
    print(f"\nfetched {fetched}, failed {len(failures)}, archive now holds {archived} reports")
    if failures:
        print(f"failure reasons written to {FAILURES.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
