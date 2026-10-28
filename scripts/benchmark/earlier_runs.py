"""Whether a scored run started without an earlier run's memory of its sample.

A benchmark run is submitted with ``ignore_earlier_runs``
(``scripts.benchmark.jobs``), and its run summary then says
``earlier_runs_ignored: true``. A run without it may have been shown the
previous run's technique list on the same sample, and its score is then
partly that run's. Where a key score has its stored run beside it, the run
summary is read (``run-summary.json``, else the ``run_summary`` of
``report-byjob.json``) and the run is one of:

- ``off``: the summary says the run started without earlier runs;
- ``stated``: the summary does not say so, and the score states that earlier
  runs were used, on a line of its own: ``**Earlier runs:** used`` and, after
  it, anything the scorer adds;
- ``not ruled out``: neither. Every score and gate output names such a run
  under :data:`FLAG`, and its JSON records it, so a number from it is never
  read as an independent run's.

A score with no run summary beside it is not ruled out either: nothing says
the run was independent. A blind sheet or a calibration score holds no stored
run and is not read here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SUMMARY_FILE, REPORT_BY_JOB_FILE = "run-summary.json", "report-byjob.json"
SUMMARY_KEY = "earlier_runs_ignored"
OFF, STATED, NOT_RULED_OUT = "off", "stated", "not ruled out"
FLAG = "EARLIER RUNS NOT RULED OUT"
STATEMENT = re.compile(r"^\s*\*\*Earlier runs:\*\*\s*used\b", re.IGNORECASE)


def _summary(root: Path) -> tuple[dict[str, Any] | None, str]:
    """The stored run summary beside a score, and the file it came from, or why none was read."""
    for name, inner in ((SUMMARY_FILE, False), (REPORT_BY_JOB_FILE, True)):
        path = root / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            return None, f"{name} is not JSON ({exc})"
        if inner:
            data = data.get("run_summary") if isinstance(data, dict) else None
        if isinstance(data, dict):
            return data, name
        return None, f"{name} holds no run summary"
    return None, f"no {SUMMARY_FILE} or {REPORT_BY_JOB_FILE} beside the score"


def check(score: Path, lines: list[str]) -> tuple[str, str]:
    """``(status, note)`` of the run a key score at ``score`` scored; ``lines`` are its lines."""
    summary, where = _summary(Path(score).parent)
    if summary is not None and summary.get(SUMMARY_KEY) is True:
        return OFF, f"off: {where} says {SUMMARY_KEY}"
    read = f"{where} does not say {SUMMARY_KEY}" if summary is not None else f"not read: {where}"
    if any(STATEMENT.match(line) for line in lines):
        return STATED, f"used, as the score states; {read}"
    return NOT_RULED_OUT, f"{read}, and the score does not state that earlier runs were used"


def flagged(runs: Any) -> dict[str, str]:
    """The runs, by name, whose earlier runs are not ruled out, with the reason."""
    return {r.name: r.earlier_runs_note for r in runs if r.earlier_runs == NOT_RULED_OUT}


def flag_lines(held: dict[str, str]) -> list[str]:
    """The lines every output prints for the runs ``flagged`` named."""
    return [f"{FLAG}: {run}: {note}" for run, note in held.items()]
