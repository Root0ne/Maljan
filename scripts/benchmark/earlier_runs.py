"""Whether a scored run read nothing an earlier run stored.

A benchmark run is submitted with ``ignore_earlier_runs`` and
``isolated_memory`` (``scripts.benchmark.jobs``), and its run summary then
says ``earlier_runs_ignored: true`` and ``isolated_memory: true``. A run
without the first may have been shown the previous run's technique list on
the same sample; a run without the second may have read, through the similar
cases, the similar samples and the function-hash families, what the series'
other runs stored for the other samples. Its score is then partly theirs.
Where a key score has its stored run beside it, the run summary is read
(``run-summary.json``, else the ``run_summary`` of ``report-byjob.json``) and
the run is one of:

- ``off``: the summary says the run started without earlier runs, and either
  says its memory was isolated or the score states, on a line of its own,
  that the run had a fresh account's memory: ``**Memory:** fresh account``
  and, after it, anything the scorer adds (a run on an empty store of its
  own, which nothing else had written to);
- ``stated``: not off, and the score states that earlier runs were used, on
  a line of its own: ``**Earlier runs:** used`` and, after it, anything the
  scorer adds;
- ``not ruled out``: neither. Every score and gate output names such a run
  under :data:`FLAG`, with the switch its summary does not say, and its JSON
  records it, so a number from it is never read as an independent run's.

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
ISOLATED_KEY = "isolated_memory"
OFF, STATED, NOT_RULED_OUT = "off", "stated", "not ruled out"
FLAG = "EARLIER RUNS NOT RULED OUT"
STATEMENT = re.compile(r"^\s*\*\*Earlier runs:\*\*\s*used\b", re.IGNORECASE)
FRESH_MEMORY = re.compile(r"^\s*\*\*Memory:\*\*\s*fresh account\b", re.IGNORECASE)


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
    ignored = summary is not None and summary.get(SUMMARY_KEY) is True
    isolated = summary is not None and summary.get(ISOLATED_KEY) is True
    fresh = any(FRESH_MEMORY.match(line) for line in lines)
    if ignored and isolated:
        return OFF, f"off: {where} says {SUMMARY_KEY} and {ISOLATED_KEY}"
    if ignored and fresh:
        return (
            OFF,
            f"off: {where} says {SUMMARY_KEY}; a fresh account's memory, as the score states",
        )
    missing = [key for key, said in ((SUMMARY_KEY, ignored), (ISOLATED_KEY, isolated)) if not said]
    read = (
        f"{where} does not say {' or '.join(missing)}"
        if summary is not None
        else f"not read: {where}"
    )
    if any(STATEMENT.match(line) for line in lines):
        return STATED, f"used, as the score states; {read}"
    if ignored:
        return (
            NOT_RULED_OUT,
            f"{read}, and the score does not state a fresh account's memory: the run may have "
            "read what other runs stored for other samples",
        )
    return NOT_RULED_OUT, f"{read}, and the score does not state that earlier runs were used"


def flagged(runs: Any) -> dict[str, str]:
    """The runs, by name, whose earlier runs are not ruled out, with the reason."""
    return {r.name: r.earlier_runs_note for r in runs if r.earlier_runs == NOT_RULED_OUT}


def flag_lines(held: dict[str, str]) -> list[str]:
    """The lines every output prints for the runs ``flagged`` named."""
    return [f"{FLAG}: {run}: {note}" for run, note in held.items()]
