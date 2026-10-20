"""A stored run, read and never written.

A run is a directory in the layout the benchmark keeps: ``evidence.json`` (the
ledger), ``report-byjob.json`` (the report row: the analysts' final answers,
their claims in force, the run summary, the report document and the
transcript), ``report.json``, ``run-summary.json``, ``stix-judge.json`` (the
judge's answer as written), ``events.json`` and ``job.json``. A job read from
the database (``scripts.replay.database``) is written out in the same layout
first, into a directory of the caller's, and replayed from there.

Every file of the directory is digested before the replay and again after it;
the replay fails when any digest differs (:func:`check_unchanged`). Files are
only ever opened for reading here, and nothing in the replay writes inside the
run's directory.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The files a run is read from, and what each holds. A run may lack any of
# them; what is missing is named by the part of the replay that needed it.
FILES: dict[str, str] = {
    "evidence.json": "the evidence ledger",
    "report-byjob.json": "the report row",
    "report.json": "the report document",
    "run-summary.json": "the run summary",
    "stix-judge.json": "the judge's answer",
    "events.json": "the run's events",
    "job.json": "the job",
}


class StoredRunChanged(RuntimeError):
    """A stored run's files changed while it was replayed."""


@dataclass
class StoredRun:
    """The parts of one stored run the replay reads."""

    name: str
    root: Path
    evidence: list[dict[str, Any]] = field(default_factory=list)
    byjob: dict[str, Any] = field(default_factory=dict)
    report: dict[str, Any] | None = None
    run_summary: dict[str, Any] = field(default_factory=dict)
    judge: dict[str, Any] | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    job: dict[str, Any] | None = None
    # The files that are there and could not be read as JSON, with why.
    unreadable: dict[str, str] = field(default_factory=dict)
    # The files the run's directory holds of :data:`FILES`.
    present: tuple[str, ...] = ()
    # Why no ledger row was read from an ``evidence.json`` that parsed; empty
    # when rows were read, or when the file is absent or unreadable.
    evidence_unread: str = ""

    @property
    def agent_reports(self) -> dict[str, str]:
        reports = self.byjob.get("agent_reports")
        return (
            {str(k): str(v or "") for k, v in reports.items()} if isinstance(reports, dict) else {}
        )

    @property
    def agent_findings(self) -> list[dict[str, Any]]:
        rows = self.byjob.get("agent_findings")
        return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []

    @property
    def transcript(self) -> list[dict[str, Any]]:
        """The analysts' messages: the report row's transcript, else the run's events."""
        rows = self.byjob.get("transcript")
        if isinstance(rows, list) and rows:
            return [row for row in rows if isinstance(row, dict)]
        return [
            {**event.get("payload", {}), "ts": event.get("ts")}
            for event in self.events
            if isinstance(event, dict)
            and event.get("type") == "agent_message"
            and isinstance(event.get("payload"), dict)
        ]

    @property
    def settings(self) -> dict[str, Any]:
        snapshot = self.run_summary.get("settings_snapshot")
        return snapshot if isinstance(snapshot, dict) else {}


def digests(root: Path) -> dict[str, str]:
    """The SHA-256 of every file under ``root``, by its path relative to ``root``.

    Every file, not only the ones the replay reads: a replay that wrote
    anywhere in a run's directory has changed the stored run.
    """
    out: dict[str, str] = {}
    for path in sorted(p for p in Path(root).rglob("*") if p.is_file()):
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
        out[path.relative_to(root).as_posix()] = digest.hexdigest()
    return out


def check_unchanged(before: dict[str, str], after: dict[str, str]) -> None:
    """Raise :class:`StoredRunChanged` naming every file added, removed or changed."""
    changed = sorted(name for name in before.keys() & after.keys() if before[name] != after[name])
    added = sorted(after.keys() - before.keys())
    removed = sorted(before.keys() - after.keys())
    if changed or added or removed:
        parts = [
            f"{what}: {', '.join(names)}"
            for what, names in (("changed", changed), ("added", added), ("removed", removed))
            if names
        ]
        raise StoredRunChanged(f"the stored run changed during the replay ({'; '.join(parts)})")


def evidence_list(document: Any) -> tuple[list[Any], str]:
    """The ledger rows an ``evidence.json`` holds, as written, and why none was found.

    The one reader of a stored ledger for every offline reader (the replay,
    the calibration scorer, the ledger verifier). The rows are under
    ``items`` (the API's page) or ``entries``, or the document is the list
    itself. Each row is returned as written, a malformed one included, for a
    reader that must see it (the verifier); the reason is empty when a row
    was found.
    """
    if isinstance(document, dict):
        found = document.get("items")
        if not (isinstance(found, list) and found) and isinstance(document.get("entries"), list):
            found = document["entries"]
    else:
        found = document
    if not isinstance(found, list):
        return [], "evidence.json holds no entry list (items or entries): no entry was read"
    if not found:
        return [], "evidence.json holds no entries: no claim's citation could be checked"
    return list(found), ""


def evidence_rows(document: Any) -> tuple[list[dict[str, Any]], str]:
    """The ledger rows of :func:`evidence_list` that are objects, and why none was read."""
    found, why = evidence_list(document)
    rows = [row for row in found if isinstance(row, dict)]
    if found and not rows:
        why = "evidence.json holds no entries: no claim's citation could be checked"
    return rows, why


def _read_json(path: Path) -> Any:
    return json.loads(path.read_bytes())


def read_run(root: Path, name: str | None = None) -> StoredRun:
    """The stored run in ``root``, read for the replay.

    A file that is missing leaves its part empty; a file that is there and
    does not parse is named in ``unreadable``. Neither stops the read: each
    part of the replay names what it could not read.
    """
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(f"no stored run at {root}")
    run = StoredRun(name=name or root.name, root=root)
    present: list[str] = []
    loaded: dict[str, Any] = {}
    for file_name in FILES:
        path = root / file_name
        if not path.is_file():
            continue
        present.append(file_name)
        try:
            loaded[file_name] = _read_json(path)
        except (OSError, ValueError) as exc:
            run.unreadable[file_name] = type(exc).__name__
    run.present = tuple(present)

    if "evidence.json" in loaded:
        run.evidence, run.evidence_unread = evidence_rows(loaded["evidence.json"])

    byjob = loaded.get("report-byjob.json")
    run.byjob = byjob if isinstance(byjob, dict) else {}

    report = loaded.get("report.json")
    if not isinstance(report, dict):
        report = run.byjob.get("malware_report")
    run.report = report if isinstance(report, dict) else None

    summary = loaded.get("run-summary.json")
    if not isinstance(summary, dict):
        summary = run.byjob.get("run_summary")
    run.run_summary = summary if isinstance(summary, dict) else {}

    judge = loaded.get("stix-judge.json")
    run.judge = judge if isinstance(judge, dict) else None

    events = loaded.get("events.json")
    run.events = [e for e in events if isinstance(e, dict)] if isinstance(events, list) else []

    job = loaded.get("job.json")
    run.job = job if isinstance(job, dict) else None
    return run
