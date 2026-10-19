"""One job's rows in the stored-run layout: read from the database, written as JSON files.

The replay export (``scripts.replay.database``) and the job package
(:mod:`app.services.job_package`) both write a job in this layout, so both use
this one reader and writer. :func:`read_job_rows` only issues Core ``SELECT``s,
so it serves an ``AsyncSession`` as well as an ``AsyncConnection`` inside a
read-only transaction. :func:`write_files` writes each file with ``json.dump``
(the same bytes ``json.dumps`` gives, encoded as it goes rather than built
whole first).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

# The stem of every file :func:`run_files` can write, each stored as
# ``<stem>.json``, in the stored-run layout (``scripts.replay.stored.FILES``
# names the same set of files, with what each holds).
_STEMS = ("job", "report-byjob", "evidence", "events", "report", "run-summary", "stix-judge")
LAYOUT: tuple[str, ...] = tuple(f"{stem}.json" for stem in _STEMS)


@dataclass
class JobRows:
    """One job's rows, each as a mapping of column to value."""

    job: dict[str, Any]
    report: dict[str, Any] | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    transcript: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)


def jsonable(value: Any) -> Any:
    """A column value as JSON holds it: ids and times as strings, numbers as numbers."""
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, Mapping):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [jsonable(v) for v in value]
    return value


def row_of(mapping: Any) -> dict[str, Any]:
    """A database row (a ``RowMapping``) as a dict of JSON values."""
    return {str(k): jsonable(v) for k, v in dict(mapping).items()}


def with_sample(job: dict[str, Any], sample: Mapping[str, Any] | None) -> dict[str, Any]:
    """The job row with its sample's hash and name, read from the joined sample row.

    A job whose sample row is gone keeps ``None`` for both and says so
    (``sample_row``): the replay then names the identity it reads from the
    report alone, rather than taking it from there in silence.
    """
    out = dict(job)
    if sample is None:
        out["sample_sha256"] = None
        out["sample_filename"] = None
        out["sample_row"] = "absent"
    else:
        out["sample_sha256"] = sample.get("sha256")
        out["sample_filename"] = sample.get("original_filename")
    return out


def run_files(rows: JobRows) -> dict[str, Any]:
    """The files of the stored-run layout for ``rows``, by file name, as JSON values."""
    report = rows.report or {}
    byjob = {
        "id": report.get("id"),
        "job_id": rows.job.get("id"),
        "verdict": report.get("verdict"),
        "overall_confidence": report.get("overall_confidence"),
        "malware_category": report.get("malware_category"),
        "stix_bundle": report.get("stix_bundle"),
        "mitre_techniques": report.get("mitre_techniques"),
        # The report row as stored: a NULL column stays null, so a verification
        # of the export reads what the database holds.
        "agent_reports": report.get("agent_reports"),
        "negotiation_log": report.get("negotiation_log"),
        "run_summary": report.get("run_summary"),
        "judge_stix_bundle": report.get("judge_stix_bundle"),
        "malware_report": report.get("malware_report"),
        "incomplete_reason": report.get("incomplete_reason"),
        # The seal of the job's ledger, the mark that it is sealed
        # (``python -m scripts.ledger.verify --run`` reads it).
        "ledger_seal": report.get("ledger_seal"),
        "agent_findings": rows.findings,
        "transcript": sorted(rows.transcript, key=lambda m: int(m.get("seq") or 0)),
    }
    files: dict[str, Any] = {
        "job.json": rows.job,
        "report-byjob.json": byjob,
        "evidence.json": {
            "total": len(rows.evidence),
            "items": sorted(rows.evidence, key=lambda e: int(e.get("seq") or 0)),
        },
        "events.json": sorted(rows.events, key=lambda e: int(e.get("seq") or 0)),
    }
    if report.get("malware_report") is not None:
        files["report.json"] = report["malware_report"]
    if report.get("run_summary") is not None:
        files["run-summary.json"] = report["run_summary"]
    if report.get("judge_stix_bundle") is not None:
        files["stix-judge.json"] = report["judge_stix_bundle"]
    return files


def write_files(files: Mapping[str, Any], into: Path) -> None:
    """Write each of ``files`` into ``into`` as indented JSON with sorted keys."""
    into.mkdir(parents=True, exist_ok=True)
    for name, value in files.items():
        with (into / name).open("w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=1, sort_keys=True)


async def _sample_row(db: Any, job: Any) -> dict[str, Any] | None:
    """The sample row of ``job`` (a database row), or ``None`` when it names none or it is gone."""
    from sqlalchemy import select

    from app.models.sample import Sample

    sample_id = job.get("sample_id")
    if sample_id is None:
        return None
    found = (
        (await db.execute(select(Sample.__table__).where(Sample.__table__.c.id == sample_id)))
        .mappings()
        .first()
    )
    return row_of(found) if found is not None else None


async def read_job_rows(db: Any, job_id: uuid.UUID) -> JobRows | None:
    """One job's rows read through ``db``; ``None`` when there is no such job.

    The job (with its sample's hash and name, never its bytes), its report,
    the per-agent findings, the transcript, the evidence ledger and the job's
    events, each in a stable order (``ORDER BY``), so the same job is
    written as the same bytes.
    """
    from sqlalchemy import select

    from app.models.evidence import EvidenceEntry
    from app.models.job import AnalysisJob
    from app.models.job_event import JobEvent
    from app.models.report import AgentFinding, AgentMessage, AnalysisReport

    jobs = AnalysisJob.__table__
    job = (await db.execute(select(jobs).where(jobs.c.id == job_id))).mappings().first()
    if job is None:
        return None
    rows = JobRows(job=with_sample(row_of(job), await _sample_row(db, job)))
    reports = AnalysisReport.__table__
    report = (
        (await db.execute(select(reports).where(reports.c.job_id == job_id))).mappings().first()
    )
    if report is not None:
        rows.report = row_of(report)
        report_id = report["id"]
        findings = AgentFinding.__table__
        rows.findings = [
            row_of(m)
            for m in (
                await db.execute(
                    select(findings)
                    .where(findings.c.report_id == report_id)
                    .order_by(findings.c.created_at, findings.c.id)
                )
            ).mappings()
        ]
        messages = AgentMessage.__table__
        rows.transcript = [
            row_of(m)
            for m in (
                await db.execute(
                    select(messages)
                    .where(messages.c.report_id == report_id)
                    .order_by(messages.c.seq, messages.c.id)
                )
            ).mappings()
        ]
    evidence = EvidenceEntry.__table__
    rows.evidence = [
        row_of(m)
        for m in (
            await db.execute(
                select(evidence).where(evidence.c.job_id == job_id).order_by(evidence.c.seq)
            )
        ).mappings()
    ]
    events = JobEvent.__table__
    rows.events = [
        row_of(m)
        for m in (
            await db.execute(select(events).where(events.c.job_id == job_id).order_by(events.c.seq))
        ).mappings()
    ]
    return rows
