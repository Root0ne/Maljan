"""A job read from the database, read-only, into the stored-run layout.

``export_jobs`` opens one read-only transaction (``SET TRANSACTION READ
ONLY``: the database itself refuses any write in it), reads each job's rows —
the job, its report, the per-agent findings, the transcript, the evidence
ledger and the job's events — and writes them into a directory per job, in
the layout :mod:`scripts.replay.stored` reads. The transaction is rolled back
when the read ends. Nothing in the database is written, locked for writing
or changed.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any


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


def _row(mapping: Any) -> dict[str, Any]:
    """A database row (a ``RowMapping``) as a dict of JSON values."""
    return {str(k): jsonable(v) for k, v in dict(mapping).items()}


def write_run(rows: JobRows, into: Path) -> tuple[Path, list[str]]:
    """Write one job's rows into ``into`` in the stored-run layout.

    Returns ``into`` and the files of the layout an earlier export had left
    there, which are removed first: a file this job has no rows for must not
    stay from another export. No other file in ``into`` is touched.
    """
    from scripts.replay.stored import FILES

    into.mkdir(parents=True, exist_ok=True)
    cleared = sorted(name for name in FILES if (into / name).is_file())
    for name in cleared:
        (into / name).unlink()
    report = rows.report or {}
    byjob = {
        "id": report.get("id"),
        "job_id": rows.job.get("id"),
        "verdict": report.get("verdict"),
        "overall_confidence": report.get("overall_confidence"),
        "malware_category": report.get("malware_category"),
        "stix_bundle": report.get("stix_bundle"),
        "mitre_techniques": report.get("mitre_techniques"),
        "agent_reports": report.get("agent_reports") or {},
        "negotiation_log": report.get("negotiation_log") or {},
        "run_summary": report.get("run_summary") or {},
        "malware_report": report.get("malware_report"),
        "incomplete_reason": report.get("incomplete_reason"),
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
    for name, value in files.items():
        (into / name).write_text(json.dumps(value, indent=1, sort_keys=True), encoding="utf-8")
    return into, cleared


def _database_url(given: str | None) -> str:
    if given:
        return given
    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    from app.config import settings

    return str(settings.database_url)


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


async def _sample_row(conn: Any, job: Any) -> dict[str, Any] | None:
    """The sample row of ``job`` (a database row), or ``None`` when it names none or it is gone."""
    from sqlalchemy import select

    from app.models.sample import Sample

    sample_id = job.get("sample_id")
    if sample_id is None:
        return None
    found = (
        (await conn.execute(select(Sample.__table__).where(Sample.__table__.c.id == sample_id)))
        .mappings()
        .first()
    )
    return _row(found) if found is not None else None


async def read_jobs(job_ids: Sequence[str], database_url: str) -> list[JobRows]:
    """Each job's rows, read in one read-only transaction that is rolled back."""
    from sqlalchemy import select, text
    from sqlalchemy.ext.asyncio import create_async_engine

    from app.models.evidence import EvidenceEntry
    from app.models.job import AnalysisJob
    from app.models.job_event import JobEvent
    from app.models.report import AgentFinding, AgentMessage, AnalysisReport

    engine = create_async_engine(database_url, pool_pre_ping=False)
    out: list[JobRows] = []
    try:
        async with engine.connect() as conn:
            transaction = await conn.begin()
            try:
                await conn.execute(text("SET TRANSACTION READ ONLY"))
                for raw in job_ids:
                    job_id = uuid.UUID(str(raw))
                    job = (
                        (
                            await conn.execute(
                                select(AnalysisJob.__table__).where(
                                    AnalysisJob.__table__.c.id == job_id
                                )
                            )
                        )
                        .mappings()
                        .first()
                    )
                    if job is None:
                        raise LookupError(f"no job {job_id}")
                    rows = JobRows(job=with_sample(_row(job), await _sample_row(conn, job)))
                    report = (
                        (
                            await conn.execute(
                                select(AnalysisReport.__table__).where(
                                    AnalysisReport.__table__.c.job_id == job_id
                                )
                            )
                        )
                        .mappings()
                        .first()
                    )
                    if report is not None:
                        rows.report = _row(report)
                        report_id = report["id"]
                        rows.findings = [
                            _row(m)
                            for m in (
                                await conn.execute(
                                    select(AgentFinding.__table__).where(
                                        AgentFinding.__table__.c.report_id == report_id
                                    )
                                )
                            ).mappings()
                        ]
                        rows.transcript = [
                            _row(m)
                            for m in (
                                await conn.execute(
                                    select(AgentMessage.__table__).where(
                                        AgentMessage.__table__.c.report_id == report_id
                                    )
                                )
                            ).mappings()
                        ]
                    rows.evidence = [
                        _row(m)
                        for m in (
                            await conn.execute(
                                select(EvidenceEntry.__table__).where(
                                    EvidenceEntry.__table__.c.job_id == job_id
                                )
                            )
                        ).mappings()
                    ]
                    rows.events = [
                        _row(m)
                        for m in (
                            await conn.execute(
                                select(JobEvent.__table__).where(
                                    JobEvent.__table__.c.job_id == job_id
                                )
                            )
                        ).mappings()
                    ]
                    out.append(rows)
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()
    return out


def export_jobs(
    job_ids: Iterable[str], into: Path, *, database_url: str | None = None
) -> list[tuple[Path, list[str]]]:
    """Each job read from the database into ``into/<job id>``.

    Returns each directory written, with the files of an earlier export it
    removed first.
    """
    ids = [str(job_id) for job_id in job_ids]
    rows = asyncio.run(read_jobs(ids, _database_url(database_url)))
    return [write_run(job, into / str(job.job.get("id"))) for job in rows]
