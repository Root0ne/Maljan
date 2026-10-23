"""Follow-up questions on a finished job: read the stored run, ask, keep the answer beside it.

An analyst asks a new question of a job that has finished
(``POST /jobs/{id}/follow-ups``). It is answered by the report's question round
from what the job stored (``maljan.reporting.follow_up``): no tool is called
and nothing is analysed again. Three steps, so no database transaction is held
across the model call:

1. :func:`prepare` reads the job's stored report, ledger and per-agent
   findings, the digest of the stored report as it reads now and the settings
   the reporter's model is built from (the run's recorded reporter model, else
   the current one). A job still pending or running, or one that stored no
   report to answer from, is refused (:class:`FollowUpRefused`).
2. :func:`answer` builds the reporter as the report stage builds it (its
   output cap, its window, the job's spend ceiling) and asks the question
   round once, with its one retry. Its calls are recorded on a token ledger of
   their own under ``follow-up``.
3. :func:`store` writes the follow-up row, the calls' ``model_usage`` records
   onto the job's event table (numbered from the job's event counter, so the
   job's usage counts them and no later publish collides) and, when the
   platform holds the chain key, a keyed record of the follow-up onto the
   audit chain (``report.follow_up``), all in one transaction. The stored
   report is never changed: the record names the report digest it was answered
   from, beside the report's seal and its last amendment.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.logging_config import get_logger

logger = get_logger("services.follow_up")

# The states a job is still producing its run in: nothing is stored to answer from.
UNFINISHED = ("pending", "running")


class FollowUpRefused(Exception):
    """A follow-up the job cannot be asked: the HTTP status and the sentence that says why."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass
class Prepared:
    """What :func:`prepare` read: the stored run, the report it was read from, the settings."""

    job_id: uuid.UUID
    report_id: uuid.UUID
    report_sha256: str
    seal: Any
    last_amendment: Any
    run: Any
    settings: Any
    model_source: str
    mock: bool = False


@dataclass
class Answered:
    """What :func:`answer` produced: the answer, the model asked, its calls, what it noted."""

    answer: Any
    model: str
    usage: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _refused_unfinished(status: str) -> FollowUpRefused:
    return FollowUpRefused(
        409,
        f"The job has not finished (it is {status}). A follow-up question is answered from "
        "a finished run's stored report and ledger; ask it once the job has finished.",
    )


async def _rows(db: Any, table: Any, *where: Any, order: Any) -> list[dict[str, Any]]:
    from sqlalchemy import select

    from app.services.run_export import row_of

    found = await db.execute(select(table).where(*where).order_by(*order))
    return [row_of(m) for m in found.mappings()]


async def prepare(db: Any, job: Any) -> Prepared:
    """Read what a follow-up on ``job`` is answered from; :class:`FollowUpRefused` if nothing.

    ``job`` is the caller's own job, as the job routes read it. Only reads.
    """
    from maljan.core.settings_overrides import StoredValueRefused, settings_from_store
    from maljan.reporting.follow_up import (
        CURRENT_MODEL,
        UNBUILT_MODEL,
        reporter_overrides,
        stored_run,
    )
    from sqlalchemy import select

    from app.models.evidence import EvidenceEntry
    from app.models.report import AgentFinding, AnalysisReport
    from app.services import ledger_chain
    from app.services.settings_service import load_core_overrides

    status = str(getattr(job, "status", "") or "")
    if status in UNFINISHED:
        raise _refused_unfinished(status)
    report = (
        await db.execute(select(AnalysisReport).where(AnalysisReport.job_id == job.id))
    ).scalar_one_or_none()
    if report is None:
        raise FollowUpRefused(
            409, f"The job {status} without storing a report, so there is nothing to answer from."
        )
    if not isinstance(report.malware_report, dict):
        raise FollowUpRefused(
            422,
            "The job's stored report predates the structured report payload, so a follow-up "
            "question cannot be answered from it.",
        )
    evidence = EvidenceEntry.__table__
    findings = AgentFinding.__table__
    try:
        run = stored_run(
            report.malware_report,
            await _rows(db, evidence, evidence.c.job_id == job.id, order=(evidence.c.seq,)),
            await _rows(
                db,
                findings,
                findings.c.report_id == report.id,
                order=(findings.c.created_at, findings.c.id),
            ),
            report.run_summary,
        )
    except ValueError as exc:
        raise FollowUpRefused(422, f"The job's {exc}; nothing can be answered from it.") from None
    payload = report.malware_report
    amendments = payload.get(ledger_chain.AMENDMENTS_KEY)
    last = amendments[-1] if isinstance(amendments, list) and amendments else None
    summary = report.run_summary if isinstance(report.run_summary, dict) else {}
    overrides = await load_core_overrides(db)
    # The current settings first: a value refused there is the current
    # settings' fault, never the run's recorded model's.
    try:
        current = settings_from_store(overrides)
    except StoredValueRefused:
        # Which key and why is the operator's detail, logged where it was
        # refused; the analyst is told what to do.
        raise FollowUpRefused(
            422,
            "A stored setting value is refused; an administrator fixes it in the console "
            "(Settings, Configuration). Nothing is asked.",
        ) from None
    except Exception as exc:  # noqa: BLE001 — said by class, as the job route says it
        raise FollowUpRefused(
            422, f"The current settings are refused ({type(exc).__name__}); nothing is asked."
        ) from None
    settings, source = current, CURRENT_MODEL
    try:
        merged, source = reporter_overrides(overrides, summary.get("settings_snapshot"), current)
        if merged != overrides:
            settings = settings_from_store(merged, stored_keys=())
    except Exception as exc:  # noqa: BLE001 — the run's model is not asked, and said why
        settings, source = current, UNBUILT_MODEL.format(error=type(exc).__name__)
    # A job that ran as a mock is answered as one: it had no report model.
    mock = bool((getattr(job, "config", None) or {}).get("mock_mode"))
    return Prepared(
        job_id=job.id,
        report_id=report.id,
        report_sha256=ledger_chain.report_digest(report),
        seal=report.ledger_seal,
        last_amendment=last,
        run=run,
        settings=settings,
        model_source=source,
        mock=mock,
    )


def _learn_reporter_windows(settings: Any) -> None:
    """Ask each of the reporter's models for its window once, off the event loop.

    What the reporter's output cap is derived from; the answers are cached for
    the process (``context_window.learn_window``), so building the reporter
    on the loop afterwards asks nothing. Never raises.
    """
    from maljan.core.config import REPORTER_AGENT_KEY
    from maljan.core.container import report_stage_budget
    from maljan.core.model_assignments import assignment_chain_for

    try:
        for assignment in assignment_chain_for(settings, REPORTER_AGENT_KEY, role="judge"):
            report_stage_budget(settings, assignment, probe=True)
    except Exception as exc:  # noqa: BLE001 — the reporter's own build says what broke
        logger.warning("follow-up: the reporter's window was not learned (%s).", type(exc).__name__)


async def answer(prepared: Prepared, question: str) -> Answered:
    """Ask the reporter's model ``question`` of the stored run, once, and check the answer.

    The reporter is built as the report stage builds it, in a container of its
    own for the job's settings with the run's reporter model laid over them,
    and closed afterwards. A reporter that cannot be built (a mock job, a
    model no provider builds) leaves the question "not determinable from this
    run" with the reason. Never raises.
    """
    from maljan.core.config import REPORTER_AGENT_KEY
    from maljan.core.container import ServiceContainer
    from maljan.core.model_assignments import model_label_for
    from maljan.pipeline.events import MODEL_USAGE
    from maljan.reporting.follow_up import answer_follow_up

    usage: list[dict[str, Any]] = []

    def _sink(event_type: str, data: dict[str, Any]) -> None:
        if event_type == MODEL_USAGE and isinstance(data, dict):
            usage.append(dict(data))

    notes = list(prepared.run.notes)
    model = model_label_for(prepared.settings, REPORTER_AGENT_KEY, role="judge")
    if not prepared.mock:
        await asyncio.to_thread(_learn_reporter_windows, prepared.settings)
    container = ServiceContainer(
        prepared.settings,
        mock=prepared.mock,
        event_sink=_sink,
        # A key of its own, so closing this container never touches the job's.
        job_id=f"follow-up-{uuid.uuid4().hex}",
    )
    try:
        reporter = None
        facts = ""
        try:
            reporter = container.get_narrative_agent()
        except Exception as exc:  # noqa: BLE001 — the round says no model answered
            notes.append(f"the report model was unavailable ({type(exc).__name__})")
        if reporter is not None:
            model = str(getattr(reporter, "model_label", "") or model)
            try:
                from maljan.pipeline.nodes import pack_text

                # Off the loop: its bound is derived from the job's windows,
                # which may be asked of the model servers.
                facts = await asyncio.to_thread(
                    pack_text,
                    {"evidence_ledger": prepared.run.ledger},  # type: ignore[typeddict-item]
                    container,
                    for_reporter=True,
                )
            except Exception as exc:  # noqa: BLE001 — asked without the pack, and said
                notes.append(f"the triage pack could not be shown ({type(exc).__name__})")
        done = await answer_follow_up(reporter, prepared.run, question, facts_block=facts)
    finally:
        try:
            await container.aclose()
        except Exception as exc:  # noqa: BLE001 — teardown never costs the answer
            logger.warning("follow-up: closing the reporter failed (%s).", type(exc).__name__)
    for said in done.degradations:
        if said not in notes:
            notes.append(said)
    return Answered(answer=done.answers[0], model=model, usage=usage, notes=notes)


# How long one call to Redis for the event counter may take before the
# follow-up numbers its usage from the table instead: a short wait, as the
# enrichment's queue read has, since a Redis that cannot answer in this long is
# not one to hold a paid answer behind.
COUNTER_TIMEOUT = 5.0
# ``store``'s default: take the usage numbers itself, before the job row is locked.
RESERVE = object()


async def reserve_seqs(
    job_id: uuid.UUID, count: int, *, redis_conn: Any = None, session_factory: Any = None
) -> int | None:
    """The first of ``count`` numbers taken from the job's event counter; ``None`` without Redis.

    The counter every publisher of the job's feed numbers from
    (``analysis_worker._next_seq``): continued from the table first when it
    has expired (``seed_seq_from_the_table``, the same ``NX`` seed), then
    advanced past the whole range at once, so a later publish (an enrichment,
    the worker's last batch) never takes one of these numbers. ``redis_conn``
    and ``session_factory`` default to the platform's. Never raises.
    """
    import redis.asyncio as aioredis

    from app.config import settings
    from app.database import async_session_factory
    from app.services.job_events import STREAM_TTL_SECONDS
    from app.worker.analysis_worker import _seq_key, seed_seq_from_the_table

    key = _seq_key(str(job_id))
    own = redis_conn is None
    conn = (
        aioredis.from_url(
            settings.redis_url,
            socket_timeout=COUNTER_TIMEOUT,
            socket_connect_timeout=COUNTER_TIMEOUT,
        )
        if own
        else redis_conn
    )
    try:
        await seed_seq_from_the_table(conn, session_factory or async_session_factory, str(job_id))
        last = int(await conn.incrby(key, count))
        try:
            await conn.expire(key, STREAM_TTL_SECONDS)
        except Exception as exc:  # noqa: BLE001 — a TTL never costs a number
            logger.debug("follow-up: the event counter's TTL was not refreshed (%s).", exc)
        return last - count + 1
    except Exception as exc:  # noqa: BLE001 — the caller numbers from the table instead
        logger.warning(
            "follow-up: the job's event counter could not be advanced (%s).", type(exc).__name__
        )
        return None
    finally:
        if own:
            try:
                await conn.aclose()
            except Exception as exc:  # noqa: BLE001 — closing never costs the answer
                logger.debug("follow-up: the Redis connection did not close (%s).", exc)


# Said on a follow-up whose usage was numbered from the table, Redis being away.
NUMBERED_FROM_THE_TABLE = (
    "the job's event counter could not be reached, so this follow-up's usage records were "
    "numbered after the job's last stored event; a later event published while the counter "
    "is behind may take one of their numbers and be dropped from the table"
)


async def _usage_events(
    db: Any, job_id: uuid.UUID, usage: list[dict[str, Any]], first: int | None
) -> str | None:
    """The follow-up's model calls as the job's ``model_usage`` events; a note when numbered late.

    Read by the job's usage endpoint as every call of the run is. ``first`` is
    the first number taken from the job's event counter (:func:`reserve_seqs`);
    ``None``, after the job's last stored event, under the job row the caller
    holds, and said.
    """
    if not usage:
        return None
    from maljan.pipeline.events import MODEL_USAGE
    from sqlalchemy import func, select

    from app.models.job_event import JobEvent
    from app.services import store_text
    from app.worker.analysis_worker import scrubbed

    note = None
    if first is None:
        last = (
            await db.execute(select(func.max(JobEvent.seq)).where(JobEvent.job_id == job_id))
        ).scalar()
        first, note = int(last or 0) + 1, NUMBERED_FROM_THE_TABLE
    now = datetime.now(UTC)
    for seq, record in enumerate(usage, first):
        payload, _replaced = store_text.storable({**scrubbed(record), "seq": seq})
        db.add(JobEvent(job_id=job_id, seq=seq, type=MODEL_USAGE, payload=payload, ts=now))
    return note


async def store(
    db: Any,
    prepared: Prepared,
    answered: Answered,
    question: str,
    *,
    user_id: Any = None,
    first: Any = RESERVE,
) -> Any:
    """Write the follow-up, its calls' usage and its chained audit row in ``db``'s transaction.

    ``first`` is the first usage number the caller took from the job's event
    counter (:func:`reserve_seqs`, ``None`` when it could not); by default it
    is taken here. Either way it is taken before the job row is locked, so no
    Redis call is made under the lock; a rollback after it leaves only a gap
    in the numbering. The job row is then locked, so follow-ups on one job
    are written one at a time. A report deleted while the question was being
    answered is refused (409): the answer named a report that is gone. Without
    the chain key the follow-up is written unchained, and its notes say why.
    Uncommitted: the caller commits.
    """
    from sqlalchemy import select

    from app.models.follow_up import JobFollowUp
    from app.models.job import AnalysisJob
    from app.models.report import AnalysisReport
    from app.services import audit_chain, ledger_chain, store_text

    if first is RESERVE:
        first = await reserve_seqs(prepared.job_id, len(answered.usage)) if answered.usage else None
    await db.execute(
        select(AnalysisJob.id).where(AnalysisJob.id == prepared.job_id).with_for_update()
    )
    report = await db.get(AnalysisReport, prepared.report_id)
    if report is None:
        raise FollowUpRefused(
            409,
            "The job's report was deleted while the follow-up question was being answered; "
            "nothing is kept.",
        )
    asked = " ".join(str(question).split())
    shown = answered.answer.model_dump(mode="json")
    stored_answer, _ = store_text.storable(shown)
    notes, _ = store_text.storable(list(answered.notes))
    at = datetime.now(UTC)
    row = JobFollowUp(
        id=uuid.uuid4(),
        job_id=prepared.job_id,
        report_id=prepared.report_id,
        asked_by=user_id,
        question=store_text.storable(asked)[0],
        outcome=str(answered.answer.outcome),
        answer=stored_answer,
        model=answered.model,
        model_source=prepared.model_source,
        report_sha256=prepared.report_sha256,
        notes=notes,
        answered_at=at,
    )
    key, no_key = ledger_chain.platform_key_status()
    if key is not None:
        row.record = ledger_chain.follow_up_record(
            follow_up_id=row.id,
            report_id=prepared.report_id,
            report_sha256=prepared.report_sha256,
            seal_record=prepared.seal,
            last_amendment=prepared.last_amendment,
            answer_sha256=ledger_chain.follow_up_digest(
                {"question": row.question, "answer": stored_answer, "model": row.model}
            ),
            at=at,
            key=key,
        )
    else:
        row.notes = [*row.notes, f"this follow-up is not on the audit chain: {no_key}"]
    db.add(row)
    numbered = await _usage_events(db, prepared.job_id, answered.usage, first)
    if numbered is not None:
        row.notes = [*row.notes, numbered]
    await db.flush()
    if key is not None:
        landed = await audit_chain.append(
            db,
            action=audit_chain.REPORT_FOLLOW_UP,
            resource_type="job",
            resource_id=str(prepared.job_id),
            details={
                "report_id": str(prepared.report_id),
                "follow_up_id": str(row.id),
                "record": row.record,
            },
            key=key,
            user_id=user_id,
        )
        if landed is None:
            row.notes = [
                *row.notes,
                "this follow-up's audit row did not land (the audit write failed and is logged)",
            ]
    return row


async def list_for(db: Any, job_id: uuid.UUID) -> list[Any]:
    """The job's follow-ups, oldest first."""
    from sqlalchemy import select

    from app.models.follow_up import JobFollowUp

    found = await db.execute(
        select(JobFollowUp)
        .where(JobFollowUp.job_id == job_id)
        .order_by(JobFollowUp.answered_at, JobFollowUp.id)
    )
    return list(found.scalars().all())


def as_mapping(row: Any) -> Mapping[str, Any]:
    """A follow-up row as the API serves it."""
    return {
        "id": row.id,
        "job_id": row.job_id,
        "report_id": row.report_id,
        "question": row.question,
        "outcome": row.outcome,
        "answer": row.answer,
        "model": row.model,
        "model_source": row.model_source,
        "report_sha256": row.report_sha256,
        "record": row.record,
        "notes": list(row.notes or []),
        "answered_at": row.answered_at,
    }
