"""ARQ task: post-hoc threat-intel enrichment for an ``AnalysisReport``.

Runs on a queue and a worker of its own (``EnrichmentWorkerSettings``, started
as a second process). It used to share the analysis worker's queue, where the
one-job-at-a-time rule that keeps two analyses off one model applied to it as
well: a measured run spent 451.98 s looking up domains at VirusTotal while the
next analysis sat ``pending`` for 4 m 33 s. Nothing about a reputation lookup
needs that rule — it waits on somebody else's HTTP — so it now waits in its own
queue, several at a time, and the analysis worker never sees it.

A deployment that would rather run one process turns
``api.enrichment_dedicated_worker`` off: the enrichment is queued beside the
analyses again and waits its turn there, which is the old behaviour and the old
cost. The task stays registered on both workers so the fallback has something
to run it.

Trigger paths:
  - automatic: ``analysis_worker.run_analysis`` enqueues this task right
    after the report row is committed.
  - manual: ``POST /api/v1/reports/{id}/enrich`` enqueues it explicitly.

Both go through :func:`enqueue_enrichment`, and both share the unique
``_job_id="enrich:{report_id}"`` so a second attempt simply replaces the queued
one — duplicate work is impossible.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

import redis.asyncio as aioredis
from maljan.core.settings_overrides import redact_url

from app.config import settings
from app.logging_config import get_logger
from app.models.report import AnalysisReport
from app.runtime_config import runtime_config
from app.worker.queues import ANALYSIS_QUEUE, ENRICHMENT_QUEUE, build_redis_settings

if TYPE_CHECKING:
    from maljan.memory.long_term_memory import MemoryStore

logger = get_logger("worker.enrich")


async def enqueue_enrichment(pool: Any, report_id: Any) -> str | None:
    """Queue one report's enrichment, on the queue the deployment asked for.

    The one place that knows the task's name and where it goes, so the
    automatic path and the operator's button cannot drift apart. Returns the
    arq job id, or ``None`` when arq refused it because the same id is already
    queued — which is how a duplicate trigger is coalesced.

    A settings store that cannot be read does not stop the work: the enrichment
    is queued on its own queue, which is the configured default.
    """
    try:
        dedicated = bool(await runtime_config.get("enrichment_dedicated_worker"))
    except Exception as exc:  # noqa: BLE001 — the queue is not worth a failed enqueue
        logger.warning(
            "enrich: could not read which queue to use (%s); using %s.",
            type(exc).__name__,
            ENRICHMENT_QUEUE,
        )
        dedicated = True
    queue = ENRICHMENT_QUEUE if dedicated else ANALYSIS_QUEUE
    job = await pool.enqueue_job(
        "enrich_threat_intel",
        str(report_id),
        _job_id=f"enrich:{report_id}",
        _queue_name=queue,
    )
    return str(job.job_id) if job is not None else None


# Process-wide singleton cache for the Qdrant LTM store. Two flags so we
# can distinguish "never attempted" (build it now) from "built but unavailable"
# (skip silently). Cannot use a ``None`` sentinel for the cache itself
# because ``None`` is a legitimate cached value (Qdrant probe failed).
_memory_store_built: bool = False
_memory_store: MemoryStore | None = None


async def _get_memory_store() -> MemoryStore | None:
    """Lazily build the Qdrant LTM store. Cached process-wide, never raises.

    Returns ``None`` when Qdrant is not installed / not reachable so the
    enrichment task degrades to reputation-only behaviour without aborting.

    The settings are ``core.memory.qdrant_*`` — the same ones the analysis path
    reads. There used to be a second set under ``api.qdrant_*``, and an
    operator who filled in one of the two got a 401 out of every enrich run
    because the worker was reading the other.
    """
    global _memory_store_built, _memory_store
    if _memory_store_built:
        return _memory_store

    try:
        from maljan.memory.qdrant_store import QdrantStore

        memory = (await runtime_config.core()).memory
        qdrant_url = memory.qdrant_url
        qdrant_collection = memory.qdrant_collection
        secret = memory.qdrant_api_key
        _memory_store = QdrantStore(
            url=qdrant_url,
            collection=qdrant_collection,
            api_key=(secret.get_secret_value() if secret else "") or None,
        )
        logger.info(
            "enrich: Qdrant LTM available (url=%s, collection=%s).",
            redact_url(qdrant_url),
            qdrant_collection,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "enrich: Qdrant LTM unavailable (%s) — similar_samples will be empty.",
            exc,
        )
        _memory_store = None
    _memory_store_built = True
    return _memory_store


async def enrich_threat_intel(ctx: dict, report_id: str) -> dict[str, Any]:
    """Enrich a single report's NetworkDomain / NetworkIP reputation fields.

    The task is **fail-safe**: any unexpected exception is logged but does
    not raise so ARQ does not retry-storm on permanent failures.
    """
    if not await runtime_config.get("enrichment_enabled"):
        logger.info("enrich: feature disabled in config, skipping.")
        return {"status": "disabled"}

    redis_conn: aioredis.Redis = ctx["redis"]
    db_session_factory = ctx["db_session"]

    try:
        report_uuid = uuid.UUID(report_id)
    except ValueError:
        logger.warning("enrich: invalid report_id %s", report_id)
        return {"status": "invalid_id"}

    # Two short sessions with the lookups between them, rather than one held
    # open across every call. The reputation lookups are third-party HTTP and
    # take as long as they take — 452 s of VirusTotal on one measured report —
    # and a session held across them is a backend sitting ``idle in
    # transaction`` for the whole of it, holding its locks and pinning a
    # snapshot while a migration or another reader waits behind it.
    async with db_session_factory() as db:
        report = await db.get(AnalysisReport, report_uuid)
        if report is None:
            logger.warning("enrich: report %s not found", report_id)
            return {"status": "not_found"}
        if not report.malware_report:
            logger.info("enrich: report %s has no malware_report payload", report_id)
            return {"status": "skipped"}
        payload = dict(report.malware_report)
        parent_job_id = str(report.job_id)
        await db.commit()

    # Lazy import keeps the API/worker startup graph free of optional
    # maljan-core dependencies.
    from maljan.enrichment import enrich_malware_report

    vt_key = await runtime_config.get_secret("virustotal_api_key") or None
    abuse_key = await runtime_config.get_secret("abuseipdb_api_key") or None

    before_domain_reps = _count_reputations(payload, "domains")
    before_ip_reps = _count_reputations(payload, "ips")

    memory_store = await _get_memory_store()

    try:
        updated = await enrich_malware_report(
            payload,
            vt_api_key=vt_key,
            abuseipdb_api_key=abuse_key,
            max_lookups_per_kind=await runtime_config.get("enrichment_max_lookups"),
            memory_store=memory_store,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("enrich: orchestrator failed (%s)", exc, exc_info=True)
        return {"status": "error", "error": str(exc)[:200]}

    async with db_session_factory() as db:
        report = await db.get(AnalysisReport, report_uuid)
        if report is None:
            # Superseded by a re-run while the lookups were in flight. The
            # enrichment belongs to a report that no longer exists.
            logger.warning("enrich: report %s went away during enrichment", report_id)
            return {"status": "not_found"}
        report.malware_report = updated
        # SQLAlchemy needs an explicit flag for in-place JSONB mutation.
        from sqlalchemy.orm.attributes import flag_modified

        flag_modified(report, "malware_report")
        await db.commit()

    after_domain_reps = _count_reputations(updated, "domains")
    after_ip_reps = _count_reputations(updated, "ips")
    similar_samples_count = _count_similar_samples(updated)

    delta = {
        "report_id": report_id,
        "domains_enriched": after_domain_reps - before_domain_reps,
        "ips_enriched": after_ip_reps - before_ip_reps,
        "similar_samples": similar_samples_count,
    }

    # WebSocket notification — job_id is the parent analysis job; clients
    # subscribed via /ws/{job_id} get the event automatically. Lazy import
    # of ``_publish_event`` keeps this module free of a circular dep on
    # ``analysis_worker`` (which registers this task on its WorkerSettings).
    try:
        from app.worker.analysis_worker import _publish_event

        await _publish_event(
            redis_conn,
            parent_job_id,
            "enrichment_complete",
            delta,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("enrich: WS publish failed (%s)", exc)

    logger.info(
        "enrich: report=%s delta=%s",
        report_id,
        delta,
    )
    return {"status": "ok", **delta}


def _count_reputations(malware_report: dict[str, Any], key: str) -> int:
    network = malware_report.get("network") or {}
    rows = network.get(key) or []
    return sum(1 for row in rows if row.get("reputation"))


def _count_similar_samples(malware_report: dict[str, Any]) -> int:
    attribution = malware_report.get("attribution") or {}
    return len(attribution.get("similar_samples") or [])


async def purge_old_job_events(ctx: dict) -> dict[str, Any]:
    """Drop feed rows older than ``core.events.retention_days``. Never raises.

    The live conversation is worth keeping for as long as somebody might open
    the run that produced it, and no longer: a busy deployment writes tens of
    thousands of rows a day, and the parts of a run that matter a month later
    — the transcript, the agent findings, the evidence ledger — are kept by
    the report and the job and are not touched here.

    Scheduled beside the enrichment task rather than as a worker of its own
    because it is one statement a night against the same database this process
    already holds a session factory for.
    """
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import delete, or_

    from app.models.job_event import JobEvent

    db_session_factory = ctx["db_session"]
    try:
        days = int((await runtime_config.core()).events.retention_days)
    except Exception as exc:  # noqa: BLE001 — an unreadable setting skips the sweep
        logger.warning("events sweep: retention not readable (%s); skipping.", exc)
        return {"status": "skipped"}

    cutoff = datetime.now(UTC) - timedelta(days=max(1, days))
    try:
        async with db_session_factory() as db:
            result = await db.execute(
                delete(JobEvent).where(
                    # ``ts`` is when the publisher stamped the event and is
                    # what age means here; a row that somehow carries none
                    # falls back to when it was written, so nothing can sit in
                    # the table for ever by having no clock.
                    or_(
                        JobEvent.ts < cutoff,
                        JobEvent.ts.is_(None) & (JobEvent.created_at < cutoff),
                    )
                )
            )
            await db.commit()
        removed = int(result.rowcount or 0)
    except Exception as exc:  # noqa: BLE001 — a sweep never takes the worker down
        logger.warning("events sweep failed (%s).", exc)
        return {"status": "failed"}

    logger.info("events sweep: removed %d row(s) older than %d day(s).", removed, days)
    return {"status": "ok", "removed": removed, "retention_days": days}


# ── The enrichment worker ───────────────────────────────────────


async def enrich_startup(ctx: dict) -> None:
    """Called when the enrichment worker starts up.

    Deliberately lighter than the analysis worker's: this process runs no
    pipeline, downloads no sample and owns no job row, so it needs a database
    session factory and a Redis connection and nothing else. The orphan sweep
    and the private-sample sweep belong to the process that runs the jobs they
    are about.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.bootstrap import BootstrapProblem, require_bootstrap
    from app.config import get_settings
    from app.logging_config import setup_logging

    setup_logging()
    try:
        require_bootstrap(get_settings())
    except BootstrapProblem as exc:
        logger.critical(str(exc))
        raise

    engine = create_async_engine(settings.database_url, pool_size=5, max_overflow=10)
    ctx["db_session"] = async_sessionmaker(engine, expire_on_commit=False)
    ctx["redis"] = aioredis.from_url(settings.redis_url)
    logger.info(
        "Enrichment worker started: reading %s",
        ENRICHMENT_QUEUE,
        extra={"component": "worker.lifecycle"},
    )


async def enrich_shutdown(ctx: dict) -> None:
    """Called when the enrichment worker shuts down."""
    redis_conn: aioredis.Redis | None = ctx.get("redis")
    if redis_conn:
        await redis_conn.aclose()

    db_session = ctx.get("db_session")
    if db_session:
        engine = db_session.kw.get("bind")
        if engine:
            await engine.dispose()

    logger.info(
        "Enrichment worker shutdown complete",
        extra={"component": "worker.lifecycle"},
    )


class EnrichmentWorkerSettings:
    """The second process: ``arq app.worker.enrich_worker.EnrichmentWorkerSettings``.

    Reads its own queue, so the analysis worker's single slot is never spent on
    a reputation lookup. Several at a time, because each one is waiting on
    somebody else's HTTP rather than on this host's model or its memory, and
    with its own timeout: the longest measured enrichment took 452 s, which the
    analysis worker's eight-hour ceiling would have hidden.

    The nightly ``job_events`` purge stays on the analysis worker. One owner for
    a scheduled task is the whole point of scheduling it.
    """

    functions = [enrich_threat_intel]
    queue_name = ENRICHMENT_QUEUE
    on_startup = enrich_startup
    on_shutdown = enrich_shutdown

    redis_settings = build_redis_settings(settings.redis_url)

    max_jobs = 4
    job_timeout = 3600
    max_tries = 1
    health_check_interval = 30
