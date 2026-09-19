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

import asyncio
import os
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

# How many enrichments this worker runs at once. A deployment knob rather than
# a setting: it sizes a process, like the analysis worker's RSS ceiling and
# teardown budget, and it is read once when the process starts.
ENRICHMENT_MAX_JOBS = max(1, int(os.environ.get("ENRICHMENT_MAX_JOBS", "2")))

# How an enrichment gets out of an analysis's way when the two share a queue.
#
# With one process — the shipped default — arq pops by score, so an enrichment
# queued a second before an analysis runs first and the analysis waits for all
# of it: 452 s in the run this was filed for. One job at a time keeps them from
# running together; it does not keep the enrichment from going first.
#
# So on that queue the task looks, before it does anything, for an analysis
# waiting behind it, and puts itself back with a short deferral if it finds
# one. The deferral is capped, and the total carried in the job's own
# arguments: past the cap it runs whatever is waiting, so a steady stream of
# analyses can never starve it, and an analysis waits for at most one
# enrichment per cap window.
ENRICHMENT_DEFER_SECONDS = 60
ENRICHMENT_DEFER_CAP_SECONDS = 1800
# How long the queue read before a deferral may take. Short: it runs at the
# head of every enrichment, and a Redis that cannot answer it in this long is
# not one to hold an enrichment behind.
QUEUE_READ_TIMEOUT = 5.0


def enrichment_health_key() -> str:
    """Where the enrichment worker writes that it is alive.

    arq gives each queue its own health key and refreshes it every
    ``health_check_interval`` with a TTL one second longer, so its absence one
    interval after a boot means no worker is reading this queue.
    """
    from arq.constants import health_check_key_suffix

    return f"{ENRICHMENT_QUEUE}{health_check_key_suffix}"


async def enrichment_worker_is_alive(redis_conn: Any) -> bool | None:
    """Whether a worker is reading the enrichment queue. ``None`` when unknown."""
    try:
        return bool(await redis_conn.exists(enrichment_health_key()))
    except Exception as exc:  # noqa: BLE001 — an unreadable queue is not a verdict
        logger.debug("enrich: could not read the worker's health key (%s).", type(exc).__name__)
        return None


async def analyses_are_waiting(redis_conn: Any) -> bool:
    """Whether the analysis queue holds an analysis this enrichment is ahead of.

    Read from the queue rather than from the database: a job row is inserted
    and the arq job enqueued inside one request, and Redis has the entry before
    Postgres commits it, so the queue is the store that cannot miss an analysis
    submitted a moment ago.

    An entry is an analysis unless it is one of ours: an enrichment is enqueued
    under ``enrich:…`` and an analysis under its own job id. Never raises — a
    queue that cannot be read is not a reason to defer, because the enrichment
    would then defer for ever.

    The whole waiting set is read rather than a page of it. A rank bound would
    answer "is an analysis among the first N by score", and the deferred
    enrichments this very function creates score into the future and sort
    *after* everything pending — so a page could be all enrichments while an
    analysis waited just past it. The set is the queue's own backlog, read once
    per enrichment start, and the read is bounded in time instead: a Redis slow
    enough to miss that budget is one whose answer this must not wait for,
    because the analysis it would have yielded to is not going anywhere either.
    """
    try:
        members = await asyncio.wait_for(
            redis_conn.zrange(ANALYSIS_QUEUE, 0, -1), timeout=QUEUE_READ_TIMEOUT
        )
    except (Exception, TimeoutError) as exc:  # noqa: BLE001 — an unreadable queue is not work
        logger.debug("enrich: could not read the analysis queue (%s).", type(exc).__name__)
        return False
    for member in members or []:
        name = member.decode() if isinstance(member, bytes | bytearray) else str(member)
        if not name.startswith("enrich:"):
            return True
    return False


async def defer_behind_the_analyses(ctx: dict, report_id: str, deferred_for: float) -> float | None:
    """Put this enrichment back behind the analyses, or ``None`` to run it now.

    Returns the total deferral the re-enqueued job carries, so the caller can
    say how long this report has been waiting. Nothing is deferred on the
    enrichment worker's own queue — that process exists so these two never
    compete — and nothing is deferred past the cap.
    """
    if ctx.get("queue") == ENRICHMENT_QUEUE:
        return None
    # The total arrives as a job argument, which a hand-enqueued job may have
    # written by hand. A negative one would put the cap out of reach and defer
    # this report for ever; anything that is not a number at all is read as
    # "has not waited yet".
    try:
        deferred_for = max(0.0, float(deferred_for))
    except (TypeError, ValueError):
        deferred_for = 0.0
    if deferred_for >= ENRICHMENT_DEFER_CAP_SECONDS:
        logger.info(
            "enrich: report %s waited %.0fs for the analyses; running it now.",
            report_id,
            deferred_for,
        )
        return None
    redis_conn = ctx.get("redis")
    if redis_conn is None or not await analyses_are_waiting(redis_conn):
        return None

    total = deferred_for + ENRICHMENT_DEFER_SECONDS
    try:
        from arq.connections import ArqRedis

        pool = ctx.get("arq_pool") or ArqRedis(connection_pool=redis_conn.connection_pool)
        queued = await pool.enqueue_job(
            "enrich_threat_intel",
            str(report_id),
            total,
            # A new id per attempt: arq refuses one it is already running, and
            # this job is the one being re-queued.
            _job_id=f"enrich:{ANALYSIS_QUEUE}:{report_id}:d{int(total)}",
            _queue_name=ANALYSIS_QUEUE,
            _defer_by=ENRICHMENT_DEFER_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001 — rather run it late than lose it
        logger.warning(
            "enrich: could not defer report %s (%s); running it now.",
            report_id,
            type(exc).__name__,
        )
        return None
    if queued is None:
        # arq says no without raising: that id is already queued, or its result
        # is still on file, or the watch on the key was broken by somebody
        # else. Deferring on that answer would drop this enrichment, because
        # nothing was put back — so it runs now.
        logger.info(
            "enrich: the queue would not take report %s back (%.0fs deferred); running it now.",
            report_id,
            deferred_for,
        )
        return None
    return total


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
    # The queue is part of the identity, not only of the destination. arq
    # refuses a job id it has seen for 24 hours, which is what coalesces two
    # triggers for one report — and which would also refuse to re-queue a
    # report after the setting flipped, leaving it waiting on the queue it was
    # first put in. One id per queue keeps the coalescing and drops that.
    job = await pool.enqueue_job(
        "enrich_threat_intel",
        str(report_id),
        _job_id=f"enrich:{queue}:{report_id}",
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


async def enrich_threat_intel(
    ctx: dict, report_id: str, deferred_for: float = 0.0
) -> dict[str, Any]:
    """Enrich a single report's NetworkDomain / NetworkIP reputation fields.

    The task is **fail-safe**: any unexpected exception is logged but does
    not raise so ARQ does not retry-storm on permanent failures.
    """
    if not await runtime_config.get("enrichment_enabled"):
        logger.info("enrich: feature disabled in config, skipping.")
        return {"status": "disabled"}

    redis_conn: aioredis.Redis = ctx["redis"]
    db_session_factory = ctx["db_session"]

    # Before anything else, and only where the two share a queue: an analysis
    # waiting behind this job goes first. An enrichment already running is
    # never interrupted — that is what the dedicated worker is for.
    waited = await defer_behind_the_analyses(ctx, report_id, deferred_for)
    if waited is not None:
        logger.info(
            "enrich: an analysis is waiting; report %s deferred %ds (%.0fs so far).",
            report_id,
            ENRICHMENT_DEFER_SECONDS,
            waited,
        )
        return {"status": "deferred", "deferred_for": waited}

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

    # The run's feed, re-opened for one line. ``job_id`` is the parent analysis
    # job; clients subscribed via /ws/{job_id} get the event automatically, and
    # the feed's table gets the row.
    #
    # It did not, and that broke the invariant both the events endpoint and the
    # console read the feed by: every event takes a sequence number from the
    # run's counter, so "how many rows are stored" has to equal "the last
    # number issued". ``run_analysis`` stops the feed when the job ends, and
    # this task runs afterwards — in another process now — so its event took a
    # number and landed nowhere. One measured run published 71 events and
    # stored 70, and the missing one vanished for good when the Redis stream
    # expired. Starting the feed here and stopping it again writes the row and
    # leaves nothing registered behind.
    #
    # Lazy import of the publisher keeps this module free of a circular
    # dependency on ``analysis_worker`` (which registers this task on its
    # WorkerSettings).
    try:
        from app.worker.analysis_worker import (
            _publish_event,
            _start_event_feed,
            _stop_event_feed,
            seed_seq_from_the_table,
        )

        # The counter this event takes its number from lives 24 hours, and the
        # rows it numbers do not: enriching an older report would start again
        # at 1, collide with that job's first event and be dropped by a feed
        # that never fails a run. Continue from the table when Redis has
        # forgotten, before the feed hands out a number.
        await seed_seq_from_the_table(redis_conn, db_session_factory, parent_job_id)
        _start_event_feed(parent_job_id, db_session_factory)
        try:
            await _publish_event(
                redis_conn,
                parent_job_id,
                "enrichment_complete",
                delta,
            )
        finally:
            await _stop_event_feed(parent_job_id)
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
    # Which queue this process reads. The task asks, because the same task runs
    # on both workers and only one of them shares its queue with the analyses.
    ctx["queue"] = ENRICHMENT_QUEUE
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
    a reputation lookup. ``ENRICHMENT_MAX_JOBS`` at a time (two by default),
    because each one is waiting on somebody else's HTTP rather than on this
    host's model or its memory, and with its own timeout: the longest measured
    enrichment took 452 s, which the analysis worker's eight-hour ceiling would
    have hidden.

    The nightly ``job_events`` purge stays on the analysis worker. One owner for
    a scheduled task is the whole point of scheduling it.
    """

    functions = [enrich_threat_intel]
    queue_name = ENRICHMENT_QUEUE
    on_startup = enrich_startup
    on_shutdown = enrich_shutdown

    redis_settings = build_redis_settings(settings.redis_url)

    # Two at a time, and tunable like the analysis worker's own sizing knobs
    # (``WORKER_RSS_RESTART_MB``, ``WORKER_TEARDOWN_TIMEOUT``). More than one
    # because each job is waiting on somebody else's HTTP; not many more
    # because they share one VirusTotal key and one AbuseIPDB key, and a
    # provider's rate limit is per key, not per job. ``enrichment_max_lookups``
    # still caps each report; what this multiplies is how many reports are in
    # flight against that shared limit.
    max_jobs = ENRICHMENT_MAX_JOBS
    job_timeout = 3600
    max_tries = 1
    health_check_interval = 30
