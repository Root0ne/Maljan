"""ARQ task: post-hoc threat-intel enrichment for an ``AnalysisReport``.

Picked up by the same worker process as :mod:`analysis_worker` — added to
``WorkerSettings.functions`` so the existing startup / shutdown / Redis /
DB session factory is reused.

Trigger paths:
  - automatic: ``analysis_worker.run_analysis`` enqueues this task right
    after the report row is committed.
  - manual: ``POST /api/v1/reports/{id}/enrich`` enqueues it explicitly.

Both paths share the unique ``_job_id="enrich:{report_id}"`` so a second
attempt simply replaces the queued one — duplicate work is impossible.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

import redis.asyncio as aioredis
from maljan.core.settings_overrides import redact_url

from app.logging_config import get_logger
from app.models.report import AnalysisReport
from app.runtime_config import runtime_config

if TYPE_CHECKING:
    from maljan.memory.long_term_memory import MemoryStore

logger = get_logger("worker.enrich")

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

    async with db_session_factory() as db:
        report = await db.get(AnalysisReport, report_uuid)
        if report is None:
            logger.warning("enrich: report %s not found", report_id)
            return {"status": "not_found"}
        if not report.malware_report:
            logger.info("enrich: report %s has no malware_report payload", report_id)
            return {"status": "skipped"}

        # Lazy import keeps the API/worker startup graph free of optional
        # maljan-core dependencies.
        from maljan.enrichment import enrich_malware_report

        vt_key = await runtime_config.get_secret("virustotal_api_key") or None
        abuse_key = await runtime_config.get_secret("abuseipdb_api_key") or None

        before_domain_reps = _count_reputations(report.malware_report, "domains")
        before_ip_reps = _count_reputations(report.malware_report, "ips")

        memory_store = await _get_memory_store()

        try:
            updated = await enrich_malware_report(
                dict(report.malware_report),
                vt_api_key=vt_key,
                abuseipdb_api_key=abuse_key,
                max_lookups_per_kind=await runtime_config.get("enrichment_max_lookups"),
                memory_store=memory_store,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("enrich: orchestrator failed (%s)", exc, exc_info=True)
            return {"status": "error", "error": str(exc)[:200]}

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
            str(report.job_id),
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
                    or_(JobEvent.ts < cutoff, JobEvent.ts.is_(None) & (JobEvent.created_at < cutoff))
                )
            )
            await db.commit()
        removed = int(result.rowcount or 0)
    except Exception as exc:  # noqa: BLE001 — a sweep never takes the worker down
        logger.warning("events sweep failed (%s).", exc)
        return {"status": "failed"}

    logger.info("events sweep: removed %d row(s) older than %d day(s).", removed, days)
    return {"status": "ok", "removed": removed, "retention_days": days}
