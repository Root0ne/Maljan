"""ARQ worker — executes MaljanApp pipeline in a background process.

This worker is started separately from the API server:

    arq app.worker.analysis_worker.WorkerSettings

It picks up jobs from Redis and runs the full multi-agent analysis
pipeline, streaming progress events via Redis PubSub.
"""

import time
import traceback
import uuid
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis
from arq import cron  # noqa: F401 — for future scheduled tasks
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import settings
from app.logging_config import get_logger, setup_logging

logger = get_logger("worker")

# ── Redis event channel helper ───────────────────────────────────


async def _publish_event(
    redis_conn: aioredis.Redis,
    job_id: str,
    event_type: str,
    data: dict[str, Any] | None = None,
) -> None:
    """Publish a pipeline progress event to Redis PubSub.

    Channel: ``analysis:{job_id}``
    Message format: JSON ``{"type": ..., "data": ..., "ts": ...}``
    """
    import json

    message = json.dumps(
        {
            "type": event_type,
            "data": data or {},
            "ts": datetime.now(UTC).isoformat(),
        }
    )
    await redis_conn.publish(f"analysis:{job_id}", message)
    logger.debug(
        f"Published event: type={event_type} job={job_id[:8]}...",
        extra={"job_id": job_id, "component": "pubsub"},
    )


# ── Main analysis task ──────────────────────────────────────────


async def run_analysis(ctx: dict, job_id: str) -> dict[str, Any]:
    """Execute the full Maljan analysis pipeline for the given job.

    This function:
    1. Loads the job from the database.
    2. Transitions status to 'running'.
    3. Instantiates MaljanApp and runs the pipeline.
    4. Saves the result as an AnalysisReport.
    5. Publishes progress events via Redis PubSub.

    Args:
        ctx: ARQ worker context (contains redis connection).
        job_id: UUID string of the AnalysisJob to process.

    Returns:
        Summary dict with verdict and timing info.
    """
    logger.info(f"Analysis task started: job={job_id}", extra={"job_id": job_id})

    redis_conn: aioredis.Redis = ctx["redis"]
    db_session: async_sessionmaker = ctx["db_session"]

    async with db_session() as db:
        try:
            # ── 1. Load job ──────────────────────────────────────
            from app.models.job import AnalysisJob
            from app.models.sample import Sample

            result = await db.execute(
                select(AnalysisJob).where(AnalysisJob.id == uuid.UUID(job_id))
            )
            job = result.scalar_one_or_none()

            if not job:
                logger.error(f"Job not found in database: {job_id}", extra={"job_id": job_id})
                await _publish_event(redis_conn, job_id, "error", {"message": "Job not found"})
                return {"status": "error", "message": "Job not found"}

            if job.status == "cancelled":
                logger.info(f"Job already cancelled: {job_id}", extra={"job_id": job_id})
                await _publish_event(redis_conn, job_id, "cancelled", {})
                return {"status": "cancelled"}

            # Load associated sample
            sample_result = await db.execute(select(Sample).where(Sample.id == job.sample_id))
            sample = sample_result.scalar_one()

            logger.info(
                "Processing sample: sha256=%s... filename=%s",
                sample.sha256[:16],
                sample.original_filename,
                extra={"job_id": job_id, "sample_id": str(sample.id)},
            )

            # ── 2. Transition to running ─────────────────────────
            job.status = "running"
            job.started_at = datetime.now(UTC)
            await db.commit()

            await _publish_event(redis_conn, job_id, "status_change", {"status": "running"})
            logger.info(f"Job status -> running: {job_id}", extra={"job_id": job_id})

            # ── 3. Run the pipeline ──────────────────────────────
            start_time = time.time()

            # Make sure core package is in sys.path
            import os
            import sys

            core_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "src")
            )
            if core_path not in sys.path:
                sys.path.insert(0, core_path)

            from maljan.app import MaljanApp
            from maljan.core.config import Settings

            logger.info(
                "Starting pipeline execution...",
                extra={"job_id": job_id, "component": "pipeline"},
            )

            # Build settings with optional overrides
            core_settings = Settings()
            if job.config:
                if "max_iterations" in job.config:
                    core_settings.negotiation.max_iterations = job.config["max_iterations"]
                if "llm_provider" in job.config:
                    core_settings.llm.provider = job.config["llm_provider"]

            app = MaljanApp(
                config=core_settings,
                # MALJAN_MOCK_MODE=true skips all LLM calls and returns fixture responses.
                # Useful when the LLM provider's daily/minute quota is exhausted.
                mock=os.environ.get("MALJAN_MOCK_MODE", "false").lower() == "true",
            )

            # Announce which agents are about to run so the frontend can show them
            registered_agents = app.container.agent_registry.list_agents()
            await _publish_event(
                redis_conn,
                job_id,
                "pipeline_started",
                {
                    "agents": registered_agents,
                    "sample_filename": sample.original_filename,
                    "sha256": sample.sha256[:16] + "...",
                },
            )
            for agent_name in registered_agents:
                await _publish_event(
                    redis_conn,
                    job_id,
                    "agent_progress",
                    {"agent": agent_name, "phase": "analyzing"},
                )

            # Execute the asynchronous pipeline natively to
            # avoid "Event loop is closed" errors caused by threading mismatches.
            pipeline_result = await app.arun(
                file_hash=sample.sha256,
                file_name=sample.original_filename,
            )

            # Announce that all analysts have finished (pipeline -> negotiation phase)
            for agent_name in registered_agents:
                await _publish_event(
                    redis_conn,
                    job_id,
                    "agent_progress",
                    {"agent": agent_name, "phase": "done"},
                )
            await _publish_event(redis_conn, job_id, "phase_change", {"phase": "negotiation"})

            elapsed = time.time() - start_time
            logger.info(
                f"Pipeline completed in {elapsed:.1f}s: job={job_id}",
                extra={"job_id": job_id, "duration_ms": round(elapsed * 1000)},
            )

            # ── 4. Save report ───────────────────────────────────
            from app.models.report import AgentFinding, AnalysisReport

            report = AnalysisReport(
                job_id=job.id,
                verdict=pipeline_result.get("final_decision", "Unknown"),
                overall_confidence=_extract_confidence(pipeline_result),
                malware_category=_extract_category(pipeline_result),
                stix_bundle=pipeline_result.get("stix_output"),
                mitre_techniques=_extract_mitre(pipeline_result),
                agent_reports=pipeline_result.get("reports"),
                negotiation_log={
                    "discussion_history": [
                        {
                            "round": i + 1,
                            "agent": (
                                arg.agent_name
                                if hasattr(arg, "agent_name")
                                else arg.get("agent_name", "")
                            ),
                            "position": "",  # derived by confidence on frontend
                            "confidence": (
                                arg.confidence_score * 100
                                if hasattr(arg, "confidence_score")
                                else arg.get("confidence_score", 0) * 100
                            ),
                            "argument": (
                                arg.finding if hasattr(arg, "finding") else arg.get("finding", "")
                            ),
                        }
                        for i, arg in enumerate(pipeline_result.get("discussion_history") or [])
                    ],
                    "confidence_history": pipeline_result.get("confidence_history", []),
                    "iteration_count": pipeline_result.get("iteration_count", 0),
                    "is_consensus": pipeline_result.get("is_consensus", False),
                },
                run_summary=pipeline_result.get("run_summary"),
            )
            db.add(report)
            await db.flush()

            logger.info(
                "Report saved: id=%s verdict=%s confidence=%s",
                report.id,
                report.verdict,
                report.overall_confidence,
                extra={"job_id": job_id, "component": "report"},
            )

            # Save per-agent findings
            isr_reports = pipeline_result.get("isr_reports", {})
            for agent_name, isr in isr_reports.items():
                if hasattr(isr, "model_dump"):
                    isr_data = isr.model_dump()
                elif isinstance(isr, dict):
                    isr_data = isr
                else:
                    continue

                finding = AgentFinding(
                    report_id=report.id,
                    agent_name=agent_name,
                    domain=isr_data.get("domain", agent_name),
                    claims=isr_data.get("claims", []),
                    dissent_items=isr_data.get("dissent_items", []),
                    revision_rounds=isr_data.get("revision_count", 0),
                    final_confidence=isr_data.get("overall_confidence", 0.0),
                )
                db.add(finding)

            logger.info(
                f"Saved {len(isr_reports)} agent findings for report={report.id}",
                extra={"job_id": job_id},
            )

            # ── 5. Mark job complete ─────────────────────────────
            job.status = "completed"
            job.completed_at = datetime.now(UTC)
            job.duration_seconds = int(elapsed)
            await db.commit()

            await _publish_event(
                redis_conn,
                job_id,
                "completed",
                {
                    "status": "completed",
                    "verdict": report.verdict,
                    "confidence": report.overall_confidence,
                    "duration_seconds": int(elapsed),
                    "report_id": str(report.id),
                },
            )

            logger.info(
                f"Job completed: job={job_id} verdict={report.verdict} duration={int(elapsed)}s",
                extra={"job_id": job_id, "component": "lifecycle"},
            )

            return {
                "status": "completed",
                "verdict": report.verdict,
                "confidence": report.overall_confidence,
                "duration_seconds": int(elapsed),
            }

        except Exception as exc:
            # ── Error handling ────────────────────────────────────
            tb = traceback.format_exc()
            error_msg = f"{type(exc).__name__}: {exc}"

            logger.error(
                f"Analysis failed: job={job_id} error={error_msg}",
                exc_info=True,
                extra={"job_id": job_id, "component": "pipeline"},
            )

            try:
                job.status = "failed"
                job.completed_at = datetime.now(UTC)
                job.error_message = error_msg[:2000]
                await db.commit()
            except Exception as db_exc:
                logger.error(
                    f"Failed to update job status: {db_exc}",
                    exc_info=True,
                    extra={"job_id": job_id},
                )
                await db.rollback()

            await _publish_event(
                redis_conn,
                job_id,
                "error",
                {"status": "failed", "error": error_msg, "traceback": tb},
            )

            return {"status": "failed", "error": error_msg}


# ── Helpers ──────────────────────────────────────────────────────


def _extract_confidence(result: dict) -> float:
    """Extract overall confidence from the pipeline result."""
    # From run_summary if available
    run_summary = result.get("run_summary")
    if run_summary and isinstance(run_summary, dict):
        conf = run_summary.get("overall_confidence")
        if conf is not None:
            return float(conf)

    # From confidence_history (last value)
    history = result.get("confidence_history", [])
    if history:
        return float(history[-1])

    return 0.0


def _extract_category(result: dict) -> str | None:
    """Extract malware category from the pipeline result."""
    run_summary = result.get("run_summary")
    if run_summary and isinstance(run_summary, dict):
        return run_summary.get("malware_category")
    return None


def _extract_mitre(result: dict) -> list | None:
    """Extract MITRE ATT&CK techniques from the STIX bundle."""
    stix = result.get("stix_output")
    if not stix or not isinstance(stix, dict):
        return None

    techniques = []
    for obj in stix.get("objects", []):
        if obj.get("type") == "attack-pattern":
            techniques.append(
                {
                    "technique_id": obj.get("external_references", [{}])[0].get("external_id", ""),
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                }
            )
    return techniques if techniques else None


# ── ARQ Worker Configuration ────────────────────────────────────


async def startup(ctx: dict) -> None:
    """Called when the ARQ worker starts up."""
    # Initialize logging for the worker process
    setup_logging()

    # Create database session factory
    engine = create_async_engine(
        settings.database_url,
        pool_size=5,
        max_overflow=10,
    )
    ctx["db_session"] = async_sessionmaker(engine, expire_on_commit=False)

    # Store a Redis connection for PubSub
    ctx["redis"] = aioredis.from_url(settings.redis_url)

    logger.info(
        "Worker started: connected to DB and Redis",
        extra={"component": "worker.lifecycle"},
    )


async def shutdown(ctx: dict) -> None:
    """Called when the ARQ worker shuts down."""
    redis_conn: aioredis.Redis = ctx.get("redis")
    if redis_conn:
        await redis_conn.aclose()

    db_session = ctx.get("db_session")
    if db_session:
        # Dispose the engine
        engine = db_session.kw.get("bind")
        if engine:
            await engine.dispose()

    logger.info(
        "Worker shutdown complete",
        extra={"component": "worker.lifecycle"},
    )


class WorkerSettings:
    """ARQ worker settings — configure connection and task functions."""

    functions = [run_analysis]
    on_startup = startup
    on_shutdown = shutdown

    # Redis connection settings
    redis_settings = None  # Will use ARQ defaults (localhost:6379)

    # Worker tuning
    max_jobs = 2  # Max concurrent analysis jobs
    job_timeout = 1800  # 30 minutes max per analysis
    max_tries = 1  # Don't retry failed analyses automatically
    health_check_interval = 30
