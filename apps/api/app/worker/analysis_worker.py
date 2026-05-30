"""ARQ worker — executes MaljanApp pipeline in a background process.

This worker is started separately from the API server:

    arq app.worker.analysis_worker.WorkerSettings

It picks up jobs from Redis and runs the full multi-agent analysis
pipeline, streaming progress events via Redis PubSub.
"""

import asyncio
import time
import traceback
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import redis.asyncio as aioredis
from arq import cron  # noqa: F401 — for future scheduled tasks
from arq.connections import RedisSettings
from sqlalchemy import func, select, update
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
    """Publish a pipeline progress event to Redis PubSub + Stream.

    PubSub channel ``analysis:{job_id}`` is used by the live WebSocket
    fan-out. A parallel Redis Stream ``analysis:{job_id}:events`` keeps
    the last 1000 events so a client opening the Live tab mid-run can
    back-fill its event log via ``GET /api/v1/jobs/{job_id}/events``
    (audit 2026-05-17, LIVE-01).

    Message format on both channels:
    ``{"type": ..., "data": ..., "ts": ...}``.
    """
    import json

    payload = {
        "type": event_type,
        "data": data or {},
        "ts": datetime.now(UTC).isoformat(),
    }
    message = json.dumps(payload)
    await redis_conn.publish(f"analysis:{job_id}", message)
    # Persist into the bounded Stream so the live page can replay missed
    # events when it mounts after the worker already started publishing.
    try:
        await redis_conn.xadd(
            f"analysis:{job_id}:events",
            {"payload": message},
            maxlen=1000,
            approximate=True,
        )
        # 24h TTL — every read keeps the key fresh; idle keys vanish.
        await redis_conn.expire(f"analysis:{job_id}:events", 86_400)
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "Event stream xadd failed (%s); pubsub-only.",
            exc,
            extra={"job_id": job_id, "component": "pubsub"},
        )
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
        job = None  # Ensure job is defined for the except block
        try:
            # ── 1. Load job ──────────────────────────────────────
            from app.models.job import AnalysisJob
            from app.models.sample import Sample

            try:
                job_uuid = uuid.UUID(job_id)
            except ValueError as exc:
                logger.error(f"Invalid job_id UUID: {job_id}", extra={"job_id": job_id})
                await _publish_event(redis_conn, job_id, "error", {"message": "Invalid job ID"})
                return {"status": "error", "message": f"Invalid job ID: {exc}"}

            result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_uuid))
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
            # Use Postgres ``NOW()`` for the persisted ``started_at`` so
            # it shares a clock source with ``TimestampMixin.created_at``
            # (which is also ``server_default=func.now()``). Mixing host
            # time ``datetime.now(UTC)`` here produced ``started_at <
            # created_at`` on Windows hosts where Docker Desktop's VM
            # clock drifts after sleep/hibernate. We still touch the
            # Python attribute so synchronous callers/tests with mocked
            # sessions can read the value before ``refresh`` lands.
            job.status = "running"
            job.started_at = datetime.now(UTC)
            await db.execute(
                update(AnalysisJob).where(AnalysisJob.id == job.id).values(started_at=func.now())
            )
            await db.commit()
            await db.refresh(job)

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

            # Mock-mode resolution (audit 2026-05-17: W-01 permanent fix).
            # Two independent toggles must agree before the pipeline runs
            # in mock mode:
            #   1. ``settings.mock_mode_allowed`` — operator-level gate
            #      (defaults False; must be flipped via API config).
            #   2. Either the per-job ``config.mock_mode`` flag OR the
            #      ``MALJAN_MOCK_MODE`` env var.
            # A leaked env var alone is no longer sufficient — production
            # workers stay on the real LLM/sandbox path even if a stale
            # shell exports ``MALJAN_MOCK_MODE=true``.
            _env_mock = os.environ.get("MALJAN_MOCK_MODE", "false").lower() == "true"
            _job_mock = bool(job.config and job.config.get("mock_mode"))
            _mock_requested = _env_mock or _job_mock
            _mock_active = bool(settings.mock_mode_allowed and _mock_requested)
            if _mock_requested and not _mock_active:
                logger.warning(
                    "Pipeline mock requested (env=%s, job=%s) but blocked: "
                    "settings.mock_mode_allowed=False. Running real pipeline.",
                    _env_mock,
                    _job_mock,
                )
            logger.info(
                "Pipeline mode: %s (env=%s job=%s allowed=%s).",
                "MOCK" if _mock_active else "REAL",
                _env_mock,
                _job_mock,
                settings.mock_mode_allowed,
            )
            app = MaljanApp(config=core_settings, mock=_mock_active)

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

            # Download sample from MinIO for sandbox submission
            temp_path: str | None = None
            static_sample_path: str | None = None
            try:
                from minio import Minio
                from pydantic import SecretStr as _SecretStr

                secret = settings.minio_secret_key
                secret_value = (
                    secret.get_secret_value() if isinstance(secret, _SecretStr) else str(secret)
                )
                minio_client = Minio(
                    settings.minio_endpoint,
                    access_key=settings.minio_access_key,
                    secret_key=secret_value,
                    secure=settings.minio_secure,
                )
                # Re-derive the storage path from the sha256 instead of trusting
                # the value in the DB row (defence in depth against tampering).
                derived_path = f"samples/{sample.sha256[:2]}/{sample.sha256}"
                if sample.storage_path != derived_path:
                    logger.warning(
                        "Sample storage_path drift detected: db=%s expected=%s",
                        sample.storage_path,
                        derived_path,
                    )
                # Preserve the original filename extension so the sandbox
                # backend can pick the right VM profile from the suffix
                # (``.elf`` → Linux, ``.exe`` → Windows, etc.). Otherwise
                # the bare sha256 would be treated as an unknown blob.
                _orig_ext = Path(sample.original_filename or "").suffix
                # Wave 9 (2026-05-29): use the Defender-excluded upload
                # tmp dir instead of the system temp dir. See
                # ``APISettings.upload_temp_dir``.
                # Wave 9 HOTFIX-08 (2026-05-29): ``.resolve()`` is critical
                # here — the 2026-05-29 ELF smoke test (job f4a1fee9)
                # produced a relative ``data\uploads\.tmp\<sha>.elf`` path
                # which then broke TriageClient.submit_and_wait with
                # ``[Errno 22] Invalid argument`` when its httpx coroutine
                # opened the path from a different CWD. The fix is to
                # resolve once at use-site so every downstream consumer
                # (Triage submit, Ghidra container path map, sandbox
                # uploader) receives an absolute path.
                _worker_tmp = Path(settings.upload_temp_dir).resolve()
                _worker_tmp.mkdir(parents=True, exist_ok=True)
                temp_path = str(_worker_tmp / f"{sample.sha256}{_orig_ext}")
                minio_client.fget_object(
                    settings.minio_bucket,
                    derived_path,
                    temp_path,
                )
                logger.info(
                    "Downloaded sample from MinIO: %s -> %s",
                    sample.storage_path,
                    temp_path,
                    extra={"job_id": job_id, "component": "minio"},
                )

                # Wave 6 (2026-05-28, GHIDRA-DELIVERY-01): mirror the binary
                # into ``data/samples/<sha256><ext>`` (relative to the project
                # root). That directory is bind-mounted into the Ghidra MCP
                # container at ``/data/samples/``, so the static analyst can
                # call ``load_program(file=/data/samples/<sha256><ext>)`` and
                # actually get a hit. Previously the file only lived in the
                # host's tempdir, invisible to the container, so every static
                # analysis ran without ever loading the sample.
                try:
                    import shutil

                    host_samples_dir = Path("data/samples")
                    host_samples_dir.mkdir(parents=True, exist_ok=True)
                    host_mirror = host_samples_dir / f"{sample.sha256}{_orig_ext}"
                    shutil.copyfile(temp_path, host_mirror)
                    # Container path mirrors the bind mount in
                    # docker/docker-compose.yml (``../data/samples:/data/samples``).
                    static_sample_path = (
                        f"{settings.ghidra_container_samples_path.rstrip('/')}/"
                        f"{sample.sha256}{_orig_ext}"
                    )
                    logger.info(
                        "Mirrored sample to %s for Ghidra container (%s).",
                        host_mirror,
                        static_sample_path,
                        extra={"job_id": job_id, "component": "ghidra-mirror"},
                    )
                except Exception as mirror_exc:
                    logger.warning(
                        "Failed to mirror sample to data/samples for Ghidra: %s. "
                        "Static analyst will fall back to metadata-only prompt.",
                        mirror_exc,
                        extra={"job_id": job_id, "component": "ghidra-mirror"},
                    )
            except Exception as exc:
                logger.warning(
                    "Failed to download sample from MinIO: %s. Sandbox submission skipped.",
                    exc,
                    extra={"job_id": job_id, "component": "minio"},
                )
                temp_path = None

            # Execute the asynchronous pipeline natively to
            # avoid "Event loop is closed" errors caused by threading mismatches.
            # Heartbeat task keeps the job alive in the DB and logs progress.
            heartbeat_stop_event = asyncio.Event()

            async def _heartbeat() -> None:
                while not heartbeat_stop_event.is_set():
                    try:
                        await asyncio.wait_for(heartbeat_stop_event.wait(), timeout=60.0)
                    except TimeoutError:
                        logger.info(
                            "Pipeline heartbeat: job=%s still running...",
                            job_id,
                            extra={"job_id": job_id, "component": "heartbeat"},
                        )

            heartbeat_task = asyncio.create_task(_heartbeat())

            # The pipeline (analysts -> mediator -> judge -> report nodes)
            # runs inside ``app.arun()`` as a single LangGraph step, so the
            # worker only sees phase boundaries at the start and end. We
            # emit a phase marker here so live consumers can distinguish
            # "running but no agent events yet" from "agents actively
            # working". Mid-pipeline phases would require LangGraph
            # callback wiring.
            await _publish_event(redis_conn, job_id, "phase_change", {"phase": "analyzing"})
            try:
                pipeline_result = await app.arun(
                    file_hash=sample.sha256,
                    file_name=sample.original_filename,
                    sample_path=temp_path,
                    static_sample_path=static_sample_path,
                )
            finally:
                heartbeat_stop_event.set()
                try:
                    heartbeat_task.cancel()
                    await heartbeat_task
                except asyncio.CancelledError:
                    pass

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

            # Persistence phase begins — the worker is about to insert
            # the report and findings into Postgres. Live consumers use
            # this to switch the UI into a "saving results" state.
            await _publish_event(redis_conn, job_id, "phase_change", {"phase": "reporting"})

            # ── 4. Save report ───────────────────────────────────
            from app.models.report import AgentFinding, AnalysisReport

            # Prefer the rich extended bundle produced by ``report_node``
            # (54+ objects with Identity/Indicator/ObservedData/Note/Report
            # SDOs) over the minimal judge bundle. The legacy field is the
            # fallback for callers that pre-date the MalwareReport refactor.
            stix_bundle_for_persist = pipeline_result.get(
                "stix_bundle_extended"
            ) or pipeline_result.get("stix_output")
            # Ensure STIX 2.1 ``spec_version`` is present on every bundle —
            # the OASIS spec requires it on top-level bundle objects, and
            # downstream tooling (OpenCTI / MISP / TAXII clients) silently
            # rejects bundles that omit the field. Defensive: covers the
            # case where the producer dropped it during serialization.
            if isinstance(stix_bundle_for_persist, dict):
                stix_bundle_for_persist.setdefault("spec_version", "2.1")

            report = AnalysisReport(
                job_id=job.id,
                verdict=pipeline_result.get("final_decision", "Unknown"),
                overall_confidence=_extract_confidence(pipeline_result),
                malware_category=_extract_category(pipeline_result),
                stix_bundle=stix_bundle_for_persist,
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
                malware_report=pipeline_result.get("malware_report"),
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
            pipeline_reports = pipeline_result.get("reports") or {}
            for agent_name, isr in isr_reports.items():
                if hasattr(isr, "model_dump"):
                    isr_data = isr.model_dump()
                elif isinstance(isr, dict):
                    isr_data = isr
                else:
                    continue

                # Derive agent confidence from claims (ISR has no overall_confidence field)
                claims = isr_data.get("claims", [])
                agent_confidence = 0.0
                if claims:
                    agent_confidence = sum(c.get("confidence", 0) for c in claims) / len(claims)

                # D15+D16: derive lifecycle status from the analyst's text
                # report + claim shape so the UI can render "FAILED" /
                # "NO DATA" badges instead of synthesising a misleading
                # verdict from an empty payload.
                _text_report = pipeline_reports.get(agent_name, "")
                _stripped = _text_report.strip() if isinstance(_text_report, str) else ""
                status: str
                status_reason: str | None
                if _stripped.startswith("[ERROR]"):
                    _reason = _stripped[len("[ERROR]") :].strip()[:500] or None
                    _low = (_reason or "").lower()
                    if "timeout" in _low or "timed out" in _low:
                        status = "timeout"
                    else:
                        status = "failed"
                    status_reason = _reason
                elif not claims:
                    status = "no_data"
                    status_reason = "Agent produced no claims"
                else:
                    status = "complete"
                    status_reason = None

                finding = AgentFinding(
                    report_id=report.id,
                    agent_name=agent_name,
                    domain=isr_data.get("domain", agent_name),
                    claims=claims,
                    dissent_items=isr_data.get("dissent_items", []),
                    revision_rounds=isr_data.get("revision_round", 0),
                    final_confidence=agent_confidence,
                    status=status,
                    status_reason=status_reason,
                )
                db.add(finding)

            logger.info(
                f"Saved {len(isr_reports)} agent findings for report={report.id}",
                extra={"job_id": job_id},
            )

            # ── 5. Mark job complete ─────────────────────────────
            # Use Python ``datetime.now(UTC)`` instead of Postgres ``NOW()``.
            # ``func.now()`` resolves to ``transaction_timestamp()`` which is
            # the START of the current transaction — that equals
            # ``started_at`` and produces a 0-second ``completed_at`` even
            # for a 20-minute pipeline. ``duration_seconds`` is computed in
            # Python anyway so a single clock source is correct.
            now = datetime.now(UTC)
            job.status = "completed"
            job.completed_at = now
            job.duration_seconds = round(float(elapsed), 1)
            await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == job.id)
                .values(
                    completed_at=now,
                    # Round to one decimal so sub-second jobs (~0.7s) don't
                    # collapse to zero; the column is ``Numeric(10,2)`` so
                    # fractional values survive the round-trip.
                    duration_seconds=round(float(elapsed), 1),
                )
            )
            await db.commit()
            await db.refresh(job)

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

            # ── 6. Auto-enqueue threat-intel enrichment (Faz 6) ────────
            # The enrichment job is post-hoc; pipeline latency is unaffected.
            # ARQ enforces the unique ``_job_id`` so duplicate triggers
            # (e.g. operator also calling /enrich manually) are coalesced.
            if settings.enrichment_enabled and report.malware_report:
                try:
                    arq_pool = ctx.get("arq_pool")
                    if arq_pool is None:
                        from arq.connections import ArqRedis

                        arq_pool = ArqRedis(connection_pool=redis_conn.connection_pool)
                    await arq_pool.enqueue_job(
                        "enrich_threat_intel",
                        str(report.id),
                        _job_id=f"enrich:{report.id}",
                    )
                    logger.info(
                        "enrich: queued report=%s",
                        report.id,
                        extra={"job_id": job_id, "component": "enrich"},
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("enrich: enqueue failed (%s).", exc)

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
                if job is not None:
                    job.status = "failed"
                    job.error_message = error_msg[:2000]
                    job.completed_at = datetime.now(UTC)
                    await db.execute(
                        update(AnalysisJob)
                        .where(AnalysisJob.id == job.id)
                        .values(completed_at=job.completed_at)
                    )
                    await db.commit()
                else:
                    logger.warning(
                        "Cannot update job status: job was never loaded (job_id=%s).",
                        job_id,
                        extra={"job_id": job_id},
                    )
            except Exception as db_exc:
                logger.error(
                    f"Failed to update job status: {db_exc}",
                    exc_info=True,
                    extra={"job_id": job_id},
                )
                await db.rollback()

            # Do not leak tracebacks to clients — only emit an opaque error id
            # that maps back to the structured log entry above.
            import uuid as _uuid

            error_id = _uuid.uuid4().hex
            logger.error(
                "Pipeline failure error_id=%s job=%s traceback=%s",
                error_id,
                job_id,
                tb,
                extra={"job_id": job_id, "error_id": error_id},
            )
            await _publish_event(
                redis_conn,
                job_id,
                "error",
                {
                    "status": "failed",
                    "error_id": error_id,
                    "message": "Analysis failed. See server logs for details.",
                },
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
        category = run_summary.get("malware_category")
        return str(category) if category is not None else None
    return None


def _extract_mitre(result: dict) -> list | None:
    """Extract MITRE ATT&CK techniques for the legacy ``mitre_techniques`` column.

    Preference order:
      1. ``malware_report.ttp_mappings`` — the deterministic mapper output
         (technique_id + name + evidence quotes + confidence).
      2. ``stix_bundle_extended`` / ``stix_output`` — fall back to walking the
         STIX bundle for ``attack-pattern`` SDOs when the report builder did
         not run (mock mode without a configured pipeline, legacy rows).
    """
    mr = result.get("malware_report") or {}
    mappings = mr.get("ttp_mappings") or []
    if mappings:
        return [
            {
                "technique_id": m.get("technique_id", ""),
                "name": m.get("technique_name") or m.get("name", ""),
                "description": " | ".join(m.get("evidence_quotes") or [])[:512],
            }
            for m in mappings
            if m.get("technique_id")
        ] or None

    stix = result.get("stix_bundle_extended") or result.get("stix_output")
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


async def _sweep_orphan_jobs(db_session: async_sessionmaker) -> None:
    """Mark abandoned ``running`` rows as ``failed`` at worker startup.

    Wave 8 ORPHAN-JOBS-01 (2026-05-28). When the worker process is killed
    mid-flight (e.g. operator ``Stop-Process`` during development, OOM
    kill, deploy rollover) the ``run_analysis`` task has no chance to
    flip the row from ``running`` → ``failed`` in its ``except`` block.
    The DB then carries phantom ``running`` rows forever — the
    dashboard reports them as in-flight even though no worker holds
    them. Auditors looking at the legacy data assume the pipeline is
    still busy.

    Cleanup rule: any ``running`` row whose ``started_at`` is older
    than ``WorkerSettings.job_timeout`` cannot possibly still be
    processed by a live worker — arq would have killed it at that
    boundary. Flip it to ``failed`` with a clear ``error_message`` so
    the UI shows the right state and the FP rate stats become real.

    This runs once per worker boot. It does not race with active jobs
    because we only touch rows older than the hard timeout.
    """
    from datetime import UTC as _UTC
    from datetime import datetime as _datetime
    from datetime import timedelta as _timedelta

    cutoff_seconds = WorkerSettings.job_timeout
    cutoff_ts = _datetime.now(_UTC) - _timedelta(seconds=cutoff_seconds)

    async with db_session() as db:
        from app.models.job import AnalysisJob

        stmt = (
            update(AnalysisJob)
            .where(
                AnalysisJob.status == "running",
                AnalysisJob.started_at < cutoff_ts,
            )
            .values(
                status="failed",
                completed_at=func.now(),
                error_message=(
                    "Worker process was killed mid-flight (no shutdown hook ran). "
                    "Marked failed by startup sweep — re-submit the sample if needed."
                ),
            )
            .returning(AnalysisJob.id)
        )
        result = await db.execute(stmt)
        affected = [str(row[0]) for row in result.all()]
        await db.commit()
        if affected:
            logger.warning(
                "Startup orphan sweep: marked %d phantom 'running' job(s) as 'failed': %s",
                len(affected),
                ", ".join(affected[:8]) + (" ..." if len(affected) > 8 else ""),
                extra={"component": "worker.lifecycle", "job_count": len(affected)},
            )
        else:
            logger.info(
                "Startup orphan sweep: no phantom 'running' jobs found.",
                extra={"component": "worker.lifecycle"},
            )


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

    # Wave 8 ORPHAN-JOBS-01: clean up phantom 'running' rows left behind
    # when the previous worker was killed mid-flight (no shutdown hook
    # fired). Without this, the dashboard accumulates fake in-flight
    # jobs every time the operator restarts the worker.
    try:
        await _sweep_orphan_jobs(ctx["db_session"])
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Startup orphan sweep failed (non-fatal): %s",
            exc,
            extra={"component": "worker.lifecycle"},
        )

    logger.info(
        "Worker started: connected to DB and Redis",
        extra={"component": "worker.lifecycle"},
    )


async def shutdown(ctx: dict) -> None:
    """Called when the ARQ worker shuts down."""
    redis_conn: aioredis.Redis | None = ctx.get("redis")
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


# The enrichment task lives in a sibling module. Importing it at module
# scope is fine — ``enrich_worker`` only re-enters this module lazily from
# inside its function, so there is no real circular dependency.
from app.worker.enrich_worker import enrich_threat_intel  # noqa: E402


class WorkerSettings:
    """ARQ worker settings — configure connection and task functions."""

    functions = [run_analysis, enrich_threat_intel]
    on_startup = startup
    on_shutdown = shutdown

    # Parse Redis URL from app config so Docker networking works
    _redis_parsed = urlparse(settings.redis_url)
    redis_settings = RedisSettings(
        host=_redis_parsed.hostname or "localhost",
        port=_redis_parsed.port or 6379,
        database=int((_redis_parsed.path or "/0").strip("/") or 0),
    )

    # Worker tuning
    # Phase A fix: max_jobs=1 prevents zombie threads from starving other jobs.
    # job_timeout=3600 (60 min) covers the Wave 4 pipeline (platform-aware
    # cascade + per-platform Sigma scan + FP linter) which can run longer
    # than 30 min on the 35B local LLM, especially on a cold-cache start.
    # Wave 3 baseline was ~21 min; Wave 4 adds ~4-5 min of cascade work +
    # variance from LLM throughput. 60 min gives ~2x headroom before
    # we'd consider the run truly hung.
    max_jobs = 1
    job_timeout = 3600
    max_tries = 1  # Don't retry failed analyses automatically
    health_check_interval = 30
