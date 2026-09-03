"""ARQ worker — executes MaljanApp pipeline in a background process.

This worker is started separately from the API server:

    arq app.worker.analysis_worker.WorkerSettings

It picks up jobs from Redis and runs the full multi-agent analysis
pipeline, streaming progress events via Redis PubSub.
"""

import asyncio
import gc
import os
import signal
import time
import traceback
import uuid
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import redis.asyncio as aioredis
from arq import cron  # noqa: F401 — for future scheduled tasks
from arq.connections import RedisSettings
from maljan.core.config import Settings as _CoreSettings
from maljan.core.settings_catalog import core_catalog
from maljan.core.settings_overrides import build_settings, public_snapshot
from pydantic import ValidationError
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import settings
from app.logging_config import get_logger, setup_logging
from app.runtime_config import runtime_config

logger = get_logger("worker")

_SECRET_PATHS = [e.path for e in core_catalog() if e.secret]


def build_job_settings(
    overrides: dict[str, Any], job_config: dict[str, Any] | None
) -> _CoreSettings:
    """UI overrides layered over the environment, then the job's own config on top.

    The job's values are folded into the override dict rather than assigned
    afterwards, so the model's Literal choices and bounds apply to them too
    (``Settings`` does not validate on assignment).
    """
    merged = dict(overrides)
    if job_config:
        if job_config.get("max_iterations") is not None:
            merged["negotiation.max_iterations"] = job_config["max_iterations"]
        if job_config.get("llm_provider") is not None:
            merged["llm.provider"] = job_config["llm_provider"]
    return build_settings(merged)


def settings_snapshot(
    core_settings: _CoreSettings, overridden_keys: Iterable[str] | None = None
) -> dict[str, Any]:
    """Non-secret view of the effective per-job Settings for ``run_summary``.

    ``overridden_keys`` names the dotted core paths (without the ``core.``
    namespace prefix) that came from a stored UI override rather than the
    environment/default, so a report reader can tell what was in effect
    without re-deriving it from the (masked) values alone.
    """
    snap: dict[str, Any] = public_snapshot(core_settings, _SECRET_PATHS)
    snap["overridden_keys"] = sorted(overridden_keys or [])
    return snap


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


def _parse_event_ts(value: Any) -> datetime | None:
    """Best-effort ISO-8601 → ``datetime`` for a recorded event timestamp.

    The recorder stamps ``datetime.now(UTC).isoformat()``, so this normally
    round-trips exactly. It returns ``None`` rather than raising on anything
    unexpected: the transcript's ordering comes from ``seq``, and a message with
    no readable clock is still worth keeping.
    """
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _make_event_sink(
    redis_conn: aioredis.Redis,
    job_id: str,
    loop: asyncio.AbstractEventLoop,
    recorder: list[dict[str, Any]] | None = None,
) -> Callable[[str, dict[str, Any]], None]:
    """Bridge the pipeline's synchronous event sink onto this event loop.

    ``maljan.pipeline.events.EventSink`` is a plain sync callable because the
    analyst node is synchronous and LangGraph runs it in a worker thread, while
    the negotiation / revision / judge nodes are coroutines on the loop. One
    signature has to serve both, so the bridge is here rather than in the core.

    ``call_soon_threadsafe`` is correct from either side — it is the documented
    way in from another thread, and a no-op-ish fast path when already on the
    loop. Scheduling rather than awaiting also means a slow Redis never adds
    latency to the analysis itself: the pipeline hands the event off and moves
    on. Publishing is best-effort by design (see ``_publish_event``), so a
    dropped progress line never costs a run.

    When ``recorder`` is supplied, every ``agent_message`` is also appended to it
    **synchronously**, before the publish is scheduled. That list becomes the
    persisted transcript (``agent_messages``), and doing it here rather than
    reconstructing the conversation from pipeline state afterwards is what makes
    the replayed transcript the same recording the live viewer saw rather than a
    second, subtly different account of it. Appending on the calling thread also
    means a Redis outage cannot cost us the record: publishing is best-effort,
    persistence is not.
    """

    # Deferred like every other ``maljan`` import in this module — the core
    # package is heavy and the API process must not pay for it at import time.
    from maljan.pipeline.events import AGENT_MESSAGE

    def sink(event_type: str, data: dict[str, Any]) -> None:
        if recorder is not None and event_type == AGENT_MESSAGE:
            try:
                recorder.append({**data, "ts": datetime.now(UTC).isoformat()})
            except Exception as exc:  # noqa: BLE001 — recording must not fail a run
                logger.debug("transcript recorder rejected an event (%s); continuing.", exc)
        try:
            loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(  # noqa: RUF006 — fire-and-forget by design
                    _publish_event(redis_conn, job_id, event_type, data)
                )
            )
        except RuntimeError:
            # Loop already closed (job cancelled / shutting down). Nothing to
            # report to, and the pipeline must not care.
            pass

    return sink


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
        app: Any = None  # released in the finally below, whichever way we leave
        # Declared here (rather than at the download site further down) so the
        # outer ``finally`` can always remove them, including on every early
        # return above the download (invalid job id, job not found, already
        # cancelled) — those paths never reach the download but still run
        # this function's one ``finally``, which references both names.
        temp_path: str | None = None
        host_mirror: Path | None = None
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

            logger.info(
                "Starting pipeline execution...",
                extra={"job_id": job_id, "component": "pipeline"},
            )

            # Build this job's Settings from env + any stored UI overrides
            # (UI > env > default; see settings_overrides.build_settings),
            # then the job's own config on top. A DB error loading overrides
            # must not fail the job -- fall back to env-only settings and
            # say so, without ever logging a secret value.
            from maljan.core.config import install_settings

            from app.services.settings_service import load_core_overrides

            try:
                overrides = await load_core_overrides(db)
            except Exception as exc:  # noqa: BLE001 — overrides are best-effort
                logger.warning(
                    "Failed to load runtime setting overrides (%s); "
                    "running job %s on environment settings only.",
                    type(exc).__name__,
                    job_id,
                    extra={"job_id": job_id},
                )
                overrides = {}
            try:
                core_settings = build_job_settings(overrides, job.config)
            except (ValidationError, ValueError) as exc:
                # Stored overrides that validated when saved can stop validating
                # after a deploy narrows a field, and two orphan rows can nest
                # into a conflict. One job must not take the queue down: run on
                # environment settings, name the fields.
                bad = (
                    sorted({".".join(str(x) for x in e["loc"]) for e in exc.errors()})
                    if isinstance(exc, ValidationError)
                    else [type(exc).__name__]
                )
                logger.warning(
                    "Runtime settings rejected by the model (%s); "
                    "retrying job %s without the stored overrides.",
                    ", ".join(bad),
                    job_id,
                    extra={"job_id": job_id},
                )
                overrides = {}
                try:
                    core_settings = build_job_settings({}, job.config)
                except (ValidationError, ValueError):
                    # The rejected value was the job's own config, not a
                    # stored override (the API validates it at submit time,
                    # but a row written another way still reaches here).
                    logger.warning(
                        "Job %s config rejected by the model; "
                        "running on environment settings only.",
                        job_id,
                        extra={"job_id": job_id},
                    )
                    core_settings = build_job_settings({}, None)
            # Agents, pipeline nodes and extractors read the process singleton
            # (``get_settings()``), not the config handed to MaljanApp. With
            # ``max_jobs = 1`` installing this job's Settings there is what
            # makes a UI override reach every consumer, not only the container.
            # The object stays installed after the job: ``enrich_threat_intel``
            # runs in this process too but reads only API settings and
            # ``runtime_config`` today; if it ever needs core config it must
            # install its own.
            install_settings(core_settings)
            if overrides:
                logger.info(
                    "Applying %d runtime setting override(s) from the UI.",
                    len(overrides),
                    extra={"job_id": job_id},
                )

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
            _mock_mode_allowed = await runtime_config.get("mock_mode_allowed")
            _mock_active = bool(_mock_mode_allowed and _mock_requested)
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
                _mock_mode_allowed,
            )
            # The sink is what turns a 30-minute silent run into a readable
            # transcript: each node reports its own findings as it produces
            # them, straight onto the same PubSub channel the Live tab is
            # already attached to. ``transcript`` collects those same messages
            # so they can be written to ``agent_messages`` when the run
            # finishes — the live feed and the permanent record are one list,
            # not two derivations that can drift.
            transcript: list[dict[str, Any]] = []
            from maljan.core import memprobe

            memprobe.reset()
            memprobe.probe("job:start", job_id=job_id)
            app = MaljanApp(
                config=core_settings,
                mock=_mock_active,
                event_sink=_make_event_sink(
                    redis_conn,
                    job_id,
                    asyncio.get_running_loop(),
                    recorder=transcript,
                ),
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
            # Roster only — "waiting", not "analyzing". Analysts are serialised
            # on the single-slot local model, so marking them all busy up front
            # was simply false; each analyst node now announces its own start
            # (see maljan.pipeline.nodes), which is the real signal.
            for agent_name in registered_agents:
                await _publish_event(
                    redis_conn,
                    job_id,
                    "agent_progress",
                    {"agent": agent_name, "phase": "waiting"},
                )

            # Download sample from MinIO for sandbox submission
            # (temp_path / host_mirror are declared above, before the early
            # returns, so the outer finally can always find them)
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
                # which then broke the sandbox client's submit path with
                # ``[Errno 22] Invalid argument`` when its httpx coroutine
                # opened the path from a different CWD. The fix is to
                # resolve once at use-site so every downstream consumer
                # (sandbox submit, Ghidra container path map, sandbox
                # uploader) receives an absolute path.
                from app.worker import sample_files

                _worker_tmp = sample_files.temp_dir()
                temp_path = str(_worker_tmp / f"{sample.sha256}{_orig_ext}")
                minio_client.fget_object(
                    settings.minio_bucket,
                    derived_path,
                    temp_path,
                )
                os.chmod(temp_path, 0o600)
                logger.info(
                    "Downloaded sample from MinIO: %s -> %s",
                    sample.storage_path,
                    temp_path,
                    extra={"job_id": job_id, "component": "minio"},
                )

                # Wave 6 (2026-05-28, GHIDRA-DELIVERY-01): mirror the binary
                # into ``<samples_dir>/.work/<sha256><ext>`` (relative to the
                # project root by default). That directory is bind-mounted
                # into the Ghidra MCP container at
                # ``ghidra_container_samples_path``, so the static analyst can
                # call ``load_program(file=<container_path>/.work/<sha256><ext>)``
                # and actually get a hit. Previously the file only lived in the
                # host's tempdir, invisible to the container, so every static
                # analysis ran without ever loading the sample.
                #
                # Wave 10 (security hardening, H3): the mirror is now a
                # private 0o600 copy under a 0o700 ``.work`` subdirectory of
                # ``samples_dir`` — never the operator's own corpus directory
                # itself — and is removed by the ``finally`` below when the
                # job ends, whichever way it ends.
                try:
                    host_mirror = sample_files.work_dir() / f"{sample.sha256}{_orig_ext}"
                    sample_files.private_copy(Path(temp_path), host_mirror)
                    # Container path mirrors the bind mount in
                    # docker/docker-compose.yml (``../data/samples:/data/samples``).
                    static_sample_path = (
                        f"{settings.ghidra_container_samples_path.rstrip('/')}/"
                        f"{sample_files.WORK_SUBDIR}/{sample.sha256}{_orig_ext}"
                    )
                    logger.info(
                        "Mirrored sample to %s for Ghidra container (%s).",
                        host_mirror,
                        static_sample_path,
                        extra={"job_id": job_id, "component": "ghidra-mirror"},
                    )
                except Exception as mirror_exc:
                    logger.warning(
                        "Failed to mirror sample to %s for Ghidra: %s. "
                        "Static analyst will fall back to metadata-only prompt.",
                        settings.samples_dir,
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
            pipeline_task: asyncio.Task | None = None
            cancelled_by_user = False

            async def _heartbeat() -> None:
                # Audit 2026-07-26 (Ö5): the heartbeat is also the cancellation
                # poller. `cancel_job` sets `analysis:{job_id}:cancel`; the
                # pipeline is a single long `await`, so cancelling that task is
                # the only way to stop the run. Previously the worker checked the
                # job status exactly once (before starting), so a cancel issued
                # mid-run was ignored and the finished pipeline overwrote the
                # `cancelled` row with `completed`/`failed`.
                nonlocal cancelled_by_user
                while not heartbeat_stop_event.is_set():
                    try:
                        await asyncio.wait_for(heartbeat_stop_event.wait(), timeout=15.0)
                    except TimeoutError:
                        try:
                            if await redis_conn.get(f"analysis:{job_id}:cancel"):
                                cancelled_by_user = True
                                logger.info(
                                    "Cancellation requested for job=%s — stopping pipeline.",
                                    job_id,
                                    extra={"job_id": job_id, "component": "heartbeat"},
                                )
                                if pipeline_task is not None:
                                    pipeline_task.cancel()
                                return
                        except Exception as exc:  # noqa: BLE001 — polling must never kill the run
                            logger.debug("Cancel-flag poll failed: %s", exc)
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
                # Run the pipeline as a task so the heartbeat poller can cancel
                # it when the user cancels the job (audit 2026-07-26, Ö5).
                pipeline_task = asyncio.create_task(
                    app.arun(
                        file_hash=sample.sha256,
                        file_name=sample.original_filename,
                        sample_path=temp_path,
                        static_sample_path=static_sample_path,
                    )
                )
                pipeline_result = await pipeline_task
            except asyncio.CancelledError:
                if not cancelled_by_user:
                    raise
                logger.info(
                    "Pipeline cancelled by user request: job=%s",
                    job_id,
                    extra={"job_id": job_id},
                )
                await _publish_event(redis_conn, job_id, "cancelled", {})
                async with db_session() as cleanup_db:
                    await cleanup_db.execute(
                        update(AnalysisJob)
                        .where(AnalysisJob.id == job.id)
                        .values(status="cancelled", completed_at=datetime.now(UTC))
                    )
                    await cleanup_db.commit()
                return {"status": "cancelled", "job_id": job_id}
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
            from app.models.report import AgentFinding, AgentMessage, AnalysisReport

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

            # A masked, non-secret record of the Settings this job actually
            # ran with, plus which core keys came from a stored UI override
            # rather than the environment/default -- lets a report reader
            # tell what was in effect without re-deriving it.
            _run_summary = pipeline_result.get("run_summary")
            _run_summary = dict(_run_summary) if isinstance(_run_summary, dict) else {}
            _run_summary["settings_snapshot"] = settings_snapshot(core_settings, overrides.keys())

            # A pipeline that produced no report is a failed run, not a
            # completed one with nothing in it (L15, security hardening):
            # ``report_node`` returns ``{"report_error": "<type>: <msg>"}``
            # instead of a ``malware_report`` when the deterministic build
            # raised. Surface that message through the same failure path
            # every other pipeline exception takes, below.
            #
            # A missing ``malware_report`` is not on its own evidence of a
            # failure, though: with ``reporting.enabled = False`` the graph
            # routes judge -> END and never runs the report node at all
            # (``pipeline/builder.py``, ``pipeline/state.py``), so
            # ``malware_report`` stays ``None`` by design on every run. Only
            # fail the job when the report node actually raised
            # (``report_error`` present) or reporting was expected to run
            # for this job and did not produce one.
            _report_error = pipeline_result.get("report_error")
            if _report_error or (
                core_settings.reporting.enabled and not pipeline_result.get("malware_report")
            ):
                logger.error(
                    "Pipeline produced no report: job=%s report_error=%s",
                    job_id,
                    _report_error,
                    extra={"job_id": job_id},
                )
                raise RuntimeError(_report_error or "pipeline produced no report")

            report = AnalysisReport(
                job_id=job.id,
                verdict=pipeline_result.get("final_decision", "Unknown"),
                overall_confidence=_extract_confidence(pipeline_result),
                malware_category=_extract_category(pipeline_result),
                stix_bundle=stix_bundle_for_persist,
                mitre_techniques=_extract_mitre(pipeline_result),
                # The agents' *final* prose. This used to persist only
                # ``reports`` — the first-pass text — so the report an analyst
                # rewrote after the negotiation was thrown away, and the stored
                # prose silently contradicted the stored claims (which do come
                # from the revised ISR). ``revised_reports`` is keyed by the
                # same agent names, so the merge is per-agent and an agent that
                # never revised keeps its original.
                agent_reports={
                    **(pipeline_result.get("reports") or {}),
                    **(pipeline_result.get("revised_reports") or {}),
                },
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
                            # ``complete`` | ``failed`` | ``timeout``. Without
                            # it a mediation that never ran is indistinguishable
                            # from one where the agents calmly disagreed: both
                            # store ``is_consensus=False`` at 0.0 confidence.
                            # Every run in this database is the former, and the
                            # UI drew all of them as the latter.
                            "status": (
                                getattr(arg, "status", "complete")
                                if hasattr(arg, "status")
                                else arg.get("status", "complete")
                            ),
                        }
                        for i, arg in enumerate(pipeline_result.get("discussion_history") or [])
                    ],
                    "confidence_history": pipeline_result.get("confidence_history", []),
                    "iteration_count": pipeline_result.get("iteration_count", 0),
                    "is_consensus": pipeline_result.get("is_consensus", False),
                    # True when at least one round failed outright, so consumers
                    # can say "the negotiation did not run" rather than "the
                    # agents did not agree".
                    "mediation_failed": any(
                        getattr(a, "status", "complete") in ("failed", "timeout")
                        for a in (pipeline_result.get("discussion_history") or [])
                        if getattr(a, "agent_name", "") == "Mediator"
                    ),
                    # Whether the last round's agreement was flagged as
                    # sycophantic — agents converging without new evidence. It
                    # reached the database only buried inside ``run_summary``
                    # before, so nothing rendering the negotiation could tell
                    # a genuine consensus from a manufactured one.
                    "sycophancy_detected": bool(pipeline_result.get("sycophancy_detected", False)),
                },
                run_summary=_run_summary,
                malware_report=pipeline_result.get("malware_report"),
            )
            # A re-run supersedes its predecessor. ``analysis_reports.job_id``
            # is unique and this path only ever inserted, so an arq retry --
            # which arq schedules on its own -- reached the end of a full
            # analysis and threw the result away on a UniqueViolationError.
            await _supersede_previous_report(db, job.id)
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

            # ── 4b. Save the transcript ──────────────────────────
            # The conversation itself, written down exactly as it was
            # broadcast. ``agent_findings`` above records where each agent
            # *ended up*; this records what was said and in what order, which
            # is the only place the per-round positions, the sycophancy
            # intervention and the revised prose survive past the 24 h Redis
            # stream. See ``AgentMessage`` for the full rationale.
            for seq, message in enumerate(transcript):
                db.add(
                    AgentMessage(
                        report_id=report.id,
                        seq=seq,
                        speaker=str(message.get("speaker", "unknown"))[:100],
                        role=str(message.get("role", "system"))[:20],
                        round=int(message.get("round", 0) or 0),
                        status=str(message.get("status", "complete"))[:20],
                        text=str(message.get("text", "") or ""),
                        report=message.get("report"),
                        report_truncated=bool(message.get("report_truncated", False)),
                        confidence=message.get("confidence"),
                        claims=message.get("claims") or [],
                        dissent=message.get("dissent") or [],
                        ts=_parse_event_ts(message.get("ts")),
                    )
                )

            logger.info(
                f"Saved {len(transcript)} transcript messages for report={report.id}",
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
            if await runtime_config.get("enrichment_enabled") and report.malware_report:
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

        finally:
            # The worker's own private copies of the sample never outlive the
            # job that downloaded them, on success, failure or cancellation
            # alike (H3, security hardening). ``remove_quietly`` is a no-op
            # on ``None`` (nothing was ever downloaded) and never raises.
            from app.worker import sample_files

            sample_files.remove_quietly(temp_path, job_id=job_id)
            sample_files.remove_quietly(host_mirror, job_id=job_id)

            # Release the agents' MCP toolkits, their stdio subprocesses and the
            # per-job caches. A ``finally`` rather than ``async with`` because
            # the body above spans ~500 lines and returns early on the
            # user-cancelled path — this covers success, failure and
            # cancellation without re-indenting any of it.
            #
            # ``aclose`` is total by construction (see MaljanApp.aclose), so a
            # failed teardown cannot turn a completed analysis into a failed
            # one. Whether it actually reclaims the memory is a separate
            # question, which is why the readings are logged either side of it
            # and why the worker also carries a hard recycle backstop.
            if app is not None:
                from maljan.core import memprobe

                memprobe.probe("job:before_teardown", job_id=job_id)
                try:
                    # The outermost fence. Each toolkit close is bounded, and
                    # the container bounds them again — this bounds the lot,
                    # because a job is not finished until this returns and
                    # ``max_jobs = 1`` means the next one cannot start.
                    #
                    # Earned the hard way: a run that had already written its
                    # report sat here for 42 minutes with arq still reporting
                    # ``j_ongoing=1``, and only ended on SIGTERM. An ``mcp``
                    # stdio exit stack waits on its child process, and a child
                    # that does not exit waits forever.
                    await asyncio.wait_for(app.aclose(), timeout=_TEARDOWN_BUDGET)
                except TimeoutError:
                    logger.error(
                        "Teardown exceeded %.0fs and was abandoned; the job is "
                        "complete and its result is stored, but MCP subprocesses "
                        "may have leaked. The RSS ceiling will recycle the worker.",
                        _TEARDOWN_BUDGET,
                        extra={"job_id": job_id},
                    )
                except Exception as exc:  # noqa: BLE001 — teardown never fails a job
                    logger.warning("Teardown failed (non-fatal): %s", exc)
                gc.collect()
                reclaimed = memprobe.malloc_trim()
                memprobe.probe("job:end", job_id=job_id, trim_reclaimed_mb=reclaimed)


# ── Helpers ──────────────────────────────────────────────────────


def _extract_confidence(result: dict) -> float:
    """Extract overall confidence from the pipeline result.

    CONF-INFL-01 (audit 2026-07-26): the degraded-run confidence cap
    (``nodes.py`` ``_DEGRADED_CONFIDENCE_CAP``) is applied while building the
    ``MalwareReport``; ``run_summary`` and ``confidence_history`` still carry the
    RAW judge value. Persisting the raw value here made the API, the reports
    list and the analysis header show an uncapped confidence — the UI displayed
    "DEGRADED RUN" and "Confidence: 91/100" side by side, which is precisely the
    inflation the guardrail exists to prevent. The ``MalwareReport`` is therefore
    the authoritative source and is checked FIRST; the other two remain as
    fallbacks for legacy/partial results that carry no report.
    """
    malware_report = result.get("malware_report")
    if isinstance(malware_report, dict):
        conf = malware_report.get("overall_confidence")
        if conf is not None:
            return float(conf)

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
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        # ``[{}]`` as a default only covers a *missing* key. An attack-pattern
        # carrying ``"external_references": []`` — which the model emits
        # routinely — got past that default and then died on ``[0]``, taking a
        # completed analysis down with it: two consecutive live runs failed
        # with ``IndexError: list index out of range`` *after* every analyst,
        # the negotiation and the judge had finished. Losing a technique ID is
        # a missing field; losing the run is not.
        refs = obj.get("external_references")
        first = refs[0] if isinstance(refs, list) and refs and isinstance(refs[0], dict) else {}
        techniques.append(
            {
                "technique_id": first.get("external_id", ""),
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
            }
        )
    return techniques if techniques else None


# ── ARQ Worker Configuration ────────────────────────────────────


# How long a ``running`` row may be untouched at worker boot before it is
# considered abandoned. See ``_sweep_orphan_jobs``.
_ORPHAN_GRACE_SECONDS = int(os.environ.get("ORPHAN_JOB_GRACE_SECONDS", "300"))


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

    Cleanup rule: at boot, any ``running`` row older than
    ``_ORPHAN_GRACE_SECONDS`` cannot be held by a live worker — this
    process is the worker, ``max_jobs = 1``, and it has just started.
    Flip it to ``failed`` with a clear ``error_message`` so the UI shows
    the right state and the FP-rate stats become real.

    This runs once per worker boot and cannot race with an active job:
    the only rows in the window are ones written before this process
    existed.
    """
    from datetime import UTC as _UTC
    from datetime import datetime as _datetime
    from datetime import timedelta as _timedelta

    # 2026-07-27: the cutoff used to be ``job_timeout`` — eight hours — which
    # made this sweep useless for the case it names first in its own docstring.
    # A worker killed mid-flight comes back within seconds, and its abandoned
    # row then sat in ``running`` for the rest of the day: no worker held it,
    # ``max_tries=1`` meant nothing retried it, and the UI showed an analysis
    # that was permanently five minutes from finishing. Observed exactly that
    # on a verification run, and adding a container memory limit makes a
    # mid-flight kill *more* likely, not less.
    #
    # The grace period only has to exceed the window in which a job can be
    # legitimately ``running`` while no worker is up. Since ``max_jobs = 1``
    # and this process has just booted, that window is the time between the
    # API writing the row and the worker picking it up — seconds. Five minutes
    # is generous and still bounded.
    cutoff_seconds = min(WorkerSettings.job_timeout, _ORPHAN_GRACE_SECONDS)
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

    # Clear stale private sample copies left behind by a worker that was
    # killed mid-job (no finally ran) before this one starts taking jobs.
    try:
        from app.worker import sample_files

        sample_files.sweep()
    except OSError as exc:
        logger.warning(
            "Startup sample sweep failed (non-fatal): %s",
            exc,
            extra={"component": "worker.lifecycle"},
        )

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

# Resident-memory ceiling for the worker process, in MiB. Above this, the
# worker finishes reporting the job it just completed and then exits so Docker
# restarts it clean.
#
# The measured problem: one analysis takes the process from ~3.4 GB to ~8.5 GB
# and it never comes back, on a 30 GB host that also runs a ~15 GB llama-server.
# Two analyses in a row exhausted RAM and all 8 GB of swap, at which point LLM
# inference crawls and analysts start hitting their own wall-clock caps — a
# memory problem wearing a timeout costume. The machine hard-locked once.
#
# This is a backstop, not the fix, and it is deliberately dumber than the fix:
# whatever the leak turns out to be, and however well the teardown in
# ``run_analysis``'s ``finally`` works, a worker that has grown this large has
# already stopped being safe to keep around.
_RSS_RESTART_MB = float(os.environ.get("WORKER_RSS_RESTART_MB", "6000"))

# Absolute ceiling on end-of-job teardown. Reclaiming a subprocess and a socket
# is never worth holding a finished job — and therefore the whole queue — open.
_TEARDOWN_BUDGET = float(os.environ.get("WORKER_TEARDOWN_TIMEOUT", "60"))


async def _recycle_if_bloated(ctx: dict, *args: Any, **kwargs: Any) -> None:
    """arq ``after_job_end`` hook: exit when the process has grown too large.

    Runs *after* ``finish_job`` has recorded the result, so nothing is lost by
    leaving. ``call_later`` rather than an immediate kill so the hook returns
    and arq can finish its own bookkeeping first; a timer handle is not one of
    the tasks arq's signal handler cancels, so the exit cannot be swallowed.

    SIGTERM, not ``os._exit``: arq's handler runs ``on_shutdown``, which closes
    the database engine and the Redis pool. ``restart: unless-stopped`` in
    compose brings the worker back, and the existing startup orphan sweep
    repairs any job row left mid-flight.
    """
    from maljan.core import memprobe

    rss = memprobe.rss_mb()
    if rss < _RSS_RESTART_MB:
        logger.info("Worker RSS %.0f MB (limit %.0f MB).", rss, _RSS_RESTART_MB)
        return

    logger.critical(
        "Worker RSS %.0f MB exceeds the %.0f MB ceiling — restarting after this job. "
        "Queued jobs are unaffected; the supervisor will bring the worker back.",
        rss,
        _RSS_RESTART_MB,
    )
    try:
        asyncio.get_running_loop().call_later(1.0, os.kill, os.getpid(), signal.SIGTERM)
    except RuntimeError:  # pragma: no cover — no loop means we are already going down
        os.kill(os.getpid(), signal.SIGTERM)


class WorkerSettings:
    """ARQ worker settings — configure connection and task functions."""

    functions = [run_analysis, enrich_threat_intel]
    on_startup = startup
    on_shutdown = shutdown
    after_job_end = _recycle_if_bloated

    # Parse Redis URL from app config so Docker networking works
    _redis_parsed = urlparse(settings.redis_url)
    redis_settings = RedisSettings(
        host=_redis_parsed.hostname or "localhost",
        port=_redis_parsed.port or 6379,
        database=int((_redis_parsed.path or "/0").strip("/") or 0),
    )

    # Worker tuning
    # Phase A fix: max_jobs=1 prevents zombie threads from starving other jobs.
    # job_timeout=28800 (8h) — 2026-07-13 deep-analysis restore. The outer ARQ
    # ceiling must sit ABOVE the sum of the inner per-loop safety nets, or it
    # fires while a run is still legitimately progressing ("a timeout is a bug").
    # Static now runs a full-depth ReAct loop PER CHUNK (~8-10 chunks, up to
    # 1530s each) plus dynamic/CAPE, network, up to 5 revision rounds, judge and
    # the report Composer; a realistic-slow cold-cache run is ~2-4h. 8h is a
    # never-fires safety net: a single-slot LLM can't run two jobs at once so a
    # high ceiling costs nothing, and every LLM/CAPE path is bounded by its own
    # inner timeout, so this only trips on a true hang outside those paths. Was
    # 3600 (60 min), sized for the pre-restore shallow static pass.
    #
    # ``max_jobs`` is arq's CONCURRENCY limit — how many jobs run at once — not
    # a "recycle the worker after N jobs" counter. arq has no such counter;
    # ``after_job_end`` above is what bounds process lifetime here.
    max_jobs = 1
    job_timeout = 28800
    max_tries = 1  # Don't retry failed analyses automatically
    health_check_interval = 30


async def _supersede_previous_report(db: Any, job_id: Any) -> None:
    """Drop any existing report row for ``job_id`` so a re-run can persist.

    One report per job remains the right constraint — a job has one current
    result, not a history — so a second run replaces rather than accumulates.
    ``agent_findings`` and ``agent_messages`` are ``ondelete="CASCADE"``, which
    is what we want here: their contents describe the superseded analysis and
    would otherwise stay attached to a report that no longer exists.

    The delete is flushed before the caller adds the new row; leaving both in
    one flush puts two rows with the same ``job_id`` in the same statement
    batch and collides exactly as before.

    Never raises. The analysis is already finished by the time this runs, and a
    failed pre-check must not be the thing that loses its result — the insert
    below will surface any real problem on its own.
    """
    try:
        from app.models.report import AnalysisReport

        existing = (
            await db.execute(select(AnalysisReport).where(AnalysisReport.job_id == job_id))
        ).scalar_one_or_none()
        if existing is None:
            return
        logger.warning(
            "Report for job %s already exists (id=%s); superseding it with this run.",
            job_id,
            getattr(existing, "id", "<unknown>"),
            extra={"job_id": str(job_id), "component": "report"},
        )
        await db.delete(existing)
        await db.flush()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not check for a previous report on job %s (%s).", job_id, exc)
