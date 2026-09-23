"""Analysis service — business logic for job lifecycle and pipeline orchestration.

Separates business logic from API routes for testability and reuse.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis
from arq import ArqRedis
from arq.jobs import Job as ArqJob
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.logging_config import get_logger
from app.logsafe import log_safe
from app.models.job import AnalysisJob
from app.models.sample import Sample
from app.models.user import User

logger = get_logger("service.analysis")

# How many completed runs the dashboard's "Tools used" list reads by default,
# and the most a caller may ask it to read.
TOOL_USAGE_RUNS = 20
TOOL_USAGE_MAX_RUNS = 100


class JobEnqueueError(RuntimeError):
    """Raised when ARQ enqueue fails so the route can return 503."""


class AnalysisService:
    """Orchestrates analysis job lifecycle and pipeline triggering."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self._arq_redis: ArqRedis | None = None

    async def _get_arq_redis(self) -> ArqRedis:
        """Lazy-initialize ARQ Redis connection for job enqueueing."""
        if self._arq_redis is None:
            from arq.connections import RedisSettings, create_pool

            self._arq_redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
        return self._arq_redis

    # ── Job Lifecycle ────────────────────────────────────────────

    async def create_job(
        self,
        sample_id: uuid.UUID,
        user: User,
        config: dict[str, Any] | None = None,
    ) -> AnalysisJob:
        """Create a new analysis job and enqueue it for processing.

        Args:
            sample_id: UUID of the uploaded sample.
            user: The authenticated user creating the job.
            config: Optional pipeline configuration overrides.

        Returns:
            The created AnalysisJob ORM instance.

        Raises:
            ValueError: If the sample doesn't exist.
        """
        # Verify sample exists AND belongs to the requesting user (IDOR guard).
        result = await self.db.execute(
            select(Sample).where(
                Sample.id == sample_id,
                Sample.uploaded_by == user.id,
            )
        )
        sample = result.scalar_one_or_none()
        if not sample:
            raise ValueError(f"Sample {sample_id} not found or access denied")

        # Create job record
        job = AnalysisJob(
            sample_id=sample_id,
            created_by=user.id,
            status="pending",
            config=config,
        )
        self.db.add(job)
        await self.db.flush()
        await self.db.refresh(job)
        # Attach the already-verified sample so the
        # ``JobResponse.sample_sha256`` / ``sample_filename`` read-only props
        # resolve on the create path too. Without this the POST /jobs
        # response returned those fields as null (the sample eager-load
        # only covered get_job / list_jobs), diverging from GET /jobs.
        job.sample = sample

        # Enqueue to ARQ worker. Failure here is **propagated** as a 503 by the
        # route handler — silently returning a "failed" job would mislead the
        # caller into believing the analysis was accepted.
        try:
            arq = await self._get_arq_redis()
            await _enqueue_analysis(arq, job.id)
        except Exception as exc:
            job.status = "failed"
            job.error_message = f"Failed to enqueue job: {exc}"
            await self.db.flush()
            raise JobEnqueueError(str(exc)) from exc

        return job

    async def get_job(
        self,
        job_id: uuid.UUID,
        user: User,
    ) -> AnalysisJob | None:
        """Retrieve a job by ID, scoped to the requesting user."""
        result = await self.db.execute(
            select(AnalysisJob)
            .where(
                AnalysisJob.id == job_id,
                AnalysisJob.created_by == user.id,
            )
            # Eager-load the sample so JobResponse.sample_sha256 /
            # sample_filename populate without an async lazy-load.
            .options(selectinload(AnalysisJob.sample))
        )
        return result.scalar_one_or_none()

    async def list_jobs(
        self,
        user: User,
        page: int = 1,
        page_size: int = 20,
        status_filter: str | None = None,
    ) -> dict[str, Any]:
        """List jobs for a user with pagination and optional status filter."""
        query = select(AnalysisJob).where(AnalysisJob.created_by == user.id)
        count_query = (
            select(func.count()).select_from(AnalysisJob).where(AnalysisJob.created_by == user.id)
        )

        if status_filter:
            query = query.where(AnalysisJob.status == status_filter)
            count_query = count_query.where(AnalysisJob.status == status_filter)

        query = query.order_by(AnalysisJob.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)
        # Eager-load the sample for sample_sha256 / sample_filename.
        query = query.options(selectinload(AnalysisJob.sample))

        result = await self.db.execute(query)
        jobs = result.scalars().all()

        total_result = await self.db.execute(count_query)
        total = total_result.scalar() or 0

        return {
            "items": jobs,
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    async def cancel_job(
        self,
        job_id: uuid.UUID,
        user: User,
    ) -> AnalysisJob:
        """Cancel a pending or running job.

        Raises:
            ValueError: If the job doesn't exist.
            RuntimeError: If the job is in a non-cancellable state.
        """
        job = await self.get_job(job_id, user)
        if not job:
            raise ValueError(f"Job {job_id} not found")

        if job.status not in ("pending", "running"):
            raise RuntimeError(f"Cannot cancel job with status '{job.status}'")

        job.status = "cancelled"
        job.completed_at = datetime.now(UTC)
        await self.db.flush()

        # This used to ONLY publish to PubSub, which had
        # two consequences:
        #   1. The running worker never learned about the cancellation — it
        #      checks the job status exactly once, before starting — so the
        #      pipeline kept burning LLM time and later overwrote the row with
        #      `completed`/`failed`, silently undoing the cancel.
        #   2. The event was absent from the replay stream, so a client that
        #      reconnected and back-filled via GET /jobs/{id}/events never saw it.
        # Now we also set a cancel flag the worker polls, and mirror the event
        # into the stream like every other event type.
        try:
            redis_conn = aioredis.from_url(settings.redis_url)
            import json

            message = json.dumps(
                {"type": "cancelled", "data": {}, "ts": datetime.now(UTC).isoformat()}
            )
            # Cooperative-cancellation flag. TTL keeps abandoned keys from
            # accumulating; it outlives any realistic single analysis.
            await redis_conn.set(f"analysis:{job_id}:cancel", "1", ex=86_400)
            # The cooperative flag only reaches a job that is already running.
            # A job still queued — or scheduled for retry — has to be removed
            # from arq as well, or it starts later as if nothing happened. See
            # ``_abort_queued_analysis`` for the live evidence.
            await _abort_queued_analysis(redis_conn, job_id)
            await redis_conn.publish(f"analysis:{job_id}", message)
            await redis_conn.xadd(
                f"analysis:{job_id}:events",
                {"payload": message},
                maxlen=1000,
                approximate=True,
            )
            await redis_conn.aclose()
        except Exception:
            pass  # Non-critical: client will see status change on next poll

        return job

    # ── Statistics ────────────────────────────────────────────────

    async def get_user_stats(self, user: User) -> dict[str, Any]:
        """Get analysis statistics for the dashboard."""
        from app.models.report import AnalysisReport

        # Total jobs
        total_result = await self.db.execute(
            select(func.count()).select_from(AnalysisJob).where(AnalysisJob.created_by == user.id)
        )
        total_jobs = total_result.scalar() or 0

        # Jobs by status
        status_result = await self.db.execute(
            select(AnalysisJob.status, func.count())
            .where(AnalysisJob.created_by == user.id)
            .group_by(AnalysisJob.status)
        )
        status_counts: dict[str, int] = {row[0]: int(row[1]) for row in status_result.all()}

        # Verdict distribution (from reports of user's jobs)
        verdict_result = await self.db.execute(
            select(AnalysisReport.verdict, func.count())
            .join(AnalysisJob, AnalysisReport.job_id == AnalysisJob.id)
            .where(AnalysisJob.created_by == user.id)
            .group_by(AnalysisReport.verdict)
        )
        verdict_counts: dict[str, int] = {row[0]: int(row[1]) for row in verdict_result.all()}

        # Average analysis time
        avg_result = await self.db.execute(
            select(func.avg(AnalysisJob.duration_seconds)).where(
                AnalysisJob.created_by == user.id,
                AnalysisJob.status == "completed",
            )
        )
        avg_duration = avg_result.scalar()

        # Total samples
        total_samples = await self.db.execute(
            select(func.count()).select_from(Sample).where(Sample.uploaded_by == user.id)
        )

        return {
            "total_jobs": total_jobs,
            "total_samples": total_samples.scalar() or 0,
            "jobs_by_status": status_counts,
            "verdict_distribution": verdict_counts,
            "avg_duration_seconds": round(float(avg_duration), 1) if avg_duration else None,
        }

    async def get_tool_usage(self, user: User, limit: int = TOOL_USAGE_RUNS) -> dict[str, Any]:
        """Which tools the caller's latest completed runs called, and how often.

        Read from each run's ``run_summary.evidence.by_tool``, the per-tool
        ledger count the report was built with, so the dashboard's bars and the
        Summary tab's evidence counts come from one record. Only the last
        ``limit`` completed runs are read, and only their JSON is opened: the
        question is what recent runs leaned on, and a whole-history scan of a
        JSON column on every landing page load is a cost it does not need.
        """
        rows = await self.db.execute(tool_usage_query(user.id, limit))
        return tally_tool_usage([row[0] for row in rows.all()], limit)


def tool_usage_query(user_id: uuid.UUID, limit: int) -> Any:
    """The per-tool counts of one user's latest ``limit`` completed runs.

    Two steps, so the database does the bounded part first. The inner query
    picks the ids of the newest ``limit`` completed runs the caller owns,
    reading only narrow columns; the outer one extracts the JSON path for
    those rows alone. With the path in a single flat select, the server is
    free to detoast ``run_summary`` — which carries the settings snapshot and
    every failure row — for every completed run of the user before the sort
    and the limit throw most of them away.
    """
    from app.models.report import AnalysisReport

    newest = (
        select(AnalysisReport.id.label("id"), AnalysisReport.created_at.label("created_at"))
        .join(AnalysisJob, AnalysisReport.job_id == AnalysisJob.id)
        .where(AnalysisJob.created_by == user_id, AnalysisJob.status == "completed")
        .order_by(AnalysisReport.created_at.desc())
        .limit(limit)
        .subquery("newest")
    )
    return (
        select(AnalysisReport.run_summary["evidence"]["by_tool"])
        .join(newest, AnalysisReport.id == newest.c.id)
        .order_by(newest.c.created_at.desc())
    )


def tally_tool_usage(by_tool_rows: list[Any], limit: int) -> dict[str, Any]:
    """Per-tool call counts summed across runs, and how many runs used each.

    ``runs`` counts only the runs whose report carries the per-tool record —
    a map, even an empty one for a run that called nothing. A report written
    before that record existed says nothing about which tools ran, so it is
    not a run that called none of them and it stays out of the denominator;
    ``read`` is every completed run looked at, so the console can say how many
    of them had no record. A count that is not a positive integer is not a
    call and is left out rather than coerced.
    """
    calls: dict[str, int] = {}
    used_in: dict[str, int] = {}
    recorded = 0
    for by_tool in by_tool_rows:
        if not isinstance(by_tool, dict):
            continue
        recorded += 1
        for tool, count in by_tool.items():
            if not isinstance(tool, str) or not tool:
                continue
            if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
                continue
            calls[tool] = calls.get(tool, 0) + count
            used_in[tool] = used_in.get(tool, 0) + 1
    tools = [
        {"tool": tool, "calls": calls[tool], "runs": used_in[tool]}
        for tool in sorted(calls, key=lambda name: (-calls[name], name))
    ]
    return {"limit": limit, "read": len(by_tool_rows), "runs": recorded, "tools": tools}


async def _enqueue_analysis(arq: Any, job_id: uuid.UUID) -> Any:
    """Queue ``run_analysis`` under **our** job id.

    Without ``_job_id`` arq mints a random identity that nothing else in the
    system knows, which is why a cancelled job could not be reached in the
    queue afterwards: ``cancel_job`` marked the row and set a cooperative flag,
    but the queued work carried on existing under a name we never recorded.

    Making the ids equal also makes enqueueing idempotent — arq refuses a
    second job with an id it already holds, so one analysis cannot end up
    queued twice under two identities.
    """
    return await arq.enqueue_job("run_analysis", str(job_id), _job_id=str(job_id))


async def _abort_queued_analysis(redis_conn: Any, job_id: uuid.UUID) -> None:
    """Remove the queued/scheduled arq job for ``job_id``. Never raises.

    Observed 2026-08-07, hours after a cancel: the arq job was still holding an
    ``in-progress`` lock (ttl ~4h) *and* was still scheduled for retry. With
    ``max_jobs = 1`` that blocked every later submission, and had the retry
    fired it would have re-run a cancelled analysis — which cannot even save a
    report, because ``analysis_reports.job_id`` is unique.

    Best-effort by design: the DB row is already ``cancelled`` before this runs,
    so a Redis hiccup must not turn a successful cancel into a 500.
    """
    try:
        await ArqJob(str(job_id), redis_conn).abort(timeout=0)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "cancel_job: could not abort queued arq job %s (%s); "
            "the cooperative cancel flag still applies.",
            log_safe(job_id),
            log_safe(exc),
        )
