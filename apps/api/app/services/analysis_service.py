"""Analysis service — business logic for job lifecycle and pipeline orchestration.

Separates business logic from API routes for testability and reuse.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis
from arq import ArqRedis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.logging_config import get_logger
from app.models.job import AnalysisJob
from app.models.sample import Sample
from app.models.user import User

logger = get_logger("service.analysis")


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

        # Enqueue to ARQ worker. Failure here is **propagated** as a 503 by the
        # route handler — silently returning a "failed" job would mislead the
        # caller into believing the analysis was accepted.
        try:
            arq = await self._get_arq_redis()
            await arq.enqueue_job("run_analysis", str(job.id))
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
            # BUG-02: eager-load the sample so JobResponse.sample_sha256 /
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
        # BUG-02: eager-load sample for sample_sha256 / sample_filename.
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

        # Publish cancellation event
        try:
            redis_conn = aioredis.from_url(settings.redis_url)
            import json

            await redis_conn.publish(
                f"analysis:{job_id}",
                json.dumps({"type": "cancelled", "data": {}, "ts": datetime.now(UTC).isoformat()}),
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
