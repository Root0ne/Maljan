"""Dashboard endpoints — user statistics and system overview."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import get_current_user
from app.models.user import User
from app.services.analysis_service import (
    TOOL_USAGE_MAX_RUNS,
    TOOL_USAGE_RUNS,
    AnalysisService,
)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats")
async def get_dashboard_stats(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get analysis statistics for the dashboard.

    Returns:
        - total_jobs: Total number of analysis jobs
        - total_samples: Total uploaded samples
        - jobs_by_status: Job count per status (pending, running, completed, failed)
        - verdict_distribution: Count per verdict (Malware, Benign, Suspicious)
        - avg_duration_seconds: Average analysis duration
    """
    svc = AnalysisService(db)
    return await svc.get_user_stats(user)


@router.get("/tools")
async def get_dashboard_tools(
    limit: int = Query(TOOL_USAGE_RUNS, ge=1, le=TOOL_USAGE_MAX_RUNS),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """The tools the caller's latest completed runs called.

    Returns:
        - limit: How many completed runs were asked for
        - read: How many completed runs were read (at most ``limit``)
        - runs: How many of those carry the per-tool record; a report older
          than the record is not counted as a run that called nothing
        - tools: One row per tool, most calls first — ``tool``, ``calls``
          (summed across the runs) and ``runs`` (how many of them called it)
    """
    svc = AnalysisService(db)
    return await svc.get_tool_usage(user, limit)
