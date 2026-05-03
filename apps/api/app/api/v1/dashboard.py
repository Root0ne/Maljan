"""Dashboard endpoints — user statistics and system overview."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import get_current_user
from app.models.user import User
from app.services.analysis_service import AnalysisService

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
