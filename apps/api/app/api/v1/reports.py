"""Report endpoints — detail, STIX export, MITRE export, negotiation timeline.

Uses ReportService for business logic separation.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import get_current_user
from app.models.user import User
from app.schemas.job import ReportDetailResponse
from app.services.report_service import ReportService

router = APIRouter(prefix="/reports", tags=["Reports"])


def _get_service(db: AsyncSession = Depends(get_db)) -> ReportService:
    return ReportService(db)


@router.get("")
async def list_reports(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(get_current_user),
    svc: ReportService = Depends(_get_service),
) -> dict:
    """List all analysis reports with pagination."""
    return await svc.list_reports(user=user, page=page, page_size=page_size)


@router.get("/{report_id}", response_model=ReportDetailResponse)
async def get_report(
    report_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: ReportService = Depends(_get_service),
) -> dict:
    """Get a full analysis report with per-agent findings."""
    report = await svc.get_report(report_id, user)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@router.get("/{report_id}/stix")
async def get_stix_bundle(
    report_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: ReportService = Depends(_get_service),
) -> dict:
    """Get the STIX 2.1 threat intelligence bundle."""
    bundle = await svc.get_stix_bundle(report_id, user)
    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found or STIX bundle not available",
        )
    return bundle


@router.get("/{report_id}/mitre")
async def get_mitre_techniques(
    report_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: ReportService = Depends(_get_service),
) -> dict:
    """Get MITRE ATT&CK technique mappings."""
    techniques = await svc.get_mitre_techniques(report_id, user)
    if techniques is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found or MITRE data not available",
        )
    return {"techniques": techniques}


@router.get("/{report_id}/timeline")
async def get_negotiation_timeline(
    report_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: ReportService = Depends(_get_service),
) -> dict:
    """Get the multi-agent negotiation timeline for visualization.

    Returns structured data showing how agents' positions evolved
    through negotiation rounds — ideal for rendering debate timelines,
    confidence convergence charts, and agent interaction graphs.
    """
    timeline = await svc.get_negotiation_timeline(report_id, user)
    if timeline is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    return timeline
