"""Analysis job endpoints — create, list, get, cancel.

Uses AnalysisService for business logic separation.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import get_current_user
from app.logging_config import get_logger
from app.models.user import User
from app.schemas.job import JobCreateRequest, JobListResponse, JobResponse
from app.services.analysis_service import AnalysisService

logger = get_logger("api.jobs")

router = APIRouter(prefix="/jobs", tags=["Analysis Jobs"])


def _get_service(db: AsyncSession = Depends(get_db)) -> AnalysisService:
    return AnalysisService(db)


@router.post("", response_model=JobResponse, status_code=status.HTTP_201_CREATED)
async def create_job(
    body: JobCreateRequest,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
) -> dict:
    """Start a new analysis job for an uploaded sample."""
    logger.info(
        f"Creating analysis job for sample={body.sample_id}",
        extra={"sample_id": str(body.sample_id), "user_id": str(user.id)},
    )
    try:
        job = await svc.create_job(
            sample_id=body.sample_id,
            user=user,
            config=body.config,
        )
        logger.info(
            f"Job created: id={job.id} status={job.status}",
            extra={"job_id": str(job.id), "user_id": str(user.id)},
        )
        return job
    except ValueError as exc:
        logger.warning(
            f"Job creation failed: {exc}",
            extra={"sample_id": str(body.sample_id), "user_id": str(user.id)},
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get("", response_model=JobListResponse)
async def list_jobs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
) -> dict:
    """List analysis jobs with pagination and optional status filter."""
    result = await svc.list_jobs(
        user=user,
        page=page,
        page_size=page_size,
        status_filter=status_filter,
    )
    logger.debug(
        f"Listed jobs: page={page} filter={status_filter} total={result.get('total', 0)}",
        extra={"user_id": str(user.id)},
    )
    return result


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
) -> dict:
    """Get a specific job's status and details."""
    job = await svc.get_job(job_id, user)
    if not job:
        logger.warning(
            f"Job not found: {job_id}",
            extra={"job_id": str(job_id), "user_id": str(user.id)},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return job


@router.delete("/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_job(
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
) -> None:
    """Cancel a pending or running job."""
    try:
        await svc.cancel_job(job_id, user)
        logger.info(
            f"Job cancelled: {job_id}",
            extra={"job_id": str(job_id), "user_id": str(user.id)},
        )
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found") from None
    except RuntimeError as exc:
        logger.warning(
            f"Job cancel rejected: {exc}",
            extra={"job_id": str(job_id), "user_id": str(user.id)},
        )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
