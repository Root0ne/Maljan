"""Analysis job endpoints — create, list, get, cancel.

Uses AnalysisService for business logic separation.
"""

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import get_current_user
from app.logging_config import get_logger
from app.logsafe import log_safe
from app.models.user import User
from app.schemas.job import JobCreateRequest, JobListResponse, JobResponse
from app.services import audit
from app.services.analysis_service import AnalysisService
from app.services.settings_service import SettingsService

logger = get_logger("api.jobs")

router = APIRouter(prefix="/jobs", tags=["Analysis Jobs"])


def _get_service(db: AsyncSession = Depends(get_db)) -> AnalysisService:
    return AnalysisService(db)


async def _known_profiles(db: AsyncSession) -> set[str]:
    """Every profile name a job may pick, stored map layered over the seeds."""
    from app.services.agent_map import effective_profiles

    return set(effective_profiles(await SettingsService(db).load_overrides()))


async def _disabled_analyst_in(db: AsyncSession, profile: str) -> str | None:
    """The first disabled analyst ``profile`` lists, or ``None`` if it lists none.

    A built-in profile may sit inactive with a disabled member — the settings
    model exempts it for exactly as long as it stays inactive (see
    ``AgentsConfig._seed_and_check``). Naming it here is what makes it active,
    so that exemption no longer applies: this refuses the job rather than
    letting the worker discover the conflict when the run actually starts.
    """
    from app.services.agent_map import effective_definitions, effective_profiles

    overrides = await SettingsService(db).load_overrides()
    definitions = effective_definitions(overrides)
    analysts = effective_profiles(overrides).get(profile, {}).get("analysts", [])
    for analyst in analysts:
        member = definitions.get(analyst, {})
        if not member.get("enabled", True):
            return str(analyst)
    return None


# The config keys an audit row may carry. A job config is operator-supplied and
# open-ended, so it is never copied wholesale: only these are named, and a
# credential someone put in it has no way through.
_AUDITED_CONFIG_KEYS = (
    "profile",
    "llm_provider",
    "static_provider",
    "sandbox_provider",
    "sandbox_report_id",
    "mock_mode",
)


def _job_details(sample_id: Any, config: dict[str, Any] | None) -> dict[str, Any]:
    details: dict[str, Any] = {"sample_id": str(sample_id)}
    for key in _AUDITED_CONFIG_KEYS:
        value = (config or {}).get(key)
        if value is not None:
            details[key] = str(value) if not isinstance(value, bool) else value
    return details


@router.post("", response_model=JobResponse, status_code=status.HTTP_201_CREATED)
async def create_job(
    request: Request,
    body: JobCreateRequest,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Start a new analysis job for an uploaded sample."""
    logger.info(
        f"Creating analysis job for sample={log_safe(body.sample_id)}",
        extra={"sample_id": log_safe(body.sample_id), "user_id": log_safe(user.id)},
    )
    profile = (body.config or {}).get("profile")
    if profile is not None:
        known = await _known_profiles(db)
        if str(profile) not in known:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"unknown profile {str(profile)!r}. Available: {', '.join(sorted(known))}",
            )
        disabled = await _disabled_analyst_in(db, str(profile))
        if disabled is not None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"profile {str(profile)!r} lists disabled analyst {disabled!r}",
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
        await audit.record(
            "job.submit",
            resource_type="job",
            resource_id=str(job.id),
            user_id=user.id,
            details=_job_details(body.sample_id, body.config),
            request=request,
        )
        return job
    except ValueError as exc:
        # Sample not found OR IDOR rejection — surface a 404 either way so
        # we do not leak existence information.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        from app.services.analysis_service import JobEnqueueError

        if isinstance(exc, JobEnqueueError):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Analysis queue is unavailable. Please retry shortly.",
            ) from exc
        raise


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
        f"Listed jobs: page={log_safe(page)} filter={log_safe(status_filter)} "
        f"total={log_safe(result.get('total', 0))}",
        extra={"user_id": log_safe(user.id)},
    )
    return result


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
) -> Any:
    """Get a specific job's status and details."""
    job = await svc.get_job(job_id, user)
    if not job:
        logger.warning(
            f"Job not found: {log_safe(job_id)}",
            extra={"job_id": log_safe(job_id), "user_id": log_safe(user.id)},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return job


@router.get("/{job_id}/events")
async def get_job_events(
    job_id: uuid.UUID,
    limit: int = Query(500, ge=1, le=1000),
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
) -> dict[str, Any]:
    """Return historical pipeline events for this job.

    The Live tab uses this on mount to back-fill its event log before
    attaching the WebSocket. Events live in
    Redis Stream ``analysis:{job_id}:events`` with a 24 h TTL and a
    1 000-entry cap. ``stream_id`` is the canonical ordering key —
    clients dedupe against it when WS events arrive concurrently.
    """
    import json

    import redis.asyncio as aioredis

    from app.config import settings

    job = await svc.get_job(job_id, user)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")

    redis_conn = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        entries = await redis_conn.xrange(
            f"analysis:{job_id}:events", min="-", max="+", count=limit
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"Event stream read failed for job={log_safe(job_id)}: {log_safe(exc)}")
        entries = []
    finally:
        try:
            await redis_conn.aclose()
        except Exception:  # noqa: BLE001
            pass

    events: list[dict[str, Any]] = []
    for stream_id, fields in entries:
        payload_raw = fields.get("payload") if isinstance(fields, dict) else None
        if not payload_raw:
            continue
        try:
            payload = json.loads(payload_raw)
        except (ValueError, TypeError):
            continue
        payload["stream_id"] = stream_id
        events.append(payload)
    return {"job_id": str(job_id), "events": events, "count": len(events)}


@router.delete("/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_job(
    request: Request,
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
) -> None:
    """Cancel a pending or running job."""
    try:
        await svc.cancel_job(job_id, user)
        logger.info(
            f"Job cancelled: {log_safe(job_id)}",
            extra={"job_id": log_safe(job_id), "user_id": log_safe(user.id)},
        )
        await audit.record(
            "job.cancel",
            resource_type="job",
            resource_id=str(job_id),
            user_id=user.id,
            request=request,
        )
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found") from None
    except RuntimeError as exc:
        logger.warning(
            f"Job cancel rejected: {log_safe(exc)}",
            extra={"job_id": log_safe(job_id), "user_id": log_safe(user.id)},
        )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
