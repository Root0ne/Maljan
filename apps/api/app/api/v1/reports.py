"""Report endpoints — detail, STIX export, MITRE export, negotiation timeline.

Uses ReportService for business logic separation.
"""

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import get_current_user
from app.models.user import User
from app.schemas.job import IOCEntry, IOCListResponse, ReportDetailResponse
from app.services.report_service import EnrichmentEnqueueError, ReportService

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
) -> Any:
    """Get a full analysis report with per-agent findings."""
    report = await svc.get_report(report_id, user)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@router.get("/job/{job_id}", response_model=ReportDetailResponse)
async def get_report_by_job_id(
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: ReportService = Depends(_get_service),
) -> Any:
    """Get a full analysis report by its associated job ID."""
    report = await svc.get_report_by_job(job_id, user)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Report not found for this job"
        )
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


# ---------------------------------------------------------------------------
# Comprehensive MalwareReport endpoints (Faz 5)
# ---------------------------------------------------------------------------


@router.get("/{report_id}/full")
async def get_full_malware_report(
    report_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: ReportService = Depends(_get_service),
) -> dict:
    """Get the comprehensive ``MalwareReport`` JSON document.

    Returns the full Pydantic dump (identity / static / dynamic / network /
    persistence / capability_matrix / executive_summary / detection_signatures
    / ...) produced by the pipeline's report node. Legacy rows produced
    before the feature shipped return 404.
    """
    mr = await svc.get_malware_report(report_id, user)
    if mr is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found or no MalwareReport persisted",
        )
    return mr


@router.get("/{report_id}/markdown", response_class=PlainTextResponse)
async def get_full_malware_report_markdown(
    report_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: ReportService = Depends(_get_service),
) -> str:
    """Render the comprehensive report as markdown (text/markdown body)."""
    markdown = await svc.get_malware_report_markdown(report_id, user)
    if markdown is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found or markdown could not be rendered",
        )
    return markdown


@router.get("/{report_id}/iocs", response_model=IOCListResponse)
async def get_full_malware_report_iocs(
    report_id: uuid.UUID,
    kind: str | None = Query(
        default=None,
        description="Filter to one of: hash, domain, ip, url, user_agent, ja3",
    ),
    user: User = Depends(get_current_user),
    svc: ReportService = Depends(_get_service),
) -> IOCListResponse:
    """Flat list of every IOC the report holds, optionally filtered by kind."""
    items = await svc.get_malware_report_iocs(report_id, user, kind=kind)
    if items is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found or no MalwareReport persisted",
        )
    parsed = [IOCEntry.model_validate(row) for row in items]
    return IOCListResponse(items=parsed, total=len(parsed))


@router.get(
    "/{report_id}/signatures/{kind}",
    response_class=PlainTextResponse,
)
async def get_full_malware_report_signatures(
    report_id: uuid.UUID,
    kind: str,
    user: User = Depends(get_current_user),
    svc: ReportService = Depends(_get_service),
) -> str:
    """Return rule bodies for a single signature ``kind`` as plain text.

    Accepted kinds: ``yara``, ``sigma``, ``suricata``, ``snort``.
    """
    if kind not in {"yara", "sigma", "suricata", "snort"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(f"Unknown signature kind '{kind}'. Use yara, sigma, suricata, or snort."),
        )
    body = await svc.get_malware_report_signature(report_id, user, kind=kind)
    if body is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report not found or no {kind} signatures generated",
        )
    return body


@router.post("/{report_id}/enrich", status_code=status.HTTP_202_ACCEPTED)
async def enqueue_enrichment_job(
    report_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: ReportService = Depends(_get_service),
) -> dict:
    """Queue a post-hoc threat-intel enrichment for ``report_id``.

    Idempotent — the ARQ job is keyed by ``enrich:{report_id}`` so repeated
    calls coalesce. Returns ``202 Accepted`` with the queued job id (or
    ``None`` when ARQ refused because an enrichment is already pending).
    """
    try:
        job_id = await svc.enqueue_enrichment(report_id, user)
    except EnrichmentEnqueueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Enrichment queue unavailable: {exc}",
        ) from exc
    if job_id is None:
        # Authorization layer returns None when the report does not exist
        # or the caller does not own it. ARQ returning None (already-queued)
        # is fine; we still surface that as 202 with job_id=None.
        report = await svc.get_report(report_id, user)
        if report is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return {"status": "queued", "report_id": str(report_id), "job_id": job_id}


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
