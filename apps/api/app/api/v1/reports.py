"""Report endpoints — detail, STIX export, MITRE export, negotiation timeline.

Uses ReportService for business logic separation.
"""

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import get_current_user, require_active_user
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
    """Get MITRE ATT&CK technique mappings.

    Returns ``{"techniques": []}`` when the report exists but the pipeline
    did not map any ATT&CK techniques (mock mode, benign sample, narrative
    LLM unavailable). Only an unknown / unauthorized report id returns 404 —
    "empty MITRE list" is a legitimate analytical outcome, not a missing
    resource.
    """
    techniques = await svc.get_mitre_techniques(report_id, user)
    if techniques is None:
        # Distinguish "report missing" from "no MITRE data" by checking
        # whether the report itself exists for this user.
        if await svc.get_report(report_id, user) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
        return {"techniques": []}
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


@router.get("/{report_id}/html", response_class=HTMLResponse)
async def get_full_malware_report_html(
    report_id: uuid.UUID,
    download: bool = Query(
        default=False,
        description="Serve as a file download instead of rendering in the browser.",
    ),
    user: User = Depends(get_current_user),
    svc: ReportService = Depends(_get_service),
) -> Response:
    """Render the comprehensive report as a standalone HTML document (Phase 6).

    Self-contained: inline CSS and inline SVG figures, no external requests, so
    it can be archived or opened in an offline analysis VM. Served inline by
    default so it opens in a tab; ``?download=true`` forces a file save.
    """
    rendered = await svc.get_malware_report_html(report_id, user)
    if rendered is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found or HTML could not be rendered",
        )
    return Response(
        content=rendered.content,
        media_type="text/html; charset=utf-8",
        headers=_disposition(rendered.filename, attachment=download),
    )


@router.get(
    "/{report_id}/pdf",
    response_class=Response,
    responses={200: {"content": {"application/pdf": {}}}},
)
async def get_full_malware_report_pdf(
    report_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: ReportService = Depends(_get_service),
) -> Response:
    """Render the comprehensive report as a print-ready PDF (Phase 6).

    Same document as ``/html``, printed through WeasyPrint: A4, numbered pages,
    a linked table of contents and the deterministic figures in place. Returns
    503 (not 500) when the PDF toolchain is unavailable on the host — the report
    is fine, only this one export cannot be produced.
    """
    from maljan.reporting.renderers import PdfUnavailableError

    try:
        rendered = await svc.get_malware_report_pdf(report_id, user)
    except PdfUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    if rendered is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found or PDF could not be rendered",
        )
    return Response(
        content=rendered.content,
        media_type="application/pdf",
        headers=_disposition(rendered.filename, attachment=True),
    )


def _disposition(filename: str, *, attachment: bool) -> dict[str, str]:
    """Build a Content-Disposition header (the name is sanitised upstream)."""
    kind = "attachment" if attachment else "inline"
    return {"Content-Disposition": f'{kind}; filename="{filename}"'}


@router.get("/{report_id}/iocs", response_model=IOCListResponse)
async def get_full_malware_report_iocs(
    report_id: uuid.UUID,
    kind: str | None = Query(
        default=None,
        description="Filter to one of: hash, domain, ip, url, user_agent, ja3, ja3s",
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
    calls coalesce. The response surfaces three distinct states so the UI can
    show "queued for enrichment" vs "already in flight" without ambiguity:

      * ``queued`` + ``job_id``: a fresh ARQ task was scheduled.
      * ``already_queued`` + ``job_id=null``: ARQ refused because an
        enrichment for this report is still pending or running.
      * 404: the report does not exist or the caller does not own it.
    """
    # Verify ownership up-front so a missing report cannot be confused with an
    # "already_queued" idempotent response.
    report_row = await svc.get_report(report_id, user)
    if report_row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    # Wave 9 (2026-05-29) pre-flight: skip the enqueue when the report
    # carries no network IOCs to enrich. The 2026-05-29 Linux ELF audit
    # found that ELF samples with no PCAP / sandbox network trace queued
    # an ARQ job that silently no-op'd; surfacing ``skipped_no_network_iocs``
    # makes the UI's "Enrich" button informative instead of misleading.
    _mr = report_row.malware_report or {}
    _net = _mr.get("network") if isinstance(_mr, dict) else None
    if not _net or (not (_net.get("domains") or []) and not (_net.get("ips") or [])):
        return {
            "status": "skipped_no_network_iocs",
            "report_id": str(report_id),
            "job_id": None,
        }

    try:
        job_id = await svc.enqueue_enrichment(report_id, user)
    except EnrichmentEnqueueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Enrichment queue unavailable: {exc}",
        ) from exc
    return {
        "status": "queued" if job_id else "already_queued",
        "report_id": str(report_id),
        "job_id": job_id,
    }


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


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    report_id: uuid.UUID,
    user: User = Depends(require_active_user),
    svc: ReportService = Depends(_get_service),
) -> None:
    """Delete a single analysis report.

    Audit 2026-07-26 (Ö4): reports could be created but never removed, so a
    mis-run or duplicate analysis stayed in the list forever. The owning job is
    kept — only its report (and the agent findings that cascade from it) is
    removed, so the job history stays intact and the sample can be re-analysed.
    """
    deleted = await svc.delete_report(report_id, user)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
