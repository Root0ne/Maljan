"""Pydantic schemas for analysis jobs and reports."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

# ── Job Schemas ──────────────────────────────────────────────────


class JobCreateRequest(BaseModel):
    """Request to start a new analysis job."""

    sample_id: uuid.UUID
    config: dict | None = Field(
        default=None,
        description="Optional pipeline config overrides (llm_provider, max_iterations, etc.)",
    )


class JobResponse(BaseModel):
    """Analysis job status response."""

    id: uuid.UUID
    sample_id: uuid.UUID
    status: str
    config: dict | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: int | None
    error_message: str | None

    model_config = {"from_attributes": True}


class JobListResponse(BaseModel):
    """Paginated job list."""

    items: list[JobResponse]
    total: int
    page: int
    page_size: int


# ── Sample Schemas ───────────────────────────────────────────────


class SampleResponse(BaseModel):
    """Uploaded sample metadata."""

    id: uuid.UUID
    sha256: str
    md5: str | None
    original_filename: str
    file_size_bytes: int
    mime_type: str | None
    uploaded_at: datetime = Field(validation_alias="created_at")

    model_config = {"from_attributes": True, "populate_by_name": True}


class SampleListResponse(BaseModel):
    """Paginated sample list."""

    items: list[SampleResponse]
    total: int
    page: int
    page_size: int


# ── Report Schemas ───────────────────────────────────────────────


class ReportSummaryResponse(BaseModel):
    """Condensed report for list views."""

    id: uuid.UUID
    job_id: uuid.UUID
    verdict: str
    overall_confidence: float
    malware_category: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AgentFindingResponse(BaseModel):
    """Per-agent finding detail."""

    agent_name: str
    domain: str
    claims: list | None
    dissent_items: list | None
    revision_rounds: int
    final_confidence: float

    model_config = {"from_attributes": True}


class ReportDetailResponse(BaseModel):
    """Full analysis report."""

    id: uuid.UUID
    job_id: uuid.UUID
    verdict: str
    overall_confidence: float
    malware_category: str | None
    stix_bundle: dict | None
    mitre_techniques: list | None
    agent_reports: dict | None
    negotiation_log: dict | None
    run_summary: dict | None
    agent_findings: list[AgentFindingResponse]
    created_at: datetime

    model_config = {"from_attributes": True}
