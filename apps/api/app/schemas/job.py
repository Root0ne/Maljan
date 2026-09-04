"""Pydantic schemas for analysis jobs and reports."""

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# ── Job Schemas ──────────────────────────────────────────────────


class _KnownJobConfig(BaseModel):
    """The job-config keys the worker folds into the per-job Settings.

    Same choices and bounds as the core model, checked at submit time so a
    bad value is a 422 here rather than a failed job minutes later. Unknown
    keys pass through untouched.
    """

    model_config = {"extra": "allow"}

    max_iterations: Annotated[int, Field(ge=1)] | None = None
    llm_provider: Literal["openai", "anthropic", "ollama", "gemini"] | None = None
    mock_mode: bool | None = None
    # Static-analysis provider for this job; repeats StaticConfig.provider's choices.
    static_provider: Literal["ghidra", "r2", "capa_yara", "generic_mcp", "none"] | None = None
    # Sandbox provider for this job; repeats SandboxConfig.provider's choices.
    sandbox_provider: Literal["mock", "cape2", "upload", "triage"] | None = None
    # An uploaded report to attach; build_job_settings forces sandbox.provider="upload".
    sandbox_report_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def _mock_mode_cannot_consume_an_uploaded_report(self) -> "_KnownJobConfig":
        if self.mock_mode and self.sandbox_report_id is not None:
            raise ValueError("a mock run cannot consume an uploaded report")
        return self


class JobCreateRequest(BaseModel):
    """Request to start a new analysis job."""

    sample_id: uuid.UUID
    config: dict | None = Field(
        default=None,
        description="Optional pipeline config overrides (llm_provider, max_iterations, etc.)",
    )

    @field_validator("config")
    @classmethod
    def _known_keys_are_valid(cls, value: dict | None) -> dict | None:
        if value:
            nulls = [k for k in _KnownJobConfig.model_fields if k in value and value[k] is None]
            if nulls:
                raise ValueError(f"explicit null is not allowed for: {', '.join(nulls)}")
            _KnownJobConfig.model_validate(value)
        return value


class JobResponse(BaseModel):
    """Analysis job status response."""

    id: uuid.UUID
    sample_id: uuid.UUID
    # BUG-02: surface the linked sample's hash + filename so the live view shows
    # a readable identity instead of the opaque sample_id UUID before the report
    # exists. Populated from the eager-loaded ``sample`` relationship; ``None``
    # when the sample row is unavailable.
    sample_sha256: str | None = None
    sample_filename: str | None = None
    status: str
    config: dict | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None
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


# ── Sandbox Report Schemas ───────────────────────────────────────


class SandboxReportResponse(BaseModel):
    """An operator-uploaded sandbox report attached to a sample."""

    id: uuid.UUID
    format: str
    task_id: str | None
    size_bytes: int
    # Set once at upload time and never recomputed — see SandboxReportRow.
    sample_sha256_match: bool
    warning: str | None = None
    uploaded_at: datetime = Field(validation_alias="created_at")

    model_config = {"from_attributes": True, "populate_by_name": True}


class SandboxReportListResponse(BaseModel):
    """Every sandbox report attached to one sample."""

    items: list[SandboxReportResponse]
    total: int


# ── Report Schemas ───────────────────────────────────────────────


class AgentFindingResponse(BaseModel):
    """Per-agent finding detail."""

    agent_name: str
    domain: str
    claims: list | None
    dissent_items: list | None
    revision_rounds: int
    final_confidence: float
    # D15+D16: lifecycle status — defaults to "complete" so legacy rows
    # (the column was added in 20250524000000) round-trip without losing
    # meaning. ``status_reason`` carries the short failure string when
    # status is "failed" or "timeout".
    status: str = "complete"
    status_reason: str | None = None

    model_config = {"from_attributes": True}


class AgentMessageResponse(BaseModel):
    """One line of the negotiation transcript, as it was broadcast.

    Mirrors the live ``agent_message`` event payload field for field, so the
    frontend maps a replayed conversation and a live one through the same code
    path — which is the point of storing the broadcast rather than
    reconstructing it from ``agent_findings``.
    """

    seq: int
    speaker: str
    role: str
    round: int
    status: str
    text: str
    report: str | None = None
    report_truncated: bool = False
    confidence: float | None = None
    claims: list | None = None
    dissent: list | None = None
    ts: datetime | None = None

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
    # Comprehensive MalwareReport JSON (Faz 5) — ``None`` for legacy rows
    # produced before the report feature shipped. Frontend tabs fall back
    # to the legacy fields above when this is missing.
    malware_report: dict | None = None
    agent_findings: list[AgentFindingResponse]
    # The conversation itself, ordered by ``seq``. Empty for reports written
    # before ``agent_messages`` existed (migration 20260726020000) — the
    # frontend falls back to reconstructing what it can from ``agent_findings``
    # and ``negotiation_log`` for those, exactly as it did before.
    transcript: list[AgentMessageResponse] = []
    created_at: datetime

    model_config = {"from_attributes": True}


class IOCEntry(BaseModel):
    """One flattened IOC row used by the ``/iocs`` endpoint."""

    kind: str  # "domain" | "ip" | "url" | "user_agent" | "ja3" | "ja3s" | "hash"
    value: str
    is_suspicious: bool = False
    notes: str | None = None


class IOCListResponse(BaseModel):
    """Container for the ``/iocs`` endpoint output."""

    items: list[IOCEntry]
    total: int
