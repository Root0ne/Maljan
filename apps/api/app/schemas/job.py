"""Pydantic schemas for analysis jobs and reports."""

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, Field, ValidationInfo, field_validator, model_validator

# ── Job Schemas ──────────────────────────────────────────────────

# The validation context key a caller hands the plugin allow-list to judge
# by: the worker, its job's own; the submit route hands none, and the stored
# list this process last read is used.
PLUGINS_ALLOWED_CONTEXT = "plugins_allowed"


def _registered(value: str | None, field: str, kind: str, info: ValidationInfo) -> str | None:
    """``value`` when it is a shipped id or an installed plugin of ``kind`` the allow-list
    names, read from package metadata; refused with the shipped ids otherwise."""
    from maljan.core.plugins import id_refusal, shipped_ids

    if value is None:
        return value
    context = info.context if isinstance(info.context, dict) else {}
    refused = id_refusal(kind, value, context.get(PLUGINS_ALLOWED_CONTEXT))
    if not refused:
        return value
    raise ValueError(f"{field} must be one of: {', '.join(shipped_ids(kind))}; {refused}")


class _KnownJobConfig(BaseModel):
    """The job-config keys the worker folds into the per-job Settings.

    Same choices and bounds as the core model, checked at submit time so a
    bad value is a 422 here rather than a failed job minutes later. Unknown
    keys pass through untouched.
    """

    model_config = {"extra": "allow"}

    max_iterations: Annotated[int, Field(ge=1)] | None = None
    # The providers for this job, each a name its registry holds (a provider
    # registered at runtime is accepted the day it is registered) or an
    # installed plugin the allow-list names, read from package metadata
    # (``maljan.core.plugins.id_refusal``).
    llm_provider: str | None = None
    mock_mode: bool | None = None
    static_provider: str | None = None
    sandbox_provider: str | None = None
    # An uploaded report to attach; build_job_settings forces sandbox.provider="upload".
    sandbox_report_id: uuid.UUID | None = None
    # The agent profile for this job. A free string rather than a Literal
    # because the valid values are settings an operator writes, not a registry
    # the code owns; the route checks it against the effective profile map at
    # submit time, which is where "known" can actually be answered.
    profile: str | None = None
    # The questions the analyst asks of this run, each answered by the report
    # in a fixed vocabulary (``maljan.reporting.question_round``). Each must
    # hold some text; none asks nothing.
    questions: list[str] | None = None

    @field_validator("questions")
    @classmethod
    def _each_question_says_something(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and any(not question.strip() for question in value):
            raise ValueError("questions: each question must hold some text")
        return value

    @field_validator("llm_provider")
    @classmethod
    def _a_registered_llm_provider(cls, value: str | None, info: ValidationInfo) -> str | None:
        from maljan.llm.provider_base import missing_block

        value = _registered(value, "llm_provider", "llm", info)
        # A provider with no settings block of its own names no role model;
        # the job would run with none, so it is refused here.
        problem = missing_block(value) if value is not None else None
        if problem:
            raise ValueError(f"llm_provider: {problem}")
        return value

    @field_validator("static_provider")
    @classmethod
    def _a_registered_static_provider(cls, value: str | None, info: ValidationInfo) -> str | None:
        return _registered(value, "static_provider", "static", info)

    @field_validator("sandbox_provider")
    @classmethod
    def _a_registered_sandbox_provider(cls, value: str | None, info: ValidationInfo) -> str | None:
        return _registered(value, "sandbox_provider", "sandbox", info)

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


class RosterAgent(BaseModel):
    """One participant of a run: its key, the label it is drawn under, its
    role, the stages it speaks in, and who can task it.

    A specialist that no stage names — the agents a lead reaches through its
    ``ask_<key>`` tools — has an empty ``stages`` and a ``via`` naming the
    agents that can task it. An agent a stage names carries no ``via``:
    nothing had to ask it to be there.
    """

    key: str
    label: str
    role: str
    stages: list[str] = []
    via: list[str] | None = None


class RosterStage(BaseModel):
    """One step of the team, and who takes part in it."""

    key: str
    label: str
    kind: str
    agents: list[str] = []


class JobRoster(BaseModel):
    """Everyone who can speak in one run, and the stages they speak in.

    ``servers`` names each tool server whose display name is not its key, by
    its key; ``None`` when no server has a label of its own.
    """

    agents: list[RosterAgent] = []
    stages: list[RosterStage] = []
    servers: dict[str, str] | None = None

    @field_validator("servers", mode="before")
    @classmethod
    def _labels_or_none(cls, value: Any) -> Any:
        # A roster is how the console draws names: anything but a map of
        # labels is read as none, and a label that is not text is left out,
        # rather than failing the response it is in.
        if not isinstance(value, dict):
            return None
        return {str(k): str(v) for k, v in value.items() if isinstance(v, str)}


class UnavailableTool(BaseModel):
    """A tool a job would call that the host running its server cannot run.

    Named when the job is submitted (``services.tool_availability``), before
    any of it runs: the job is still accepted, and this is the warning.
    """

    server: str
    tool: str
    # The server's own words: "capa is not installed (No module named 'capa')".
    reason: str
    # What to do about it: "... uv sync --extra capa".
    remediation: str = ""
    # What the tool still answers without it; empty when it answers nothing.
    still_answers: str = ""
    # The words the run's degraded block would use for the same tool.
    degradation_reason: str
    # The manifest's code: ``not_configured`` for a setting left unset, which
    # a run lists as the operator's choice rather than as a degradation.
    manifest_code: str = ""


class JobResponse(BaseModel):
    """Analysis job status response."""

    id: uuid.UUID
    sample_id: uuid.UUID
    # Surface the linked sample's hash + filename so the live view shows
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
    # Who can speak in this run, with the label an operator gave each agent
    # and the stages it takes part in. Filled on the single-job endpoint,
    # where the team can be resolved; ``None`` in a listing, which is a page
    # of rows rather than a run somebody is watching.
    roster: JobRoster | None = None
    # The tools this job would call that this host cannot run, each with why
    # and the remedy. Filled on the answer to ``POST /jobs`` alone, and only
    # when there is one to name; ``None`` everywhere else.
    unavailable_tools: list[UnavailableTool] | None = None

    model_config = {"from_attributes": True}


class JobListResponse(BaseModel):
    """Paginated job list."""

    items: list[JobResponse]
    total: int
    page: int
    page_size: int


class FollowUpRequest(BaseModel):
    """A question asked of a finished job, answered from what the run stored."""

    question: str

    @field_validator("question")
    @classmethod
    def _the_question_says_something(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("question: the question must hold some text")
        return value


class FollowUpResponse(BaseModel):
    """One follow-up question and its answer (``app.models.follow_up.JobFollowUp``).

    ``answer`` is the answer as ``reporting.models.QuestionAnswer`` dumps it:
    the outcome, the report model's words, the ids cited, the platform's
    checks. ``report_sha256`` is the digest of the stored report it was
    answered from; ``record`` the keyed record the audit chain holds, ``None``
    when the platform held no chain key (``notes`` says so).
    """

    id: uuid.UUID
    job_id: uuid.UUID
    report_id: uuid.UUID
    question: str
    outcome: str
    answer: dict[str, Any]
    model: str
    model_source: str
    report_sha256: str
    record: dict[str, Any] | None = None
    notes: list[str] = []
    answered_at: datetime


class FollowUpListResponse(BaseModel):
    """A job's follow-up questions, oldest first."""

    job_id: uuid.UUID
    follow_ups: list[FollowUpResponse]


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
    # For a report accepted unread: a proposed format declaration read from its
    # shape (``maljan.core.report_proposals``), each field with its evidence and
    # confidence, for an operator to accept or edit. Nothing reads it but the
    # console.
    proposal: dict[str, Any] | None = None

    model_config = {"from_attributes": True, "populate_by_name": True}


class AcceptReportFormatRequest(BaseModel):
    """A report format declaration an operator accepts, and the unread upload it is for."""

    declaration: dict[str, Any]
    sample_id: uuid.UUID
    report_id: uuid.UUID


class SandboxReportListResponse(BaseModel):
    """Every sandbox report attached to one sample."""

    items: list[SandboxReportResponse]
    total: int


class SignatureScaleResponse(BaseModel):
    """A signature severity scale: the rung each score from 1 to ``max`` means."""

    name: str
    max: int
    rungs: list[str]


class SandboxReportFormatResponse(BaseModel):
    """One declared sandbox report format, as the upload route and the run read it."""

    name: str
    builtin: bool
    # Whether ``sandbox.upload.allowed_formats`` accepts it for upload.
    allowed: bool
    reader: str
    detect: list[list[dict[str, Any]]]
    task_id_paths: list[str]
    target_sha256_paths: list[str]
    signature_scale: SignatureScaleResponse | None = None
    # The operator's declaration as written (only the fields it sets), or null
    # for a built-in served as shipped. The fields above are what is in effect.
    declared: dict[str, Any] | None = None


class SandboxReportFormatListResponse(BaseModel):
    """Every declared sandbox report format, in the order a payload is tried against them."""

    items: list[SandboxReportFormatResponse]
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

    ``seq`` is the number the publisher gave the message when it went out, and
    is the identity a client collapses a stored row onto its live twin with.
    It is ``None`` for a run recorded before the publisher numbered anything:
    such a row carries its old position within the report, which is a
    different number from the same run's live events, and sending it would
    have a client draw every line of that run twice. The endpoint tells the
    two apart from the rows themselves — see ``app.api.v1.reports._is_numbered``.
    """

    seq: int | None = None
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
    # The agent this line was said to, or ``None`` for a line said to the room.
    addressed_to: str | None = None
    # What the line is, the stage it was said in and the operator's label for
    # its speaker. ``None`` on a run recorded before the columns existed, and
    # the client is required to fall back rather than read the absence as a
    # value: a missing ``kind`` is a kind that was never written down, not a
    # ``says``.
    kind: str | None = None
    stage: str | None = None
    display_name: str | None = None
    ts: datetime | None = None

    model_config = {"from_attributes": True}


class ReportDetailResponse(BaseModel):
    """Full analysis report."""

    id: uuid.UUID
    job_id: uuid.UUID
    verdict: str
    # How the verdict above was read, as one word: ``stated`` when the judge
    # wrote it, ``unrecognised`` when it wrote something this pipeline could
    # not read, ``unstated`` when it wrote nothing and the bundle's objects
    # answered, ``fallback`` when the answer was not a bundle at all. The two
    # middle readings publish the inconclusive verdict, which is one of the
    # same three words a judge may state — so without this a client cannot
    # tell "the judge concluded Suspicious" from "the judge's conclusion could
    # not be read", and the difference lives only in a free-text degradation
    # sentence. ``None`` for a report stored before the field existed.
    verdict_reading: str | None = None
    # ``None`` when nothing assessed one. A client shows "not assessed" for it
    # rather than 0, which is a confidence and a different statement.
    overall_confidence: float | None
    malware_category: str | None
    stix_bundle: dict | None
    mitre_techniques: list | None
    agent_reports: dict | None
    negotiation_log: dict | None
    run_summary: dict | None
    # Comprehensive MalwareReport JSON — ``None`` for legacy rows
    # produced before the report feature shipped. Frontend tabs fall back
    # to the legacy fields above when this is missing.
    malware_report: dict | None = None
    # The console tab each section an operator's tool produced is drawn on,
    # by section key (``maljan.reporting.section_tabs``): read from the kind
    # its tool declared, else the analyst whose call it cites. Computed when
    # the report is served, never stored; a section it does not name is
    # placed by its key, as before. ``None`` when no section is placed.
    section_tabs: dict[str, str] | None = None
    # Set on a report stored before its IOC table, ``/iocs`` and MISP
    # attributes were built by the current publish rule: they are rebuilt when
    # served, while the stored STIX bundle is served as it was rendered then,
    # and this says so. ``None`` on a report built under the current rule.
    stix_note: str | None = None
    # A report kept from a run that failed after the report was built says so
    # here: where the run failed and the error id. ``None`` on a report of a
    # completed run.
    incomplete_reason: str | None = None
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

    # The row kind of the report's IOC table the row is: "hash" | "domain" |
    # "ip" | "url" | "email" | "user_agent" | "ja3" | "ja3s" | "path" |
    # "registry" | "mutex" | "scheduled_task" | "service" | "command" | ...
    kind: str
    value: str
    is_suspicious: bool = False
    notes: str | None = None
    # Where the row came from: ``sandbox`` for something the sample resolved,
    # reached or requested, ``analyst`` for something an agent put in an
    # artefact, ``strings`` for a run of bytes in the file that has the shape
    # of one, ``judge`` for a value the export publishes from the judge's own
    # indicators. The service has always attached it and this model did not declare
    # it, so ``response_model`` dropped it and a name only the sample's own
    # bytes knew shipped looking exactly like one the sandbox watched.
    source: str | None = None
    # Whether the publish rule would publish this row — the same rule the STIX
    # bundle is built with. A feed another system consumes returns only these
    # by default; ``include`` widens it.
    published: bool = True
    # The publish rule's answer as the report's IOC table prints it: ``yes:``
    # and why the row is published, or ``no:`` and why not. Absent on a row
    # the service did not ask the rule about.
    publish_answer: str | None = None
    # For a domain, address or URL a recovering tool read from text the sample
    # hid: which tool (``floss``, emulation; ``decode_string_blobs``, a static
    # decoding of the file's bytes), its ledger entry and where in the file,
    # as the report's IOC table states it. Absent for every other row.
    recovered_by: str | None = None


class IOCListResponse(BaseModel):
    """Container for the ``/iocs`` endpoint output."""

    items: list[IOCEntry]
    total: int
