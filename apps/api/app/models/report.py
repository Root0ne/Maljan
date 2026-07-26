"""Report models — analysis results and per-agent findings."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class AnalysisReport(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Final analysis report produced by the pipeline."""

    __tablename__ = "analysis_reports"

    # 1:1 with AnalysisJob
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analysis_jobs.id"), unique=True, nullable=False
    )

    # Verdict
    verdict: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    overall_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    malware_category: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Structured data (stored as JSONB for flexibility)
    stix_bundle: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    mitre_techniques: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    agent_reports: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    negotiation_log: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    run_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Comprehensive MalwareReport (Faz 5) — full Pydantic model_dump from
    # the pipeline's report_node. ``NULL`` for legacy rows produced before
    # the report feature shipped; the API ``/full`` endpoint surfaces this
    # field directly to consumers.
    malware_report: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    job = relationship("AnalysisJob", back_populates="report")
    agent_findings = relationship(
        "AgentFinding", back_populates="report", lazy="selectin", cascade="all, delete-orphan"
    )
    transcript = relationship(
        "AgentMessage",
        # ``report_ref``, not ``report``: AgentMessage already uses ``report``
        # for the speaker's prose body.
        back_populates="report_ref",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="AgentMessage.seq",
    )

    def __repr__(self) -> str:
        return f"<AnalysisReport verdict={self.verdict} confidence={self.overall_confidence:.2f}>"


class AgentFinding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Per-agent detailed findings (ISR decomposition)."""

    __tablename__ = "agent_findings"

    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analysis_reports.id"), nullable=False, index=True
    )

    agent_name: Mapped[str] = mapped_column(String(100), nullable=False)
    domain: Mapped[str] = mapped_column(String(50), nullable=False)

    # Structured claim data
    claims: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    dissent_items: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    revision_rounds: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    final_confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # D15+D16: lifecycle status separate from confidence so the UI can
    # tell a successful analyst with low confidence ("complete /
    # benign") apart from one that failed entirely ("static analyst
    # crashed loading the APK as a PE binary"). The 2026-05-23 E2E run
    # surfaced this gap when the Ghidra static loop produced 0 claims
    # but the row was persisted as "Benign 0%" — indistinguishable from
    # a benign verdict.
    #
    # Values:
    #   "complete" - analyst returned claims as expected
    #   "no_data"  - analyst ran but produced 0 claims (e.g. nothing to
    #                report, or LLM refused to contradict an obvious
    #                empty sandbox report)
    #   "failed"   - analyst raised / returned ``[ERROR]`` text
    #   "timeout"  - analyst ReAct loop hit its asyncio.wait_for limit
    #
    # ``server_default`` is set so the Alembic migration backfills
    # existing rows with the legacy meaning.
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="complete",
        server_default="complete",
        index=True,
    )
    status_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Relationships
    report = relationship("AnalysisReport", back_populates="agent_findings")

    def __repr__(self) -> str:
        return (
            f"<AgentFinding {self.agent_name} status={self.status} "
            f"confidence={self.final_confidence:.2f}>"
        )


class AgentMessage(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One line of the negotiation transcript, exactly as it was broadcast.

    ``agent_findings`` records where each agent *ended up*: one row per agent,
    holding its final ISR. That is the right shape for "what did the static
    analyst conclude", and the wrong shape for "what was said, in order" — the
    per-round positions are overwritten in pipeline state as the negotiation
    loops, so an agent's round-2 argument existed nowhere but the live event
    stream, which expires after 24 hours. The mediator's rounds survived (in
    ``negotiation_log``); the agents' replies to them did not, and neither did
    the sycophancy detector's intervention.

    This table is that stream, written down. The worker tees every
    ``agent_message`` event as it is published and persists the list verbatim,
    so the conversation a reader sees a month later is not a reconstruction of
    the live one — it is the same recording. Columns mirror the payload built by
    ``maljan.pipeline.events.emit_agent_message`` field for field; the frontend
    maps them straight onto its transcript model with no reshaping.

    Rows are immutable and append-only. ``seq`` is emission order within the
    run, and is the ordering key: round number alone cannot separate the
    speakers inside a round, and timestamps are too coarse for messages emitted
    in the same millisecond.
    """

    __tablename__ = "agent_messages"

    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_reports.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    seq: Mapped[int] = mapped_column(Integer, nullable=False)

    speaker: Mapped[str] = mapped_column(String(100), nullable=False)
    # analyst | reviser | negotiator | judge | system
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    # Negotiation round; 0 for the initial pass.
    round: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # complete | no_data | failed | timeout — same vocabulary as AgentFinding.
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="complete")

    # The skimmable one-line body.
    text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # The speaker's full prose report for this round, when it wrote one. Text,
    # not String(n): analyst reports run to thousands of characters and the
    # producer already caps them (events.REPORT_CHAR_LIMIT).
    report: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_truncated: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )

    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    claims: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    dissent: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # When the pipeline emitted it, not when the row was written — the run can
    # finish minutes after the message was spoken.
    ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    report_ref = relationship("AnalysisReport", back_populates="transcript")

    def __repr__(self) -> str:
        return f"<AgentMessage #{self.seq} {self.speaker}/{self.role} round={self.round}>"
