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
    # ``NULL`` when nothing assessed a confidence: a verdict the pipeline
    # wrote itself because the judge never answered has none, and storing 0.0
    # there would print "0/100" for a run that reached no number at all.
    overall_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    malware_category: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Structured data (stored as JSONB for flexibility)
    stix_bundle: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # The judge's own bundle, as the judge wrote it when ``as_written`` is
    # true, and the map from each label the judge wrote to the id it was
    # published under: ``{"bundle": {...}, "labels": {...}, "as_written": ...}``.
    # The export's decline rows say an object "is unchanged in the judge's own
    # bundle"; this is that bundle. ``NULL`` on a report stored before it was
    # kept, or when the judge produced none.
    judge_stix_bundle: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    mitre_techniques: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    agent_reports: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    negotiation_log: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    run_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Comprehensive MalwareReport — full Pydantic model_dump from
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
        confidence = (
            "not assessed" if self.overall_confidence is None else f"{self.overall_confidence:.2f}"
        )
        return f"<AnalysisReport verdict={self.verdict} confidence={confidence}>"


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
    #   "no_claims"- analyst read its data and its model ended without a
    #                structured report, even after being asked for one
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
    ``agent_message`` event as it is published and persists the list as it was
    published — scrubbed of credential shapes, URL userinfo and host paths as
    the copy is taken, exactly as the socket saw it — so the conversation a reader
    sees a month later is not a reconstruction of the live one, and not a more
    revealing version of it either: it is the same recording. The verbatim
    text of a tool call stays on the evidence ledger, behind the report's
    ownership check. Columns mirror the payload built by
    ``maljan.pipeline.events.emit_agent_message`` field for field; the frontend
    maps them straight onto its transcript model with no reshaping.

    Rows are immutable and append-only. ``seq`` is the number the publisher
    gave the message when it went out — the same one the live event carries —
    and is the ordering key: round number alone cannot separate the speakers
    inside a round, and timestamps are too coarse for messages emitted in the
    same millisecond. One number for the live message and its stored row is
    what lets a console holding both collapse them into one line instead of
    drawing it twice. It counts the whole run's events rather than only this
    conversation, so it is monotonic and sparse.
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
    # What the line *is*, from ``maljan.pipeline.events.MESSAGE_KINDS``: a
    # report, a delegated ask, the answer to one, a verdict, a system notice.
    # NULL on a row written before the column existed, and NULL is the only
    # honest value there: such a row was recorded without its kind, so a
    # reader falls back to deriving one rather than claiming it was a
    # ``says``. Without it a stored ask and its answer replay as two plain
    # lines and lose the arrow between them, although ``addressed_to`` — the
    # other half of that pair — is stored.
    kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # The team stage the speaker was working in, when the producer knew it.
    # The console groups a replayed conversation by it; without it every
    # replayed line falls into one unnamed stage.
    stage: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # The label the operator gave this agent, so a replay names it the way the
    # live view did. Never a substitute for ``speaker``, which stays the
    # identity everything joins on.
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Negotiation round; 0 for the initial pass.
    round: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # complete | no_data | no_claims | failed | timeout — the AgentFinding vocabulary.
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

    # The agent this line was said *to*, when it was said to one agent rather
    # than to the room: a delegated ask names the callee and its answer names
    # the caller. NULL everywhere else, which is what a line to the room is.
    # Without it a stored ask and a stored report by the same agent in the
    # same round were indistinguishable, and the console had to key them apart
    # on a digest of the text.
    addressed_to: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # When the pipeline emitted it, not when the row was written — the run can
    # finish minutes after the message was spoken.
    ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    report_ref = relationship("AnalysisReport", back_populates="transcript")

    def __repr__(self) -> str:
        return f"<AgentMessage #{self.seq} {self.speaker}/{self.role} round={self.round}>"
