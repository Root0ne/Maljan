"""Report models — analysis results and per-agent findings."""

import uuid

from sqlalchemy import Float, ForeignKey, Integer, String
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

    # Relationships
    job = relationship("AnalysisJob", back_populates="report")
    agent_findings = relationship(
        "AgentFinding", back_populates="report", lazy="selectin", cascade="all, delete-orphan"
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

    # Relationships
    report = relationship("AnalysisReport", back_populates="agent_findings")

    def __repr__(self) -> str:
        return f"<AgentFinding {self.agent_name} confidence={self.final_confidence:.2f}>"
