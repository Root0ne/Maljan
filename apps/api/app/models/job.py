"""AnalysisJob model — tracks pipeline execution lifecycle."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class AnalysisJob(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A single analysis pipeline execution."""

    __tablename__ = "analysis_jobs"

    # Foreign keys
    sample_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("samples.id"), nullable=False, index=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )

    # Lifecycle
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False, index=True)
    # Valid statuses: pending, running, completed, failed, cancelled

    # Timestamps
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # ``Numeric(10, 2)`` so sub-second analyses (e.g. mock pipeline at ~0.7s)
    # survive serialization. Integer truncated to 0 and broke the dashboard
    # "AVG DURATION" tile + analysis page duration badge.
    duration_seconds: Mapped[float | None] = mapped_column(Numeric(10, 2), nullable=True)

    # Configuration snapshot (LLM provider, max_iterations, etc.)
    config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Error handling
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    sample = relationship("Sample", back_populates="jobs")
    created_by_user = relationship("User", back_populates="jobs")
    report = relationship("AnalysisReport", back_populates="job", uselist=False, lazy="selectin")

    # BUG-02 (2026-06-23 live-UI audit): the job API exposed only the opaque
    # ``sample_id`` UUID, so the live analysis header showed a UUID instead of
    # the sample hash/name until the report landed. These read-only properties
    # surface the linked sample's hash + filename on ``JobResponse``. Callers
    # eager-load ``sample`` (AnalysisService.get_job / list_jobs); the inspection
    # guard returns None rather than triggering an async lazy load if they don't.
    @property
    def sample_sha256(self) -> str | None:
        from sqlalchemy import inspect as sa_inspect

        if "sample" in sa_inspect(self).unloaded:
            return None
        return self.sample.sha256 if self.sample is not None else None

    @property
    def sample_filename(self) -> str | None:
        from sqlalchemy import inspect as sa_inspect

        if "sample" in sa_inspect(self).unloaded:
            return None
        return self.sample.original_filename if self.sample is not None else None

    def __repr__(self) -> str:
        return f"<AnalysisJob {self.id} status={self.status}>"
