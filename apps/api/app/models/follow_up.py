"""A question an analyst asked of a finished job, and the answer the stored run gave.

One row per follow-up question (``app.services.follow_up``). The stored report
is never changed by one: the row names the report it was answered from and
that report's digest as stored (``ledger_chain.report_digest``), and carries a
keyed record of itself that a chained ``report.follow_up`` audit row holds as
well, so a follow-up is checked against the report it was answered from the
way an amendment is.

Append-only: nothing edits a follow-up after it is written; a new question is
a new row.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class JobFollowUp(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "job_follow_ups"

    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # The stored report the question was answered from.
    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_reports.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asked_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    question: Mapped[str] = mapped_column(Text, nullable=False)
    # The word the answer stands by (``reporting.models.QuestionOutcome``).
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    # The answer as ``reporting.models.QuestionAnswer`` dumps it.
    answer: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    # The model asked, as its label reads, and where that model came from
    # (``reporting.follow_up.RUN_MODEL`` and the rest).
    model: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    model_source: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # The digest of the stored report row it was answered from, as it read then.
    report_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    # The keyed record a chained ``report.follow_up`` audit row holds
    # (``ledger_chain.follow_up_record``); ``NULL`` when the platform held no
    # chain key, which ``notes`` says.
    record: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # What the answer could not use or record, in the platform's words: the
    # stored rows that did not read, what the reporter's prompt could not hold,
    # a record not chained and why.
    notes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    answered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:
        return f"<JobFollowUp {self.id} job={self.job_id} outcome={self.outcome}>"
