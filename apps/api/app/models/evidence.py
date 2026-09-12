"""One tool call a job made, kept so the report's citations resolve.

A report section says which ledger entries it was built from; this table is
what those ids point at. Rows hang off the job rather than the report because
a run that failed before the report assembled still made the calls, and the
calls are the part worth keeping.

Append-only and immutable. ``seq`` is the order the ids were issued in across
the whole job, and it is the ordering key: agent names cannot separate calls
that two analysts made in parallel, and ``created_at`` is written when the row
is persisted, long after the call happened.
"""

import uuid
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class EvidenceEntry(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "evidence_entries"

    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # The citation string the model was shown and the report quotes, e.g.
    # ``ev_0007``.
    entry_id: Mapped[str] = mapped_column(String(32), nullable=False)
    stage: Mapped[str] = mapped_column(String(32), nullable=False, default="analysis")
    agent: Mapped[str] = mapped_column(String(100), nullable=False)
    # The tool server the tool came from; NULL for an in-process tool.
    server: Mapped[str | None] = mapped_column(String(100), nullable=True)
    tool: Mapped[str] = mapped_column(String(200), nullable=False)

    ok: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    args: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # Text, not String(n): a decompilation runs to thousands of characters and
    # the producer already caps it (schemas.evidence).
    output: Mapped[str] = mapped_column(Text, nullable=False, default="")
    structured: Mapped[Any | None] = mapped_column(JSONB, nullable=True)

    def __repr__(self) -> str:
        return f"<EvidenceEntry {self.entry_id} {self.agent}/{self.tool} ok={self.ok}>"
