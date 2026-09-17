"""The live conversation of one job, written down as it happens.

The events a run publishes lived only in a Redis stream with a 24 h TTL and a
1 000-entry cap. A run longer than the cap lost its beginning while it was
still running; a run whose report never assembled — a crash, a cancellation —
lost the whole conversation a day later, which is exactly the run somebody
wants to read afterwards.

Rows hang off the job rather than the report for that reason, the same way the
evidence ledger does: the conversation is a record of what the run did and is
worth keeping whether or not a verdict came out of it.

``seq`` is the publisher's per-job counter and is the ordering key. It is
unique within a job, which is what lets a client ask for "everything after N"
and get an answer that is neither short nor doubled, and what lets a reconnect
cost one query rather than a re-read of the whole stream.

Append-only and immutable. Nothing edits an event after it is published; a
correction is another event.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class JobEvent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "job_events"

    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    # ``agent_message``, ``tool_call_started``, … — the event type as the
    # publisher sent it. Not an enum: a new type is a new console feature, not
    # a migration.
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    # The event's ``data``, exactly as it went out on the socket, so a replay
    # and a live view are the same recording rather than two accounts of it.
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # When the publisher stamped it, not when the row was written: a batch
    # lands up to two seconds after the events in it were published.
    ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (UniqueConstraint("job_id", "seq", name="uq_job_events_job_seq"),)

    def __repr__(self) -> str:
        return f"<JobEvent #{self.seq} {self.type} job={self.job_id}>"
