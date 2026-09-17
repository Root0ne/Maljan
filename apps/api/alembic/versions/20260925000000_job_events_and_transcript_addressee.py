"""Add ``job_events``, and the addressee column the transcript was missing.

Two changes, one revision, because they are two halves of one thing: the
conversation of a run, kept past the run.

``job_events`` is the live feed written down. It lived only in a Redis stream
with a day's TTL and a thousand-entry cap, so a long run lost its own
beginning while it was still going, and a run that failed or was cancelled —
which writes no report — lost the whole conversation a day later. Rows hang
off the job, like the evidence ledger and for the same reason: what the run
did is worth keeping whether or not a verdict came out of it. ``seq`` is the
publisher's per-job counter and is unique within the job, which is what makes
"everything after N" answerable.

``agent_messages.addressed_to`` is the other half. A delegated line is said to
one agent rather than to the room, and the live event has carried the
addressee since delegation landed while the stored row had no column for it.
The console therefore could not tell a stored ask from a stored report by the
same agent in the same round, and had to key the two apart on a digest of the
text. Existing rows are left NULL, which is what they were: a line said to the
room.

The ``id`` column carries no server-side default, matching every other table
built on ``UUIDPrimaryKeyMixin``: the mixin generates the value in Python
before the row is ever sent to the database.

Revision ID: 20260925000000
Revises: 20260924000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260925000000"
down_revision = "20260924000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "job_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["job_id"], ["analysis_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        # Unique rather than merely indexed: a resumed client asks for
        # everything after a cursor, and a doubled ``seq`` is a message it
        # draws twice with no way to tell which copy is which. It also makes a
        # re-published batch idempotent instead of silently doubling the feed.
        sa.UniqueConstraint("job_id", "seq", name="uq_job_events_job_seq"),
    )
    # Every query this table serves is "one job's feed after a cursor", which
    # the unique constraint's own index already answers; this one exists for
    # the retention sweep, which walks by age across all jobs.
    op.create_index("ix_job_events_ts", "job_events", ["ts"])

    op.add_column("agent_messages", sa.Column("addressed_to", sa.String(length=100), nullable=True))


def downgrade() -> None:
    op.drop_column("agent_messages", "addressed_to")
    op.drop_index("ix_job_events_ts", table_name="job_events")
    op.drop_table("job_events")
