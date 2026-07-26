"""Add ``agent_messages`` — the negotiation transcript, persisted.

Until now the full conversation existed in exactly one place: the Redis stream
``analysis:{job_id}:events``, which is capped at 1000 entries and expires after
24 hours. What the database kept was a summary of the *outcome*, not a record of
the exchange:

* ``agent_findings`` holds one row per agent — its **final** ISR. Pipeline state
  merges ``isr_reports`` per agent on every revision round, so an agent's
  round-2 position was overwritten in memory and never written down at all.
* ``analysis_reports.negotiation_log`` kept the mediator's rounds, but not the
  agents' replies to them.
* The sycophancy detector's intervention — arguably the most interesting thing
  the pipeline says, "you agreed without new evidence, argue again" — was
  emitted as a live event and persisted nowhere.
* ``agent_reports`` stored the analysts' **first-pass** prose. The reports they
  rewrote after negotiating (``revised_reports``) were dropped entirely.

So a run older than a day showed a reconstruction: final positions, mediator
rounds, and a synthesised verdict line. This table stores the broadcast itself.
The worker tees every ``agent_message`` event as it publishes it and writes the
list verbatim, which means the replayed conversation is not assembled from
leftovers — it is the same recording the live viewer saw.

``seq`` is emission order and is the ordering key. Round number cannot separate
speakers within a round, and timestamps are too coarse for messages emitted in
the same millisecond.

No backfill is possible or attempted: for existing reports the source data is
gone. The frontend keeps its reconstruction path for those rows and prefers this
table whenever it is populated.

Revision ID: 20260726020000
Revises: 20260726010000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260726020000"
down_revision = "20260726010000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_messages",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("report_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("speaker", sa.String(length=100), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("round", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="complete"),
        sa.Column("text", sa.Text(), nullable=False, server_default=""),
        sa.Column("report", sa.Text(), nullable=True),
        sa.Column(
            "report_truncated", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("claims", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("dissent", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["report_id"], ["analysis_reports.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    # The only query this table serves is "the whole transcript for one report,
    # in order", so index the pair rather than the FK alone.
    op.create_index(
        "ix_agent_messages_report_id_seq",
        "agent_messages",
        ["report_id", "seq"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_agent_messages_report_id_seq", table_name="agent_messages")
    op.drop_table("agent_messages")
