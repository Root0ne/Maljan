"""Add ``evidence_entries`` — the tool calls a job's report cites.

The report's sections name the ledger entries they were built from, and until
now those entries lived only inside the pipeline's state and the JSONB blob of
the finished report. A reader who wanted the actual output behind
``ev_0007`` had to download the whole report and search it.

One row per tool call, keyed by job rather than by report: the ledger is a
record of what the run did, and it is worth keeping even for a run whose
report never assembled. ``entry_id`` is the citation string (``ev_0007``) and
``seq`` its numeric order, so the endpoint can page in call order without
parsing ids.

The ``id`` column carries no server-side default, matching every other table
built on ``UUIDPrimaryKeyMixin``: the mixin generates the value in Python
before the row is ever sent to the database.

Revision ID: 20260914000000
Revises: 20260913000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260914000000"
down_revision = "20260913000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entry_id", sa.String(length=32), nullable=False),
        sa.Column("stage", sa.String(length=32), nullable=False, server_default="analysis"),
        sa.Column("agent", sa.String(length=100), nullable=False),
        sa.Column("server", sa.String(length=100), nullable=True),
        sa.Column("tool", sa.String(length=200), nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("seq", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("args", postgresql.JSONB(), nullable=True),
        sa.Column("output", sa.Text(), nullable=False, server_default=""),
        sa.Column("structured", postgresql.JSONB(), nullable=True),
        sa.ForeignKeyConstraint(["job_id"], ["analysis_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    # Every query this table serves is "one job's ledger, in call order", so
    # the composite index is the one the endpoint actually uses.
    op.create_index("ix_evidence_entries_job_seq", "evidence_entries", ["job_id", "seq"])


def downgrade() -> None:
    op.drop_index("ix_evidence_entries_job_seq", table_name="evidence_entries")
    op.drop_table("evidence_entries")
