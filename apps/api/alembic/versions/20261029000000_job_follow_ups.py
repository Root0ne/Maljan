"""A finished job keeps the follow-up questions asked of it, beside its report.

``job_follow_ups`` holds one row per question an analyst asked of a finished
job and the answer its stored run gave (``app.services.follow_up``): the
question, the outcome and the answer, the model asked and where it came from,
the digest of the stored report it was answered from, the keyed record the
chained ``report.follow_up`` audit row holds and the notes. A row goes with
its job and with its report (``ON DELETE CASCADE``); a deleted account leaves
it unattributed (``SET NULL``). The report itself is never changed by one.

It follows revision ``20261028000000``. A new, empty table: nothing is read or
rewritten. ``lock_timeout`` bounds the statements on PostgreSQL.

Revision ID: 20261029000000
Revises: 20261028000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261029000000"
down_revision = "20261028000000"
branch_labels = None
depends_on = None

# How long each statement waits for a lock before the migration fails instead,
# so a busy catalogue is retried by the operator rather than queueing requests.
_LOCK = sa.text("SET LOCAL lock_timeout = '5s'")


def _postgres() -> bool:
    return bool(op.get_bind().dialect.name == "postgresql")


def upgrade() -> None:
    if _postgres():
        op.execute(_LOCK)
    op.create_table(
        "job_follow_ups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "report_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_reports.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asked_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("answer", postgresql.JSONB(), nullable=False),
        sa.Column("model", sa.String(300), nullable=False),
        sa.Column("model_source", sa.Text(), nullable=False),
        sa.Column("report_sha256", sa.String(64), nullable=False),
        sa.Column("record", postgresql.JSONB(), nullable=True),
        sa.Column("notes", postgresql.JSONB(), nullable=False),
        sa.Column("answered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_job_follow_ups_job_id", "job_follow_ups", ["job_id"])
    # A report's follow-ups are found by it when it is deleted (the cascade).
    op.create_index("ix_job_follow_ups_report_id", "job_follow_ups", ["report_id"])


def downgrade() -> None:
    if _postgres():
        op.execute(_LOCK)
    op.drop_index("ix_job_follow_ups_report_id", table_name="job_follow_ups")
    op.drop_index("ix_job_follow_ups_job_id", table_name="job_follow_ups")
    op.drop_table("job_follow_ups")
