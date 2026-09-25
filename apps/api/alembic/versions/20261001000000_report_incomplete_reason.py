"""A report kept from a failed run says it is incomplete, and why.

The report node's output used to reach the database only on the success path,
so a run that failed after its report was built lost the report. The worker
now stores that report against the failed job, and
``analysis_reports.incomplete_reason`` holds the sentence saying where the run
failed and under which error id. ``NULL`` is a report of a run that completed.

Nullable with no default: every report stored before this revision came from a
completed run.

Revision ID: 20261001000000
Revises: 20260930000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261001000000"
down_revision = "20260930000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analysis_reports",
        sa.Column("incomplete_reason", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("analysis_reports", "incomplete_reason")
