"""Per-user sample dedup + numeric duration_seconds.

Two related schema changes:

1. ``samples.sha256`` is no longer globally unique. The previous design made
   every second uploader of the same hash trip the IDOR guard on job
   creation. Replace the single-column unique index with a composite
   ``(sha256, uploaded_by)`` unique constraint so each user owns their own
   metadata row while sharing the MinIO storage path.

2. ``analysis_jobs.duration_seconds`` Integer → Numeric(10, 2) so sub-second
   mock pipelines (~0.7s) no longer collapse to 0 and tank the dashboard
   "AVG DURATION" tile.

Revision ID: 20250517010000
Revises: 20250517000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20250517010000"
down_revision = "20250517000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop the legacy single-column unique index, then add composite.
    op.drop_index("ix_samples_sha256", table_name="samples")
    op.create_index("ix_samples_sha256", "samples", ["sha256"], unique=False)
    op.create_unique_constraint(
        "uq_samples_sha256_uploader",
        "samples",
        ["sha256", "uploaded_by"],
    )

    op.alter_column(
        "analysis_jobs",
        "duration_seconds",
        type_=sa.Numeric(10, 2),
        existing_nullable=True,
        postgresql_using="duration_seconds::numeric",
    )


def downgrade() -> None:
    op.alter_column(
        "analysis_jobs",
        "duration_seconds",
        type_=sa.Integer(),
        existing_nullable=True,
        postgresql_using="duration_seconds::integer",
    )

    op.drop_constraint("uq_samples_sha256_uploader", "samples", type_="unique")
    op.drop_index("ix_samples_sha256", table_name="samples")
    op.create_index("ix_samples_sha256", "samples", ["sha256"], unique=True)
