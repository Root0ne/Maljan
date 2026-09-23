"""The judge's own STIX bundle, kept beside the export.

Every decline the export records ends "It is unchanged in the judge's own
bundle", and nothing stored that bundle: the worker persisted the extended
export, or the judge's bundle only when there was no export, so the sentence
pointed at a record no reader could open. ``analysis_reports.judge_stix_bundle``
holds the judge's bundle as the pipeline read it — ids minted, references
rewired — and the map from each label the judge wrote to the id it was
published under, as ``{"bundle": …, "labels": {…}}``.

Nullable with no default: a report stored before this revision has no judge
bundle on record, and ``NULL`` says exactly that.

Revision ID: 20260928000000
Revises: 20260927000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260928000000"
down_revision = "20260927000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analysis_reports",
        sa.Column("judge_stix_bundle", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("analysis_reports", "judge_stix_bundle")
