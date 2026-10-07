"""A stored ledger entry keeps the function ranges beside the index's answer.

``evidence_entries`` gains ``function_ranges``: the file's own
exception-directory ranges, by function start, that the function index
entry carries beside its answer for evidence roots. Without the column a
ledger read back from the database lost them, and a root that groups places
by function could not be read again.

The column is nullable JSONB like ``structured``: every other entry, and every
row written before this revision, holds none, and none is invented for it.

Revision ID: 20261008000000
Revises: 20261007000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261008000000"
down_revision = "20261007000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "evidence_entries",
        sa.Column(
            "function_ranges",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("evidence_entries", "function_ranges")
