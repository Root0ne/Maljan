"""A stored ledger entry references the parts of its answer kept whole.

``evidence_entries`` gains ``spilled``: the references the entry carries
(``maljan.schemas.evidence_spill``) to the parts of its answer the run
shortened, blanked or dropped and kept whole in object storage, each with the
part, the object key, the byte length and the SHA-256, or the reason the upload
failed.

Nullable. A row written before this revision, and a row nothing was taken
from, holds none: it reads as absent.

Revision ID: 20261019000000
Revises: 20261018000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261019000000"
down_revision = "20261018000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "evidence_entries",
        sa.Column(
            "spilled",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("evidence_entries", "spilled")
