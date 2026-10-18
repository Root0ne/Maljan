"""A stored report carries the seal of its job's ledger.

``analysis_reports`` gains ``ledger_seal`` (``app.services.ledger_chain``): the
chain head, what it covers, the key id and the digest of the stored report's
documents, written in the transaction that stores the ledger. Its presence
marks the job's ledger as sealed.

Nullable. A report stored before this revision holds none, and a reader says
the run predates sealing.

Revision ID: 20261021000000
Revises: 20261020000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261021000000"
down_revision = "20261020000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analysis_reports",
        sa.Column(
            "ledger_seal",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("analysis_reports", "ledger_seal")
