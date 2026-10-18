"""Each stored ledger row carries its digest and its place in the job's hash chain.

``evidence_entries`` gains ``digest`` and ``chain``, each the hex of a SHA-256
(``app.services.ledger_chain``): the digest of the row's persisted columns in
canonical form, and the chain value after the row in ``seq`` order.

Nullable. A row written before this revision holds neither, and a reader says
the run predates sealing rather than that its chain is broken.

Revision ID: 20261020000000
Revises: 20261019000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261020000000"
down_revision = "20261019000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("evidence_entries", sa.Column("digest", sa.String(64), nullable=True))
    op.add_column("evidence_entries", sa.Column("chain", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("evidence_entries", "chain")
    op.drop_column("evidence_entries", "digest")
