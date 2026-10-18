"""The audit chain's head anchors the rotation boundary.

``audit_chain_head`` gains ``rotated_at_seq``: the ``chain_seq`` of the first
chained row under the head's key, covered by the head's MAC
(``app.services.audit_chain``). It is 1 for a chain that never rotated and is
set by the first append under a new key. Verification reads the boundary only
from a head that verifies under the current key, never from a row's own key id.

Nullable: a head written before this revision holds none and reads as not
verifiable until the next append rewrites it.

Revision ID: 20261024000000
Revises: 20261023000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261024000000"
down_revision = "20261023000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_chain_head", sa.Column("rotated_at_seq", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_chain_head", "rotated_at_seq")
