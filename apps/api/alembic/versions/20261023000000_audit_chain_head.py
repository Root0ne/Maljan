"""The audit chain keeps a keyed head record.

``audit_chain_head`` holds one row per chain (``name`` ``"audit"``): the last
``chain_seq``, its chain value, the id of the key and a MAC over both under
that key (``app.services.audit_chain``). Every chained append rewrites it in
the same transaction, so rows cut off the end of the log are found.

A new, empty table: nothing is read or rewritten.

Revision ID: 20261023000000
Revises: 20261022000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261023000000"
down_revision = "20261022000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_chain_head",
        sa.Column("name", sa.String(32), primary_key=True),
        sa.Column("chain_seq", sa.Integer(), nullable=False),
        sa.Column("chain", sa.String(64), nullable=False),
        sa.Column("key_id", sa.String(16), nullable=True),
        sa.Column("mac", sa.String(64), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("audit_chain_head")
