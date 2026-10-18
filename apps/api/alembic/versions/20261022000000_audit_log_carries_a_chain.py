"""The audit log can hold a hash chain: chained rows carry their place, digest and chain value.

``audit_log`` gains ``chain_seq`` (unique), ``digest``, ``chain`` and
``chain_key_id`` (``app.services.audit_chain``). A chained row (a ledger seal,
an amendment to a sealed report) takes the next ``chain_seq`` and its chain
value links it to the chained row before it. Every other row, and every row
written before this revision, holds none of them.

On PostgreSQL the unique index is built ``CONCURRENTLY`` in an autocommit
block, so writers are not locked out while it is built; SQLite builds it in
place.

Revision ID: 20261022000000
Revises: 20261021000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261022000000"
down_revision = "20261021000000"
branch_labels = None
depends_on = None

_INDEX = "uq_audit_log_chain_seq"


def upgrade() -> None:
    op.add_column("audit_log", sa.Column("chain_seq", sa.Integer(), nullable=True))
    op.add_column("audit_log", sa.Column("digest", sa.String(64), nullable=True))
    op.add_column("audit_log", sa.Column("chain", sa.String(64), nullable=True))
    op.add_column("audit_log", sa.Column("chain_key_id", sa.String(16), nullable=True))
    if op.get_context().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.create_index(
                _INDEX, "audit_log", ["chain_seq"], unique=True, postgresql_concurrently=True
            )
    else:
        op.create_index(_INDEX, "audit_log", ["chain_seq"], unique=True)


def downgrade() -> None:
    op.drop_index(_INDEX, table_name="audit_log")
    op.drop_column("audit_log", "chain_key_id")
    op.drop_column("audit_log", "chain")
    op.drop_column("audit_log", "digest")
    op.drop_column("audit_log", "chain_seq")
