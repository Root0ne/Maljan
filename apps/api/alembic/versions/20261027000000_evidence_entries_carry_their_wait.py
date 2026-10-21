"""Evidence entries carry how long a call waited for its server.

``evidence_entries.waited_ms`` is the time a tool call queued for a free slot at
its server before it was sent; ``duration_ms`` runs from the moment it was
sent. Existing rows start at 0, which is what a call that never queued reads as.
The ledger chain's digest carries the column only when it is non-zero, so every
stored digest and chain value stays what it was.

One added column with a constant default: Postgres stores the default in the
catalogue and rewrites no row, so the only cost is the ACCESS EXCLUSIVE lock,
bounded by ``LOCK_TIMEOUT``.

The downgrade drops the column and the wait it recorded; the duration of each
call is unchanged.

Revision ID: 20261027000000
Revises: 20261026000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261027000000"
down_revision = "20261026000000"
branch_labels = None
depends_on = None

# How long the ALTER waits for its lock before the migration fails instead, so
# a busy table is retried by the operator rather than queueing requests.
LOCK_TIMEOUT = "5s"


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _columns() -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns("evidence_entries")}


def upgrade() -> None:
    if _is_postgres():
        op.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
    if "waited_ms" not in _columns():
        op.add_column(
            "evidence_entries",
            sa.Column("waited_ms", sa.Integer(), nullable=False, server_default="0"),
        )


def downgrade() -> None:
    if _is_postgres():
        op.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
    if "waited_ms" in _columns():
        op.drop_column("evidence_entries", "waited_ms")
