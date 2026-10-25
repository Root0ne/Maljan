"""Evidence entries name where the pack's own readings ran.

``evidence_entries`` gains ``ran_on``, the field ``maljan.schemas.evidence.LedgerEntry``
carries for a triage pack entry whose readings of the sample ran on a server
of their own (``maljan.tools.readers``): a JSON list of sources, ``mcp:<server
key>`` for each such server and ``pack`` for the worker beside one. The
isolation part of a run's disclosure counts the entry under those rather than
as read in the worker.

The column is nullable and has no default. A row written before this
revision, or for an entry whose readings all ran in the worker, holds none
and reads as absent; the ledger chain's digest seals it only when it is set,
so every stored digest and chain value stays what it was.

One added nullable column with no default: Postgres changes the catalogue
and rewrites no row, so the only cost is the ACCESS EXCLUSIVE lock, bounded by
``LOCK_TIMEOUT``.

The downgrade drops the column and what it named; the entry's source is
unchanged.

Revision ID: 20261031000000
Revises: 20261030000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261031000000"
down_revision = "20261030000000"
branch_labels = None
depends_on = None

# How long the ALTER waits for its lock before the migration fails instead, so
# a busy table is retried by the operator rather than queueing requests.
LOCK_TIMEOUT = "5s"

COLUMN = "ran_on"


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _columns() -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns("evidence_entries")}


def _json() -> sa.types.TypeEngine:
    return sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    if _is_postgres():
        op.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
    if COLUMN not in _columns():
        op.add_column("evidence_entries", sa.Column(COLUMN, _json(), nullable=True))


def downgrade() -> None:
    if _is_postgres():
        op.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
    if COLUMN in _columns():
        op.drop_column("evidence_entries", COLUMN)
