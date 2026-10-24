"""Evidence entries name the nulls a call left out.

``evidence_entries`` gains ``args_nulls_dropped`` and ``args_nulls_withheld``,
the two fields ``maljan.schemas.evidence.LedgerEntry`` carries for a call with
a ``null`` the tool boundary read as the argument left out
(``maljan.agents.null_arguments``): the fields whose ``null`` the schema did
not allow and was dropped so the field took its declared default, and the
top-level ones it admitted that the transport did not send. Each is a JSON list
of paths, a path a list of segments.

Both columns are nullable and have no default. A row written before this
revision, or for a call with no such ``null``, holds neither and reads as
absent; the ledger chain's digest seals each only when it is set, so every
stored digest and chain value stays what it was.

Two added nullable columns with no default: Postgres changes the catalogue
and rewrites no row, so the only cost is the ACCESS EXCLUSIVE lock, bounded by
``LOCK_TIMEOUT``.

The downgrade drops both columns and what they named; the call's arguments
are unchanged.

Revision ID: 20261030000000
Revises: 20261029000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261030000000"
down_revision = "20261029000000"
branch_labels = None
depends_on = None

# How long the ALTER waits for its lock before the migration fails instead, so
# a busy table is retried by the operator rather than queueing requests.
LOCK_TIMEOUT = "5s"

COLUMNS = ("args_nulls_dropped", "args_nulls_withheld")


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _columns() -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns("evidence_entries")}


def _json() -> sa.types.TypeEngine:
    return sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    if _is_postgres():
        op.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
    present = _columns()
    for name in COLUMNS:
        if name not in present:
            op.add_column("evidence_entries", sa.Column(name, _json(), nullable=True))


def downgrade() -> None:
    if _is_postgres():
        op.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
    present = _columns()
    for name in reversed(COLUMNS):
        if name in present:
            op.drop_column("evidence_entries", name)
