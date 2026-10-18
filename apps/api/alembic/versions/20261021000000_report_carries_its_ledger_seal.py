"""A stored report carries the seal of its job's ledger.

``analysis_reports`` gains ``ledger_seal`` (``app.services.ledger_chain``): the
chain head, what it covers, the key id and the digest of the stored report row,
written in the transaction that stores the ledger. Its presence marks the
job's ledger as sealed.

Nullable. A report stored before this revision holds none, and a reader says
the run predates sealing.

The downgrade takes the seals out of every report it wrote them into: the
``ledger_seal`` and ``ledger_amendments`` keys leave ``malware_report`` and
``run_summary`` of each sealed report before the column goes, so a report
upgraded again later reads as stored before sealing, not as tampered.

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

_KEYS = ("ledger_seal", "ledger_amendments")


def upgrade() -> None:
    op.add_column(
        "analysis_reports",
        sa.Column(
            "ledger_seal",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
    )


def _without_seal(bind: sa.engine.Connection, column: sa.ColumnClause) -> sa.ColumnElement:
    """``column`` with the seal keys taken out, in the dialect's own JSON functions."""
    if bind.dialect.name == "postgresql":
        keys = sa.cast(sa.literal(list(_KEYS)), postgresql.ARRAY(sa.Text()))
        return sa.type_coerce(column, postgresql.JSONB()).op("-")(keys)
    return sa.func.json_remove(column, *(f"$.{key}" for key in _KEYS))


def downgrade() -> None:
    bind = op.get_bind()
    reports = sa.table(
        "analysis_reports",
        sa.column("ledger_seal"),
        sa.column("malware_report"),
        sa.column("run_summary"),
    )
    for name in ("malware_report", "run_summary"):
        column = reports.c[name]
        bind.execute(
            sa.update(reports)
            .where(reports.c.ledger_seal.is_not(None), column.is_not(None))
            .values({name: _without_seal(bind, column)})
        )
    op.drop_column("analysis_reports", "ledger_seal")
