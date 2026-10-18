"""A stored ledger entry keeps every field the entry carries.

``evidence_entries`` gains the seven fields ``maljan.schemas.evidence.LedgerEntry``
carried with no column: ``source``, ``facts``, ``reputation``, ``pack_step``,
``structured_from_server``, ``agent_role`` and ``agent_tab``. Without them a
ledger read back from the database lost where each tool was declared, what
its declaration said about the answer, the reputation record, the operator's
pack step, whether ``structured`` came from the server, and the calling
agent's role and tab.

Every column is nullable. A row written before this revision holds none of
them, and none is invented for it: it reads as absent, never as false or empty.
``structured_from_server`` is stored only when it is true, the rule the
entry's own dump keeps.

Revision ID: 20261017000000
Revises: 20261016000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261017000000"
down_revision = "20261016000000"
branch_labels = None
depends_on = None


def _json() -> sa.types.TypeEngine:
    return sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("source", sa.String()),
    ("facts", _json()),
    ("reputation", _json()),
    ("pack_step", _json()),
    ("structured_from_server", sa.Boolean()),
    ("agent_role", sa.String()),
    ("agent_tab", sa.String()),
)


def upgrade() -> None:
    for name, type_ in _COLUMNS:
        op.add_column("evidence_entries", sa.Column(name, type_, nullable=True))


def downgrade() -> None:
    for name, _type in reversed(_COLUMNS):
        op.drop_column("evidence_entries", name)
