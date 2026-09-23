"""The evidence ledger names the model whose turn asked for each call.

An agent may fall back to another model when the first one fails as a
provider, so which model a call came from is no longer a fact of the agent's
settings: it is a fact of the turn. ``model`` is ``provider/model`` as the
turn recorded it, and NULL for every row written before this revision — a
call whose model nothing named.

Downgrade drops the column.

Revision ID: 20260928000000
Revises: 20260927000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260928000000"
down_revision = "20260927000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("evidence_entries", sa.Column("model", sa.String(300), nullable=True))


def downgrade() -> None:
    op.drop_column("evidence_entries", "model")
