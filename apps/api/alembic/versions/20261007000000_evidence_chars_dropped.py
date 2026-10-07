"""A stored ledger entry says how much of its answer the guardrail cut.

``evidence_entries`` gains ``chars_dropped``: the characters the tool-output
guardrail cut, shortened or summarised away from an answer before the model
read it. Such an entry keeps what the model was handed and is marked
``truncated``; without the count, a decompilation cut by thousands of
characters was stored as if it were the whole answer.

The column is false-defaulted like ``truncated`` before it, as zero: a row
written before this revision recorded no cut, and none is invented for it.

Revision ID: 20261007000000
Revises: 20261002000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261007000000"
down_revision = "20261002000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "evidence_entries",
        sa.Column("chars_dropped", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("evidence_entries", "chars_dropped")
