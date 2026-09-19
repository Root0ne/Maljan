"""The evidence ledger says when a call ran on arguments that were closed off.

A model that runs out of generation mid-call emits tool arguments that stop in
the middle. Appending the quote and the brackets they are missing makes the
call readable, and the call then runs — but a reader of the ledger has to be
able to see that it did, and to check the repair against what the model
actually wrote. So both become columns: ``args_repaired``, false for every
ordinary call, and ``args_raw``, the arguments as they arrived.

``args_repaired`` is not null with a false default, so a row written before
this revision reads as what it was: a call whose arguments parsed.

Downgrade drops the two columns.

Revision ID: 20260923000000
Revises: 20260922000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260923000000"
down_revision = "20260922000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "evidence_entries",
        sa.Column(
            "args_repaired",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column("evidence_entries", sa.Column("args_raw", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("evidence_entries", "args_raw")
    op.drop_column("evidence_entries", "args_repaired")
