"""The evidence ledger keeps a failed call's message and its remedy.

``evidence_entries`` recorded that a call failed (``ok``) and what it printed
(``output``); the message a tool gave for the failure and the remediation it
authored (``maljan.tools.errors``) were only inside that text. The console's
evidence row and the report header show both, so they become columns of their
own: ``error``, the failure text, and ``remediation``, what would make the
next call succeed. Both are nullable; a row written before this revision reads
as it did.

Downgrade drops the two columns.

Revision ID: 20260922000000
Revises: 20260921000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260922000000"
down_revision = "20260921000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("evidence_entries", sa.Column("error", sa.Text(), nullable=True))
    op.add_column("evidence_entries", sa.Column("remediation", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("evidence_entries", "remediation")
    op.drop_column("evidence_entries", "error")
