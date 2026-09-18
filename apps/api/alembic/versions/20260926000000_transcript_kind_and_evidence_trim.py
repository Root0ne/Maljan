"""The fields a stored conversation and a stored ledger were losing.

Two tables, one revision, because both are the same defect: a payload the
pipeline builds in full is written down without some of its fields, and the
console then has to guess them back from what survived.

``agent_messages`` gains ``kind``, ``stage`` and ``display_name``. The live
``agent_message`` event has carried all three since delegation landed, and the
model's docstring says the columns mirror that payload field for field. They
did not. Without ``kind`` a stored ``delegation_ask``/``delegation_answer``
pair replays as two plain lines and loses the arrow between them, although the
addressee itself is stored; without ``stage`` every replayed line falls into
one unnamed stage; without ``display_name`` a replay shows the registry key
where the live view showed the operator's label.

``evidence_entries`` gains ``truncated``, ``repeated_of``, ``symbol`` and
``started_at``. ``truncated`` is the one that changes what a reader is told: a
budget-trimmed entry says so with that flag, and with no column for it the
console inferred the trim from an empty output — so a call that *failed*, which
also has an empty output, was explained as one whose result was dropped to keep
its agent inside a byte budget.

Every column is nullable and carries no default, except ``truncated``, which
is false-defaulted like ``args_repaired`` before it. A row written before this
revision therefore reads as what it is: a row whose value was never recorded,
which every reader is required to fall back from rather than treat as a fact.

``analysis_reports.overall_confidence`` becomes nullable for the same reason.
A verdict the pipeline wrote itself, because the judge raised, has no
confidence: nothing assessed one. The column could not say that, so the number
stored there was the mean of the analysts' confidence in their own claims —
a number about their reports, printed on the front page beside a decision none
of them made. ``NULL`` is the fact, and the header says "not assessed".

Downgrade drops the seven columns and restores the NOT NULL. It has to write a
zero into every row that says "not assessed", because the older schema has no
way to express the difference; that is a loss the downgrade cannot avoid and
the reason it is recorded here.

Revision ID: 20260926000000
Revises: 20260925000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260926000000"
down_revision = "20260925000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_messages", sa.Column("kind", sa.String(length=32), nullable=True))
    op.add_column("agent_messages", sa.Column("stage", sa.String(length=64), nullable=True))
    op.add_column("agent_messages", sa.Column("display_name", sa.String(length=200), nullable=True))

    op.add_column(
        "evidence_entries",
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("evidence_entries", sa.Column("repeated_of", sa.String(length=32), nullable=True))
    op.add_column("evidence_entries", sa.Column("symbol", sa.String(length=200), nullable=True))
    op.add_column("evidence_entries", sa.Column("started_at", sa.Float(), nullable=True))

    op.alter_column(
        "analysis_reports", "overall_confidence", existing_type=sa.Float(), nullable=True
    )


def downgrade() -> None:
    op.execute(
        "UPDATE analysis_reports SET overall_confidence = 0 WHERE overall_confidence IS NULL"
    )
    op.alter_column(
        "analysis_reports", "overall_confidence", existing_type=sa.Float(), nullable=False
    )

    op.drop_column("evidence_entries", "started_at")
    op.drop_column("evidence_entries", "symbol")
    op.drop_column("evidence_entries", "repeated_of")
    op.drop_column("evidence_entries", "truncated")

    op.drop_column("agent_messages", "display_name")
    op.drop_column("agent_messages", "stage")
    op.drop_column("agent_messages", "kind")
