"""Drop the retired ``reporting.narrative_max_tokens`` from the stored overrides.

The setting was described as a hard output-token cap for the narrative round,
but its value only ever reached a constructor argument nothing read: the round
was capped by the reporter's model like every other report call. The report
stage's budget is now the operator's ``llm.judge_max_tokens``, else the
model's declared maximum output, else the analysts' derivation, and the
setting that claimed otherwise is gone. This revision deletes its row. A
stored override that names a setting the catalog no longer knows would
otherwise be refused by the settings service on the next import; building the
settings from the store ignores it either way.

Downgrade restores nothing: the value capped nothing.

Revision ID: 20260930000000
Revises: 20260929000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260930000000"
down_revision = "20260929000000"
branch_labels = None
depends_on = None

FLAT_KEYS = ("core.reporting.narrative_max_tokens",)


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM runtime_settings WHERE key IN :keys").bindparams(
            sa.bindparam("keys", expanding=True)
        ),
        {"keys": list(FLAT_KEYS)},
    )


def downgrade() -> None:
    pass
