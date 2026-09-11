"""Drop ``settings_meta`` — the one-off configuration bookkeeping markers.

The table existed for a single row that recorded whether the one-shot import
of a previous ``.env``-based configuration into ``runtime_settings`` had
already run. That import is gone: a deployment upgrading from ``.env`` enters
its configuration in Settings -> Configuration or imports a JSON export, so
nothing writes or reads the marker any more.

Revision ID: 20260912000000
Revises: 20260911000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260912000000"
down_revision = "20260911000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_table("settings_meta")


def downgrade() -> None:
    op.create_table(
        "settings_meta",
        sa.Column("key", sa.String(255), primary_key=True),
        sa.Column("value", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
