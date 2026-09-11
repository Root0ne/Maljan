"""Add ``settings_meta`` — one-off configuration bookkeeping markers.

The env-free configuration work imports the legacy ``.env``-based
configuration into ``runtime_settings`` exactly once, on the first start
after this change; this table's ``legacy_env_import`` row is how the API
remembers that it already happened, so a later restart does not repeat the
walk. Its ``value`` carries ``{"imported": <int>, "at": <iso8601 utc>}``.

Revision ID: 20260911000000
Revises: 20260906000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260911000000"
down_revision = "20260906000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "settings_meta",
        sa.Column("key", sa.String(255), primary_key=True),
        sa.Column("value", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )


def downgrade() -> None:
    op.drop_table("settings_meta")
