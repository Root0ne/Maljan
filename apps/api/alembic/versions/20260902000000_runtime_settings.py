"""Add ``runtime_settings`` — configuration overrides set from the web UI.

Until now every knob lived in ``.env`` and changing one meant editing a file
on the host and restarting processes. Overrides now live here, keyed by the
dotted setting path with a namespace (``core.llm.openai.base_url``,
``api.enrichment_enabled``), and layer over the environment: the worker reads
them at the start of each job, the API through a short-lived cache. Secret
values are stored Fernet-encrypted as ``enc:v1:<token>``; ``is_secret`` marks
them so a reader never has to guess. An empty table is exactly today's system.

Revision ID: 20260902000000
Revises: 20260726020000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260902000000"
down_revision = "20260726020000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runtime_settings",
        sa.Column("key", sa.String(255), primary_key=True),
        sa.Column("value", postgresql.JSONB(), nullable=False),
        sa.Column("is_secret", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "updated_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )


def downgrade() -> None:
    op.drop_table("runtime_settings")
