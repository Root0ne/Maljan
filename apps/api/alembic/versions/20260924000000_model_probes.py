"""What a model probe reached, kept so a job can be refused before it starts.

A model name is the one part of an agent definition nothing validates until
the run gets to that agent, and the settings probe's answer used to live only
as long as the console page was open. ``model_probes`` writes it down: one row
per ``(endpoint, model)``, with the provider, whether the probe reached it and
the probe's own last sentence.

The pair is unique, and it is also the invalidation: a changed endpoint or a
changed model is a different question and finds no row, so nothing has to
expire a result.

Downgrade drops the table.

Revision ID: 20260924000000
Revises: 20260923000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "20260924000000"
down_revision = "20260923000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "model_probes",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("endpoint", sa.String(length=500), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False, server_default=""),
        sa.Column("ok", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("endpoint", "model", name="uq_model_probes_endpoint_model"),
    )


def downgrade() -> None:
    op.drop_table("model_probes")
