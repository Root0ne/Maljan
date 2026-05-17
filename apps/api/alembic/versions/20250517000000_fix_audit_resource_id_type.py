"""Convert audit_log.resource_id from UUID to VARCHAR(255).

The ORM model declares ``resource_id: Mapped[str | None] = mapped_column(String(255))``
but the original migration created the column as ``UUID``. Asyncpg refuses to
cast a varchar argument to UUID and rolls back every auth INSERT, while the
route returns 201 because the commit failure happens after the response is
serialized. Aligning the column with the model unblocks auth, audit, and every
downstream IDOR-checked flow.

Revision ID: 20250517000000
Revises: 20250516000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20250517000000"
down_revision = "20250516000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "audit_log",
        "resource_id",
        type_=sa.String(length=255),
        existing_nullable=True,
        postgresql_using="resource_id::text",
    )


def downgrade() -> None:
    op.alter_column(
        "audit_log",
        "resource_id",
        type_=sa.dialects.postgresql.UUID(as_uuid=True),
        existing_nullable=True,
        postgresql_using="resource_id::uuid",
    )
