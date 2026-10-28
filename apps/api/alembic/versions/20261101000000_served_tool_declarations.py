"""What each tool server last declared of its own tools is kept past the process.

``served_tool_declarations`` holds one row per source (``mcp:<key>``,
``provider:<id>``): the declaration the server gave of its own tools when it
was last listed, per tool and field (``maljan.core.served_declarations``), and
the launch identity of the block that reached it, and whether that launch was
the one the source ships with on the host that listed it, so a reader on
another host (an API on the host, a worker in a container) reads it under its
own shipped launch. The platform's own sidecars
ship no table of their tools anywhere else, so a reader that runs before any
server attaches (a worker's next job, a restarted worker, the API) reads what
they declared from here (``app.services.served_declarations_store``).

It follows revision ``20261031000000``. A new, empty table: nothing is read or
rewritten. Until a server is first listed it holds no row for it, and its
tools are read as any undeclared server's are. ``lock_timeout`` bounds the
statements on PostgreSQL.

The downgrade drops the table; the next listing of each server declares its
tools again in the process that lists it.

Revision ID: 20261101000000
Revises: 20261031000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261101000000"
down_revision = "20261031000000"
branch_labels = None
depends_on = None

# How long each statement waits for a lock before the migration fails instead,
# so a busy catalogue is retried by the operator rather than queueing requests.
_LOCK = sa.text("SET LOCAL lock_timeout = '5s'")


def _postgres() -> bool:
    return bool(op.get_bind().dialect.name == "postgresql")


def upgrade() -> None:
    if _postgres():
        op.execute(_LOCK)
    op.create_table(
        "served_tool_declarations",
        sa.Column("source", sa.String(255), primary_key=True),
        sa.Column("launch", sa.String(64), nullable=False, server_default=""),
        sa.Column("shipped", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("tool_facts", postgresql.JSONB(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    if _postgres():
        op.execute(_LOCK)
    op.drop_table("served_tool_declarations")
