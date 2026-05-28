"""Add ``status`` + ``status_reason`` to agent_findings (D15+D16).

The 2026-05-23 E2E run on zararli.apk exposed a UX gap: the Static
analyst's Ghidra ReAct loop produced zero claims because Ghidra could
not load the APK as a PE binary. The row was persisted with
``final_confidence=0.0`` and rendered as "Benign 0%" — visually
indistinguishable from an analyst that ran successfully and judged the
sample benign. Similar issue for Dynamic + Network analysts, whose LLM
output claimed "no malicious activity detected" but the aggregator
defaulted the verdict label to "Malicious 100%".

Adding ``status`` (Enum-as-string) lets the worker tag the row as
``complete`` / ``no_data`` / ``failed`` / ``timeout`` and lets the
frontend render a "FAILED" or "NO DATA" badge instead of synthesising
a misleading verdict from the empty payload. ``status_reason`` carries
the short failure message (truncated to 500 chars) when status is
``failed`` or ``timeout``.

``server_default='complete'`` backfills every existing row with the
legacy meaning. Index on ``status`` so dashboard queries can filter
``WHERE status != 'complete'`` cheaply for the "degraded runs" tile.

Revision ID: 20250524000000
Revises: 20250517010000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20250524000000"
down_revision = "20250517010000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agent_findings",
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default="complete",
        ),
    )
    op.add_column(
        "agent_findings",
        sa.Column("status_reason", sa.String(length=500), nullable=True),
    )
    op.create_index(
        "ix_agent_findings_status",
        "agent_findings",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_agent_findings_status", table_name="agent_findings")
    op.drop_column("agent_findings", "status_reason")
    op.drop_column("agent_findings", "status")
