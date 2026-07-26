"""Backfill analysis_reports.overall_confidence from the capped MalwareReport value.

Audit 2026-07-26 (K4). The degraded-run confidence cap
(``nodes.py`` ``_DEGRADED_CONFIDENCE_CAP`` = 0.60) is applied while building the
``MalwareReport``, but the worker persisted the column from the RAW judge value
(``run_summary`` / ``confidence_history``). The API, the reports list and the
analysis header all read that column, so the UI displayed a "DEGRADED RUN"
banner and "Confidence: 91/100" at the same time — exactly the confidence
inflation the guardrail exists to prevent.

The code fix (``_extract_confidence`` now prefers ``malware_report``) only
applies to new runs; rows written before it keep the inflated value. This
migration realigns them with their own report, which is the authoritative
source. Rows without a ``malware_report`` (legacy/partial results) are left
untouched — there is nothing authoritative to copy from.

Measured on the audit database: 7 of 12 reports disagreed, by as much as
0.94 vs 0.60.

Revision ID: 20260726010000
Revises: 20260726000000
"""

from __future__ import annotations

from alembic import op

revision = "20260726010000"
down_revision = "20260726000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE analysis_reports
        SET overall_confidence = (malware_report->>'overall_confidence')::float
        WHERE malware_report IS NOT NULL
          AND (malware_report->>'overall_confidence') IS NOT NULL
          AND abs(
                overall_confidence - (malware_report->>'overall_confidence')::float
              ) > 0.001
        """
    )


def downgrade() -> None:
    # One-way data repair: the raw pre-cap value is not recoverable from the
    # column once realigned, and restoring an inflated confidence would
    # re-introduce the defect. Intentionally a no-op.
    pass
