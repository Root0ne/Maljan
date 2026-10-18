"""A job's ledger holds each entry id and each sequence number once.

``evidence_entries`` gains two unique constraints, ``(job_id, entry_id)`` and
``(job_id, seq)``. The ids are issued once per job from one counter and the
report cites them, so two rows with one id, or one position, under one job
make a citation resolve to two calls.

The upgrade first counts the duplicates already stored. Where any exist it
stops with a stated reason that names the jobs, and changes nothing: it never
deletes or renumbers a row, because which of two rows a citation meant is not
something a migration can know. The operator decides, and runs it again.

Revision ID: 20261018000000
Revises: 20261017000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261018000000"
down_revision = "20261017000000"
branch_labels = None
depends_on = None

_CONSTRAINTS = (
    ("uq_evidence_entries_job_entry_id", "entry_id"),
    ("uq_evidence_entries_job_seq", "seq"),
)


def _jobs_with_duplicates(column: str) -> list[str]:
    rows = op.get_bind().execute(
        sa.text(
            f"SELECT DISTINCT job_id FROM ("  # noqa: S608 - the column is one of two constants
            f"SELECT job_id FROM evidence_entries GROUP BY job_id, {column} "
            f"HAVING COUNT(*) > 1) AS duplicated ORDER BY job_id"
        )
    )
    return [str(row[0]) for row in rows]


def upgrade() -> None:
    reasons = []
    for _name, column in _CONSTRAINTS:
        jobs = _jobs_with_duplicates(column)
        if jobs:
            reasons.append(
                f"{len(jobs)} job(s) hold more than one evidence row with one {column}: "
                + ", ".join(jobs)
            )
    if reasons:
        raise RuntimeError(
            "evidence_entries cannot be made unique per job, and nothing was changed: "
            + "; ".join(reasons)
            + ". Decide which row each citation meant, remove or re-run those jobs, "
            "and run the upgrade again."
        )
    with op.batch_alter_table("evidence_entries") as batch:
        for name, column in _CONSTRAINTS:
            batch.create_unique_constraint(name, ["job_id", column])


def downgrade() -> None:
    with op.batch_alter_table("evidence_entries") as batch:
        for name, _column in reversed(_CONSTRAINTS):
            batch.drop_constraint(name, type_="unique")
