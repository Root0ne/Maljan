"""A job's ledger holds each entry id and each sequence number once.

``evidence_entries`` gains two unique constraints, ``(job_id, entry_id)`` and
``(job_id, seq)``. The ids are issued once per job from one counter and the
report cites them, so two rows with one id, or one position, under one job
make a citation resolve to two calls. The non-unique
``ix_evidence_entries_job_seq`` the ``(job_id, seq)`` constraint makes
redundant is dropped, and the downgrade puts it back.

The upgrade first counts the duplicates already stored. Where any exist it
stops with a stated reason that names the jobs, and changes nothing: it never
deletes or renumbers a row, because which of two rows a citation meant is not
something a migration can know. The operator decides, and runs it again.

On PostgreSQL each unique index is built with ``CREATE UNIQUE INDEX
CONCURRENTLY`` outside the migration's transaction, so the worker keeps
writing ledgers while it builds, and the constraint is then attached to the
built index (``ADD CONSTRAINT ... USING INDEX``), which takes its lock only
for a moment. A build that fails (a duplicate written after the count) leaves
no half-built index behind. SQLite, which the migration tests use, takes the
constraints through batch mode.

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

_TABLE = "evidence_entries"
_OLD_INDEX = "ix_evidence_entries_job_seq"
_CONSTRAINTS = (
    ("uq_evidence_entries_job_entry_id", "entry_id"),
    ("uq_evidence_entries_job_seq", "seq"),
)


def _jobs_with_duplicates(column: str) -> list[str]:
    rows = op.get_bind().execute(
        sa.text(
            f"SELECT DISTINCT job_id FROM ("  # noqa: S608 - the column is one of two constants
            f"SELECT job_id FROM {_TABLE} GROUP BY job_id, {column} "
            f"HAVING COUNT(*) > 1) AS duplicated ORDER BY job_id"
        )
    )
    return [str(row[0]) for row in rows]


def _refuse_on_duplicates() -> None:
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
            f"{_TABLE} cannot be made unique per job, and nothing was changed: "
            + "; ".join(reasons)
            + ". Decide which row each citation meant, remove or re-run those jobs, "
            "and run the upgrade again."
        )


def _postgres() -> bool:
    return op.get_context().dialect.name == "postgresql"


def _upgrade_postgres() -> None:
    with op.get_context().autocommit_block():
        try:
            for name, column in _CONSTRAINTS:
                op.execute(
                    f"CREATE UNIQUE INDEX CONCURRENTLY {name} ON {_TABLE} (job_id, {column})"
                )
        except Exception:
            # A concurrent build that fails leaves an invalid index; none is kept.
            for name, _column in _CONSTRAINTS:
                op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {name}")
            raise
    for name, _column in _CONSTRAINTS:
        op.execute(f"ALTER TABLE {_TABLE} ADD CONSTRAINT {name} UNIQUE USING INDEX {name}")
    with op.get_context().autocommit_block():
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {_OLD_INDEX}")


def upgrade() -> None:
    # An offline SQL script has no rows to count; the pre-check runs online.
    if not op.get_context().as_sql:
        _refuse_on_duplicates()
    if _postgres():
        _upgrade_postgres()
        return
    with op.batch_alter_table(_TABLE) as batch:
        for name, column in _CONSTRAINTS:
            batch.create_unique_constraint(name, ["job_id", column])
        batch.drop_index(_OLD_INDEX)


def downgrade() -> None:
    if _postgres():
        with op.get_context().autocommit_block():
            op.execute(
                f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {_OLD_INDEX} ON {_TABLE} (job_id, seq)"
            )
        for name, _column in reversed(_CONSTRAINTS):
            op.execute(f"ALTER TABLE {_TABLE} DROP CONSTRAINT IF EXISTS {name}")
        return
    with op.batch_alter_table(_TABLE) as batch:
        for name, _column in reversed(_CONSTRAINTS):
            batch.drop_constraint(name, type_="unique")
        batch.create_index(_OLD_INDEX, ["job_id", "seq"])
