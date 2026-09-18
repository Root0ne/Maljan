"""A session factory that records when a transaction is open.

The worker's contract is about transaction *lifetime*: the run may read and
write as much as it likes, as long as no session is left open across the
models. Postgres answers that question with ``pg_stat_activity``; this answers
the same question without a database, by counting what a session does — a
statement or a pending object opens a transaction, a commit or a rollback ends
one, and closing the session ends whichever one is still open.

The ``asyncpg`` driver is not involved and neither is SQLAlchemy's own unit of
work, so this proves nothing about SQL. It proves what the worker holds, which
is the defect it exists for: a backend left ``idle in transaction`` for the
length of an analysis.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock


class Recorded:
    """What one tracked session did, in the order it did it."""

    def __init__(self, index: int) -> None:
        self.index = index
        self.open = True
        self.in_transaction = False
        self.begins = 0
        self.commits = 0
        self.rollbacks = 0
        self.statements: list[Any] = []
        self.added: list[Any] = []


class TrackedSession:
    """The subset of ``AsyncSession`` the worker uses, with a transaction flag.

    ``rows`` answers ``execute`` for a ``SELECT``: a callable that is handed
    the statement and returns the result object, so a test decides what each
    read finds. ``on_execute`` is handed this session's record and the
    statement before either happens, which is how a test makes one session —
    and only that one — behave like a session whose backend has gone.
    Everything else answers the way a session does and records it.
    """

    def __init__(self, record: Recorded, rows: Any, on_execute: Any = None) -> None:
        self._record = record
        self._rows = rows
        self._on_execute = on_execute

    # ── the transaction ──────────────────────────────────────────
    def _begin(self) -> None:
        if not self._record.in_transaction:
            self._record.in_transaction = True
            self._record.begins += 1

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        if self._on_execute is not None:
            self._on_execute(self._record, statement)
        self._begin()
        self._record.statements.append(statement)
        return self._rows(statement)

    async def get(self, *args: Any, **kwargs: Any) -> Any:
        self._begin()
        return None

    def add(self, obj: Any) -> None:
        self._begin()
        self._record.added.append(obj)

    def add_all(self, objs: Any) -> None:
        for obj in objs:
            self.add(obj)

    async def delete(self, obj: Any) -> None:
        self._begin()

    async def flush(self) -> None:
        self._begin()

    async def commit(self) -> None:
        self._record.in_transaction = False
        self._record.commits += 1

    async def rollback(self) -> None:
        self._record.in_transaction = False
        self._record.rollbacks += 1

    async def refresh(self, obj: Any) -> None:
        self._begin()

    async def close(self) -> None:
        self._record.in_transaction = False
        self._record.open = False

    async def __aenter__(self) -> TrackedSession:
        return self

    async def __aexit__(self, *exc_info: Any) -> bool:
        await self.close()
        return False


class SessionFactory:
    """``ctx["db_session"]`` for a test: one tracked session per call."""

    def __init__(self, rows: Any, on_execute: Any = None) -> None:
        self.sessions: list[Recorded] = []
        self._rows = rows
        self._on_execute = on_execute

    def __call__(self) -> TrackedSession:
        record = Recorded(len(self.sessions))
        self.sessions.append(record)
        return TrackedSession(record, self._rows, self._on_execute)

    @property
    def open_transactions(self) -> list[Recorded]:
        """Every session that is holding a transaction right now."""
        return [s for s in self.sessions if s.open and s.in_transaction]

    def statements(self) -> list[Any]:
        found: list[Any] = []
        for session in self.sessions:
            found.extend(session.statements)
        return found


def values_of(statement: Any) -> dict[str, Any]:
    """The column values an ``UPDATE`` carries, by column name.

    Each one arrives as a bound parameter; what a caller wants is what was
    bound to it.
    """
    return {
        column.name: getattr(value, "value", value) for column, value in statement._values.items()
    }


def updates_in(statements: Any, table: str) -> list[dict[str, Any]]:
    """Every ``UPDATE`` against ``table`` among ``statements``, as value maps."""
    found: list[dict[str, Any]] = []
    for statement in statements:
        if getattr(statement, "is_update", False) and statement.table.name == table:
            found.append(values_of(statement))
    return found


def updates_to(factory: SessionFactory, table: str) -> list[dict[str, Any]]:
    """Every ``UPDATE`` this factory's sessions ran against ``table``."""
    return updates_in(factory.statements(), table)


def fake_job(
    job_id: uuid.UUID | None = None,
    *,
    status: str = "queued",
    config: dict[str, Any] | None = None,
) -> MagicMock:
    job = MagicMock()
    job.id = job_id or uuid.uuid4()
    job.status = status
    job.sample_id = uuid.uuid4()
    job.config = config
    job.started_at = None
    job.completed_at = None
    job.duration_seconds = None
    job.error_message = None
    return job


def fake_sample(sample_id: uuid.UUID, *, sha256: str = "a" * 64) -> MagicMock:
    sample = MagicMock()
    sample.id = sample_id
    sample.sha256 = sha256
    sample.original_filename = "sample.exe"
    sample.storage_path = f"samples/{sha256[:2]}/{sha256}"
    return sample


def rows_for(job: Any, sample: Any) -> Any:
    """An ``execute`` answer that routes on the entity the statement names."""

    def answer(statement: Any) -> MagicMock:
        result = MagicMock()
        entity = ""
        descriptions = getattr(statement, "column_descriptions", None) or []
        if descriptions:
            entity = getattr(descriptions[0].get("entity"), "__name__", "") or ""
        if entity == "AnalysisJob":
            result.scalar_one_or_none.return_value = job
            result.scalar_one.return_value = job
        elif entity == "Sample":
            result.scalar_one_or_none.return_value = sample
            result.scalar_one.return_value = sample
        else:
            result.scalar_one_or_none.return_value = None
            result.all.return_value = []
        return result

    return answer
