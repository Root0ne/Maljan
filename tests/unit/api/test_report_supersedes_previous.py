"""Re-running an analysis has to be able to store its result.

``analysis_reports.job_id`` is unique and the worker only ever inserted, so a
job that runs a second time dies at the very end with:

    asyncpg.exceptions.UniqueViolationError: duplicate key value violates
      unique constraint "ix_analysis_reports_job_id"
    DETAIL:  Key (job_id)=(e6bdcb3d-…) already exists.

Observed live 2026-08-07 after an arq retry fired: a full analysis — Ghidra,
nineteen tool calls, the judge, the composer, twenty-two minutes — reached the
persist step and threw it all away. arq schedules retries on its own, so this
was reachable without anyone asking for it.

One report per job stays the right constraint; a re-run *supersedes* rather
than accumulates. ``agent_findings`` and ``agent_messages`` carry
``ondelete="CASCADE"``, so removing the prior row takes its stale children with
it instead of leaving them attached to a superseded analysis.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.worker.analysis_worker import _supersede_previous_report


class _Result:
    def __init__(self, value: Any) -> None:
        self._value = value

    def scalar_one_or_none(self) -> Any:
        return self._value


def _db(existing: Any) -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock(return_value=_Result(existing))
    db.delete = AsyncMock()
    db.flush = AsyncMock()
    return db


class TestAPriorReportIsRemovedFirst:
    @pytest.mark.asyncio
    async def test_the_existing_report_is_deleted(self) -> None:
        prior = MagicMock(id=uuid.uuid4())
        db = _db(prior)

        await _supersede_previous_report(db, uuid.uuid4())

        db.delete.assert_awaited_once_with(prior)
        db.flush.assert_awaited()

    @pytest.mark.asyncio
    async def test_the_delete_is_flushed_before_the_insert(self) -> None:
        """Both rows would otherwise be in the same flush and still collide."""
        prior = MagicMock(id=uuid.uuid4())
        db = _db(prior)

        await _supersede_previous_report(db, uuid.uuid4())

        assert db.flush.await_count >= 1


class TestTheFirstRunIsUnaffected:
    @pytest.mark.asyncio
    async def test_nothing_is_deleted_when_no_report_exists(self) -> None:
        db = _db(None)

        await _supersede_previous_report(db, uuid.uuid4())

        db.delete.assert_not_awaited()


class TestItNeverBlocksThePersist:
    @pytest.mark.asyncio
    async def test_a_lookup_failure_does_not_raise(self) -> None:
        """A failed pre-check must not cost a finished analysis its report."""
        db = MagicMock()
        db.execute = AsyncMock(side_effect=RuntimeError("connection reset"))
        db.delete = AsyncMock()
        db.flush = AsyncMock()

        await _supersede_previous_report(db, uuid.uuid4())
