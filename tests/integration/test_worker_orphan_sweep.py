"""The startup sweep repairs unowned ``running`` rows and only those.

A worker that was killed mid-flight leaves its job row saying ``running`` for
ever: nothing retries it (``max_tries = 1``) and the dashboard counts it as
in-flight. The sweep at boot repairs those rows — and must not touch a job
another worker is running, which is what it would do if it assumed, as it used
to, that this process is the only worker there is.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.worker.analysis_worker import (
    _ORPHAN_GRACE_SECONDS,
    WorkerSettings,
    _sweep_orphan_jobs,
    health_check_key,
)
from tests.integration._session_probe import SessionFactory, updates_to


def _row(job_id: uuid.UUID, *, age_seconds: float) -> tuple[Any, ...]:
    started = datetime.now(UTC) - timedelta(seconds=age_seconds)
    return (job_id, started, started)


def _factory(rows: list[tuple[Any, ...]]) -> SessionFactory:
    def answer(statement: Any) -> MagicMock:
        result = MagicMock()
        result.all.return_value = [] if getattr(statement, "is_update", False) else rows
        return result

    return SessionFactory(answer)


def _redis(*, worker_alive: bool, claimed: set[str] | None = None) -> MagicMock:
    held = claimed or set()

    async def _exists(key: str) -> int:
        assert key == health_check_key()
        return 1 if worker_alive else 0

    async def _mget(keys: list[str]) -> list[Any]:
        return [b"1" if key.rsplit(":", 1)[-1] in held else None for key in keys]

    redis = MagicMock()
    redis.exists = AsyncMock(side_effect=_exists)
    redis.mget = AsyncMock(side_effect=_mget)
    return redis


@pytest.mark.asyncio
async def test_a_job_a_live_worker_holds_is_left_alone() -> None:
    """A claim in the queue plus a live worker means somebody is running it."""
    owned = uuid.uuid4()
    factory = _factory([_row(owned, age_seconds=_ORPHAN_GRACE_SECONDS + 60)])

    await _sweep_orphan_jobs(factory, _redis(worker_alive=True, claimed={str(owned)}))

    assert updates_to(factory, "analysis_jobs") == []


@pytest.mark.asyncio
async def test_a_job_no_worker_holds_is_marked_failed() -> None:
    orphan = uuid.uuid4()
    factory = _factory([_row(orphan, age_seconds=_ORPHAN_GRACE_SECONDS + 60)])

    await _sweep_orphan_jobs(factory, _redis(worker_alive=True, claimed=set()))

    failed = updates_to(factory, "analysis_jobs")
    assert len(failed) == 1
    assert failed[0]["status"] == "failed"
    assert "No worker holds this job" in failed[0]["error_message"]


@pytest.mark.asyncio
async def test_a_claim_without_a_live_worker_is_not_ownership() -> None:
    """arq sets the claim once and never refreshes it, so it outlives its worker."""
    orphan = uuid.uuid4()
    factory = _factory([_row(orphan, age_seconds=_ORPHAN_GRACE_SECONDS + 60)])

    await _sweep_orphan_jobs(factory, _redis(worker_alive=False, claimed={str(orphan)}))

    failed = updates_to(factory, "analysis_jobs")
    assert len(failed) == 1
    assert failed[0]["status"] == "failed"


@pytest.mark.asyncio
async def test_a_job_inside_the_grace_period_is_left_alone() -> None:
    """The window between the API writing the row and a worker claiming it."""
    fresh = uuid.uuid4()
    factory = _factory([_row(fresh, age_seconds=5)])

    await _sweep_orphan_jobs(factory, _redis(worker_alive=False))

    assert updates_to(factory, "analysis_jobs") == []


@pytest.mark.asyncio
async def test_a_job_past_the_job_timeout_is_swept_whatever_the_queue_says() -> None:
    stale = uuid.uuid4()
    factory = _factory([_row(stale, age_seconds=WorkerSettings.job_timeout + 60)])

    await _sweep_orphan_jobs(factory, _redis(worker_alive=True, claimed={str(stale)}))

    failed = updates_to(factory, "analysis_jobs")
    assert len(failed) == 1
    assert "job timeout" in failed[0]["error_message"]


@pytest.mark.asyncio
async def test_an_unreadable_queue_sweeps_only_what_it_can_be_sure_of() -> None:
    """Ownership unknown is not ownership refused."""
    aged = uuid.uuid4()
    stale = uuid.uuid4()
    factory = _factory(
        [
            _row(aged, age_seconds=_ORPHAN_GRACE_SECONDS + 60),
            _row(stale, age_seconds=WorkerSettings.job_timeout + 60),
        ]
    )
    redis = MagicMock()
    redis.exists = AsyncMock(side_effect=ConnectionError("queue unreachable"))
    redis.mget = AsyncMock(side_effect=ConnectionError("queue unreachable"))

    await _sweep_orphan_jobs(factory, redis)

    failed = updates_to(factory, "analysis_jobs")
    assert len(failed) == 1
    assert "job timeout" in failed[0]["error_message"]


@pytest.mark.asyncio
async def test_no_redis_at_all_sweeps_only_what_it_can_be_sure_of() -> None:
    aged = uuid.uuid4()
    factory = _factory([_row(aged, age_seconds=_ORPHAN_GRACE_SECONDS + 60)])

    await _sweep_orphan_jobs(factory)

    assert updates_to(factory, "analysis_jobs") == []


@pytest.mark.asyncio
async def test_a_clean_database_writes_nothing() -> None:
    factory = _factory([])

    await _sweep_orphan_jobs(factory, _redis(worker_alive=False))

    assert updates_to(factory, "analysis_jobs") == []
    assert [s for s in factory.sessions if s.open] == []


def test_the_grace_period_is_minutes_rather_than_hours() -> None:
    """A worker killed mid-flight is back within seconds; its row must not wait."""
    assert _ORPHAN_GRACE_SECONDS <= 900
    assert WorkerSettings.job_timeout == 28800
    assert WorkerSettings.max_tries == 1
