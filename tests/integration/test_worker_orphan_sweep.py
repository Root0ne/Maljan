"""The sweep repairs ``running`` rows no worker is holding, and only those.

Ownership is a heartbeat the owner writes about the job it is running
(``maljan:job-owner:<job id>``, ninety seconds, refreshed every thirty). arq's
own keys cannot answer the question: its in-progress claim outlives the process
that wrote it by the length of the job timeout, and its health key is
queue-wide and outlives a killed worker by thirty-one seconds — which is
exactly when a restarted worker looks at it.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.worker.analysis_worker import (
    _OWNED_JOBS,
    JOB_OWNER_TTL_SECONDS,
    WORKER_ID,
    _sweep_orphan_jobs,
    claim_job,
    job_owner_key,
    sweep_orphans_forever,
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


def _redis(heartbeats: dict[str, str] | None = None) -> MagicMock:
    """A Redis whose owner keys are exactly ``heartbeats``."""
    held = heartbeats or {}

    async def _mget(keys: list[str]) -> list[Any]:
        return [held.get(key) for key in keys]

    redis = MagicMock()
    redis.mget = AsyncMock(side_effect=_mget)
    redis.set = AsyncMock()
    redis.delete = AsyncMock()
    return redis


@pytest.fixture(autouse=True)
def _no_jobs_owned_by_this_process():
    """This process runs no job in these tests; a leak would mask an orphan."""
    before = set(_OWNED_JOBS)
    _OWNED_JOBS.clear()
    yield
    _OWNED_JOBS.clear()
    _OWNED_JOBS.update(before)


@pytest.mark.asyncio
async def test_a_job_with_a_live_heartbeat_is_left_alone() -> None:
    owned = uuid.uuid4()
    factory = _factory([_row(owned, age_seconds=JOB_OWNER_TTL_SECONDS + 60)])

    await _sweep_orphan_jobs(factory, _redis({job_owner_key(str(owned)): WORKER_ID}))

    assert updates_to(factory, "analysis_jobs") == []


@pytest.mark.asyncio
async def test_a_job_another_worker_is_holding_is_left_alone() -> None:
    """The heartbeat names its writer, and any writer but nobody means owned."""
    theirs = uuid.uuid4()
    factory = _factory([_row(theirs, age_seconds=JOB_OWNER_TTL_SECONDS + 600)])

    await _sweep_orphan_jobs(factory, _redis({job_owner_key(str(theirs)): "otherhost:4242"}))

    assert updates_to(factory, "analysis_jobs") == []


@pytest.mark.asyncio
async def test_a_job_with_no_heartbeat_is_marked_failed() -> None:
    """The crash-restart case: the worker died and its heartbeat expired with it."""
    orphan = uuid.uuid4()
    factory = _factory([_row(orphan, age_seconds=JOB_OWNER_TTL_SECONDS + 60)])

    await _sweep_orphan_jobs(factory, _redis({}))

    failed = updates_to(factory, "analysis_jobs")
    assert len(failed) == 1
    assert failed[0]["status"] == "failed"
    assert "No worker is holding this job" in failed[0]["error_message"]
    # Written by the database's own clock, in the same statement.
    assert "now" in str(failed[0]["completed_at"]).lower()


@pytest.mark.asyncio
async def test_a_crash_inside_the_old_health_key_window_is_repaired() -> None:
    """The case the previous rule could not see.

    A worker is killed twenty minutes into a run and its container is back five
    seconds later. arq's queue-wide health key is still there for another
    twenty-five seconds and its in-progress claim for another eight hours, so
    the old rule read the dead worker's own leftovers as ownership and left the
    row. The per-job heartbeat is gone as soon as its ninety seconds are up,
    and the first pass happens after exactly that long.
    """
    killed = uuid.uuid4()
    factory = _factory([_row(killed, age_seconds=1200)])
    redis = _redis({})
    # Whatever arq left behind is not consulted at all.
    redis.exists = AsyncMock(side_effect=AssertionError("arq's keys are not ownership"))

    await _sweep_orphan_jobs(factory, redis)

    failed = updates_to(factory, "analysis_jobs")
    assert len(failed) == 1
    assert failed[0]["status"] == "failed"


@pytest.mark.asyncio
async def test_a_job_younger_than_one_ttl_is_left_for_the_next_pass() -> None:
    """A worker may have claimed it a moment ago and not yet been read."""
    fresh = uuid.uuid4()
    factory = _factory([_row(fresh, age_seconds=5)])

    await _sweep_orphan_jobs(factory, _redis({}))

    assert updates_to(factory, "analysis_jobs") == []


@pytest.mark.asyncio
async def test_a_job_this_process_is_running_is_never_swept() -> None:
    """A heartbeat that could not be written is a Redis problem, not an orphan."""
    mine = uuid.uuid4()
    factory = _factory([_row(mine, age_seconds=JOB_OWNER_TTL_SECONDS + 600)])
    _OWNED_JOBS.add(str(mine))

    await _sweep_orphan_jobs(factory, _redis({}))

    assert updates_to(factory, "analysis_jobs") == []


@pytest.mark.asyncio
async def test_a_claim_under_another_spelling_of_the_id_still_protects_the_job() -> None:
    """``uuid.UUID`` accepts spellings the database never writes.

    arq hands the task whatever the caller enqueued under, and the sweep spells
    the same job from its row. A claim written under the uppercase form and
    looked for under the canonical one would be a live job with no heartbeat as
    far as the sweep can tell — so both sides canonicalise.
    """
    job_id = uuid.uuid4()
    shouted = str(job_id).upper()
    redis = _redis({})

    await claim_job(redis, shouted)

    # Written under the one spelling, and remembered under it.
    assert redis.set.call_args.args[0] == job_owner_key(str(job_id))
    assert str(job_id) in _OWNED_JOBS
    assert shouted not in _OWNED_JOBS

    # And the sweep, reading the row's own spelling, leaves the job alone even
    # though this Redis holds no key for it at all.
    factory = _factory([_row(job_id, age_seconds=JOB_OWNER_TTL_SECONDS + 600)])
    await _sweep_orphan_jobs(factory, redis)

    assert updates_to(factory, "analysis_jobs") == []


@pytest.mark.asyncio
async def test_an_unreadable_queue_touches_nothing() -> None:
    aged = uuid.uuid4()
    factory = _factory([_row(aged, age_seconds=JOB_OWNER_TTL_SECONDS + 6000)])
    redis = _redis({})
    redis.mget = AsyncMock(side_effect=ConnectionError("queue unreachable"))

    await _sweep_orphan_jobs(factory, redis)

    assert updates_to(factory, "analysis_jobs") == []


@pytest.mark.asyncio
async def test_no_redis_at_all_touches_nothing() -> None:
    aged = uuid.uuid4()
    factory = _factory([_row(aged, age_seconds=JOB_OWNER_TTL_SECONDS + 6000)])

    await _sweep_orphan_jobs(factory)

    assert updates_to(factory, "analysis_jobs") == []


@pytest.mark.asyncio
async def test_a_clean_database_writes_nothing() -> None:
    factory = _factory([])

    await _sweep_orphan_jobs(factory, _redis({}))

    assert updates_to(factory, "analysis_jobs") == []
    assert [s for s in factory.sessions if s.open] == []


@pytest.mark.asyncio
async def test_the_first_pass_waits_and_then_the_loop_runs_on_a_clock() -> None:
    """Not at the instant of startup, and not only once.

    The delays are the loop's arguments here so the test can watch it turn;
    what ships is the pair of constants below, checked in the next test.
    """
    passes: list[float] = []

    async def _sweep(db_session: Any, redis_conn: Any = None) -> None:
        passes.append(asyncio.get_running_loop().time())

    from app.worker import analysis_worker as worker_module

    original = worker_module._sweep_orphan_jobs
    worker_module._sweep_orphan_jobs = _sweep  # type: ignore[assignment]
    try:
        task = asyncio.create_task(
            sweep_orphans_forever(
                {"db_session": _factory([]), "redis": _redis({})},
                first_delay=0.05,
                interval=0.02,
            )
        )
        started = asyncio.get_running_loop().time()
        while len(passes) < 3:
            await asyncio.sleep(0.01)
            assert asyncio.get_running_loop().time() - started < 5, "the loop never turned"
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        worker_module._sweep_orphan_jobs = original  # type: ignore[assignment]

    # The first pass waited longer than the ones after it.
    assert passes[0] - started >= 0.05
    assert passes[1] - passes[0] < 0.05
    assert task.done()


def test_the_shipped_clock_is_one_ttl_then_ten_minutes() -> None:
    from app.worker import analysis_worker as worker_module

    assert worker_module.SWEEP_FIRST_DELAY_SECONDS == JOB_OWNER_TTL_SECONDS
    assert worker_module.SWEEP_INTERVAL_SECONDS == 600
    assert worker_module.JOB_OWNER_REFRESH_SECONDS * 2 < JOB_OWNER_TTL_SECONDS, (
        "a missed refresh must not expire the claim"
    )


@pytest.mark.asyncio
async def test_a_failing_pass_does_not_end_the_loop() -> None:
    from app.worker import analysis_worker as worker_module

    calls: list[int] = []

    async def _sweep(db_session: Any, redis_conn: Any = None) -> None:
        calls.append(1)
        raise RuntimeError("the database went away")

    original = worker_module._sweep_orphan_jobs
    worker_module._sweep_orphan_jobs = _sweep  # type: ignore[assignment]
    try:
        task = asyncio.create_task(
            sweep_orphans_forever(
                {"db_session": _factory([]), "redis": _redis({})},
                first_delay=0,
                interval=0.01,
            )
        )
        started = asyncio.get_running_loop().time()
        while len(calls) < 3:
            await asyncio.sleep(0.01)
            assert asyncio.get_running_loop().time() - started < 5, "the loop stopped on a failure"
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        worker_module._sweep_orphan_jobs = original  # type: ignore[assignment]
