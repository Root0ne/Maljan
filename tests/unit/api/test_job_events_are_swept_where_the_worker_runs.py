"""``job_events`` is kept to ``core.events.retention_days``, nightly and when the worker starts.

The sweep is an arq cron on the analysis worker (03:17). It fires only in a
process alive at that minute, and arq does not run a window it missed while no
worker was up: a stack that starts its worker for a run and stops it after
(the local stack) swept only on the nights a run happened to straddle 03:17.
The worker now sweeps once as it starts, beside its job slot.

The sweep's statement is run here on a throwaway SQLite database built by the
table's own migration, the technique of ``test_job_events_migration.py``, and
its retention is read from the stored settings or not at all: a failed read
skips the sweep instead of deleting by the shipped default.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from tests.unit.api.test_job_events_migration import _job, _upgraded

# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_the_analysis_worker_registers_the_nightly_sweep_once() -> None:
    from app.worker import analysis_worker
    from app.worker.enrich_worker import EnrichmentWorkerSettings

    sweeps = [
        job
        for job in analysis_worker.WorkerSettings.cron_jobs
        if job.name == "cron:purge_old_job_events"
        or getattr(job.coroutine, "__qualname__", "") == "purge_old_job_events"
    ]
    assert len(sweeps) == 1, sweeps
    [job] = sweeps
    assert job.name == "cron:purge_old_job_events"
    # The function the worker itself refers to, the one its start-up sweep
    # calls too. Not compared with ``enrich_worker``'s attribute: another test
    # reloads ``enrich_worker``, which binds a new function object there while
    # the worker keeps the one it imported.
    assert job.coroutine is analysis_worker.purge_old_job_events
    assert job.coroutine.__module__ == "app.worker.enrich_worker"
    assert job.coroutine.__qualname__ == "purge_old_job_events"
    assert (job.hour, job.minute) == (3, 17)
    # The start-up sweep is a task of the worker's own, not a queued job: it
    # never takes the analysis slot and never reaches ``after_job_end``.
    assert job.run_at_startup is False
    assert not getattr(EnrichmentWorkerSettings, "cron_jobs", [])


def _quiet_startup(monkeypatch: pytest.MonkeyPatch, worker_module: Any) -> None:
    """``startup`` with no database, Redis, bootstrap or sample directory behind it."""
    import sys

    async def _forever(ctx: dict, **kwargs: Any) -> None:
        await asyncio.sleep(3600)

    async def _no_watch(ctx: dict) -> None:
        return None

    async def _no_mirrors(session_factory: Any) -> None:
        return None

    monkeypatch.setattr(worker_module, "sweep_orphans_forever", _forever)
    monkeypatch.setattr(worker_module, "warn_if_enrichment_is_unmanned", _no_watch)
    monkeypatch.setattr(worker_module, "state_the_mirrors", _no_mirrors)
    monkeypatch.setattr(worker_module, "setup_logging", lambda: None)
    monkeypatch.setattr(worker_module, "create_async_engine", lambda *a, **k: MagicMock())
    monkeypatch.setattr(
        worker_module.aioredis, "from_url", lambda *a, **k: MagicMock(), raising=False
    )
    monkeypatch.setattr("app.bootstrap.require_bootstrap", lambda settings: None, raising=False)
    monkeypatch.setitem(sys.modules, "app.worker.sample_files", MagicMock())

    async def _no_attck(ctx: dict) -> None:
        return None

    monkeypatch.setattr("app.worker.attck_worker.start_attck_worker", _no_attck)


@pytest.mark.asyncio
async def test_startup_sweeps_once_beside_the_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.worker import analysis_worker as worker_module

    swept: list[dict[str, Any]] = []

    async def _sweep(ctx: dict) -> dict[str, Any]:
        swept.append(ctx)
        return {"status": "ok", "removed": 0, "retention_days": 30}

    _quiet_startup(monkeypatch, worker_module)
    monkeypatch.setattr(worker_module, "purge_old_job_events", _sweep)

    ctx: dict[str, Any] = {}
    await worker_module.startup(ctx)
    task = ctx.get("events_sweep_task")
    try:
        assert isinstance(task, asyncio.Task), "the worker does not sweep when it starts"
        await task
        assert swept == [ctx]
        assert "db_session" in swept[0], "the sweep runs before it has a session factory"
    finally:
        for name in ("sweep_task", "events_sweep_task"):
            held = ctx.get(name)
            if isinstance(held, asyncio.Task):
                held.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await held


@pytest.mark.asyncio
async def test_shutdown_stops_a_sweep_still_running() -> None:
    from app.worker import analysis_worker as worker_module

    running = asyncio.Event()

    async def _long_sweep() -> None:
        running.set()
        await asyncio.sleep(3600)

    task = asyncio.create_task(_long_sweep())
    await running.wait()
    redis = MagicMock()

    async def _aclose() -> None:
        return None

    redis.aclose = _aclose

    await worker_module.shutdown({"events_sweep_task": task, "redis": redis})

    assert task.cancelled()


@pytest.mark.asyncio
async def test_a_start_task_that_failed_is_logged_and_the_shutdown_goes_on(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The Redis close, the engine dispose and the closing line run whatever a task raised."""
    import logging

    from app.worker import analysis_worker as worker_module

    async def _failed() -> None:
        raise OverflowError("date value out of range")

    task = asyncio.create_task(_failed())
    await asyncio.sleep(0)
    assert task.done()
    order: list[str] = []
    redis = MagicMock()

    async def _aclose() -> None:
        order.append("redis closed")

    async def _dispose() -> None:
        order.append("engine disposed")

    redis.aclose = _aclose
    engine = MagicMock()
    engine.dispose = _dispose
    db_session = MagicMock()
    db_session.kw = {"bind": engine}

    with caplog.at_level(logging.INFO):
        await worker_module.shutdown(
            {"events_sweep_task": task, "redis": redis, "db_session": db_session}
        )

    assert order == ["redis closed", "engine disposed"]
    said = " ".join(record.getMessage() for record in caplog.records)
    assert "events_sweep_task had ended with OverflowError" in said
    assert "Worker shutdown complete" in said


# ---------------------------------------------------------------------------
# The statement, on a throwaway database
# ---------------------------------------------------------------------------


class _AsyncFace:
    """The two ``AsyncSession`` calls the sweep makes, over a sync session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    async def __aenter__(self) -> _AsyncFace:
        return self

    async def __aexit__(self, *exc: object) -> None:
        self._session.close()

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        return self._session.execute(statement, *args, **kwargs)

    async def commit(self) -> None:
        self._session.commit()


NOW = datetime.now(UTC)
# Each row: its seq, ``ts`` and ``created_at``, by age in days.
ROWS = {
    1: (40, 40),  # stamped and written long ago
    2: (5, 5),  # recent
    3: (None, 40),  # no stamp, written long ago: its write time is its age
    4: (None, 5),  # no stamp, written recently
    5: (10, 40),  # stamped ten days ago, its batch written late: the stamp decides
}


@pytest.fixture
def engine() -> Iterator[sa.Engine]:
    from app.models.job_event import JobEvent

    engine = sa.create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    with engine.connect() as conn:
        _upgraded(conn)
        job_id = _job(conn)
        conn.execute(
            JobEvent.__table__.insert(),
            [
                {
                    "id": uuid.uuid4(),
                    "job_id": uuid.UUID(job_id),
                    "seq": seq,
                    "type": "agent_message",
                    "payload": None,
                    "ts": None if ts is None else NOW - timedelta(days=ts),
                    "created_at": NOW - timedelta(days=written),
                    "updated_at": NOW - timedelta(days=written),
                }
                for seq, (ts, written) in ROWS.items()
            ],
        )
        conn.commit()
    yield engine
    engine.dispose()


def _kept(engine: sa.Engine) -> list[int]:
    with engine.connect() as conn:
        return sorted(conn.execute(sa.text("SELECT seq FROM job_events")).scalars())


def _sweep(engine: sa.Engine) -> dict[str, Any]:
    from app.worker.enrich_worker import purge_old_job_events

    ctx = {"db_session": lambda: _AsyncFace(Session(engine))}
    return asyncio.run(purge_old_job_events(ctx))


def _stored(monkeypatch: pytest.MonkeyPatch, days: int) -> None:
    """The stored settings, as the sweep's own read of them answers."""
    from app.services import settings_service
    from maljan.core.settings_overrides import build_settings

    built = build_settings({"events.retention_days": days})

    async def _get(db: Any) -> Any:
        return built

    monkeypatch.setattr(settings_service.core_settings_cache, "get", _get)


@pytest.mark.parametrize(
    ("days", "kept"),
    [(30, [2, 4, 5]), (7, [2, 4]), (60, [1, 2, 3, 4, 5])],
)
def test_the_sweep_removes_exactly_the_rows_older_than_the_retention(
    engine: sa.Engine, monkeypatch: pytest.MonkeyPatch, days: int, kept: list[int]
) -> None:
    _stored(monkeypatch, days)

    answer = _sweep(engine)

    assert answer == {"status": "ok", "removed": len(ROWS) - len(kept), "retention_days": days}
    assert _kept(engine) == kept


def test_an_unreadable_retention_skips_the_sweep_rather_than_using_the_default(
    engine: sa.Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The shared reader would answer the shipped 30 days; the sweep deletes nothing."""
    from app.runtime_config import runtime_config
    from app.services import settings_service

    async def _unreadable(db: Any) -> Any:
        raise ConnectionError("the database did not answer")

    async def _default(*a: Any, **k: Any) -> Any:
        from maljan.core.settings_overrides import build_settings

        return build_settings({"events.retention_days": 1})

    monkeypatch.setattr(settings_service.core_settings_cache, "get", _unreadable)
    monkeypatch.setattr(runtime_config, "core", _default)

    assert _sweep(engine) == {"status": "skipped"}
    assert _kept(engine) == sorted(ROWS)


def test_a_refused_stored_retention_skips_the_sweep(
    engine: sa.Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services import settings_service
    from maljan.core.settings_overrides import StoredValueRefused

    async def _refused(db: Any) -> Any:
        raise StoredValueRefused({"events.retention_days": "Input should be greater than 0"})

    monkeypatch.setattr(settings_service.core_settings_cache, "get", _refused)

    assert _sweep(engine) == {"status": "skipped"}
    assert _kept(engine) == sorted(ROWS)


@pytest.mark.parametrize("days", [740_000, 10**12], ids=["past-the-earliest-date", "past-a-span"])
def test_a_retention_past_the_earliest_date_removes_nothing_and_is_said_once(
    engine: sa.Engine,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    days: int,
) -> None:
    """The model takes any whole number of days; one no date can count back to keeps every row."""
    import logging

    from app.worker import enrich_worker

    monkeypatch.setattr(enrich_worker, "_RETENTIONS_PAST_THE_EARLIEST_DATE", set())
    _stored(monkeypatch, days)

    with caplog.at_level(logging.INFO):
        first, second = _sweep(engine), _sweep(engine)

    assert first == second == {"status": "ok", "removed": 0, "retention_days": days}
    assert _kept(engine) == sorted(ROWS)
    said = [r.getMessage() for r in caplog.records if "earliest date" in r.getMessage()]
    assert len(said) == 1 and str(days) in said[0]
