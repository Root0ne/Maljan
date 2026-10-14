"""The ATT&CK cache's worker: its queue, its jobs and the automatic check."""

from __future__ import annotations

import asyncio
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.worker import attck_worker
from app.worker.queues import ANALYSIS_QUEUE, ATTCK_QUEUE, ENRICHMENT_QUEUE
from maljan.memory import attck_loader, attck_update


def _factory(days: Any) -> Any:
    """A session factory whose stored settings carry ``days`` (or raise it)."""

    @asynccontextmanager
    async def factory() -> Any:
        yield MagicMock()

    async def get(db: Any) -> Any:
        if isinstance(days, Exception):
            raise days
        core = MagicMock()
        core.validation.attck_refresh_days = days
        return core

    return factory, get


class TestTheQueue:
    def test_it_is_a_queue_of_its_own(self) -> None:
        assert ATTCK_QUEUE not in (ANALYSIS_QUEUE, ENRICHMENT_QUEUE)

    def test_the_worker_reads_it_beside_the_analysis_slot(self) -> None:
        async def build() -> Any:
            return attck_worker.build_attck_worker(db_session=None)

        worker = asyncio.run(build())
        assert worker.queue_name == ATTCK_QUEUE
        assert set(worker.functions) >= {"attck_status", "attck_check", "attck_update_now"}
        assert worker._handle_signals is False
        assert worker.max_jobs > 1
        assert [job.name for job in worker.cron_jobs] == ["cron:attck_scheduled_update"]


class TestTheJobs:
    def test_each_job_answers_and_never_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(*_a: Any, **_k: Any) -> Any:
            raise OSError("disk gone")

        monkeypatch.setattr(attck_update, "status", boom)
        monkeypatch.setattr(attck_update, "check", boom)
        monkeypatch.setattr(attck_update, "update", boom)

        for answer in (
            asyncio.run(attck_worker.attck_status({}, 7)),
            asyncio.run(attck_worker.attck_check({}, {"user_id": "u"}, 7)),
            asyncio.run(attck_worker.attck_update_now({}, {"user_id": "u"})),
        ):
            assert answer["ok"] is False and "disk gone" in answer["reason"]

    def test_the_update_is_run_as_the_console_s_with_who_asked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, Any] = {}

        def update(triggered_by: Any, *, trigger: str, **_kw: Any) -> dict[str, Any]:
            seen.update(triggered_by=triggered_by, trigger=trigger)
            return {"ok": True}

        monkeypatch.setattr(attck_update, "update", update)
        asyncio.run(attck_worker.attck_update_now({}, {"user_id": "u1", "name": "Ada"}))
        assert seen == {"triggered_by": {"user_id": "u1", "name": "Ada"}, "trigger": "console"}


class TestACancelledUpdate:
    def test_its_thread_is_told_to_stop_before_the_swap(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, Any] = {}
        entered = threading.Event()

        def update(triggered_by: Any, *, trigger: str, deadline: float, stop: Any) -> dict:
            seen.update(deadline=deadline, stop=stop)
            entered.set()
            stop.wait(5)
            return {"ok": False, "outcome": "stopped"}

        monkeypatch.setattr(attck_update, "update", update)

        async def cancel_it() -> None:
            job = asyncio.create_task(attck_worker.attck_update_now({}, {"user_id": "u"}))
            await asyncio.to_thread(entered.wait, 5)
            job.cancel()
            with pytest.raises(asyncio.CancelledError):
                await job

        asyncio.run(cancel_it())
        assert seen["stop"].is_set()
        assert seen["deadline"] - time.monotonic() < attck_worker.ATTCK_JOB_TIMEOUT


class TestTheAutomaticCheck:
    def test_it_reads_the_stored_interval(self, monkeypatch: pytest.MonkeyPatch) -> None:
        factory, get = _factory(30)
        monkeypatch.setattr("app.services.settings_service.core_settings_cache.get", get)
        asked: list[int] = []
        monkeypatch.setattr(attck_update, "scheduled_update", lambda days: asked.append(days))

        answer = asyncio.run(attck_worker.attck_scheduled_update({"db_session": factory}))

        assert asked == [30]
        assert answer["outcome"] == "not_due"

    def test_an_unreadable_store_skips_it_rather_than_using_the_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        factory, get = _factory(ConnectionError("database down"))
        monkeypatch.setattr("app.services.settings_service.core_settings_cache.get", get)

        def never(days: int) -> None:
            raise AssertionError("no update without a readable interval")

        monkeypatch.setattr(attck_update, "scheduled_update", never)
        answer = asyncio.run(attck_worker.attck_scheduled_update({"db_session": factory}))
        assert answer["outcome"] == "skipped"

    def test_a_due_check_returns_the_update_s_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        factory, get = _factory(7)
        monkeypatch.setattr("app.services.settings_service.core_settings_cache.get", get)
        monkeypatch.setattr(attck_update, "scheduled_update", lambda days: {"ok": True, "n": days})
        answer = asyncio.run(attck_worker.attck_scheduled_update({"db_session": factory}))
        assert answer == {"ok": True, "n": 7}


class TestTheCatalogueInThisProcess:
    def test_a_replaced_cache_is_read_afresh_by_the_next_analysis(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        directory = tmp_path / "attck"
        directory.mkdir()
        monkeypatch.setattr(
            attck_loader,
            "ATTCK_CACHE_FILES",
            {d: directory / f"{d}-attack.json" for d in attck_loader.DOMAINS},
        )
        monkeypatch.setattr(attck_worker, "_seen_signature", None)
        dropped: list[str] = []
        monkeypatch.setattr(attck_loader, "reset_caches", lambda: dropped.append("loader"))
        monkeypatch.setattr("maljan.tools.knowledge.reset_indices", lambda: dropped.append("index"))

        bundle = directory / "enterprise-attack.json"
        bundle.write_text("{}")
        assert attck_worker.drop_a_replaced_catalogue() is False
        assert attck_worker.drop_a_replaced_catalogue() is False

        replacement = directory / "next.json"
        replacement.write_text('{"objects": []}')
        replacement.replace(bundle)

        assert attck_worker.drop_a_replaced_catalogue() is True
        assert dropped == ["loader", "index"]
        assert attck_worker.drop_a_replaced_catalogue() is False


class FakeWorker:
    def __init__(self) -> None:
        self.closed = False
        self.main_task: Any = None
        self._pool: Any = None

    async def main(self) -> None:
        await asyncio.Event().wait()

    async def close(self) -> None:
        self.closed = True


class TestItsLife:
    def test_it_starts_beside_the_analyses_and_stops_with_them(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeWorker()
        monkeypatch.setattr(attck_worker, "build_attck_worker", lambda db_session: fake)
        cleared: list[bool] = []
        monkeypatch.setattr(
            attck_update, "clear_leftovers_at_start", lambda: cleared.append(True) or []
        )

        async def life() -> dict[str, Any]:
            ctx: dict[str, Any] = {"db_session": None}
            await attck_worker.start_attck_worker(ctx)
            assert fake.main_task is ctx["attck_worker_task"]
            await attck_worker.stop_attck_worker(ctx, grace=1.0)
            return ctx

        ctx = asyncio.run(life())
        assert cleared == [True]
        assert fake.closed
        assert ctx["attck_worker_task"].done()

    def test_a_worker_that_cannot_start_leaves_the_analyses_running(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken(db_session: Any) -> Any:
            raise RuntimeError("no redis settings")

        monkeypatch.setattr(attck_worker, "build_attck_worker", broken)
        ctx: dict[str, Any] = {}
        asyncio.run(attck_worker.start_attck_worker(ctx))
        assert "attck_worker" not in ctx
        asyncio.run(attck_worker.stop_attck_worker(ctx, grace=1.0))
