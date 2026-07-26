"""The worker must release what it borrowed, and leave when it gets too big.

Two independent guarantees, both added after a live session in which the host
hard-locked and a later analysis crawled for 25 minutes against a full swap:

* **Teardown.** ``run_analysis`` closes the app in a ``finally``, so the MCP
  toolkits and their subprocesses are released whether the job succeeded,
  failed, or returned early because the user cancelled it. The early-return
  path is the one worth pinning — it is easy to write a teardown that only
  covers the two obvious exits.
* **Recycle.** ``after_job_end`` exits the process when RSS is past its
  ceiling. It has to fire only above the threshold, and it must schedule the
  signal rather than raise, because it runs inside arq's own bookkeeping.
"""

from __future__ import annotations

import os
import signal
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from app.worker import analysis_worker


class TestRecycleFiresOnlyWhenBloated:
    @staticmethod
    def _loop_spy() -> Any:
        loop = MagicMock()
        loop.call_later = MagicMock()
        return loop

    @pytest.mark.asyncio
    async def test_a_small_worker_is_left_alone(self) -> None:
        loop = self._loop_spy()
        with (
            patch("maljan.core.memprobe.rss_mb", return_value=1200.0),
            patch("asyncio.get_running_loop", return_value=loop),
        ):
            await analysis_worker._recycle_if_bloated({})
        loop.call_later.assert_not_called()

    @pytest.mark.asyncio
    async def test_a_bloated_worker_schedules_its_own_exit(self) -> None:
        loop = self._loop_spy()
        with (
            patch("maljan.core.memprobe.rss_mb", return_value=9001.0),
            patch("asyncio.get_running_loop", return_value=loop),
        ):
            await analysis_worker._recycle_if_bloated({})

        loop.call_later.assert_called_once()
        delay, func, pid, sig = loop.call_later.call_args[0]
        assert delay > 0, "must return to arq before the signal lands"
        assert func is os.kill
        assert pid == os.getpid()
        # SIGTERM, not SIGKILL: arq's handler runs on_shutdown, which closes the
        # database engine and the Redis pool.
        assert sig == signal.SIGTERM

    def test_the_threshold_comes_from_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Sized for a 30 GB host that also runs a 15 GB model. A bigger box
        should raise it with an env var, not a patch."""
        import importlib

        monkeypatch.setenv("WORKER_RSS_RESTART_MB", "12345")
        reloaded = importlib.reload(analysis_worker)
        try:
            assert reloaded._RSS_RESTART_MB == 12345.0
        finally:
            monkeypatch.delenv("WORKER_RSS_RESTART_MB", raising=False)
            importlib.reload(analysis_worker)

    def test_the_hook_is_actually_wired_into_arq(self) -> None:
        """arq reads hooks off WorkerSettings by name; a rename silently
        disables this, and nothing else would notice."""
        import inspect

        from arq.worker import Worker

        assert analysis_worker.WorkerSettings.after_job_end is analysis_worker._recycle_if_bloated
        assert "after_job_end" in inspect.signature(Worker.__init__).parameters, (
            "arq no longer accepts after_job_end — the recycle backstop is dead"
        )

    def test_max_jobs_is_documented_as_concurrency(self) -> None:
        """It reads like a recycle counter and is not one. The comment is the
        only thing stopping the next reader from 'fixing' the leak with it."""
        import inspect

        source = inspect.getsource(analysis_worker.WorkerSettings)
        assert "CONCURRENCY" in source
