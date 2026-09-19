"""What a job opens, a job closes — the handles and the children both.

An instrumented full test run found eighty-three ``ServerHandle``s still in the
module-global ``_LIVE_HANDLES`` at the end of the session, twenty-odd of them
still holding live child pids, nearly all bound to the shared agent loop. When
that loop is retired the abandon hook walks every one of them, and the reap it
runs cost a SIGTERM, a two-second grace and a log line *per handle* on a daemon
thread — sixty-one handles in one retirement, two minutes of a thread that
pytest had already closed the streams under.

Two questions, and they are different. Whether a *job* leaves handles behind is
a question about production, answered here against live sidecars through the
container's own teardown. Whether a *session* does is a question about the
tests, answered by closing what a test opened. The reap's shape is the third:
signal everything, wait once, kill the survivors, say it once.
"""

from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

LIVE_BUDGET_S = 90.0

_INTERPRETER_MISSING = not sys.executable or not shutil.which(sys.executable)


def _live_pids() -> set[int]:
    from maljan.providers.servers import _own_child_pids

    return _own_child_pids()


def _still_running(pid: int) -> bool:
    """Whether the process is alive at all, reaped or not.

    The child of a handle dies with the loop whether or not the handle was
    closed, so "no longer our child" on its own says nothing; this asks the
    procfs entry, and reads a zombie as gone.
    """
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            fields = fh.read().rsplit(") ", 1)
    except OSError:
        return False
    return bool(fields[1:]) and fields[1].split(" ", 1)[0] != "Z"


@pytest.mark.skipif(
    _INTERPRETER_MISSING, reason="no python interpreter available to launch the sidecar"
)
class TestAFinishedJobHoldsNoSidecar:
    """Production first: the teardown the worker runs, against real children."""

    @staticmethod
    def _container(job_id: str, tmp_path: Path) -> Any:
        from maljan.core.container import ServiceContainer
        from maljan.core.settings_overrides import build_settings

        return ServiceContainer(
            build_settings({}), mock=True, samples_dir=str(tmp_path), job_id=job_id
        )

    def _run(self, job_id: str, tmp_path: Path, outcome: str) -> tuple[list[Any], set[int]]:
        """One job's tool phase, ended the way ``outcome`` names, then torn down.

        The three endings are three code paths and not three labels: one
        returns, one raises out of the body into the caller's own ``finally``,
        and one is a task another task cancels while it is awaiting. All three
        reach ``container.aclose()`` the way the worker's ``finally`` does.
        """
        from maljan.providers import servers

        container = self._container(job_id, tmp_path)
        spawned: set[int] = set()

        async def tool_phase() -> None:
            registry = container.get_server_registry()
            handle = registry.get("analysis")
            await handle.aopen(job_id)
            assert handle.is_open
            spawned.update(handle._child_pids)
            assert spawned, "the sidecar really is a child of this process"
            if outcome == "failure":
                raise RuntimeError("the analysis failed")
            if outcome == "cancel":
                await asyncio.sleep(LIVE_BUDGET_S)

        async def one_job() -> list[Any]:
            task = asyncio.ensure_future(tool_phase())
            try:
                if outcome == "cancel":
                    while not spawned:
                        await asyncio.sleep(0.05)
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await task
                elif outcome == "failure":
                    with pytest.raises(RuntimeError):
                        await task
                else:
                    await task
            finally:
                await container.aclose()
            return [h for h in servers._LIVE_HANDLES if h._job_id == job_id]

        held = asyncio.run(asyncio.wait_for(one_job(), timeout=LIVE_BUDGET_S))
        return held, spawned

    @pytest.mark.parametrize("outcome", ["success", "failure", "cancel"])
    def test_nothing_of_the_job_is_left_attached(self, tmp_path: Path, outcome: str) -> None:
        from maljan.providers import servers

        job_id = f"lifecycle-{outcome}"

        held, spawned = self._run(job_id, tmp_path, outcome)

        assert [handle for handle in held if handle.is_open] == []
        assert [handle for handle in held if handle._owner_loop is not None] == []
        assert [handle for handle in servers._ATTACHED_HANDLES if handle._job_id == job_id] == []
        assert not (spawned & _live_pids()), "the sidecar's child process is gone"
        assert not any(_still_running(pid) for pid in spawned), (
            "and it is not merely no longer our child"
        )

    def test_the_registry_the_container_dropped_is_collectable(self, tmp_path: Path) -> None:
        """``_LIVE_HANDLES`` is weak, so a closed job's handles simply go."""
        import gc

        job_id = "lifecycle-collectable"
        self._run(job_id, tmp_path, "success")
        gc.collect()

        from maljan.providers import servers

        assert [handle for handle in servers._LIVE_HANDLES if handle._job_id == job_id] == []


class _Handle:
    """A handle with children, without a transport to spawn them."""

    def __init__(self, name: str, pids: tuple[int, ...], loop: Any) -> None:
        from maljan.core.config import MCPServerConfig
        from maljan.providers.servers import ServerHandle

        self.inner = ServerHandle(name, MCPServerConfig(transport="stdio", command="/bin/true"))
        self.inner._owner_loop = loop
        self.inner._toolkit = object()
        self.inner._child_pids = pids
        self.inner._launch_argv = ("/bin/true",)
        self.signalled: list[tuple[list[int], int]] = []
        self.inner._signal_children = self._signal  # type: ignore[method-assign]
        self.inner._live_children = lambda: list(pids)  # type: ignore[method-assign]

    def _signal(self, pids: list[int], sig: int) -> None:
        self.signalled.append((list(pids), sig))


class TestTheReapPaysOneGraceForTheWholeSet:
    """A retirement that meets sixty-one handles must not cost sixty-one
    grace periods on the watchdog thread."""

    @staticmethod
    def _retire(handles: list[_Handle], loop: Any, monkeypatch: pytest.MonkeyPatch) -> list[float]:
        # The grace is a ``time.sleep`` inside the function, so the module it
        # imports is the one to watch.
        import time as time_module

        from maljan.providers import servers

        slept: list[float] = []
        monkeypatch.setattr(time_module, "sleep", slept.append)
        monkeypatch.setattr(servers, "_own_child_pids", lambda: set())
        servers._abandon_handles_on(loop)
        return slept

    def test_one_sleep_for_many_handles(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from maljan.providers import servers

        loop = asyncio.new_event_loop()
        try:
            handles = [_Handle(f"s{index}", (9000 + index,), loop) for index in range(12)]

            slept = self._retire(handles, loop, monkeypatch)

            assert slept == [servers.CHILD_TERM_GRACE], "one grace period, not one per handle"
            assert all(handle.signalled for handle in handles), "every child was signalled"
            assert all(not handle.inner.is_open for handle in handles)
            assert all(handle.inner._owner_loop is None for handle in handles)
        finally:
            loop.close()

    def test_nothing_sleeps_when_no_handle_has_a_child(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        loop = asyncio.new_event_loop()
        try:
            handles = [_Handle(f"q{index}", (), loop) for index in range(4)]

            slept = self._retire(handles, loop, monkeypatch)

            assert slept == []
            assert all(not handle.inner.is_open for handle in handles)
        finally:
            loop.close()

    def test_the_whole_set_is_one_line(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        loop = asyncio.new_event_loop()
        try:
            [_Handle(f"r{index}", (9100 + index,), loop) for index in range(8)]

            with caplog.at_level(logging.ERROR, logger="maljan"):
                self._retire([], loop, monkeypatch)

            abandoned = [rec for rec in caplog.records if "retired" in rec.getMessage()]
            assert len(abandoned) == 1, [rec.getMessage() for rec in abandoned]
            assert "r0" in abandoned[0].getMessage()
        finally:
            loop.close()

    def test_a_handle_on_another_loop_is_left_alone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        retired = asyncio.new_event_loop()
        other = asyncio.new_event_loop()
        try:
            mine = _Handle("mine", (9200,), retired)
            yours = _Handle("yours", (9201,), other)

            self._retire([mine, yours], retired, monkeypatch)

            assert mine.signalled and not yours.signalled
            assert yours.inner.is_open
        finally:
            retired.close()
            other.close()

    def test_an_interpreter_that_is_finalising_is_not_signalled_at_all(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The watchdog stands down once pytest has closed its streams."""
        from maljan.providers import servers

        loop = asyncio.new_event_loop()
        try:
            handle = _Handle("late", (9300,), loop)
            monkeypatch.setattr(sys, "is_finalizing", lambda: True)

            servers._abandon_handles_on(loop)

            assert handle.signalled == []
            assert handle.inner._kill_survivors([9300]) == []
            assert handle.inner._terminate_children() == []
        finally:
            loop.close()


class TestTheRemovalCannotBeSkipped:
    """A job's ``finally`` awaits three things before it takes the staging
    directory away, and a worker being shut down cancels the task again while
    one of them is unwinding. ``CancelledError`` is a ``BaseException``, so
    none of the handlers there catch it and the block would simply end."""

    def test_a_second_cancellation_during_the_teardown_does_not_skip_it(self) -> None:
        removed: list[str] = []

        async def job() -> None:
            try:
                await asyncio.sleep(LIVE_BUDGET_S)
            finally:
                try:
                    # Standing in for the three awaits the worker makes here:
                    # the event feed, the owner heartbeat and the teardown. The
                    # second cancellation lands on the first of them.
                    task = asyncio.current_task()
                    assert task is not None
                    task.cancel()
                    await asyncio.sleep(0)
                    await asyncio.sleep(0)
                finally:
                    removed.append("staging")

        async def cancelled_twice() -> None:
            task: asyncio.Task[None] = asyncio.ensure_future(job())
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(cancelled_twice())

        assert removed == ["staging"], "the guarded statement ran anyway"

    def test_the_worker_guards_it_that_way(self) -> None:
        """The pattern above, read out of the function that has to carry it."""
        import ast
        import inspect

        from app.worker import analysis_worker

        tree = ast.parse(inspect.getsource(analysis_worker.run_analysis))
        outer = [node for node in ast.walk(tree) if isinstance(node, ast.Try) and node.finalbody]
        guarded = [
            node
            for node in outer
            for statement in node.finalbody
            if isinstance(statement, ast.Try)
            for inner in statement.finalbody
            if "remove_job_staging" in ast.dump(inner)
        ]

        assert guarded, "the removal is the body of a finally of its own"
