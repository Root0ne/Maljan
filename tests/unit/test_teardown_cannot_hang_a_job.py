"""Teardown must never be able to hold a finished job open.

Found live, and it was a regression introduced by the teardown itself. A run
completed, wrote its report and its transcript, logged `job:before_teardown` —
and then sat there. arq kept reporting `j_ongoing=1` for **42 minutes**, until
the worker took a SIGTERM. `job:end` never logged.

The cause is ordinary and will recur: an `mcp` stdio transport's
`AsyncExitStack` waits on its child process, and a child that does not exit
waits forever. What made it serious is `max_jobs = 1` — one stuck teardown
blocks every analysis after it, and nothing in the system says why, because the
job that is holding the slot has already finished its actual work.

So there are three fences, and these tests check each one holds independently:

1. `BaseAnalyst.close_tools()` — bounded per toolkit, and *awaited* rather than
   blocked on, so it cannot pin the worker's event loop either.
2. `ServiceContainer.aclose()` — bounds each closer again.
3. `run_analysis`'s `finally` — bounds the whole thing, so even a teardown path
   nobody anticipated cannot cost more than a minute.

The bug got through the first cut precisely because each layer trusted the one
below it to return.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest


class _NeverReturns:
    """A toolkit whose close hangs — the stdio-child-that-will-not-die."""

    def __init__(self) -> None:
        self.close_started = False

    async def cleanup(self) -> None:
        self.close_started = True
        await asyncio.sleep(3600)


class TestTheAnalystCloseIsBounded:
    @pytest.mark.asyncio
    async def test_a_hanging_toolkit_does_not_hang_close_tools(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import base_agent
        from maljan.agents.static_analyst import StaticAnalyst

        monkeypatch.setattr(base_agent, "CLOSE_TOOLS_TIMEOUT", 0.3)

        agent = StaticAnalyst(llm=MagicMock(), name="StaticAnalyst")
        toolkit = _NeverReturns()
        agent.toolkit = toolkit

        await asyncio.wait_for(agent.close_tools(), timeout=5)

        assert toolkit.close_started, "it must actually try before giving up"
        # References are dropped either way — a half-closed session must not be
        # left reachable from a retained agent.
        assert agent.toolkit is None
        assert agent.tools == []

    @pytest.mark.asyncio
    async def test_close_tools_is_a_coroutine_not_a_blocking_call(self) -> None:
        """It used to block the worker's loop while it waited, which is how one
        stuck subprocess froze the whole worker rather than just its own job."""
        import inspect

        from maljan.agents.base_agent import BaseAnalyst

        assert inspect.iscoroutinefunction(BaseAnalyst.close_tools)

    @pytest.mark.asyncio
    async def test_the_loop_keeps_running_while_a_close_hangs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import base_agent
        from maljan.agents.static_analyst import StaticAnalyst

        monkeypatch.setattr(base_agent, "CLOSE_TOOLS_TIMEOUT", 0.5)
        agent = StaticAnalyst(llm=MagicMock(), name="StaticAnalyst")
        agent.toolkit = _NeverReturns()

        ticks = 0

        async def _heartbeat() -> None:
            nonlocal ticks
            for _ in range(5):
                await asyncio.sleep(0.05)
                ticks += 1

        await asyncio.gather(agent.close_tools(), _heartbeat())
        assert ticks == 5, "the event loop must stay responsive during teardown"


class TestTheContainerBoundsEachCloser:
    @pytest.mark.asyncio
    async def test_one_stuck_agent_does_not_block_the_others(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core import container as container_mod

        monkeypatch.setattr(container_mod, "_ACLOSE_BUDGET", 0.3)

        async def _hangs() -> None:
            await asyncio.sleep(3600)

        stuck = MagicMock()
        stuck.name = "static"
        stuck.close_tools = _hangs
        quick = MagicMock()
        quick.name = "network"
        quick.close_tools = AsyncMock()

        c = MagicMock()
        c._lock = MagicMock()
        c._lock.__enter__ = MagicMock(return_value=None)
        c._lock.__exit__ = MagicMock(return_value=False)
        c._agent_cache = {"static": stuck, "network": quick}
        c._judge_agent_cache = {}
        c._data_cache = {}

        await asyncio.wait_for(
            container_mod.ServiceContainer.aclose(c),  # type: ignore[arg-type]
            timeout=5,
        )

        quick.close_tools.assert_awaited(), "a stuck peer must not skip the rest"
        assert c._agent_cache == {}

    @pytest.mark.asyncio
    async def test_a_stuck_judge_is_abandoned_too(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from maljan.core import container as container_mod

        monkeypatch.setattr(container_mod, "_ACLOSE_BUDGET", 0.3)

        async def _hangs() -> None:
            await asyncio.sleep(3600)

        judge = MagicMock()
        judge.aclose = _hangs

        c = MagicMock()
        c._lock = MagicMock()
        c._lock.__enter__ = MagicMock(return_value=None)
        c._lock.__exit__ = MagicMock(return_value=False)
        c._agent_cache = {}
        c._judge_agent_cache = {"expert": judge}
        c._data_cache = {}

        await asyncio.wait_for(
            container_mod.ServiceContainer.aclose(c),  # type: ignore[arg-type]
            timeout=5,
        )
        assert c._judge_agent_cache == {}


class TestTheWorkerBoundsTheWholeThing:
    def test_the_teardown_budget_exists_and_is_short(self) -> None:
        """A minute is already generous for closing a socket and a subprocess;
        the value only has to be small next to an analysis."""
        from app.worker import analysis_worker

        assert 0 < analysis_worker._TEARDOWN_BUDGET <= 300

    def test_the_finally_waits_with_a_timeout(self) -> None:
        """The specific shape matters: a bare ``await app.aclose()`` here is
        what cost 42 minutes, and it reads as perfectly correct code."""
        import inspect

        from app.worker import analysis_worker

        source = inspect.getsource(analysis_worker.run_analysis)
        assert "asyncio.wait_for(app.aclose()" in source
        assert "_TEARDOWN_BUDGET" in source

    def test_job_end_is_probed_after_teardown_whatever_happened(self) -> None:
        """`job:end` never appearing in the log is what exposed the hang; keep
        it unconditional so the next hang is visible the same way."""
        import inspect

        from app.worker import analysis_worker

        source = inspect.getsource(analysis_worker.run_analysis)
        finally_block = source.split("finally:")[-1]
        assert 'memprobe.probe("job:end"' in finally_block
        # It must sit outside the try that guards aclose, or a timeout skips it.
        assert finally_block.index("except TimeoutError") < finally_block.index(
            'memprobe.probe("job:end"'
        )


class TestTheJudgeCloseIsBounded:
    @pytest.mark.asyncio
    async def test_a_hanging_stdio_toolkit_is_abandoned(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bound moved into ``ServerHandle.aclose`` (tool-server registry
        refactor, Task 7): the judge no longer owns a single ``toolkit`` to
        close, it closes every handle bound to its role through
        ``JudgeAgent.aclose``, and each handle's own fixed 20s budget is what
        stands between a hung child process and a stuck job. The 20s itself
        is a literal inside ``ServerHandle.aclose``, not a setting, so this
        shortens only that specific call rather than every ``wait_for`` in
        the test.
        """
        from maljan.core.config import MCPServerConfig
        from maljan.providers.servers import ServerHandle

        real_wait_for = asyncio.wait_for

        async def fast_wait_for(coro: Any, timeout: float | None = None) -> Any:
            if timeout == 20.0:
                timeout = 0.1
            return await real_wait_for(coro, timeout=timeout)

        monkeypatch.setattr(asyncio, "wait_for", fast_wait_for)

        handle = ServerHandle("threatintel", MCPServerConfig(enabled=True))
        toolkit: Any = _NeverReturns()
        handle._toolkit = toolkit

        await asyncio.wait_for(handle.aclose(), timeout=5)
        assert toolkit.close_started
        assert handle._toolkit is None

    @pytest.mark.asyncio
    async def test_judge_aclose_itself_is_bounded_by_a_hanging_handle(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The handle-level bound above is necessary but not sufficient: this
        proves the judge-level property again, that ``JudgeAgent.aclose()``
        itself returns quickly when one of its registry-bound handles hangs
        on close, exactly as the single-``toolkit`` version of this test did
        before the tool-server registry refactor (Task 7).
        """
        from maljan.agents.judge_agent import JudgeAgent
        from maljan.core.config import Settings
        from maljan.providers.servers import ServerRegistry

        real_wait_for = asyncio.wait_for

        async def fast_wait_for(coro: Any, timeout: float | None = None) -> Any:
            if timeout == 20.0:
                timeout = 0.1
            return await real_wait_for(coro, timeout=timeout)

        monkeypatch.setattr(asyncio, "wait_for", fast_wait_for)

        registry = ServerRegistry(Settings(_env_file=None))
        handle = registry.get("threatintel")
        toolkit: Any = _NeverReturns()
        handle._toolkit = toolkit
        handle._job_id = "job"

        judge = JudgeAgent(llm=MagicMock())
        container = MagicMock()
        container.get_server_registry.return_value = registry
        judge._container = container

        await asyncio.wait_for(judge.aclose(), timeout=5)
        assert toolkit.close_started
        assert handle._toolkit is None
        assert judge.tools == []


# ---------------------------------------------------------------------------
# Fix wave 2: the bound above is worthless when the close is on the wrong loop.
#
# The three fences all assume the same thing: that a `wait_for` around the
# close can end it. A live run on the tool-servers branch proved that
# assumption false. The job finished at 05:58:44, logged `job:before_teardown`,
# and ten minutes later still held `j_ongoing=1` with both stdio sidecars
# running — the worker's 60s fence had fired and been discarded.
#
# The mediator judge attaches its tool servers from inside `run_on_agent_loop`
# (`pipeline/nodes.py`), so `ServerHandle.aopen` runs on the *shared agent
# loop* and the toolkit's exit stack — an anyio task group, a child process —
# belongs there. `JudgeAgent.aclose` and `ServiceContainer.aclose` then await
# `handle.aclose()` on the graph loop. That parks the teardown task on a Future
# owned by the agent loop, and such a task can be woken by neither loop:
# `wait_for`'s timeout raises `CancelledError` into a task nothing will
# resume, so the timeout is silently lost and teardown never returns.
#
# `_opened_async` recorded *that* a handle was opened asynchronously; these
# tests pin the thing that actually matters, *which loop* it was opened on,
# and that the close is routed back to it.
# ---------------------------------------------------------------------------


def _run_isolated(coro_factory: Any, timeout: float) -> Any:
    """Run an async scenario on its own loop in a thread, bounded by a watchdog.

    The failure being tested for is a hang, and a hang inside `pytest-asyncio`
    would take the whole suite with it. The scenario therefore gets its own
    thread and its own loop; when the join times out the thread is left behind
    as a daemon and the test fails with a message instead of the run stopping.
    """
    import threading

    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["result"] = asyncio.run(coro_factory())
        except BaseException as exc:  # noqa: BLE001 — re-raised on the main thread
            box["error"] = exc

    thread = threading.Thread(target=target, name="teardown-scenario", daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        pytest.fail(f"the teardown scenario did not finish within {timeout}s — it hung")
    if "error" in box:
        raise box["error"]
    return box.get("result")


class _OwnerLoopBound:
    """A toolkit whose close only works on the loop that opened it.

    The two behaviours of an `mcp` stdio exit stack that matter here: it is
    entered on one loop and its anyio cancel scope refuses to unwind anywhere
    else, and it owns a child process that nothing else will reap. Closing it
    from a foreign loop parks on a Future owned by the loop that opened it —
    which is why the real one is uncancellable, and why this one is too.
    """

    def __init__(self) -> None:
        self.owner_loop: asyncio.AbstractEventLoop | None = None
        self.closed_on: asyncio.AbstractEventLoop | None = None
        self.child_running = False

    async def initialize(self) -> None:
        self.owner_loop = asyncio.get_running_loop()
        self.child_running = True

    def get_tools(self) -> list[Any]:
        return []

    async def cleanup(self) -> None:
        loop = asyncio.get_running_loop()
        if loop is not self.owner_loop:
            # What the live worker did. The wait belongs to the loop that
            # entered the stack, so nothing on *this* loop completes it; and
            # `MCPLangChainToolkit.cleanup` catches `BaseException`, so the
            # cancellation the fence delivers is swallowed rather than ending
            # the close. Both halves are needed: a fence that fires and a
            # close that neither finishes nor dies.
            parked = loop.create_future()
            while True:
                try:
                    await parked
                except asyncio.CancelledError:
                    continue
        self.closed_on = loop
        self.child_running = False


def _handle_with(toolkit: Any) -> Any:
    """A handle whose toolkit factory yields ``toolkit``, nothing else patched."""
    from maljan.core.config import MCPServerConfig
    from maljan.providers.servers import ServerHandle

    handle = ServerHandle("threatintel", MCPServerConfig(enabled=True, command="mcp"))
    handle._build_toolkit = lambda *a, **kw: toolkit  # type: ignore[method-assign]
    return handle


class TestACrossLoopCloseIsRoutedBack:
    def test_a_handle_opened_on_another_loop_still_closes(self) -> None:
        """The live Critical: `aopen` on loop A, `aclose` on loop B.

        Before the fix this never returned and no `wait_for` could end it —
        exactly what the worker saw. The assertion is not just that `aclose`
        returns: it is that the close ran on the loop that opened the handle.
        """
        import threading

        owner = asyncio.new_event_loop()
        running = threading.Event()

        def serve() -> None:
            asyncio.set_event_loop(owner)
            owner.call_soon(running.set)
            owner.run_forever()

        thread = threading.Thread(target=serve, daemon=True, name="owner-loop")
        thread.start()
        # Waited for rather than assumed: under a loaded machine the thread can
        # take seconds to reach `run_forever`, and a budget measured from
        # before that is measuring the scheduler, not the close.
        assert running.wait(60), "the owner loop never started"
        toolkit = _OwnerLoopBound()
        handle = _handle_with(toolkit)

        try:
            # The mediator's shape: the whole attach runs on the other loop.
            asyncio.run_coroutine_threadsafe(handle.aopen("job-1"), owner).result(timeout=60)
            assert handle._owner_loop is owner
            assert toolkit.child_running

            async def scenario() -> None:
                await asyncio.wait_for(handle.aclose(), timeout=30)

            _run_isolated(scenario, timeout=60)
        finally:
            owner.call_soon_threadsafe(owner.stop)
            thread.join(timeout=30)

        assert toolkit.closed_on is owner, "the close must run on the loop that opened it"
        assert toolkit.child_running is False
        assert handle._toolkit is None
        assert handle._owner_loop is None
