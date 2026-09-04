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
