"""BUG-06 regression: the shared, never-closing agent event loop.

The old model spun up a fresh ``asyncio.new_event_loop()`` per agent call and
``close()``d it afterwards. The openai SDK's httpx ASYNC connection pool, bound
to that loop, was orphaned on close, so the SECOND+ invocation hit
``RuntimeError: Event loop is closed`` -> a bogus ``APIConnectionError`` that
aborted the negotiation/mediator phases. The fix runs every agent coroutine on
one process-wide loop that never closes, so a client created on it is reused on
the SAME loop forever and one call's failure cannot poison the next.

Mock-LLM / plain-coroutine only -- no llama-server, no real httpx.
"""

import asyncio
from unittest.mock import MagicMock

import pytest

from maljan.agents.base_agent import _get_agent_loop, _run_coro_blocking
from maljan.agents.static_analyst import StaticAnalyst


def test_agent_loop_is_single_persistent_running_loop() -> None:
    loop1 = _get_agent_loop()
    loop2 = _get_agent_loop()
    assert loop1 is loop2  # reused, never recreated per call
    assert loop1.is_running()
    assert not loop1.is_closed()


def test_run_coro_blocking_runs_many_times_on_same_loop() -> None:
    async def _add(a: int, b: int) -> int:
        await asyncio.sleep(0)
        return a + b

    results = [_run_coro_blocking(_add(i, i), hard_timeout=5) for i in range(5)]
    assert results == [0, 2, 4, 6, 8]


def test_timeout_does_not_poison_subsequent_calls() -> None:
    """The core BUG-06 invariant: a timed-out call must not break the loop."""

    async def _hang() -> None:
        await asyncio.sleep(60)

    async def _quick() -> str:
        await asyncio.sleep(0)
        return "ok"

    with pytest.raises(TimeoutError):
        _run_coro_blocking(_hang(), hard_timeout=0.3)
    # Loop must still be healthy for the very next submission.
    assert _run_coro_blocking(_quick(), hard_timeout=5) == "ok"


def test_exception_in_coro_propagates_and_loop_survives() -> None:
    async def _boom() -> None:
        raise ValueError("kaboom")

    async def _quick() -> str:
        return "ok"

    with pytest.raises(ValueError, match="kaboom"):
        _run_coro_blocking(_boom(), hard_timeout=5)
    assert _run_coro_blocking(_quick(), hard_timeout=5) == "ok"


def test_repeated_no_tools_invocations_reuse_one_loop() -> None:
    """Sequential no-tools agent calls all succeed on the shared loop.

    This is the path that originally raised "Event loop is closed" on call #2.
    """
    before = _get_agent_loop()
    for _ in range(3):
        llm = MagicMock()
        llm.invoke.return_value = MagicMock(content="answer")
        agent = StaticAnalyst(llm=llm, name="StaticAnalyst")
        out = agent._invoke_llm_with_timeout(["hi"], timeout=5)
        assert out == "answer"
    assert _get_agent_loop() is before  # same loop throughout
