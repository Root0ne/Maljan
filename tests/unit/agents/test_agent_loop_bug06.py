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
import contextlib
from unittest.mock import MagicMock

import pytest

from maljan.agents.base_agent import _get_agent_loop, _run_coro_blocking, run_on_agent_loop
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


class TestGraphNodesReachTheSameLoop:
    """The other half of BUG-06, found live on 2026-07-26.

    Moving the *analysts* onto the shared loop was only half a fix. The graph's
    own coroutine nodes still awaited their agent calls on the worker's loop,
    and the openai SDK's httpx pool is process-wide and bound to whichever loop
    first awaited it — always the agent loop, because the analysts run first.
    So the mediator's call died instantly with ``RuntimeError: ... bound to a
    different event loop``, which the SDK reports as a bare
    ``APIConnectionError("Connection error.")``.

    Every run in the database carried ``Mediation failed: Connection error.``
    The negotiation had never once completed, and the node's fault-isolation
    boundary degraded it to "no consensus" quietly enough that nothing showed.
    """

    def test_a_resource_born_on_the_agent_loop_rejects_another_loop(self) -> None:
        """The mechanism itself, with an ``Event`` standing in for httpx.

        No llama-server needed: any loop-bound primitive reproduces it. This is
        why building a fresh ``ChatOpenAI`` never helped — the *pool* is shared,
        so a new client object inherits the old client's loop affinity.
        """
        agent_loop = _get_agent_loop()

        async def _make() -> asyncio.Event:
            evt = asyncio.Event()
            # Binding happens on first *use*, not construction — same as the
            # httpx pool, which is why the failure only appears once an
            # analyst has actually made a call.
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(evt.wait(), 0.01)
            return evt

        shared = _run_coro_blocking(_make(), hard_timeout=5)

        async def _await_from_a_different_loop() -> str:
            try:
                await asyncio.wait_for(shared.wait(), timeout=0.2)
            except RuntimeError as exc:  # the real failure, verbatim
                return f"rejected: {exc}"
            except TimeoutError:
                return "waited"
            return "waited"

        outcome = asyncio.run(_await_from_a_different_loop())
        assert "different event loop" in outcome

        # Routed onto the loop that owns it, the same await behaves normally.
        async def _via_helper() -> str:
            async def _wait_on_agent_loop() -> str:
                try:
                    await asyncio.wait_for(shared.wait(), timeout=0.2)
                except TimeoutError:
                    return "waited"
                return "waited"

            return await run_on_agent_loop(_wait_on_agent_loop(), hard_timeout=5)

        assert asyncio.run(_via_helper()) == "waited"
        assert _get_agent_loop() is agent_loop

    def test_the_helper_runs_the_coroutine_on_the_agent_loop(self) -> None:
        async def _where_am_i() -> asyncio.AbstractEventLoop:
            return asyncio.get_running_loop()

        async def _caller() -> tuple[asyncio.AbstractEventLoop, asyncio.AbstractEventLoop]:
            ran_on = await run_on_agent_loop(_where_am_i(), hard_timeout=5)
            return ran_on, asyncio.get_running_loop()

        ran_on, caller_loop = asyncio.run(_caller())
        assert ran_on is _get_agent_loop()
        assert ran_on is not caller_loop  # the whole point

    def test_exceptions_cross_the_loop_boundary_unchanged(self) -> None:
        """Fault isolation upstream depends on seeing the real exception."""

        async def _boom() -> None:
            raise ValueError("kaboom")

        async def _caller() -> None:
            await run_on_agent_loop(_boom(), hard_timeout=5)

        with pytest.raises(ValueError, match="kaboom"):
            asyncio.run(_caller())

    def test_a_hung_mediation_times_out_without_poisoning_the_loop(self) -> None:
        async def _hang() -> None:
            await asyncio.sleep(60)

        async def _quick() -> str:
            return "ok"

        async def _caller() -> None:
            await run_on_agent_loop(_hang(), hard_timeout=0.3)

        with pytest.raises(TimeoutError):
            asyncio.run(_caller())
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
