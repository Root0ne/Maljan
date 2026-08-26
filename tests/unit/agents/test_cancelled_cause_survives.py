"""The loop boundary must not eat the reason a coroutine stopped.

Every dynamic-analyst failure in this deployment's database reads exactly
``dynamic ISR analysis failed: CancelledError`` — one word, no cause, no
service, no URL. Nothing was broken in an obvious way; the information was
destroyed in transit, by four layers each behaving as written:

1. ``mcp``'s transport lives in an anyio task group. A peer that accepts TCP
   and immediately closes it — a stale port-forward — kills the child task, the
   group cancels its scope, and ``asyncio.CancelledError`` lands in
   ``MCPLangChainToolkit.initialize()``.
2. That is a ``BaseException``, so ``except Exception`` never saw it: nothing
   was logged and ``cleanup()`` never ran.
3. The task ends CANCELLED, so ``concurrent.futures.Future.result()`` raises
   ``concurrent.futures.CancelledError`` — which in Python 3.13 IS an
   ``Exception`` and whose ``str()`` is **empty**.
4. ``describe_exception`` fell back to the bare class name.

These tests pin each link. They need no llama-server, no CAPE and no network:
a coroutine that cancels itself reproduces the whole chain exactly.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.agents.base_agent import (
    _get_agent_loop,
    _run_coro_blocking,
    describe_exception,
    run_on_agent_loop,
)
from maljan.core.exceptions import AgentLoopCancelled, AnalystError


class TestTheTwoCancellationsAreNotTheSameEvent:
    """A timeout means "wait longer". A self-cancel means "it is not there"."""

    def test_our_timeout_still_says_timeout(self) -> None:
        async def _hang() -> None:
            await asyncio.sleep(60)

        with pytest.raises(TimeoutError, match="cape-mcp-init exceeded hard cap"):
            _run_coro_blocking(_hang(), hard_timeout=0.3, label="cape-mcp-init")

    def test_a_self_cancel_is_reported_as_a_cancel_not_a_timeout(self) -> None:
        """The exact shape of the CAPE failure: instant, not slow."""

        async def _transport_dies() -> None:
            # What anyio does to the awaiting task when the task group aborts.
            raise asyncio.CancelledError

        with pytest.raises(AgentLoopCancelled) as caught:
            _run_coro_blocking(_transport_dies(), hard_timeout=30.0, label="cape-mcp-init")

        message = str(caught.value)
        assert "cape-mcp-init" in message  # which service
        assert "no timeout was reached" in message  # and that waiting would not help
        # It must still route through the pipeline's degraded-analyst path.
        assert isinstance(caught.value, AnalystError)

    def test_the_async_sibling_makes_the_same_distinction(self) -> None:
        """``run_on_agent_loop`` folded both into TimeoutError — worse, because
        it claimed a multi-minute cap had elapsed for a failure that took
        milliseconds. This is the mediator and judge path."""

        async def _transport_dies() -> None:
            raise asyncio.CancelledError

        async def _caller() -> None:
            await run_on_agent_loop(_transport_dies(), hard_timeout=300.0, label="mediation")

        with pytest.raises(AgentLoopCancelled) as caught:
            asyncio.run(_caller())
        assert "mediation" in str(caught.value)
        assert "exceeded hard cap" not in str(caught.value)

    def test_a_real_timeout_on_the_async_path_still_times_out(self) -> None:
        async def _hang() -> None:
            await asyncio.sleep(60)

        async def _caller() -> None:
            await run_on_agent_loop(_hang(), hard_timeout=0.3, label="mediation")

        with pytest.raises(TimeoutError, match="mediation exceeded hard cap"):
            asyncio.run(_caller())

    def test_ordinary_exceptions_still_cross_unchanged(self) -> None:
        """Fault isolation upstream depends on seeing the real exception."""

        async def _boom() -> None:
            raise ValueError("kaboom")

        with pytest.raises(ValueError, match="kaboom"):
            _run_coro_blocking(_boom(), hard_timeout=5, label="x")

    def test_the_loop_survives_a_cancellation(self) -> None:
        async def _transport_dies() -> None:
            raise asyncio.CancelledError

        async def _quick() -> str:
            return "ok"

        before = _get_agent_loop()
        with pytest.raises(AgentLoopCancelled):
            _run_coro_blocking(_transport_dies(), hard_timeout=5, label="x")
        assert _run_coro_blocking(_quick(), hard_timeout=5, label="y") == "ok"
        assert _get_agent_loop() is before


class TestDescribeExceptionNeverReturnsAWordAlone:
    def test_the_two_cancellederrors_are_told_apart(self) -> None:
        """They are different classes that print the same word, and only one is
        an ``Exception`` — which is exactly why it slipped through."""
        futures_text = describe_exception(concurrent.futures.CancelledError())
        asyncio_text = describe_exception(asyncio.CancelledError())

        assert futures_text != asyncio_text
        assert "concurrent.futures" in futures_text
        assert "asyncio" in asyncio_text

    def test_a_message_is_preferred_when_there_is_one(self) -> None:
        assert describe_exception(ValueError("real detail")) == "ValueError: real detail"

    def test_builtins_are_not_needlessly_qualified(self) -> None:
        assert describe_exception(ValueError()) == "ValueError"


class TestInitializeRunsCleanupOnCancellation:
    """The leak half: ``except Exception`` also meant ``cleanup()`` never ran,
    so every failed init abandoned an ``AsyncExitStack`` and its transport
    tasks on the process-wide agent loop — for the life of the worker."""

    @staticmethod
    def _toolkit() -> Any:
        from maljan.agents.mcp_client import MCPLangChainToolkit

        return MCPLangChainToolkit(
            transport="http", http_url="http://127.0.0.1:9/mcp", output_guardrail=False
        )

    def test_a_cancelled_transport_still_triggers_cleanup_and_propagates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import contextlib as _contextlib

        toolkit = self._toolkit()
        cleaned = MagicMock()

        async def _cleanup() -> None:
            cleaned()

        toolkit.cleanup = _cleanup  # type: ignore[method-assign]

        class _CancellingStack(_contextlib.AsyncExitStack):
            """Stands in for a transport whose anyio task group aborts."""

            async def enter_async_context(self, cm: Any) -> Any:
                raise asyncio.CancelledError

        # ``initialize`` imports AsyncExitStack inside the function body, so the
        # substitution has to happen on the module it imports from.
        monkeypatch.setattr(_contextlib, "AsyncExitStack", _CancellingStack)

        async def _run() -> None:
            with pytest.raises(asyncio.CancelledError):
                await toolkit.initialize()

        asyncio.run(_run())
        cleaned.assert_called_once()

    def test_cleanup_is_total_and_repeatable(self) -> None:
        """Teardown that can throw is teardown nobody calls — and this is now
        driven from a job-end ``finally``, so it must survive anything."""
        toolkit = self._toolkit()
        stack = MagicMock()
        stack.aclose = AsyncMock(side_effect=RuntimeError("Attempted to exit cancel scope"))
        toolkit._exit_stack = stack

        asyncio.run(toolkit.cleanup())  # must not raise
        assert toolkit._exit_stack is None
        asyncio.run(toolkit.cleanup())  # second call is a no-op
        stack.aclose.assert_awaited_once()
