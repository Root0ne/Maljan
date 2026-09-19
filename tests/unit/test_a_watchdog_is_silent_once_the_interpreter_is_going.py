"""A daemon thread that speaks during finalisation can abort a finished run.

The cancel watchdog is a daemon thread with a ten-second fuse. When a test
session ends inside that fuse — which it does, because the last tests in the
tree retire an agent loop on purpose and the loop carries every sidecar handle
the session leaked — the thread wakes after pytest has closed its streams,
reaps the children it was told to reap, and logs. Writing to a closed stream is
a ``ValueError`` the logging module prints and swallows; holding the stderr
buffer lock while the interpreter finalises is a ``Fatal Python error`` and an
exit code of 134 on a run where every test passed.

So once the interpreter is going, the watchdog stops: it does not retire, it
does not reap, it does not log, and nothing it does can escape the thread. The
children it would have killed are the operating system's to collect a moment
later anyway.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

import pytest

from maljan.agents import base_agent
from maljan.providers import servers


class _Loop:
    """Enough event loop for the retirement to be attempted on it."""

    def __init__(self) -> None:
        self.stopped = False

    def call_soon_threadsafe(self, fn: Any, *args: Any) -> None:
        self.stopped = True

    def is_closed(self) -> bool:
        return True

    def is_running(self) -> bool:
        return False


class TestNothingHappensOnceTheInterpreterIsFinalising:
    def test_a_retirement_is_abandoned_rather_than_carried_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        called: list[Any] = []
        monkeypatch.setattr(base_agent.sys, "is_finalizing", lambda: True)
        monkeypatch.setattr(
            base_agent, "_invalidate_loop_bound_state", lambda loop: called.append(loop)
        )
        loop = _Loop()

        base_agent._retire_wedged_loop(loop, "wedged")  # type: ignore[arg-type]

        assert called == [], "the retirement hooks ran while the interpreter was going"
        assert loop.stopped is False

    def test_a_reap_signals_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        handle = servers.ServerHandle.__new__(servers.ServerHandle)
        handle.name = "knowledge"
        handle._child_pids = (1,)
        signalled: list[Any] = []
        monkeypatch.setattr(servers, "_own_child_pids", lambda: {1})
        monkeypatch.setattr(servers.ServerHandle, "_live_children", lambda self: [1])
        monkeypatch.setattr(
            servers.ServerHandle, "_signal_children", lambda self, pids, sig: signalled.append(pids)
        )
        monkeypatch.setattr(servers.sys, "is_finalizing", lambda: True)

        handle._reap_children()

        assert signalled == [], "a child was signalled during finalisation"

    def test_a_reap_that_began_in_time_stops_before_the_second_signal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The grace sleep is two seconds; finalisation can start inside it."""
        handle = servers.ServerHandle.__new__(servers.ServerHandle)
        handle.name = "knowledge"
        handle._child_pids = (1,)
        signalled: list[Any] = []
        going = iter([False, True, True, True])
        monkeypatch.setattr(servers, "_own_child_pids", lambda: {1})
        monkeypatch.setattr(servers.ServerHandle, "_live_children", lambda self: [1])
        monkeypatch.setattr(
            servers.ServerHandle, "_signal_children", lambda self, pids, sig: signalled.append(pids)
        )
        monkeypatch.setattr(servers, "CHILD_TERM_GRACE", 0.01)
        monkeypatch.setattr(servers.sys, "is_finalizing", lambda: next(going, True))

        handle._reap_children()

        assert signalled == [[1]], "the kill ran after the interpreter started finalising"

    def test_the_abandon_hook_drops_out_before_it_walks_the_handles(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reaped: list[Any] = []
        handle = servers.ServerHandle.__new__(servers.ServerHandle)
        handle.name = "knowledge"
        handle._owner_loop = "loop"
        monkeypatch.setattr(servers, "_LIVE_HANDLES", {handle})
        monkeypatch.setattr(
            servers.ServerHandle, "_reap_children", lambda self: reaped.append(self.name)
        )
        monkeypatch.setattr(servers.sys, "is_finalizing", lambda: True)

        servers._abandon_handles_on("loop")  # type: ignore[arg-type]

        assert reaped == []


class TestTheWatchdogThreadCannotThrow:
    def test_a_retirement_that_raises_does_not_escape_the_thread(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An exception out of a daemon thread prints a traceback at shutdown.

        The thread has nobody to report to, so what it must not do is die
        noisily on a stream somebody else has closed.
        """
        escaped: list[Any] = []
        monkeypatch.setattr(base_agent, "CANCEL_DELIVERY_GRACE", 0.05, raising=False)

        def boom(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("the hook exploded")

        monkeypatch.setattr(base_agent, "_retire_wedged_loop", boom)
        monkeypatch.setattr(threading, "excepthook", lambda args: escaped.append(args))

        loop = _Loop()
        future: Any = asyncio.Future(loop=asyncio.new_event_loop())
        base_agent._cancel_and_watch(loop, future, [], "wedged")  # type: ignore[arg-type]
        time.sleep(0.5)

        assert escaped == [], "the watchdog let an exception out of its thread"

    def test_the_watchdog_is_a_daemon_that_says_what_it_is(self) -> None:
        """Named, so a thread dump at exit says which thread is still awake."""
        import inspect

        source = inspect.getsource(base_agent._cancel_and_watch)

        assert 'name="maljan-agent-loop-watchdog"' in source
        assert "daemon=True" in source
