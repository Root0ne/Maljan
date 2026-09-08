"""A cancelled MCP teardown must not leave the agent loop spinning (BUG 7).

The live capture (`other/audit/2026-09-07-live-e2e/S6-worker-hang-pyspy.txt`)
showed the thread `maljan-agent-loop` at 100 % CPU for 80 minutes inside
anyio's `CancelScope._deliver_cancellation`, with `_run_once` computing
`timeout: 0` every iteration, while the worker's own thread was starved of the
GIL and the job's heartbeat stopped. The chain:

1. `ServerHandle._acleanup` bounded the toolkit close with
   `asyncio.wait_for(closer(), CLEANUP_TIMEOUT)`.
2. When that budget expired, `wait_for` **cancelled** the task that was
   half-way through unwinding `mcp.client.stdio.stdio_client`.
3. That transport's shutdown block is *unshielded*. Under an already-delivered
   cancellation every `await` in it raises `CancelledError` at once, and its
   `except TimeoutError:` does not catch that — so `_terminate_process_tree`,
   the SIGTERM -> SIGKILL escalation, never runs and the child stays alive.
4. anyio's live child wait is shielded (`Process.aclose`), so the cancellation
   can never be *delivered* to it; and `CancelScope._deliver_cancellation` sets
   `should_retry = True` for every task still in the scope, re-arming itself
   with `loop.call_soon` on every single iteration. A scope that can never
   empty therefore spins the loop thread for the life of the process.

So the fix is not a bigger budget or a better watchdog: it is to stop
cancelling a transport that is parked on a child, and take the child instead.
These tests model that path — a real subprocess that ignores SIGTERM, a
shielded waiter that cannot receive a cancellation, and a shutdown block that
is skipped when one is delivered.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import threading
import time
from typing import Any

import pytest

# A child that survives everything except SIGKILL, and never exits on its own.
_DEAF_CHILD = "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(600)"


def _spawn_sigterm_deaf_child() -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603 — fixed argv, no shell
        [sys.executable, "-c", _DEAF_CHILD],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )


class _StdioLikeToolkit:
    """A toolkit whose close behaves the way `mcp`'s stdio transport does.

    Two properties, both taken from the real code rather than invented:

    * the shutdown escalation lives *after* an unshielded `await`, so a
      cancellation delivered into the unwind skips it entirely
      (`mcp/client/stdio/__init__.py`, the `finally:` at the end of
      `stdio_client`);
    * the wait on the child is shielded, so the cancellation is never received
      and the scope it belongs to can never empty (anyio's `Process.aclose`).
    """

    def __init__(self, child: subprocess.Popen[bytes]) -> None:
        self.child = child
        self.escalation_ran = False
        self.close_returned = False

    async def _shielded_child_wait(self) -> None:
        import anyio

        with anyio.CancelScope(shield=True):
            while self.child.poll() is None:
                await anyio.sleep(0.02)

    async def cleanup(self) -> None:
        import anyio

        async with anyio.create_task_group() as tg:
            tg.start_soon(self._shielded_child_wait)
            try:
                with anyio.fail_after(0.2):
                    await self._shielded_child_wait()
            except TimeoutError:
                # The SIGTERM -> SIGKILL escalation. A cancellation raises
                # `CancelledError` out of the `await` above instead, which this
                # clause does not catch, so none of it runs.
                self.escalation_ran = True
                self.child.terminate()
        self.close_returned = True


class _LoopThread:
    """A private event loop in its own thread, with its per-thread CPU clock.

    The scenario may not run on the shared agent loop: the failure being tested
    for wedges whatever loop it lands on, and the shared one outlives the test.
    """

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.tid = 0
        started = threading.Event()

        def serve() -> None:
            self.tid = threading.get_native_id()
            asyncio.set_event_loop(self.loop)
            self.loop.call_soon(started.set)
            self.loop.run_forever()

        self.thread = threading.Thread(target=serve, name="spin-probe-loop", daemon=True)
        self.thread.start()
        started.wait(5)

    def cpu_seconds(self) -> float:
        """utime + stime of this loop's thread, in seconds."""
        with open(f"/proc/self/task/{self.tid}/stat", "rb") as fh:
            fields = fh.read().rsplit(b") ", 1)[1].split()
        ticks = int(fields[11]) + int(fields[12])
        return ticks / os.sysconf("SC_CLK_TCK")

    def run(self, coro: Any, timeout: float) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


def _handle_for(child: subprocess.Popen[bytes]) -> Any:
    """A handle that owns ``child`` the way an attached stdio server does."""
    from maljan.core.config import MCPServerConfig
    from maljan.providers.servers import ServerHandle

    handle = ServerHandle("network", MCPServerConfig(enabled=True, command=sys.executable))
    handle._child_pids = (child.pid,)
    handle._launch_argv = (sys.executable, "-c", _DEAF_CHILD)
    return handle


@pytest.fixture
def deaf_child() -> Any:
    child = _spawn_sigterm_deaf_child()
    try:
        yield child
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(10)


@pytest.fixture
def loop_thread() -> Any:
    lt = _LoopThread()
    try:
        yield lt
    finally:
        lt.stop()


class TestACleanupThatOverrunsTakesTheChildRatherThanCancelling:
    def test_the_child_is_dead_when_the_cleanup_budget_expires(
        self, deaf_child: subprocess.Popen[bytes], loop_thread: _LoopThread
    ) -> None:
        """The property the 80-minute spin came down to.

        Before the fix `_acleanup` cancelled the unwinding transport and left
        the child running — the log line "abandoning it" followed by a sidecar
        that was still alive an hour later. The reap that ran afterwards only
        sent SIGTERM, which this child ignores by construction, exactly as the
        network sidecar did while it was inside scapy.
        """
        from maljan.providers import servers

        toolkit = _StdioLikeToolkit(deaf_child)
        handle = _handle_for(deaf_child)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(servers, "CLEANUP_TIMEOUT", 0.5)
            loop_thread.run(handle._acleanup(toolkit), timeout=20)

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and deaf_child.poll() is None:
            time.sleep(0.05)
        assert deaf_child.poll() is not None, (
            "the cleanup overran its budget and the child that held it open is "
            "still running: the teardown cancelled the transport instead of "
            "killing the process the transport was waiting for"
        )

    def test_the_loop_is_not_left_spinning_afterwards(
        self, deaf_child: subprocess.Popen[bytes], loop_thread: _LoopThread
    ) -> None:
        """The symptom itself: 100 % of a core, for as long as the process lives.

        A cancellation delivered into a scope that can never empty makes anyio
        re-arm `_deliver_cancellation` with `call_soon` every iteration, so the
        loop never sleeps. Measured on the loop's own thread clock rather than
        by wall time, so an unrelated busy machine cannot fake a pass.
        """
        from maljan.providers import servers

        toolkit = _StdioLikeToolkit(deaf_child)
        handle = _handle_for(deaf_child)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(servers, "CLEANUP_TIMEOUT", 0.5)
            loop_thread.run(handle._acleanup(toolkit), timeout=20)

        before = loop_thread.cpu_seconds()
        time.sleep(1.0)
        burned = loop_thread.cpu_seconds() - before
        assert burned < 0.25, (
            f"the loop thread burned {burned:.2f}s of CPU in one idle second — it is "
            "spinning on a cancellation nothing can receive (BUG 7)"
        )

    def test_the_transport_is_allowed_to_finish_rather_than_cancelled(
        self, deaf_child: subprocess.Popen[bytes], loop_thread: _LoopThread
    ) -> None:
        """Killing the child is what *lets* the unwind complete.

        The distinction matters: a cancelled unwind leaves an anyio cancel
        scope that is never exited, which is the state the loop spins in. With
        the child gone the transport's own waits return and the stack unwinds
        normally, so there is nothing left to cancel.
        """
        from maljan.providers import servers

        toolkit = _StdioLikeToolkit(deaf_child)
        handle = _handle_for(deaf_child)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(servers, "CLEANUP_TIMEOUT", 0.5)
            loop_thread.run(handle._acleanup(toolkit), timeout=20)

        assert toolkit.close_returned, (
            "the toolkit close never returned: it was cancelled mid-unwind instead "
            "of being unblocked"
        )

    def test_a_healthy_cleanup_is_untouched(self, loop_thread: _LoopThread) -> None:
        """Nothing is killed on the path that closes itself in time."""
        from maljan.core.config import MCPServerConfig
        from maljan.providers.servers import ServerHandle

        class _Prompt:
            def __init__(self) -> None:
                self.closed = False

            async def cleanup(self) -> None:
                await asyncio.sleep(0)
                self.closed = True

        handle = ServerHandle("threatintel", MCPServerConfig(enabled=True, command="mcp"))
        toolkit = _Prompt()
        assert loop_thread.run(handle._acleanup(toolkit), timeout=10) is True
        assert toolkit.closed


class TestTheAgentLoopThreadNeverBlocksOnItself:
    def test_a_blocking_submit_from_the_agent_loop_thread_is_refused(self) -> None:
        """`_run_coro_blocking` on the agent loop's own thread is a deadlock.

        `future.result(timeout)` blocks the calling thread; when that thread is
        the one serving the loop, the coroutine it is waiting for can never be
        run. It parks for the whole hard cap with the loop dead underneath it —
        one of the two ways `_retire_wedged_loop` describes a loop that "never
        returns to the loop". Refusing it names the caller instead.
        """
        from maljan.agents.base_agent import _get_agent_loop, _run_coro_blocking

        async def _noop() -> str:
            return "ok"

        async def _from_inside() -> Exception | None:
            try:
                _run_coro_blocking(_noop(), hard_timeout=1.0, label="probe")
            except RuntimeError as exc:
                return exc
            return None

        loop = _get_agent_loop()
        caught = asyncio.run_coroutine_threadsafe(_from_inside(), loop).result(10)
        assert isinstance(caught, RuntimeError)
        assert "agent loop" in str(caught).lower()
