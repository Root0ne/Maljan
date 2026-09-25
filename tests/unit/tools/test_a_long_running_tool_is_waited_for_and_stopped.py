"""capa and FLOSS on the sidecar: waited for, joined, and stopped with their caller.

The analysis server runs them with no wall clock of its own. So the client
waits for them with no deadline unless its operator set one; a timeout or a
cancellation of such a call is not the server failing, so the breaker does not
count it; a second call of the same run joins the first rather than starting a
second child; and when every caller of a run has gone, the run's child process
is killed with its process group.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import threading
import time

from maljan.providers.server_guard import ServerGuard
from maljan.tools import children

MANIFEST = {
    "capa": {"name": "capa", "timeout_s": None, "long_running": True},
    "yara_scan": {"name": "yara_scan", "timeout_s": 60},
    "strings": {"name": "strings", "timeout_s": None},
}


class TestTheClientWaits:
    def test_a_long_running_tool_has_no_client_deadline_by_default(self) -> None:
        guard = ServerGuard("analysis", call_timeout_seconds=300.0)
        guard.declare(MANIFEST)
        assert guard.call_timeout("capa") is None
        assert guard.call_timeout("yara_scan") == 300.0 + 30.0
        assert guard.call_timeout("strings") == 300.0 + 30.0

    def test_an_operator_s_budget_still_bounds_it(self) -> None:
        guard = ServerGuard("analysis", call_timeout_seconds=900.0, explicit_call_timeout=True)
        guard.declare(MANIFEST)
        assert guard.call_timeout("capa") == 900.0 + 30.0


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie still answers; ask the table.
    with open(f"/proc/{pid}/stat") as handle:
        return handle.read().split()[2] != "Z"


class TestOneRunAtATime:
    def test_a_second_caller_joins_the_first_run(self) -> None:
        started: list[int] = []

        def work() -> str:
            started.append(1)
            time.sleep(0.3)
            return "answer"

        async def two_callers() -> list[str]:
            return list(
                await asyncio.gather(
                    children.joined(("capa", "s.bin"), work),
                    children.joined(("capa", "s.bin"), work),
                )
            )

        assert asyncio.run(two_callers()) == ["answer", "answer"]
        assert started == [1], "one child for one run"

    def test_the_child_is_killed_when_every_caller_has_gone(self) -> None:
        pids: list[int] = []
        spawned = threading.Event()

        def work() -> int:
            process = subprocess.Popen(["sleep", "30"], start_new_session=True)  # noqa: S607
            children.register(lambda: children.kill_process_group(process.pid))
            pids.append(process.pid)
            spawned.set()
            return process.wait()

        async def caller_gives_up() -> None:
            call = asyncio.ensure_future(children.joined(("floss", "big.dll"), work))
            await asyncio.get_running_loop().run_in_executor(None, spawned.wait, 5)
            call.cancel()
            try:
                await call
            except asyncio.CancelledError:
                pass

        asyncio.run(caller_gives_up())
        (pid,) = pids
        deadline = time.monotonic() + 5
        while _alive(pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _alive(pid), "the sleeping child was killed with its group"

    def test_a_child_is_not_killed_while_a_caller_still_waits(self) -> None:
        def work() -> str:
            time.sleep(0.4)
            return "done"

        async def one_leaves_one_stays() -> str:
            first = asyncio.ensure_future(children.joined(("capa", "x"), work))
            second = asyncio.ensure_future(children.joined(("capa", "x"), work))
            await asyncio.sleep(0.05)
            first.cancel()
            return str(await second)

        assert asyncio.run(one_leaves_one_stays()) == "done"
