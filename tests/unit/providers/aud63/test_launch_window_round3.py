"""PS-L1 round 3: watcher release, loop refusal, process identity, off-loop join."""

from __future__ import annotations

import asyncio
import builtins
import io
import os
import threading
import time

from maljan.core.config import MCPServerConfig
from maljan.core.settings_overrides import redact_url
from maljan.providers import servers
from maljan.providers.servers import ServerHandle


def test_a_launcher_child_frees_the_window_though_its_argv_never_matches(monkeypatch):
    servers._CLAIMED_PIDS.clear()
    children: set[int] = set()
    monkeypatch.setattr(servers, "_own_child_pids", lambda: set(children))
    handle = ServerHandle("srv", MCPServerConfig(command="npx"))
    handle._launch_argv = ("npx",)
    monkeypatch.setattr(ServerHandle, "_child_matches", lambda self, pid: False)
    lock = servers._launch_lock(("npx-launcher",))
    lock.acquire()
    window = servers._LaunchWindow(lock)
    watch = servers._watch_for_child(handle, set(), window)
    children.add(7)  # the launcher's own argv, which is not ours
    deadline = time.monotonic() + 2
    while window.held and time.monotonic() < deadline:
        time.sleep(0.01)
    watch.stop()
    watch.thread.join()
    assert not window.held and handle._child_pids == ()
    assert lock.acquire(timeout=1)
    lock.release()


def test_a_blocking_open_on_the_agent_loop_thread_is_refused(monkeypatch):
    from maljan.agents.base_agent import _get_agent_loop, run_on_agent_loop

    monkeypatch.setattr(
        ServerHandle,
        "_build_toolkit",
        lambda self, *a, **k: setattr(self, "_launch_argv", ("x",)) or object(),
    )
    handle = ServerHandle("srv", MCPServerConfig(command="x", enabled=True))

    async def call():
        handle.open("job")

    async def scenario():
        await run_on_agent_loop(call(), 10.0, "refusal")

    _get_agent_loop()
    try:
        asyncio.run(scenario())
    except RuntimeError as exc:
        assert "agent loop" in str(exc)
    else:
        raise AssertionError("open on the agent loop thread was not refused")
    lock = servers._launch_lock(("x",))
    assert lock.acquire(timeout=1), "the refusal left the launch lock held"
    lock.release()


def test_a_reused_pid_is_not_the_old_child(monkeypatch):
    servers._CLAIMED_PIDS.clear()
    real_open = builtins.open

    def fake_open(path, *args, **kwargs):
        if str(path) == "/proc/10/cmdline":
            return io.BytesIO(b"x\0")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr(servers, "_own_child_pids", lambda: {10})
    started = {"now": "100"}
    monkeypatch.setattr(servers, "_start_time", lambda pid: started["now"])
    a = ServerHandle("srv", MCPServerConfig(command="x"))
    a._launch_argv = ("x",)
    a._note_child_pids(set())
    assert a._child_pids == (10,)
    started["now"] = "200"  # the pid was handed out again
    assert a._child_matches(10) is False
    b = ServerHandle("srv", MCPServerConfig(command="x"))
    b._launch_argv = ("x",)
    b._note_child_pids(set())
    assert (10, "100") not in servers._CLAIMED_PIDS, "the old claim was purged"
    assert b._child_pids == (10,)


def test_start_time_reads_field_22_of_proc_stat():
    assert servers._start_time(os.getpid()) not in (None, "")
    assert servers._start_time(2**22 + 12345) is None


def test_an_async_open_joins_its_watcher(monkeypatch):
    servers._CLAIMED_PIDS.clear()
    children: set[int] = set()

    class _Toolkit:
        server_info: dict = {}

        async def initialize(self):
            children.add(300)
            await asyncio.sleep(0.05)

    async def nothing(self, toolkit):
        return None

    monkeypatch.setattr(servers, "_own_child_pids", lambda: set(children))
    monkeypatch.setattr(
        ServerHandle,
        "_build_toolkit",
        lambda self, *a, **k: setattr(self, "_launch_argv", ("aw",)) or _Toolkit(),
    )
    monkeypatch.setattr(ServerHandle, "_child_matches", lambda self, pid: True)
    monkeypatch.setattr(ServerHandle, "_afinish_open", nothing)
    handle = ServerHandle("srv", MCPServerConfig(command="x", enabled=True))
    asyncio.run(handle.aopen("job"))
    assert handle._child_pids == (300,)
    assert not any(t.name == "child-watch" for t in threading.enumerate())


def test_camel_case_secret_names_are_masked_and_plain_words_are_not():
    out = redact_url("https://h/x?clientSecret=A&accessToken=B&refreshToken=C&authToken=D")
    assert not any(f"={v}" in out for v in "ABCD")
    kept = "https://h/x?design=1&keyword=2&author=3"
    assert redact_url(kept) == kept
