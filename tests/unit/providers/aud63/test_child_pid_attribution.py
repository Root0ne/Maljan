"""PS-L1: two handles that launch the same argv never claim one child twice."""

from __future__ import annotations

from maljan.core.config import MCPServerConfig
from maljan.providers import servers
from maljan.providers.servers import ServerHandle


def test_a_pid_claimed_by_one_handle_is_not_taken_by_another(monkeypatch):
    servers._CLAIMED_PIDS.clear()
    a = ServerHandle("srv", MCPServerConfig(command="x"))
    b = ServerHandle("srv", MCPServerConfig(command="x"))
    a._launch_argv = b._launch_argv = ("x",)
    monkeypatch.setattr(ServerHandle, "_child_matches", lambda self, pid: True)
    seen = [{10}, {10, 11}]
    monkeypatch.setattr(servers, "_own_child_pids", lambda: seen.pop(0))
    a._note_child_pids(set())
    b._note_child_pids(set())
    assert a._child_pids == (10,)
    assert b._child_pids == (11,)


def test_concurrent_inits_of_one_argv_are_serialised(monkeypatch):
    """The snapshot-to-note window of one argv is never shared by two attaches."""
    import threading
    import time

    servers._CLAIMED_PIDS.clear()
    inside = []
    overlap = []

    def attach():
        lock = servers._launch_lock(("same", "argv"))
        with lock:
            inside.append(1)
            if len(inside) > 1:
                overlap.append(1)
            time.sleep(0.05)
            inside.pop()

    threads = [threading.Thread(target=attach) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert overlap == []
    assert servers._launch_lock(()) is None
    assert servers._launch_lock(("same", "argv")) is servers._launch_lock(("same", "argv"))


def test_forgetting_an_attachment_releases_its_claims():
    servers._CLAIMED_PIDS.clear()
    a = ServerHandle("srv", MCPServerConfig(command="x"))
    servers._CLAIMED_PIDS[(10, None)] = id(a)
    a._forget_attachment()
    assert servers._CLAIMED_PIDS == {}


def test_two_handles_opening_together_each_get_their_own_child(monkeypatch):
    import itertools
    import threading
    import time

    servers._CLAIMED_PIDS.clear()
    children: set[int] = set()
    counter = itertools.count(100)

    class _Toolkit:
        server_info: dict = {}

        async def initialize(self):
            pass

    def run(coro, label):
        coro.close()
        time.sleep(0.05)  # the child appears part-way through initialize
        children.add(next(counter))
        time.sleep(0.05)

    def build(self, *args, **kwargs):
        self._launch_argv = ("same",)
        return _Toolkit()

    import maljan.agents.base_agent as base_agent

    monkeypatch.setattr(servers, "_run_async", run)
    monkeypatch.setattr(servers, "_own_child_pids", lambda: set(children))
    monkeypatch.setattr(ServerHandle, "_build_toolkit", build)
    monkeypatch.setattr(ServerHandle, "_child_matches", lambda self, pid: True)
    monkeypatch.setattr(ServerHandle, "_finish_open_sync", lambda self, toolkit: None)
    monkeypatch.setattr(base_agent, "_get_agent_loop", lambda: None)
    handles = [ServerHandle("srv", MCPServerConfig(command="x", enabled=True)) for _ in range(2)]
    threads = [threading.Thread(target=h.open, args=(f"job{i}",)) for i, h in enumerate(handles)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(h._child_pids for h in handles) == [(100,), (101,)]


def test_a_cancelled_waiter_leaves_the_launch_lock_free():
    import asyncio
    import threading

    lock = threading.Lock()
    lock.acquire()

    async def scenario():
        task = asyncio.ensure_future(servers._acquire_launch(lock))
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        lock.release()  # the holder lets go; the abandoned acquire takes it...
        await asyncio.sleep(0.1)  # ...and gives it straight back

    asyncio.run(scenario())
    assert lock.acquire(timeout=1)
    lock.release()


def test_opens_are_not_serialised_across_initialize(monkeypatch):
    import itertools
    import threading
    import time

    servers._CLAIMED_PIDS.clear()
    children: set[int] = set()
    counter = itertools.count(200)
    started = []

    class _Toolkit:
        server_info: dict = {}

        async def initialize(self):
            pass

    def run(coro, label):
        coro.close()
        children.add(next(counter))  # spawn at once, then a slow handshake
        started.append(time.monotonic())
        time.sleep(0.4)

    def build(self, *args, **kwargs):
        self._launch_argv = ("slow",)
        return _Toolkit()

    import maljan.agents.base_agent as base_agent

    monkeypatch.setattr(servers, "_run_async", run)
    monkeypatch.setattr(servers, "_own_child_pids", lambda: set(children))
    monkeypatch.setattr(ServerHandle, "_build_toolkit", build)
    monkeypatch.setattr(ServerHandle, "_child_matches", lambda self, pid: True)
    monkeypatch.setattr(ServerHandle, "_finish_open_sync", lambda self, toolkit: None)
    monkeypatch.setattr(base_agent, "_get_agent_loop", lambda: None)
    handles = [ServerHandle("srv", MCPServerConfig(command="x", enabled=True)) for _ in range(2)]
    threads = [threading.Thread(target=h.open, args=(f"job{i}",)) for i, h in enumerate(handles)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert max(started) - min(started) < 0.3, "the second handshake waited for the first"
    assert sorted(h._child_pids for h in handles) == [(200,), (201,)]
