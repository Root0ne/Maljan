"""An upload to the object store does not stop the process serving anything else.

The MinIO client is synchronous. Called straight from a handler it blocks the
event loop for the length of the transfer — a 100 MB sample or a slow store
stalls every other request, every WebSocket frame and the worker's own
heartbeat if they share a process — and the loop cannot even answer `/health`
while it waits. Every such call now goes through a worker thread, and these
tests prove it by running the loop while the store is busy.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


class _SlowStore:
    """A store whose calls block their thread until the test lets them go."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.thread: str | None = None

    def _block(self) -> None:
        self.thread = threading.current_thread().name
        self.entered.set()
        assert self.release.wait(timeout=5), "the test never released the store"

    def bucket_exists(self, bucket: str) -> bool:
        return True

    def fput_object(self, *args: Any, **kwargs: Any) -> None:
        self._block()

    def put_object(self, *args: Any, **kwargs: Any) -> None:
        self._block()

    def get_object(self, *args: Any, **kwargs: Any) -> Any:
        self._block()
        response = MagicMock()
        response.read.return_value = b"{}"
        return response


async def _loop_keeps_turning(store: _SlowStore, call: Any) -> int:
    """Run ``call`` and count the turns the loop took while the store was busy."""
    task = asyncio.create_task(call)
    turns = 0
    while not store.entered.is_set():
        await asyncio.sleep(0.005)
        turns += 1
        assert turns < 200, "the store call never started"
    # The store is inside its call now. If it were on the loop, nothing below
    # this line could run until it returned.
    for _ in range(3):
        await asyncio.sleep(0)
        turns += 1
    store.release.set()
    await task
    return turns


@pytest.mark.asyncio
async def test_the_sandbox_report_upload_writes_from_a_thread() -> None:
    from app.api.v1 import sandbox_reports

    store = _SlowStore()
    with patch.object(sandbox_reports, "_minio_client", lambda: store):
        turns = await _loop_keeps_turning(store, sandbox_reports.put_object("x/y", b"{}"))

    assert turns > 0
    assert store.thread != threading.main_thread().name


@pytest.mark.asyncio
async def test_reading_an_uploaded_report_back_reads_from_a_thread() -> None:
    from app.api.v1 import sandbox_reports

    store = _SlowStore()
    with patch.object(sandbox_reports, "_minio_client", lambda: store):
        task = asyncio.create_task(sandbox_reports.get_object_async("x/y"))
        while not store.entered.is_set():
            await asyncio.sleep(0.005)
        store.release.set()
        assert await task == b"{}"

    assert store.thread != threading.main_thread().name


@pytest.mark.asyncio
async def test_the_sample_upload_streams_from_a_thread(tmp_path: Any) -> None:
    from app.api.v1 import samples

    blob = tmp_path / "sample.bin"
    blob.write_bytes(b"MZ")
    store = _SlowStore()

    with patch.object(samples, "_minio_client", lambda: store):
        turns = await _loop_keeps_turning(
            store,
            samples.store_sample_bytes(
                storage_path="samples/aa/aaaa",
                source=blob,
                content_type="application/octet-stream",
            ),
        )

    assert turns > 0
    assert store.thread != threading.main_thread().name


def test_nothing_on_the_loop_calls_the_store_directly() -> None:
    """The guard: an ``await``-less store call inside an ``async def``.

    Written as a source check because the next one of these will be added by
    somebody who did not read this file, and a synchronous client is easy to
    call by accident.
    """
    import ast
    import inspect

    from app.api.v1 import samples, sandbox_reports
    from app.worker import analysis_worker

    blocking = {"fput_object", "put_object", "get_object", "remove_object", "fget_object"}
    offenders: list[str] = []
    for module in (samples, sandbox_reports, analysis_worker):
        tree = ast.parse(inspect.getsource(module))
        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            for call in ast.walk(node):
                if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
                    continue
                if call.func.attr not in blocking:
                    continue
                # ``asyncio.to_thread(client.put_object, …)`` passes the method
                # rather than calling it, so what is left here is a direct call.
                offenders.append(f"{module.__name__}.{node.name}: {call.func.attr}")
    assert offenders == [], offenders
