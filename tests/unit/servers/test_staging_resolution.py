"""What the resolver does about staging before it hands anything to a loop.

The live run spent two minutes per agent on this step and staged nothing: every
server was stdio, so the answer was ``{}`` before any transport was touched,
and the coroutine that would have said so was submitted to the shared agent
loop from a thread holding the container's cache lock — which the coroutine
then asked for. These tests hold both halves: the question is answered on the
caller's own thread, and the coroutine that does run never reaches back into
the container for anything guarded.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from maljan.agents import composition, sample_staging


class _Handle:
    def __init__(self, name: str, transport: str) -> None:
        self.name = name
        self.is_open = True
        self.config = type("_Cfg", (), {"transport": transport})()
        self.staged: list[str] = []

    def all_tool_names(self) -> list[str]:
        return ["identify_file", "put_sample"]

    def tools(self) -> list[Any]:
        from langchain_core.tools import StructuredTool

        def _put_sample(filename: str, content_b64: str, sha256: str = "") -> dict[str, Any]:
            self.staged.append(filename)
            return {"path": f"/remote/{filename}"}

        return [
            StructuredTool.from_function(func=_put_sample, name="put_sample", description="upload")
        ]


class _Registry:
    def __init__(self, handles: dict[str, _Handle]) -> None:
        self._handles = handles
        self.degradation_reasons: list[str] = []

    def get(self, name: str) -> _Handle:
        return self._handles[name]


class _Container:
    """A container that guards its registry the way ``ServiceContainer`` does."""

    def __init__(self, registry: _Registry, sample_path: str) -> None:
        self._registry = registry
        self._lock = threading.RLock()
        self.sample_path = sample_path
        self.sample_sha256 = "a" * 64

    def get_server_registry(self) -> _Registry:
        with self._lock:
            return self._registry


def _tool_from(server: str) -> Any:
    from langchain_core.tools import StructuredTool

    return StructuredTool.from_function(
        func=lambda: "x",
        name="identify_file",
        description="x",
        metadata={"maljan_server": server},
    )


@pytest.fixture(autouse=True)
def _clear_cache():
    sample_staging.clear_cache()
    yield
    sample_staging.clear_cache()


def _sample(tmp_path: Path) -> str:
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ" + b"\x00" * 64)
    return str(target)


class TestNothingRemoteToStageTo:
    def test_a_stdio_only_deployment_hands_the_loop_nothing(self, tmp_path: Path) -> None:
        registry = _Registry({"analysis": _Handle("analysis", "stdio")})
        container = _Container(registry, _sample(tmp_path))

        def _must_not_run(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("a stdio-only deployment must not submit a staging coroutine")

        from maljan.agents import base_agent

        original = base_agent.run_coro_blocking
        base_agent.run_coro_blocking = _must_not_run  # type: ignore[assignment]
        try:
            staged, reasons = composition._stage(container, [_tool_from("analysis")], "job-7")
        finally:
            base_agent.run_coro_blocking = original  # type: ignore[assignment]

        assert staged == {}
        assert reasons == []

    def test_a_job_with_no_sample_stages_nothing(self) -> None:
        registry = _Registry({"remote": _Handle("remote", "http")})
        container = _Container(registry, "")
        container.sample_path = None  # type: ignore[assignment]

        assert composition._stage(container, [_tool_from("remote")], "job-7") == ({}, [])


class TestARemoteServerIsStagedTo:
    def test_the_upload_happens_and_the_path_comes_back(self, tmp_path: Path) -> None:
        handle = _Handle("remote", "streamable-http")
        container = _Container(_Registry({"remote": handle}), _sample(tmp_path))

        staged, reasons = composition._stage(container, [_tool_from("remote")], "job-7")

        assert staged == {"remote": "/remote/sample.exe"}
        assert handle.staged == ["sample.exe"]
        assert reasons == []

    def test_the_caller_may_hold_the_container_s_cache_lock(self, tmp_path: Path) -> None:
        """``get_agent`` resolves under that lock, and the coroutine runs on
        another thread: anything guarded reached from there would wait for a
        lock only the blocked caller can release."""
        handle = _Handle("remote", "http")
        container = _Container(_Registry({"remote": handle}), _sample(tmp_path))

        with container._lock:
            staged, _ = composition._stage(container, [_tool_from("remote")], "job-7")

        assert staged == {"remote": "/remote/sample.exe"}


class TestTheWarningNamesTheJob:
    def test_a_staging_failure_is_logged_against_the_job_id(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        container = _Container(_Registry({"remote": _Handle("remote", "http")}), _sample(tmp_path))

        from maljan.agents import base_agent

        original = base_agent.run_coro_blocking

        def _times_out(*args: Any, **kwargs: Any) -> Any:
            for arg in args:
                if hasattr(arg, "close"):
                    arg.close()
            raise TimeoutError("sample-staging exceeded hard cap of 120.0s")

        base_agent.run_coro_blocking = _times_out  # type: ignore[assignment]
        try:
            with caplog.at_level("WARNING"):
                staged, reasons = composition._stage(container, [_tool_from("remote")], "job-42")
        finally:
            base_agent.run_coro_blocking = original  # type: ignore[assignment]

        assert (staged, reasons) == ({}, [])
        assert "sample staging skipped for job job-42" in caplog.text

    def test_the_container_hands_the_resolver_its_job_id(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        assert ServiceContainer(Settings(), mock=True, job_id="job-9").job_key() == "job-9"

    def test_a_caller_with_no_job_id_gets_one_per_run(self) -> None:
        """The key names a staging directory. A constant would have two
        concurrent command-line runs writing into one, and a value derived from
        the process alone would hand a recycled pid the last run's directory."""
        import os

        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(Settings(), mock=True)
        key = container.job_key()

        assert key.startswith(f"cli-{os.getpid()}-")
        assert container.job_key() == key, "fixed for the life of one container"
        assert ServiceContainer(Settings(), mock=True).job_key() != key, "and only that one"
