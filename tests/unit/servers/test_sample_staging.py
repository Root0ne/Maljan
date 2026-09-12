"""Uploading the sample to a server that cannot see the worker's filesystem.

Against a fake registry rather than a live sidecar: what matters here is the
convention — single-shot below the threshold, chunked above it when the server
offers all three calls, a failure that degrades instead of raising, and a
second ask that does not re-upload. A live server would exercise the same four
paths more slowly and prove less about them.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
from pathlib import Path
from typing import Any

import pytest

from maljan.agents import sample_staging


class _FakeTool:
    def __init__(self, name: str, handler: Any) -> None:
        self.name = name
        self._handler = handler

    async def ainvoke(self, kwargs: dict[str, Any]) -> Any:
        return self._handler(**kwargs)


class _FakeServer:
    """A stand-in tool server that implements the convention in memory."""

    def __init__(self, *, chunked: bool = True, fail: str = "") -> None:
        self.name = "remote"
        self.is_open = True
        self.config = type("_Cfg", (), {"transport": "streamable-http"})()
        self.calls: list[str] = []
        self.received: bytes = b""
        self._uploads: dict[str, dict[int, bytes]] = {}
        self._chunked = chunked
        self._fail = fail

    def all_tool_names(self) -> list[str]:
        names = ["identify_file", "put_sample"]
        if self._chunked:
            names += ["put_sample_begin", "put_sample_chunk", "put_sample_finish"]
        return names

    def tools(self) -> list[Any]:
        handlers = {
            "put_sample": self._put_sample,
            "put_sample_begin": self._begin,
            "put_sample_chunk": self._chunk,
            "put_sample_finish": self._finish,
        }
        return [
            _FakeTool(name, handlers[name]) for name in self.all_tool_names() if name in handlers
        ]

    def _put_sample(self, filename: str, content_b64: str, sha256: str = "") -> dict[str, Any]:
        self.calls.append("put_sample")
        if self._fail:
            return {"error": self._fail}
        self.received = base64.b64decode(content_b64)
        return {"path": f"/remote/staging/{filename}", "sha256": sha256}

    def _begin(self, filename: str, sha256: str, size: int) -> dict[str, Any]:
        self.calls.append("put_sample_begin")
        self._uploads["u1"] = {}
        self._filename = filename
        return {"upload_id": "u1"}

    def _chunk(self, upload_id: str, seq: int, content_b64: str) -> dict[str, Any]:
        self.calls.append("put_sample_chunk")
        self._uploads[upload_id][seq] = base64.b64decode(content_b64)
        return {"seq": seq}

    def _finish(self, upload_id: str) -> dict[str, Any]:
        self.calls.append("put_sample_finish")
        chunks = self._uploads.pop(upload_id)
        self.received = b"".join(chunks[s] for s in sorted(chunks))
        return {"path": f"/remote/staging/{self._filename}"}


class _FakeRegistry:
    def __init__(self, handle: Any | None) -> None:
        self._handle = handle
        self.degradation_reasons: list[str] = []

    def get(self, name: str) -> Any:
        if self._handle is None:
            raise KeyError(name)
        return self._handle


@pytest.fixture(autouse=True)
def _clear_cache():
    sample_staging.clear_cache()
    yield
    sample_staging.clear_cache()


def _sample(tmp_path: Path, size: int) -> tuple[str, str]:
    target = tmp_path / "sample.exe"
    blob = bytes((i * 7) % 251 for i in range(size))
    target.write_bytes(blob)
    return str(target), hashlib.sha256(blob).hexdigest()


class TestSingleShot:
    def test_a_small_sample_goes_in_one_call_and_the_bytes_arrive_intact(
        self, tmp_path: Path
    ) -> None:
        path, digest = _sample(tmp_path, 4096)
        server = _FakeServer()
        registry = _FakeRegistry(server)

        staged = asyncio.run(
            sample_staging.stage_sample(registry, "remote", path, sha256=digest, job_id="job-1")
        )

        assert staged == "/remote/staging/sample.exe"
        assert server.calls == ["put_sample"]
        assert hashlib.sha256(server.received).hexdigest() == digest
        assert registry.degradation_reasons == []

    def test_a_server_offering_no_put_sample_is_left_alone(self, tmp_path: Path) -> None:
        """``None`` is "call it with the local path", not a failure — a local
        stdio sidecar reads the same filesystem the worker does."""
        path, digest = _sample(tmp_path, 128)
        server = _FakeServer()
        server.all_tool_names = lambda: ["identify_file"]  # type: ignore[method-assign]
        registry = _FakeRegistry(server)

        staged = asyncio.run(
            sample_staging.stage_sample(registry, "remote", path, sha256=digest, job_id="job-1")
        )

        assert staged is None
        assert registry.degradation_reasons == []


class TestChunked:
    def test_a_large_sample_is_split_and_reassembled_byte_for_byte(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setattr(sample_staging, "CHUNK_THRESHOLD_BYTES", 1024)
        monkeypatch.setattr(sample_staging, "CHUNK_BYTES", 512)
        path, digest = _sample(tmp_path, 4096)
        server = _FakeServer(chunked=True)
        registry = _FakeRegistry(server)

        staged = asyncio.run(
            sample_staging.stage_sample(registry, "remote", path, sha256=digest, job_id="job-1")
        )

        assert staged == "/remote/staging/sample.exe"
        assert server.calls[0] == "put_sample_begin"
        assert server.calls.count("put_sample_chunk") == 8
        assert server.calls[-1] == "put_sample_finish"
        assert hashlib.sha256(server.received).hexdigest() == digest

    def test_a_server_without_the_chunked_calls_gets_the_single_shot_one(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setattr(sample_staging, "CHUNK_THRESHOLD_BYTES", 1024)
        path, digest = _sample(tmp_path, 4096)
        server = _FakeServer(chunked=False)
        registry = _FakeRegistry(server)

        staged = asyncio.run(
            sample_staging.stage_sample(registry, "remote", path, sha256=digest, job_id="job-1")
        )

        assert staged == "/remote/staging/sample.exe"
        assert server.calls == ["put_sample"]


class TestFailure:
    def test_a_returned_error_becomes_a_degradation_reason_and_no_path(
        self, tmp_path: Path
    ) -> None:
        path, digest = _sample(tmp_path, 128)
        server = _FakeServer(fail="disk full")
        registry = _FakeRegistry(server)

        staged = asyncio.run(
            sample_staging.stage_sample(registry, "remote", path, sha256=digest, job_id="job-1")
        )

        assert staged is None
        assert registry.degradation_reasons == [
            "sample staging failed for 'remote': RuntimeError: disk full"
        ]

    def test_a_sample_that_is_not_on_disk_says_so_and_does_not_raise(self, tmp_path: Path) -> None:
        registry = _FakeRegistry(_FakeServer())

        staged = asyncio.run(
            sample_staging.stage_sample(
                registry, "remote", str(tmp_path / "gone.exe"), sha256="a" * 64, job_id="job-1"
            )
        )

        assert staged is None
        assert "no sample at" in registry.degradation_reasons[0]

    def test_an_unknown_server_is_a_reason_rather_than_a_lookup_error(self) -> None:
        registry = _FakeRegistry(None)

        staged = asyncio.run(
            sample_staging.stage_sample(
                registry, "ghost", "/tmp/x", sha256="a" * 64, job_id="job-1"
            )
        )

        assert staged is None
        assert "unknown server" in registry.degradation_reasons[0]

    def test_a_reason_is_recorded_once_however_many_agents_hit_it(self, tmp_path: Path) -> None:
        path, digest = _sample(tmp_path, 128)
        registry = _FakeRegistry(_FakeServer(fail="disk full"))

        for _ in range(3):
            asyncio.run(
                sample_staging.stage_sample(registry, "remote", path, sha256=digest, job_id="job-1")
            )

        assert len(registry.degradation_reasons) == 1


class TestCache:
    def test_a_second_ask_for_the_same_sample_does_not_upload_it_again(
        self, tmp_path: Path
    ) -> None:
        path, digest = _sample(tmp_path, 512)
        server = _FakeServer()
        registry = _FakeRegistry(server)

        first = asyncio.run(
            sample_staging.stage_sample(registry, "remote", path, sha256=digest, job_id="job-1")
        )
        second = asyncio.run(
            sample_staging.stage_sample(registry, "remote", path, sha256=digest, job_id="job-1")
        )

        assert first == second
        assert server.calls == ["put_sample"], "the second ask is served from the cache"

    def test_an_entry_past_its_ttl_is_uploaded_again(self, tmp_path: Path, monkeypatch) -> None:
        """A sidecar that restarted lost its staging directory, and a path that
        no longer exists is worse than one upload too many."""
        monkeypatch.setattr(sample_staging, "CACHE_TTL_SECONDS", -1)
        path, digest = _sample(tmp_path, 512)
        server = _FakeServer()
        registry = _FakeRegistry(server)

        asyncio.run(
            sample_staging.stage_sample(registry, "remote", path, sha256=digest, job_id="job-1")
        )
        asyncio.run(
            sample_staging.stage_sample(registry, "remote", path, sha256=digest, job_id="job-1")
        )

        assert server.calls == ["put_sample", "put_sample"]

    def test_a_caller_that_passes_no_digest_still_hits_the_cache(self, tmp_path: Path) -> None:
        """The lookup used the caller's hash and the store used the computed
        one, so ``sha256=""`` missed every time and every agent bound to the
        server re-uploaded the same sample."""
        path, _ = _sample(tmp_path, 512)
        server = _FakeServer()
        registry = _FakeRegistry(server)

        first = asyncio.run(
            sample_staging.stage_sample(registry, "remote", path, sha256="", job_id="job-1")
        )
        second = asyncio.run(
            sample_staging.stage_sample(registry, "remote", path, sha256="", job_id="job-1")
        )

        assert first == second
        assert server.calls == ["put_sample"]

    def test_a_different_sample_is_not_served_the_first_one_s_path(self, tmp_path: Path) -> None:
        first_path, first_digest = _sample(tmp_path, 512)
        other = tmp_path / "other.exe"
        other.write_bytes(b"different bytes entirely")
        other_digest = hashlib.sha256(other.read_bytes()).hexdigest()
        server = _FakeServer()
        registry = _FakeRegistry(server)

        asyncio.run(
            sample_staging.stage_sample(
                registry, "remote", first_path, sha256=first_digest, job_id="job-1"
            )
        )
        asyncio.run(
            sample_staging.stage_sample(
                registry, "remote", str(other), sha256=other_digest, job_id="job-1"
            )
        )

        assert server.calls == ["put_sample", "put_sample"]
        assert server.received == b"different bytes entirely"


def _tool_from(server: str):
    from langchain_core.tools import StructuredTool

    return StructuredTool.from_function(
        func=lambda: "x",
        name="identify_file",
        description="x",
        metadata={"maljan_server": server},
    )


class TestStageForAgent:
    def test_only_the_servers_the_agent_s_tools_came_from_are_staged_to(
        self, tmp_path: Path
    ) -> None:
        path, digest = _sample(tmp_path, 256)
        server = _FakeServer()
        registry = _FakeRegistry(server)

        staged = asyncio.run(
            sample_staging.stage_for_agent(
                registry, [_tool_from("remote")], path, sha256=digest, job_id="job-1"
            )
        )

        assert staged == {"remote": "/remote/staging/sample.exe"}

    def test_a_stdio_server_is_handed_the_path_and_never_the_bytes(self, tmp_path: Path) -> None:
        """The transport decides, not the manifest. A stdio sidecar is a child
        of this worker reading this filesystem, so uploading to it would write
        a second copy of the sample to tell it about a file it can open."""
        path, digest = _sample(tmp_path, 256)
        server = _FakeServer()
        server.config = type("_Cfg", (), {"transport": "stdio"})()
        registry = _FakeRegistry(server)

        staged = asyncio.run(
            sample_staging.stage_for_agent(
                registry, [_tool_from("remote")], path, sha256=digest, job_id="job-1"
            )
        )

        assert staged == {}
        assert server.calls == [], "a stdio server must never be uploaded to"
        assert registry.degradation_reasons == []

    def test_every_http_style_transport_stages(self, tmp_path: Path) -> None:
        for transport in ("http", "streamable-http", "sse"):
            sample_staging.clear_cache()
            path, digest = _sample(tmp_path, 256)
            server = _FakeServer()
            server.config = type("_Cfg", (), {"transport": transport})()
            registry = _FakeRegistry(server)

            staged = asyncio.run(
                sample_staging.stage_for_agent(
                    registry, [_tool_from("remote")], path, sha256=digest, job_id="job-1"
                )
            )

            assert staged == {"remote": "/remote/staging/sample.exe"}, transport

    def test_an_agent_with_no_sample_path_stages_nothing(self) -> None:
        registry = _FakeRegistry(_FakeServer())
        staged = asyncio.run(
            sample_staging.stage_for_agent(registry, [], None, sha256="", job_id="job-1")
        )
        assert staged == {}
