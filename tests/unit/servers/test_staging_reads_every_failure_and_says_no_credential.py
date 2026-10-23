"""Staging reads a failure in every shape a tool says one, names no credential, and says its bound.

Three things were wrong. A chunk the MCP client answered with its
``tool_error`` marker read as a success and the upload went on, while
``"error": null`` beside a path read as a failure. A failure's reason, which
is published, carried the exception's message whole, URL credentials and
all. And the whole upload was waited on for a fixed 120 s nobody set, whose
running out was recorded nowhere and left the upload "attempted".
"""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any

import pytest

from maljan.agents import composition, sample_staging
from maljan.agents.mcp_client import tool_error_marker
from maljan.analysis.disclosure import STAGING_FAILED
from tests.credential_shapes import password


@pytest.fixture(autouse=True)
def _clear_cache():
    sample_staging.clear_cache()
    yield
    sample_staging.clear_cache()


class _Tool:
    def __init__(self, name: str, handler: Any) -> None:
        self.name = name
        self._handler = handler

    async def ainvoke(self, kwargs: dict[str, Any]) -> Any:
        return await self._handler(**kwargs)


class _Guard:
    def __init__(self, seconds: float | None) -> None:
        self.seconds = seconds

    def call_timeout(self, tool: str) -> float | None:
        return self.seconds


class _Server:
    def __init__(self, answers: dict[str, Any], *, chunked: bool = False) -> None:
        self.is_open = True
        self.config = type("_Cfg", (), {"transport": "streamable-http", "url": ""})()
        self.calls: list[str] = []
        self._answers = answers
        self._chunked = chunked
        self.guard: Any = None

    def all_tool_names(self) -> list[str]:
        names = ["put_sample"]
        if self._chunked:
            names += list(sample_staging.CHUNKED_TOOLS)
        return names

    def tools(self) -> list[Any]:
        def _handler(name: str) -> Any:
            async def _answer(**kwargs: Any) -> Any:
                self.calls.append(name)
                answer = self._answers[name]
                if callable(answer):
                    return await answer()
                return answer

            return _answer

        return [_Tool(name, _handler(name)) for name in self.all_tool_names()]


class _Registry:
    def __init__(self, handle: Any) -> None:
        self._handle = handle
        self.degradation_reasons: list[str] = []

    def get(self, name: str) -> Any:
        return self._handle


def _sample(tmp_path: Path, size: int = 64) -> str:
    target = tmp_path / "sample.exe"
    target.write_bytes(b"M" * size)
    return str(target)


def _stage(registry: Any, path: str, stagings: list[Any] | None = None) -> Any:
    return asyncio.run(
        sample_staging.stage_sample(
            registry, "remote", path, sha256="a" * 64, job_id="j", stagings=stagings
        )
    )


class TestEveryFailureShapeIsRead:
    def test_a_chunk_answered_with_the_client_s_marker_stops_the_upload(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sample_staging, "CHUNK_THRESHOLD_BYTES", 8)
        monkeypatch.setattr(sample_staging, "CHUNK_BYTES", 16)
        failed = tool_error_marker("tool_returned_error", "put_sample_chunk", detail="disk full")
        server = _Server(
            {
                "put_sample_begin": {"upload_id": "u1"},
                "put_sample_chunk": failed,
                "put_sample_finish": {"path": "/remote/sample.exe"},
            },
            chunked=True,
        )
        registry = _Registry(server)

        assert _stage(registry, _sample(tmp_path)) is None
        assert "put_sample_finish" not in server.calls
        assert server.calls.count("put_sample_chunk") == 1
        assert "disk full" in registry.degradation_reasons[0]

    def test_a_null_error_beside_a_path_is_an_answer(self, tmp_path: Path) -> None:
        server = _Server({"put_sample": json.dumps({"error": None, "path": "/remote/s.exe"})})
        registry = _Registry(server)

        assert _stage(registry, _sample(tmp_path)) == "/remote/s.exe"
        assert registry.degradation_reasons == []


class TestAReasonNamesNoCredential:
    def test_a_raised_failure_is_named_by_its_kind(self, tmp_path: Path) -> None:
        secret = password()

        async def _raise() -> Any:
            raise ConnectionError(f"could not reach https://op:{secret}@sandbox.example:8443/mcp")

        registry = _Registry(_Server({"put_sample": _raise}))
        assert _stage(registry, _sample(tmp_path)) is None
        reason = registry.degradation_reasons[0]
        assert secret not in reason
        assert "ConnectionError" in reason

    def test_a_server_s_own_words_are_said_with_a_url_credential_masked(
        self, tmp_path: Path
    ) -> None:
        secret = password()
        said = {"error": f"upload refused for https://op:{secret}@store.example/x"}
        registry = _Registry(_Server({"put_sample": said}))
        assert _stage(registry, _sample(tmp_path)) is None
        reason = registry.degradation_reasons[0]
        assert secret not in reason
        assert "upload refused" in reason


def _tool_from(server: str) -> Any:
    from langchain_core.tools import StructuredTool

    return StructuredTool.from_function(
        func=lambda: "x", name="identify_file", description="x", metadata={"maljan_server": server}
    )


class _Container:
    def __init__(self, registry: Any, sample_path: str) -> None:
        self._registry = registry
        self._lock = threading.RLock()
        self.sample_path = sample_path
        self.sample_sha256 = "a" * 64
        self.sample_stagings: list[dict[str, Any]] = []

    def get_server_registry(self) -> Any:
        return self._registry


class TestTheWaitIsDerivedAndItsEndRecorded:
    def test_the_bound_is_the_sum_of_the_calls_deadlines(self, tmp_path: Path) -> None:
        server = _Server({"put_sample": {"path": "/r"}})
        server.guard = _Guard(7.0)
        bound, servers, unlimited = composition._staging_bound(
            _Registry(server), [_tool_from("remote")], _sample(tmp_path)
        )
        assert (bound, servers, unlimited) == (7.0, ["remote"], [])

    def test_a_chunked_upload_counts_every_chunk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sample_staging, "CHUNK_THRESHOLD_BYTES", 8)
        monkeypatch.setattr(sample_staging, "CHUNK_BYTES", 16)
        server = _Server({}, chunked=True)
        server.guard = _Guard(2.0)
        bound, _, _ = composition._staging_bound(
            _Registry(server), [_tool_from("remote")], _sample(tmp_path, 64)
        )
        # begin + four chunks + finish.
        assert bound == 12.0

    def test_a_call_with_no_deadline_leaves_the_wait_unlimited(self, tmp_path: Path) -> None:
        server = _Server({"put_sample": {"path": "/r"}})
        server.guard = _Guard(None)
        bound, _, unlimited = composition._staging_bound(
            _Registry(server), [_tool_from("remote")], _sample(tmp_path)
        )
        assert bound is None
        assert unlimited == ["remote.put_sample"]

    def test_an_unlimited_staging_names_its_calls_with_no_deadline(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        server = _Server({"put_sample": {"path": "/r"}})
        server.guard = _Guard(None)
        container = _Container(_Registry(server), _sample(tmp_path))
        with caplog.at_level("WARNING"):
            composition._stage(container, [_tool_from("remote")], "job-9")
        assert "no deadline (remote.put_sample)" in caplog.text

    def test_a_slow_call_is_not_cut_by_the_sum(self, tmp_path: Path) -> None:
        """The calls are each held to their own deadline; the sum cuts nothing."""

        async def _slow() -> Any:
            await asyncio.sleep(0.5)
            return {"path": "/r"}

        server = _Server({"put_sample": _slow})
        server.guard = _Guard(0.1)
        container = _Container(_Registry(server), _sample(tmp_path))

        staged, reasons = composition._stage(container, [_tool_from("remote")], "job-9")

        assert staged == {"remote": "/r"}
        assert reasons == []

    def test_a_stopped_staging_keeps_what_was_staged_and_fails_only_the_unfinished(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import base_agent
        from maljan.analysis.disclosure import STAGING_ATTEMPTED, STAGING_DONE

        server = _Server({"put_sample": {"path": "/r"}})
        server.guard = _Guard(5.0)
        registry = _Registry(server)
        container = _Container(registry, _sample(tmp_path))
        sample_staging._CACHE[("job-9", "remote", "a" * 64)] = ("/kept", 1e18)
        container.sample_stagings.append({"server": "other", "state": STAGING_ATTEMPTED})
        container.sample_stagings.append({"server": "remote", "state": STAGING_DONE})

        def _stopped(coro: Any, **kwargs: Any) -> Any:
            coro.close()
            raise base_agent.HardCapExceeded("sample-staging exceeded hard cap")

        monkeypatch.setattr(base_agent, "run_coro_blocking", _stopped)
        staged, reasons = composition._stage(container, [_tool_from("remote")], "job-9")

        assert staged == {"remote": "/kept"}, "a path already staged is kept"
        assert reasons == []
        # The records written before this staging are not its own.
        assert container.sample_stagings[0]["state"] == STAGING_ATTEMPTED
        assert container.sample_stagings[1]["state"] == STAGING_DONE

    def test_a_stopped_staging_names_the_unfinished_upload_by_its_kind(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import base_agent
        from maljan.analysis.disclosure import STAGING_ATTEMPTED

        server = _Server({"put_sample": {"path": "/r"}})
        server.guard = _Guard(5.0)
        container = _Container(_Registry(server), _sample(tmp_path))

        def _run(coro: Any, **kwargs: Any) -> Any:
            coro.close()
            container.sample_stagings.append({"server": "remote", "state": STAGING_ATTEMPTED})
            raise RuntimeError("x")

        monkeypatch.setattr(base_agent, "run_coro_blocking", _run)
        _staged, reasons = composition._stage(container, [_tool_from("remote")], "job-9")
        assert "did not finish within" not in reasons[0] and "RuntimeError" in reasons[0]
        assert container.sample_stagings[-1]["state"] == STAGING_FAILED

    def test_a_staged_upload_whose_path_cannot_be_read_back_is_said_so(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import base_agent
        from maljan.analysis.disclosure import STAGING_DONE

        server = _Server({"put_sample": {"path": "/r"}})
        server.guard = _Guard(5.0)
        container = _Container(_Registry(server), _sample(tmp_path))
        container.sample_sha256 = ""

        def _run(coro: Any, **kwargs: Any) -> Any:
            coro.close()
            container.sample_stagings.append({"server": "remote", "state": STAGING_DONE})
            raise RuntimeError("x")

        monkeypatch.setattr(base_agent, "run_coro_blocking", _run)
        staged, reasons = composition._stage(container, [_tool_from("remote")], "job-9")
        assert staged == {}
        assert reasons == ["sample staging failed for 'remote': staged, path not recovered"]


class TestAFailedRecordStaysFailed:
    def test_a_late_done_does_not_undo_a_failure(self) -> None:
        from maljan.analysis.disclosure import STAGING_ATTEMPTED

        record = {"server": "remote", "state": STAGING_ATTEMPTED}
        assert sample_staging.mark_unfinished_failed([record], 0) == {"remote"}
        sample_staging._mark_staging(record, done=True)
        assert record["state"] == STAGING_FAILED


class TestOnlyTheServersOwnWordsAreQuoted:
    @pytest.mark.parametrize(
        "answer, said",
        [
            (
                tool_error_marker("exception", "put_sample", type="OSError", detail="/srv/x"),
                "exception (OSError)",
            ),
            (tool_error_marker("mcp_session_inactive", "put_sample"), "mcp_session_inactive"),
            (
                json.dumps(
                    {"error": {"code": "server_resting", "message": "rest until 12:00 /srv"}}
                ),
                "server_resting",
            ),
            (
                json.dumps({"error": {"code": "tool_failed", "message": "wrote /srv/x"}}),
                "tool_failed",
            ),
        ],
    )
    def test_a_client_or_guard_failure_is_named_by_its_kind(
        self, tmp_path: Path, answer: str, said: str
    ) -> None:
        registry = _Registry(_Server({"put_sample": answer}))
        assert _stage(registry, _sample(tmp_path)) is None
        reason = registry.degradation_reasons[0]
        assert reason.endswith(said)
        assert "/srv" not in reason

    def test_an_is_error_reply_is_quoted(self, tmp_path: Path) -> None:
        answer = tool_error_marker("tool_returned_error", "put_sample", detail="quota exceeded")
        registry = _Registry(_Server({"put_sample": answer}))
        assert _stage(registry, _sample(tmp_path)) is None
        assert registry.degradation_reasons[0].endswith("the server answered: quota exceeded")

    def test_a_missing_sample_names_no_host_path(self, tmp_path: Path) -> None:
        registry = _Registry(_Server({"put_sample": {"path": "/r"}}))
        missing = str(tmp_path / "secret-dir" / "gone.exe")
        assert _stage(registry, missing) is None
        assert "secret-dir" not in registry.degradation_reasons[0]
        assert "no sample at the staged path" in registry.degradation_reasons[0]
