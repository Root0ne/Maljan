"""Unit tests for the Recorded Future Sandbox (tria.ge) client.

These are pure unit tests — no real network. The submit/poll/fetch path is
exercised against ``httpx.MockTransport`` so the API contract stays
self-checking without needing a Triage API token.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from maljan.loaders.sandbox_client import SubmissionResult
from maljan.loaders.triage_client import (
    TriageClient,
    _normalize_report,
    _resolve_sample_name,
    _sha256_file,
    _view_url,
)


def _sample_triage_summary() -> dict[str, Any]:
    return {
        "sample": {
            "id": "220411-abc123",
            "sha256": "a" * 64,
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "name": "malware_sample.exe",
            "size": 45678,
        },
        "tasks": {
            "behavioral1": {
                "kind": "behavioral1",
                "ttp_tags": ["T1055", "T1059.001"],
                "processes": [
                    {
                        "name": "malware.exe",
                        "pid": 1234,
                        "ppid": 5678,
                        "cmd": "C:\\malware.exe --silent",
                        "calls": [
                            {
                                "api": "VirtualAllocEx",
                                "category": "process",
                                "args": [{"name": "size", "value": "4096"}],
                                "return_value": "0x12340000",
                            }
                        ],
                    }
                ],
            }
        },
        "network": {
            "dns": [{"name": "evil.example.com", "answers": ["1.2.3.4"]}],
            "http": [{"url": "http://evil.example.com/c2", "method": "POST"}],
            "flows": [],
        },
        "signatures": [{"name": "proc_injection", "score": 9, "description": "Process injection"}],
        "status": "reported",
    }


@pytest.fixture()
def sample_file(tmp_path: Path) -> Path:
    f = tmp_path / "sample.exe"
    f.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    return f


# ---------------------------------------------------------------------------
# _normalize_report
# ---------------------------------------------------------------------------


class TestNormalizeReport:
    def test_target_section_populated(self) -> None:
        raw = _sample_triage_summary()
        result = _normalize_report(raw, "sample.exe")
        assert result["target"]["file"]["sha256"] == "a" * 64
        assert result["target"]["file"]["name"] == "malware_sample.exe"
        assert result["target"]["file"]["size"] == 45678

    def test_behavior_processes_extracted(self) -> None:
        raw = _sample_triage_summary()
        result = _normalize_report(raw, "sample.exe")
        processes = result["behavior"]["processes"]
        assert len(processes) == 1
        assert processes[0]["process_name"] == "malware.exe"
        assert processes[0]["pid"] == 1234

    def test_behavior_calls_and_apistats(self) -> None:
        raw = _sample_triage_summary()
        result = _normalize_report(raw, "sample.exe")
        calls = result["behavior"]["calls"]
        assert len(calls) == 1
        assert calls[0]["api"] == "VirtualAllocEx"
        apistats = result["behavior"]["apistats"]
        assert apistats["malware.exe"]["VirtualAllocEx"] == 1

    def test_network_section_mapped(self) -> None:
        raw = _sample_triage_summary()
        result = _normalize_report(raw, "sample.exe")
        assert result["network"]["dns"][0]["name"] == "evil.example.com"
        assert result["network"]["http"][0]["method"] == "POST"
        # tcp falls back to flows[] when tcp[] is absent
        assert result["network"]["tcp"] == []

    def test_ttp_tags_merged_from_tasks(self) -> None:
        raw = _sample_triage_summary()
        result = _normalize_report(raw, "sample.exe")
        assert "T1055" in result["ttp_tags"]
        assert "T1059.001" in result["ttp_tags"]
        assert result["ttp_tags"] == sorted(result["ttp_tags"])

    def test_signatures_normalized(self) -> None:
        raw = _sample_triage_summary()
        result = _normalize_report(raw, "sample.exe")
        sigs = result["signatures"]
        assert sigs[0]["name"] == "proc_injection"
        assert sigs[0]["severity"] == 9

    def test_empty_report_produces_valid_schema(self) -> None:
        result = _normalize_report({}, "unknown.exe")
        assert {"target", "behavior", "network", "signatures", "ttp_tags"} <= set(result)
        assert result["behavior"]["processes"] == []

    def test_malformed_nested_types_do_not_raise(self) -> None:
        # ``sample`` as a bare string, ``tasks`` as a list — _normalize_report
        # must tolerate non-conformant Triage payloads instead of crashing the
        # pipeline.
        result = _normalize_report({"sample": "abc", "tasks": [], "network": []}, "fallback.exe")
        assert result["target"]["file"]["name"] == "fallback.exe"


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


class TestModuleHelpers:
    def test_sha256_file_returns_hex(self, tmp_path: Path) -> None:
        f = tmp_path / "x.bin"
        f.write_bytes(b"hello world")
        digest = _sha256_file(f)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_sha256_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        assert _sha256_file(f).startswith("e3b0")

    def test_view_url_format(self) -> None:
        assert _view_url("220411-abc123") == "https://tria.ge/220411-abc123"

    def test_resolve_sample_name_prefers_dict_name(self) -> None:
        assert _resolve_sample_name({"sample": {"name": "evil.exe"}}, "t") == "evil.exe"

    def test_resolve_sample_name_accepts_bare_sha256(self) -> None:
        sha = "f" * 64
        assert _resolve_sample_name({"sample": sha}, "t") == sha

    def test_resolve_sample_name_falls_back_with_placeholder(self) -> None:
        # APK-SAND-01: when Triage returns no resolvable filename the
        # placeholder must contain the task id so downstream prompts can
        # surface the gap rather than mistaking the task id for a filename.
        name = _resolve_sample_name({"sample": {}}, "220411-abc123")
        assert name == "_triage_no_name_220411-abc123"


# ---------------------------------------------------------------------------
# TriageClient init
# ---------------------------------------------------------------------------


class TestTriageClientInit:
    def test_default_base_url(self) -> None:
        client = TriageClient()
        assert client._api_prefix == "https://api.tria.ge/v0"

    def test_strips_trailing_v0(self) -> None:
        client = TriageClient(base_url="https://api.tria.ge/v0")
        assert client._api_prefix == "https://api.tria.ge/v0"

    def test_secretstr_token_unwrapped(self) -> None:
        client = TriageClient(api_token=SecretStr("tria_secret"))
        assert client._api_token == "tria_secret"

    def test_http_clients_are_lazy(self) -> None:
        client = TriageClient()
        assert client._http_async is None
        assert client._http_sync is None


# ---------------------------------------------------------------------------
# End-to-end (mocked httpx transport)
# ---------------------------------------------------------------------------


class TestTriageClientSyncFlow:
    @staticmethod
    def _install_mock_transport(client: TriageClient, handler: Any) -> None:
        """Inject an httpx.Client backed by MockTransport into the lazy slot."""
        transport = httpx.MockTransport(handler)
        client._http_sync = httpx.Client(
            base_url=client._api_prefix,
            headers=client._headers(),
            timeout=5.0,
            transport=transport,
        )

    def test_submit_returns_task_id(self, sample_file: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "POST"
            assert request.url.path.endswith("/samples")
            return httpx.Response(200, json={"id": "220411-zzz", "status": "pending"})

        client = TriageClient(api_token="tria_demo")
        self._install_mock_transport(client, handler)
        try:
            task_id = client.submit(sample_file)
        finally:
            client.close()
        assert task_id == "220411-zzz"

    def test_submit_raises_on_http_error(self, sample_file: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, text="invalid token")

        client = TriageClient(api_token="bad")
        self._install_mock_transport(client, handler)
        try:
            with pytest.raises(RuntimeError, match="HTTP 401"):
                client.submit(sample_file)
        finally:
            client.close()

    def test_submit_raises_when_file_missing(self) -> None:
        client = TriageClient()
        with pytest.raises(FileNotFoundError):
            client.submit("/no/such/file.exe")

    def test_wait_returns_status_when_reported(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"status": "reported"})

        client = TriageClient()
        self._install_mock_transport(client, handler)
        try:
            status = client.wait_for_completion("tid", timeout_seconds=5, poll_interval_seconds=0)
        finally:
            client.close()
        assert status == "reported"

    def test_fetch_report_returns_normalized_with_url(self) -> None:
        summary = _sample_triage_summary()

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/samples/tid/summary")
            return httpx.Response(200, json=summary)

        client = TriageClient()
        self._install_mock_transport(client, handler)
        try:
            result = client.fetch_report("tid")
        finally:
            client.close()
        assert isinstance(result, SubmissionResult)
        assert result.succeeded
        assert result.sample_sha256 == "a" * 64
        assert result.report["sandbox_url"] == "https://tria.ge/tid"
        assert "T1055" in result.report["ttp_tags"]

    def test_fetch_report_handles_non_dict_body(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json="not-a-dict")

        client = TriageClient()
        self._install_mock_transport(client, handler)
        try:
            result = client.fetch_report("tid")
        finally:
            client.close()
        assert result.status == "failed"
        assert "non-dict" in result.error


# ---------------------------------------------------------------------------
# SubmissionResult sanity
# ---------------------------------------------------------------------------


class TestSubmissionResultSanity:
    def test_succeeded_true_when_reported_with_report(self) -> None:
        result = SubmissionResult(task_id="t", status="reported", report={"a": 1})
        assert result.succeeded

    def test_succeeded_false_when_empty_report(self) -> None:
        result = SubmissionResult(task_id="t", status="reported", report={})
        assert not result.succeeded

    def test_succeeded_false_when_failed(self) -> None:
        result = SubmissionResult(task_id="t", status="failed", error="boom")
        assert not result.succeeded


# Silence the unused-import warning for json when running pytest in isolation.
_ = json
