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
    _apply_overview,
    _apply_per_task_report,
    _classify_c2,
    _normalize_report,
    _pick_profile_tag,
    _resolve_sample_name,
    _sha256_file,
    _synthesize_cti,
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

    def test_consumes_modern_top_level_shape(self) -> None:
        # Modern Recorded Future Sandbox summary: sample is a bare task-id
        # string but sha256/target/score live at the top level.
        modern = {
            "sample": "260523-v9veqaat9x",
            "status": "reported",
            "target": "zararli.apk",
            "sha256": "a" * 64,
            "score": 6,
            "tasks": {},
        }
        result = _normalize_report(modern, "irrelevant-fallback")
        assert result["target"]["file"]["sha256"] == "a" * 64
        assert result["target"]["file"]["name"] == "zararli.apk"
        assert result["triage_score"] == 6


# ---------------------------------------------------------------------------
# _apply_overview
# ---------------------------------------------------------------------------


class TestApplyOverview:
    def _base_normalized(self) -> dict[str, Any]:
        return _normalize_report({}, "placeholder.bin")

    def test_promotes_overview_signatures_when_main_list_empty(self) -> None:
        normalized = self._base_normalized()
        overview = {
            "signatures": [
                {"name": "Dangerous perms", "score": 6, "desc": "asks for SMS"},
                {"name": "Untrusted codesign", "score": 3, "label": "codesign_untrusted"},
            ]
        }
        _apply_overview(overview, normalized, fallback_sample_id="t")
        sigs = normalized["signatures"]
        assert len(sigs) == 2
        assert sigs[0]["name"] == "Dangerous perms"
        assert sigs[0]["description"] == "asks for SMS"
        assert sigs[0]["severity"] == 6
        # Raw form also exposed for callers that want the original shape.
        assert "signatures_rich" in normalized

    def test_keeps_existing_signatures_intact(self) -> None:
        normalized = self._base_normalized()
        normalized["signatures"] = [{"name": "from_summary", "severity": 9}]
        _apply_overview({"signatures": [{"name": "from_overview", "score": 3}]}, normalized, "t")
        assert normalized["signatures"] == [{"name": "from_summary", "severity": 9}]

    def test_backfills_sample_identity(self) -> None:
        normalized = self._base_normalized()
        # Simulate a normalized report where the summary did not carry sha256.
        normalized["target"]["file"]["sha256"] = ""
        normalized["target"]["file"]["name"] = "t"
        overview = {
            "sample": {
                "sha256": "B" * 64,
                "md5": "abc",
                "size": 1234,
                "target": "real.apk",
            }
        }
        _apply_overview(overview, normalized, fallback_sample_id="t")
        f = normalized["target"]["file"]
        assert f["sha256"] == "b" * 64
        assert f["md5"] == "abc"
        assert f["size"] == 1234
        assert f["name"] == "real.apk"

    def test_promotes_extracted_config_block(self) -> None:
        normalized = self._base_normalized()
        overview = {"extracted": [{"config": {"family": "emotet", "c2": ["http://x"]}}]}
        _apply_overview(overview, normalized, "t")
        assert normalized["extracted"][0]["config"]["family"] == "emotet"

    def test_surfaces_analysis_score_when_top_level_missing(self) -> None:
        normalized = self._base_normalized()
        _apply_overview({"analysis": {"score": 8}}, normalized, "t")
        assert normalized["triage_score"] == 8

    def test_resolve_sample_name_prefers_top_level_target(self) -> None:
        assert _resolve_sample_name({"target": "real.apk"}, "task-1") == "real.apk"

    def test_resolve_sample_name_falls_through_to_filename(self) -> None:
        assert _resolve_sample_name({"filename": "x.exe"}, "task-1") == "x.exe"


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
# Interactive submit + auto-profile flow
# ---------------------------------------------------------------------------


class TestInteractiveFlow:
    @staticmethod
    def _install_mock_transport(client: TriageClient, handler: Any) -> None:
        transport = httpx.MockTransport(handler)
        client._http_sync = httpx.Client(
            base_url=client._api_prefix,
            headers=client._headers(),
            timeout=5.0,
            transport=transport,
        )

    def test_submit_embeds_extension_derived_os_tag(self, tmp_path: Path) -> None:
        captured: dict[str, Any] = {}
        elf = tmp_path / "evil.elf"
        elf.write_bytes(b"\x7fELFdummy")

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content
            return httpx.Response(200, json={"id": "tid", "status": "pending"})

        client = TriageClient()
        self._install_mock_transport(client, handler)
        try:
            client.submit(elf)
        finally:
            client.close()
        body = captured["body"].decode("utf-8", errors="ignore")
        # Default is embedded profile (interactive=false) with the Linux tag
        # for .elf samples + a behavioral defaults block. (OS-support scope:
        # Windows + Linux only.)
        assert '"interactive": false' in body
        assert '"os:ubuntu-22.04-amd64"' in body
        assert '"defaults"' in body
        assert '"network": "internet"' in body

    def test_submit_honours_force_os_tag(self, sample_file: Path) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content
            return httpx.Response(200, json={"id": "tid", "status": "pending"})

        client = TriageClient(force_os_tag="os:windows11-21h2-x64")
        self._install_mock_transport(client, handler)
        try:
            client.submit(sample_file)
        finally:
            client.close()
        body = captured["body"].decode("utf-8", errors="ignore")
        assert '"os:windows11-21h2-x64"' in body

    def test_submit_interactive_mode_skips_embedded_profile(self, sample_file: Path) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content
            return httpx.Response(200, json={"id": "tid", "status": "pending"})

        client = TriageClient(interactive=True, auto_profile=True)
        self._install_mock_transport(client, handler)
        try:
            client.submit(sample_file)
        finally:
            client.close()
        body = captured["body"].decode("utf-8", errors="ignore")
        assert '"interactive": true' in body
        # When interactive=True we do NOT embed a profile — wait posts /profile.
        assert '"profiles"' not in body

    def test_wait_posts_auto_profile_on_static_analysis(self) -> None:
        call_log: list[tuple[str, str]] = []
        states = iter(
            [
                "pending",
                "static_analysis",
                "running",
                "processing",
                "reported",
            ]
        )

        def handler(request: httpx.Request) -> httpx.Response:
            call_log.append((request.method, request.url.path))
            if request.method == "POST" and request.url.path.endswith("/profile"):
                return httpx.Response(200, json={})
            try:
                state = next(states)
            except StopIteration:
                state = "reported"
            return httpx.Response(200, json={"status": state})

        client = TriageClient(interactive=True, auto_profile=True)
        self._install_mock_transport(client, handler)
        try:
            status = client.wait_for_completion("tid", timeout_seconds=10, poll_interval_seconds=0)
        finally:
            client.close()
        assert status == "reported"
        posts = [c for c in call_log if c[0] == "POST"]
        assert len(posts) == 1
        assert posts[0][1].endswith("/samples/tid/profile")


class TestSubmitExtras:
    @staticmethod
    def _install_mock_transport(client: TriageClient, handler: Any) -> None:
        transport = httpx.MockTransport(handler)
        client._http_sync = httpx.Client(
            base_url=client._api_prefix,
            headers=client._headers(),
            timeout=5.0,
            transport=transport,
        )

    def test_payload_includes_password_user_tags_target(self, sample_file: Path) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content
            return httpx.Response(200, json={"id": "tid", "status": "pending"})

        client = TriageClient(
            archive_password="infected",
            user_tags=["experiment:rq2", "batch:7"],
            target_filename="renamed.exe",
        )
        self._install_mock_transport(client, handler)
        try:
            client.submit(sample_file)
        finally:
            client.close()
        body = captured["body"].decode("utf-8", errors="ignore")
        assert '"password": "infected"' in body
        assert '"experiment:rq2"' in body
        assert '"batch:7"' in body
        assert '"target": "renamed.exe"' in body

    def test_payload_includes_geolocation_when_set(self, sample_file: Path) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content
            return httpx.Response(200, json={"id": "tid", "status": "pending"})

        client = TriageClient(geolocation="north-america", network_mode="vpn")
        self._install_mock_transport(client, handler)
        try:
            client.submit(sample_file)
        finally:
            client.close()
        body = captured["body"].decode("utf-8", errors="ignore")
        assert '"geolocation": "north-america"' in body
        assert '"network": "vpn"' in body


class TestSubmitURL:
    @staticmethod
    def _install_mock_transport(client: TriageClient, handler: Any) -> None:
        transport = httpx.MockTransport(handler)
        client._http_sync = httpx.Client(
            base_url=client._api_prefix,
            headers=client._headers(),
            timeout=5.0,
            transport=transport,
        )

    def test_submit_url_kind(self) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content
            captured["content_type"] = request.headers.get("content-type", "")
            return httpx.Response(200, json={"id": "260523-zzz", "status": "pending"})

        client = TriageClient()
        self._install_mock_transport(client, handler)
        try:
            task_id = client.submit_url("http://malicious.example.com/landing")
        finally:
            client.close()
        assert task_id == "260523-zzz"
        body = captured["body"].decode("utf-8", errors="ignore")
        assert '"kind": "url"' in body
        assert '"url": "http://malicious.example.com/landing"' in body
        # Falls back to Windows when no explicit force_os_tag.
        assert '"os:windows10-2004-x64"' in body
        assert captured["content_type"].startswith("application/json")

    def test_submit_url_rejects_bad_kind(self) -> None:
        client = TriageClient()
        with pytest.raises(ValueError, match="kind must be url"):
            client.submit_url("http://x", kind="garbage")

    def test_submit_import_kind(self) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content
            return httpx.Response(200, json={"id": "260523-imp", "status": "pending"})

        client = TriageClient()
        self._install_mock_transport(client, handler)
        try:
            client.submit_url("https://tria.ge/250303-abcdefg", kind="import")
        finally:
            client.close()
        body = captured["body"].decode("utf-8", errors="ignore")
        assert '"kind": "import"' in body


class TestApplyOverviewErrors:
    def test_errors_promoted_into_sandbox_errors(self) -> None:
        normalized = _normalize_report({}, "p.bin")
        overview = {
            "errors": [
                {"task": "behavioral1", "backend": "win10", "reason": "Sample crashed"},
                {"task": "behavioral2", "backend": "android-13", "reason": "Timeout"},
            ]
        }
        _apply_overview(overview, normalized, fallback_sample_id="t")
        errs = normalized["sandbox_errors"]
        assert len(errs) == 2
        assert errs[0]["task"] == "behavioral1"
        assert errs[0]["reason"] == "Sample crashed"


class TestPickProfileTag:
    def test_elf_maps_to_ubuntu(self, tmp_path: Path) -> None:
        assert _pick_profile_tag(tmp_path / "evil.elf") == "os:ubuntu-22.04-amd64"

    def test_unknown_extension_falls_back_to_windows(self, tmp_path: Path) -> None:
        assert _pick_profile_tag(tmp_path / "evil.foobar") == "os:windows10-2004-x64"

    def test_foreign_os_extensions_fall_back_to_windows(self, tmp_path: Path) -> None:
        # OS-support scope (2026-06-02): the macOS/Android rows were removed from
        # _EXT_TO_OS_TAG — those samples are rejected at the pipeline entry
        # (UnsupportedSampleError) and never reach submission. Any residual call
        # defaults to the Windows profile, not a foreign sandbox.
        for name in ("evil.apk", "evil.dex", "evil.dmg", "evil.pkg", "evil.app"):
            assert _pick_profile_tag(tmp_path / name) == "os:windows10-2004-x64"

    def test_force_tag_overrides_extension(self, tmp_path: Path) -> None:
        assert (
            _pick_profile_tag(tmp_path / "evil.apk", force_tag="os:windows11-21h2-x64")
            == "os:windows11-21h2-x64"
        )


# ---------------------------------------------------------------------------
# _apply_per_task_report
# ---------------------------------------------------------------------------


class TestApplyPerTaskReport:
    def _base(self) -> dict[str, Any]:
        return _normalize_report({}, "placeholder.bin")

    def test_pours_processes_and_network_into_normalized(self) -> None:
        per_task = [
            {
                "task_id": "behavioral1",
                "report": {
                    "processes": [
                        {"image": "C:\\evil.exe", "pid": 1234, "cmd": "evil.exe --c2 1.2.3.4"}
                    ],
                    "network": {
                        "flows": [
                            {
                                "proto": "tcp",
                                "src": "10.0.0.5:54321",
                                "dst": "1.2.3.4:443",
                                "domain": "evil.com",
                                "tls_sni": "evil.com",
                                "tls_ja3": "deadbeef" * 4,
                                "country": "NL",
                            }
                        ],
                        "requests": [
                            {
                                "at": 1,
                                "dns_request": {"questions": [{"name": "evil.com", "type": "A"}]},
                                "dns_response": {"ip": ["1.2.3.4"]},
                            },
                            {
                                "at": 2,
                                "http_request": {"method": "GET", "url": "http://evil.com/x"},
                            },
                        ],
                    },
                    "dumped": [{"name": "payload.bin", "sha256": "f" * 64, "kind": "memory_dump"}],
                    "signatures": [
                        {"name": "C2 beacon", "ttp": ["T1071.001"], "yara_rule": "emotet_c2"}
                    ],
                    "analysis": {"tags": ["family:emotet"], "ttp": ["T1059.001"]},
                },
            }
        ]
        normalized = self._base()
        _apply_per_task_report(per_task, normalized)
        assert normalized["behavior"]["processes"][0]["pid"] == 1234
        tcp = normalized["network"]["tcp"]
        assert tcp[0]["dst"] == "1.2.3.4:443"
        assert tcp[0]["tls_ja3"].startswith("deadbeef")
        assert any("evil.com" in d for d in normalized["network"]["domains"])
        assert normalized["network"]["dns"][0]["response"]["ip"] == ["1.2.3.4"]
        assert normalized["network"]["http"][0]["url"] == "http://evil.com/x"
        assert normalized["dumped"][0]["sha256"] == "f" * 64
        assert "T1059.001" in normalized["ttp_tags"]
        assert "T1071.001" in normalized["ttp_tags"]
        assert any(s.get("yara_rule") == "emotet_c2" for s in normalized["signatures_rich"])

    def test_empty_per_task_is_noop(self) -> None:
        normalized = self._base()
        _apply_per_task_report([], normalized)
        assert normalized["behavior"]["processes"] == []


# ---------------------------------------------------------------------------
# _classify_c2 + _synthesize_cti
# ---------------------------------------------------------------------------


class TestClassifyC2:
    def test_buckets_url_domain_ip(self) -> None:
        c2: dict[str, list[str]] = {"urls": [], "domains": [], "ips": []}
        _classify_c2("http://evil.com/beacon", c2)
        _classify_c2("evil.com", c2)
        _classify_c2("evil.com:443/path", c2)
        _classify_c2("1.2.3.4", c2)
        _classify_c2("1.2.3.4:443", c2)
        assert c2["urls"] == ["http://evil.com/beacon"]
        assert c2["domains"] == ["evil.com", "evil.com"]
        assert c2["ips"] == ["1.2.3.4", "1.2.3.4"]


class TestSynthesizeCTI:
    def test_promotes_extracted_config_into_cti(self) -> None:
        normalized = _normalize_report({}, "p.bin")
        normalized["extracted"] = [
            {
                "config": {
                    "family": "emotet",
                    "c2": ["http://evil.com/", "evil.com", "1.2.3.4:443"],
                    "mutex": ["GlobalMutex_xyz"],
                    "keys": [{"kind": "AES", "key": "deadbeef", "value": None}],
                    "credentials": [{"protocol": "ftp", "host": "ftp.evil.com", "username": "u"}],
                }
            }
        ]
        cti = _synthesize_cti(normalized)
        assert "emotet" in cti["family"]
        assert "http://evil.com/" in cti["c2"]["urls"]
        assert "evil.com" in cti["c2"]["domains"]
        assert "1.2.3.4" in cti["c2"]["ips"]
        assert "GlobalMutex_xyz" in cti["mutexes"]
        assert cti["keys"][0]["kind"] == "AES"
        assert cti["credentials"][0]["host"] == "ftp.evil.com"

    def test_dedupes_lists(self) -> None:
        normalized = _normalize_report({}, "p.bin")
        normalized["ttp_tags"] = ["T1055", "T1055", "T1059.001"]
        normalized["families"] = ["emotet", "emotet", "trickbot"]
        cti = _synthesize_cti(normalized)
        assert cti["ttp"] == ["T1055", "T1059.001"]
        assert cti["family"] == ["emotet", "trickbot"]

    def test_surfaces_network_iocs_and_dropped_files(self) -> None:
        normalized = _normalize_report({}, "p.bin")
        normalized["network"]["http"].append({"url": "http://evil.com/payload"})
        normalized["network"]["domains"].append("evil.com")
        normalized["network"]["tcp"].append(
            {
                "dst": "1.2.3.4:443",
                "domain": "evil.com",
                "tls_sni": "evil.com",
                "tls_ja3": "abc",
                "tls_ja3s": "srv-abc",
            }
        )
        normalized["dumped"] = [{"name": "d.bin", "sha256": "f" * 64}]
        normalized["signatures"] = [
            {
                "name": "sig1",
                "indicators": [{"ioc": "evil.com", "description": "C2 contacted"}],
                "yara_rule": "evil_rule",
            }
        ]
        cti = _synthesize_cti(normalized)
        assert "http://evil.com/payload" in cti["network"]["http_urls"]
        assert "evil.com" in cti["network"]["domains"]
        assert "1.2.3.4" in cti["network"]["ips"]
        assert "evil.com" in cti["network"]["tls_sni"]
        assert "abc" in cti["network"]["tls_ja3"]
        assert "srv-abc" in cti["network"]["tls_ja3s"]
        assert cti["dropped_files"][0]["sha256"] == "f" * 64
        assert "evil_rule" in cti["yara_rules"]
        assert cti["indicators"][0]["ioc"] == "evil.com"


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
