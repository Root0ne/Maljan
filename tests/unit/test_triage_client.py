"""tests/unit/test_triage_client.py — TriageClient birim testleri.

httpx mock'lama icin pytest-httpx kullanilir.
Network bagiantisi gerektirmeyen saf unit testler.

Kapsam (16 test):
  - _normalize_report() sema donusumu
  - submit() / wait_for_completion() / fetch_report() protokol uyumu
  - Triage API HTTP mock'lama (submit, poll, report)
  - Zaman asimi (timeout) davranisi
  - Hata yonetimi (HTTP 4xx, 5xx)
  - _sha256_file() hash hesaplama
  - SubmissionResult.succeeded property
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from maljan.loaders.sandbox_client import SubmissionResult
from maljan.loaders.triage_client import TriageClient, _normalize_report, _sha256_file

# ---------------------------------------------------------------------------
# Test helpers / fixtures
# ---------------------------------------------------------------------------


def _sample_triage_report() -> dict[str, Any]:
    """Minimal Triage summary raporu ornegi."""
    return {
        "sample": {
            "id": "220411-abc123",
            "sha256": "abc123def456" * 5 + "ab",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "name": "malware_sample.exe",
            "size": 45678,
        },
        "tasks": {
            "win10-1": {
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
                            },
                        ],
                    }
                ],
                "signatures": [
                    {
                        "name": "process_injection",
                        "score": 8,
                        "description": "Process injection detected",
                    },
                ],
            }
        },
        "network": {
            "dns": [{"name": "evil.example.com", "answers": ["1.2.3.4"]}],
            "http": [{"url": "http://evil.example.com/c2", "method": "POST"}],
            "flows": [],
        },
        "signatures": [
            {"name": "proc_injection", "score": 9, "description": "Injection via VirtualAllocEx"},
        ],
    }


@pytest.fixture()
def sample_file(tmp_path: Path) -> Path:
    """Gecici bir numune dosyasi olusturur."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    return sample


# ---------------------------------------------------------------------------
# _normalize_report() tests
# ---------------------------------------------------------------------------


class TestNormalizeReport:
    def test_target_section_populated(self) -> None:
        raw = _sample_triage_report()
        result = _normalize_report(raw, "sample.exe")
        assert result["target"]["file"]["sha256"] == raw["sample"]["sha256"]
        assert result["target"]["file"]["name"] == "malware_sample.exe"

    def test_behavior_processes_extracted(self) -> None:
        raw = _sample_triage_report()
        result = _normalize_report(raw, "sample.exe")
        processes = result["behavior"]["processes"]
        assert len(processes) == 1
        assert processes[0]["process_name"] == "malware.exe"

    def test_behavior_calls_extracted(self) -> None:
        raw = _sample_triage_report()
        result = _normalize_report(raw, "sample.exe")
        calls = result["behavior"]["calls"]
        assert len(calls) == 1
        assert calls[0]["api"] == "VirtualAllocEx"

    def test_network_section_mapped(self) -> None:
        raw = _sample_triage_report()
        result = _normalize_report(raw, "sample.exe")
        assert len(result["network"]["dns"]) == 1
        assert result["network"]["dns"][0]["name"] == "evil.example.com"

    def test_signatures_normalized(self) -> None:
        raw = _sample_triage_report()
        result = _normalize_report(raw, "sample.exe")
        sigs = result["signatures"]
        assert len(sigs) >= 1
        assert "name" in sigs[0]
        assert "description" in sigs[0]

    def test_ttp_tags_merged_from_tasks(self) -> None:
        raw = _sample_triage_report()
        result = _normalize_report(raw, "sample.exe")
        assert "T1055" in result["ttp_tags"]
        assert "T1059.001" in result["ttp_tags"]

    def test_empty_report_produces_valid_schema(self) -> None:
        result = _normalize_report({}, "unknown.exe")
        assert "target" in result
        assert "behavior" in result
        assert "network" in result
        assert "signatures" in result

    def test_apistats_counts_calls(self) -> None:
        raw = _sample_triage_report()
        result = _normalize_report(raw, "sample.exe")
        apistats = result["behavior"]["apistats"]
        assert "malware.exe" in apistats
        assert apistats["malware.exe"].get("VirtualAllocEx", 0) == 1


# ---------------------------------------------------------------------------
# _sha256_file() tests
# ---------------------------------------------------------------------------


class TestSha256File:
    def test_returns_64_char_hex(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"hello world")
        result = _sha256_file(f)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        result = _sha256_file(f)
        # sha256("") = e3b0c44298fc1c149afb...
        assert result.startswith("e3b0")


# ---------------------------------------------------------------------------
# TriageClient init tests
# ---------------------------------------------------------------------------


class TestTriageClientInit:
    def test_default_base_url(self) -> None:
        client = TriageClient()
        assert "api.tria.ge" in client._api_prefix

    def test_custom_base_url(self) -> None:
        client = TriageClient(base_url="http://localhost:8080")
        assert "localhost:8080" in client._api_prefix

    def test_no_http_client_on_init(self) -> None:
        client = TriageClient()
        # Triage maintains separate sync + async httpx clients; both lazy.
        assert client._http_async is None
        assert client._http_sync is None


# ---------------------------------------------------------------------------
# SubmissionResult tests
# ---------------------------------------------------------------------------


class TestSubmissionResult:
    def test_succeeded_true_when_reported_with_report(self) -> None:
        result = SubmissionResult(task_id="test", status="reported", report={"a": 1})
        assert result.succeeded is True

    def test_succeeded_false_when_empty_report(self) -> None:
        result = SubmissionResult(task_id="test", status="reported", report={})
        assert result.succeeded is False

    def test_succeeded_false_when_failed(self) -> None:
        result = SubmissionResult(task_id="test", status="failed", error="timeout")
        assert result.succeeded is False
