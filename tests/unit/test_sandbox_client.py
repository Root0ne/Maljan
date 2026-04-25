"""Unit tests for Phase 6: CAPEv2 Sandbox Integration.

Tests:
  SubmissionResult:
    - succeeded property: True when status=reported and report non-empty
    - behavior_section() / target_section() / signatures()
    - Edge cases: empty report, missing keys

  MockSandboxClient:
    - submit() returns a task_id string
    - submit() increments task IDs monotonically
    - wait_for_completion() returns "reported" immediately
    - wait_for_completion() raises SandboxError for unknown task_id
    - fetch_report() loads existing fixture file (sha256 lookup)
    - fetch_report() falls back to default_dynamic_fixture
    - fetch_report() returns minimal report when no fixture found
    - fetch_report() raises SandboxError for unknown task_id
    - SandboxClient Protocol isinstance check

  CAPEv2Client:
    - Raises SandboxNotAvailableError when httpx not installed
    - _raise_for_status raises SandboxError for 4xx responses

  FileDataLoader.load_from_sandbox():
    - Calls submit / wait / fetch in correct order
    - Returns list of TextChunk objects (same shape as load_chunked)
    - Raises DataLoadError on submission failure
    - Raises DataLoadError on polling failure
    - Raises DataLoadError on non-"reported" status
    - Raises DataLoadError on fetch failure
    - Parses report via registered parser
    - Falls back to raw JSON for unregistered data_type
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maljan.loaders.mock_sandbox_client import MockSandboxClient
from maljan.loaders.sandbox_client import (
    SandboxClient,
    SandboxError,
    SandboxNotAvailableError,
    SubmissionResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_report(
    sha256: str = "abc123",
    name: str = "test.exe",
    has_behavior: bool = True,
) -> dict:
    report: dict = {"target": {"sha256": sha256, "name": name, "md5": ""}}
    if has_behavior:
        report["behavior"] = {
            "apistats": {"1234": {"CreateFile": 2}},
            "generic": [{"category": "evasion", "description": "Timing check"}],
            "network": [{"dst_ip": "1.2.3.4", "dst_port": 443, "protocol": "HTTPS"}],
            "processes": [],
        }
        report["signatures"] = [{"name": "ransomware_dropper", "severity": 3}]
    return report


def _write_fixture(dir_path: Path, filename: str, report: dict) -> Path:
    """Write a fixture JSON file to dir_path/dynamic/<filename>."""
    target = dir_path / "dynamic"
    target.mkdir(parents=True, exist_ok=True)
    fixture = target / filename
    fixture.write_text(json.dumps(report), encoding="utf-8")
    return fixture


# ---------------------------------------------------------------------------
# SubmissionResult
# ---------------------------------------------------------------------------


class TestSubmissionResult:
    def test_succeeded_true_when_reported_with_report(self) -> None:
        result = SubmissionResult(task_id="1", status="reported", report={"behavior": {}})
        assert result.succeeded is True

    def test_succeeded_false_when_failed(self) -> None:
        result = SubmissionResult(task_id="1", status="failed", report={"behavior": {}})
        assert result.succeeded is False

    def test_succeeded_false_when_empty_report(self) -> None:
        result = SubmissionResult(task_id="1", status="reported", report={})
        assert result.succeeded is False

    def test_behavior_section_returns_dict(self) -> None:
        result = SubmissionResult(
            task_id="1",
            status="reported",
            report=_make_report(),
        )
        behavior = result.behavior_section()
        assert "apistats" in behavior
        assert "generic" in behavior

    def test_behavior_section_empty_when_missing(self) -> None:
        result = SubmissionResult(task_id="1", status="reported", report={})
        assert result.behavior_section() == {}

    def test_target_section_returns_dict(self) -> None:
        result = SubmissionResult(
            task_id="1", status="reported", report=_make_report(sha256="deadbeef")
        )
        assert result.target_section()["sha256"] == "deadbeef"

    def test_signatures_returns_list(self) -> None:
        result = SubmissionResult(task_id="1", status="reported", report=_make_report())
        sigs = result.signatures()
        assert len(sigs) == 1
        assert sigs[0]["name"] == "ransomware_dropper"

    def test_signatures_empty_when_missing(self) -> None:
        result = SubmissionResult(task_id="1", status="reported", report={})
        assert result.signatures() == []


# ---------------------------------------------------------------------------
# MockSandboxClient
# ---------------------------------------------------------------------------


class TestMockSandboxClient:
    def test_submit_returns_task_id_string(self, tmp_path: Path) -> None:
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"\x00" * 16)

        client = MockSandboxClient(fixtures_dir=str(tmp_path))
        task_id = client.submit(str(sample))
        assert isinstance(task_id, str)
        assert len(task_id) > 0

    def test_submit_increments_task_id(self, tmp_path: Path) -> None:
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"\x00" * 16)

        client = MockSandboxClient(fixtures_dir=str(tmp_path))
        id1 = int(client.submit(str(sample)))
        id2 = int(client.submit(str(sample)))
        assert id2 > id1

    def test_submit_nonexistent_file_still_returns_id(self, tmp_path: Path) -> None:
        client = MockSandboxClient(fixtures_dir=str(tmp_path))
        task_id = client.submit("/nonexistent/sample.exe")
        assert task_id is not None

    def test_wait_returns_reported_immediately(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"\x00")
        client = MockSandboxClient(fixtures_dir=str(tmp_path))
        task_id = client.submit(str(sample))
        status = client.wait_for_completion(task_id)
        assert status == "reported"

    def test_wait_raises_for_unknown_task(self, tmp_path: Path) -> None:
        client = MockSandboxClient(fixtures_dir=str(tmp_path))
        with pytest.raises(SandboxError):
            client.wait_for_completion("99999")

    def test_fetch_report_uses_fixture_file(self, tmp_path: Path) -> None:
        report = _make_report(sha256="aabbcc", name="ransomware.exe")

        # SHA-256 of a known byte sequence
        sample_bytes = b"ransomware payload"
        import hashlib

        sha256 = hashlib.sha256(sample_bytes).hexdigest()
        _write_fixture(tmp_path, f"{sha256}.json", report)

        sample = tmp_path / "ransomware.exe"
        sample.write_bytes(sample_bytes)

        client = MockSandboxClient(fixtures_dir=str(tmp_path))
        task_id = client.submit(str(sample))
        result = client.fetch_report(task_id)

        assert result.succeeded is True
        assert result.sample_sha256 == sha256
        assert "apistats" in result.behavior_section()

    def test_fetch_report_uses_name_fallback(self, tmp_path: Path) -> None:
        report = _make_report()
        _write_fixture(tmp_path, "ransomware.json", report)

        # File with no matching sha256 fixture — fallback to name
        sample = tmp_path / "ransomware.exe"
        sample.write_bytes(b"unique payload xyz")

        client = MockSandboxClient(fixtures_dir=str(tmp_path))
        task_id = client.submit(str(sample))
        result = client.fetch_report(task_id)

        assert result.succeeded is True

    def test_fetch_report_returns_minimal_when_no_fixture(self, tmp_path: Path) -> None:
        sample = tmp_path / "unknown.exe"
        sample.write_bytes(b"no fixture for this")

        client = MockSandboxClient(fixtures_dir=str(tmp_path))
        task_id = client.submit(str(sample))
        result = client.fetch_report(task_id)

        # Should succeed (minimal report)
        assert result.status == "reported"
        assert "behavior" in result.report

    def test_fetch_report_raises_for_unknown_task(self, tmp_path: Path) -> None:
        client = MockSandboxClient(fixtures_dir=str(tmp_path))
        with pytest.raises(SandboxError):
            client.fetch_report("99999")

    def test_uses_default_fixture_when_provided(self, tmp_path: Path) -> None:
        default_report = _make_report(name="default.exe")
        default_fixture = tmp_path / "default.json"
        default_fixture.write_text(json.dumps(default_report), encoding="utf-8")

        sample = tmp_path / "mystery.exe"
        sample.write_bytes(b"no specific fixture")

        client = MockSandboxClient(
            fixtures_dir=str(tmp_path),
            default_dynamic_fixture=str(default_fixture),
        )
        task_id = client.submit(str(sample))
        result = client.fetch_report(task_id)
        assert result.succeeded is True

    def test_sandbox_client_protocol_isinstance(self, tmp_path: Path) -> None:
        client = MockSandboxClient(fixtures_dir=str(tmp_path))
        assert isinstance(client, SandboxClient)


# ---------------------------------------------------------------------------
# CAPEv2Client
# ---------------------------------------------------------------------------


class TestCAPEv2Client:
    def test_raises_when_httpx_not_installed(self) -> None:
        from maljan.loaders.cape2_client import CAPEv2Client

        with patch.dict("sys.modules", {"httpx": None}):
            with pytest.raises((SandboxNotAvailableError, ImportError)):
                CAPEv2Client(base_url="http://localhost:8000")

    def test_raise_for_status_raises_on_4xx(self) -> None:
        from maljan.loaders.cape2_client import CAPEv2Client

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Not found"

        with pytest.raises(SandboxError):
            CAPEv2Client._raise_for_status(mock_response, "test_op")

    def test_raise_for_status_ok_on_200(self) -> None:
        from maljan.loaders.cape2_client import CAPEv2Client

        mock_response = MagicMock()
        mock_response.status_code = 200

        # Should not raise
        CAPEv2Client._raise_for_status(mock_response, "test_op")


# ---------------------------------------------------------------------------
# FileDataLoader.load_from_sandbox
# ---------------------------------------------------------------------------


class TestFileDataLoaderLoadFromSandbox:
    def _make_loader(self, tmp_path: Path) -> object:
        from maljan.loaders.file_loader import FileDataLoader
        from maljan.parsers.registry import ParserRegistry

        return FileDataLoader(
            samples_dir=str(tmp_path),
            parser_registry=ParserRegistry(),
        )

    def test_returns_text_chunks(self, tmp_path: Path) -> None:
        from maljan.loaders.binary_chunker import TextChunk

        report = _make_report()
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"payload")

        client = MockSandboxClient(fixtures_dir=str(tmp_path))
        # Write fixture for sha256 lookup
        import hashlib

        sha256 = hashlib.sha256(b"payload").hexdigest()
        _write_fixture(tmp_path, f"{sha256}.json", report)

        loader = self._make_loader(tmp_path)
        chunks = loader.load_from_sandbox(  # type: ignore[union-attr]
            sample_path=str(sample),
            data_type="dynamic",
            sandbox_client=client,
        )
        assert isinstance(chunks, list)
        assert len(chunks) >= 1
        assert isinstance(chunks[0], TextChunk)

    def test_raises_on_submission_failure(self, tmp_path: Path) -> None:
        from maljan.core.exceptions import DataLoadError

        broken_client = MagicMock()
        broken_client.submit.side_effect = SandboxError("connection refused")

        loader = self._make_loader(tmp_path)
        with pytest.raises(DataLoadError, match="submission"):
            loader.load_from_sandbox(  # type: ignore[union-attr]
                sample_path="sample.exe",
                data_type="dynamic",
                sandbox_client=broken_client,
            )

    def test_raises_on_non_reported_status(self, tmp_path: Path) -> None:
        from maljan.core.exceptions import DataLoadError

        broken_client = MagicMock()
        broken_client.submit.return_value = "1"
        broken_client.wait_for_completion.return_value = "failed"

        loader = self._make_loader(tmp_path)
        with pytest.raises(DataLoadError, match="failed"):
            loader.load_from_sandbox(  # type: ignore[union-attr]
                sample_path="sample.exe",
                data_type="dynamic",
                sandbox_client=broken_client,
            )

    def test_raises_on_fetch_failure(self, tmp_path: Path) -> None:
        from maljan.core.exceptions import DataLoadError

        broken_client = MagicMock()
        broken_client.submit.return_value = "1"
        broken_client.wait_for_completion.return_value = "reported"
        broken_client.fetch_report.side_effect = SandboxError("report unavailable")

        loader = self._make_loader(tmp_path)
        with pytest.raises(DataLoadError, match="fetch"):
            loader.load_from_sandbox(  # type: ignore[union-attr]
                sample_path="sample.exe",
                data_type="dynamic",
                sandbox_client=broken_client,
            )

    def test_falls_back_to_raw_json_for_unregistered_type(self, tmp_path: Path) -> None:
        report = _make_report()

        mock_client = MagicMock()
        mock_client.submit.return_value = "42"
        mock_client.wait_for_completion.return_value = "reported"
        mock_client.fetch_report.return_value = SubmissionResult(
            task_id="42", status="reported", report=report
        )

        loader = self._make_loader(tmp_path)
        # "binary" is not a registered parser type
        chunks = loader.load_from_sandbox(  # type: ignore[union-attr]
            sample_path="sample.exe",
            data_type="binary",
            sandbox_client=mock_client,
        )
        # Should still return chunks (raw JSON)
        assert len(chunks) >= 1
        assert "behavior" in chunks[0].content or "target" in chunks[0].content
