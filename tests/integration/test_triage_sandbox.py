"""Integration tests for TriageClient sandbox submission.

These tests mock httpx.AsyncClient so no real network calls are made.
They verify:
  - Happy path: submit -> wait -> fetch -> normalize
  - Error paths: HTTP 500, invalid JSON, string response, timeout
  - SubmissionResult.report is ALWAYS a dict (never a string or None).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from maljan.loaders.sandbox_client import SubmissionResult
from maljan.loaders.triage_client import TriageClient, _normalize_report

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client() -> TriageClient:
    return TriageClient(api_token="test-token")


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    p = tmp_path / "evil.exe"
    p.write_bytes(b"MZ fake malware")
    return p


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(
    status: int = 200,
    json_data: Any | None = None,
    text: str = "",
) -> MagicMock:
    """Build a mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = json.JSONDecodeError("", "", 0)
    return resp


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_submit_and_wait_success(client: TriageClient, sample_file: Path) -> None:
    """Full happy path: submit -> wait(reported) -> fetch summary."""
    submit_resp = _mock_response(200, {"id": "240101-abc123"})
    wait_resp = _mock_response(200, {"status": "reported"})
    summary_json = {
        "sample": {
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "name": sample_file.name,
            "size": 15,
        },
        "tasks": {
            "win10-1": {
                "processes": [{"name": "evil.exe", "pid": 1234, "cmd": "evil.exe"}],
                "ttp_tags": ["T1055"],
            }
        },
        "network": {"dns": [], "http": []},
        "signatures": [{"name": "creates_exe", "score": 5}],
    }
    fetch_resp = _mock_response(200, summary_json)

    with patch.object(client, "_get_http") as mock_http_factory:
        mock_http = AsyncMock()
        mock_http.post.return_value = submit_resp
        mock_http.get.side_effect = [wait_resp, fetch_resp]
        mock_http_factory.return_value = mock_http

        result = await client.submit_and_wait(sample_file)

    assert isinstance(result, SubmissionResult)
    assert result.status == "reported"
    assert result.task_id == "240101-abc123"
    assert isinstance(result.report, dict)
    assert result.report["target"]["file"]["name"] == sample_file.name
    assert "T1055" in result.report["ttp_tags"]


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_submit_http_500(client: TriageClient, sample_file: Path) -> None:
    """HTTP 500 on submit raises RuntimeError."""
    resp = _mock_response(500, text="Internal Server Error")

    with patch.object(client, "_get_http") as mock_http_factory:
        mock_http = AsyncMock()
        mock_http.post.return_value = resp
        mock_http_factory.return_value = mock_http

        with pytest.raises(RuntimeError, match="Triage /samples submission failed"):
            await client._async_submit(sample_file)


@pytest.mark.asyncio
async def test_submit_returns_string_json(client: TriageClient, sample_file: Path) -> None:
    """If response.json() returns a string instead of dict, raise RuntimeError."""
    resp = _mock_response(200, json_data="unexpected string")

    with patch.object(client, "_get_http") as mock_http_factory:
        mock_http = AsyncMock()
        mock_http.post.return_value = resp
        mock_http_factory.return_value = mock_http

        with pytest.raises(RuntimeError, match="unexpected type"):
            await client._async_submit(sample_file)


@pytest.mark.asyncio
async def test_wait_returns_string_json(client: TriageClient) -> None:
    """If wait poll returns string JSON, treat as retryable error and return timeout."""
    resp = _mock_response(200, json_data="not a dict")

    with patch.object(client, "_get_http") as mock_http_factory:
        mock_http = AsyncMock()
        mock_http.get.return_value = resp
        mock_http_factory.return_value = mock_http

        # Override timeout so the loop exits quickly
        client._timeout = 1
        client._poll_interval = 0
        status = await client._async_wait("240101-abc123")

    assert status == "timeout"


@pytest.mark.asyncio
async def test_fetch_report_http_404(client: TriageClient) -> None:
    """Report fetch 404 returns failed SubmissionResult."""
    resp = _mock_response(404, text="Not Found")

    with patch.object(client, "_get_http") as mock_http_factory:
        mock_http = AsyncMock()
        mock_http.get.return_value = resp
        mock_http_factory.return_value = mock_http

        result = await client._async_fetch_report("240101-abc123")

    assert result.status == "failed"
    assert isinstance(result.report, dict)
    assert "404" in result.error


@pytest.mark.asyncio
async def test_fetch_report_returns_string_json(client: TriageClient) -> None:
    """Report fetch returning string JSON yields failed SubmissionResult."""
    resp = _mock_response(200, json_data="malformed")

    with patch.object(client, "_get_http") as mock_http_factory:
        mock_http = AsyncMock()
        mock_http.get.return_value = resp
        mock_http_factory.return_value = mock_http

        result = await client._async_fetch_report("240101-abc123")

    assert result.status == "failed"
    assert isinstance(result.report, dict)
    assert "unexpected type" in result.error


@pytest.mark.asyncio
async def test_submit_and_wait_task_failed(client: TriageClient, sample_file: Path) -> None:
    """If task ends with status 'failed', return SubmissionResult with error."""
    submit_resp = _mock_response(200, {"id": "240101-abc123"})
    wait_resp = _mock_response(200, {"status": "failed"})

    with patch.object(client, "_get_http") as mock_http_factory:
        mock_http = AsyncMock()
        mock_http.post.return_value = submit_resp
        mock_http.get.return_value = wait_resp
        mock_http_factory.return_value = mock_http

        result = await client.submit_and_wait(sample_file)

    assert result.status == "failed"
    assert isinstance(result.report, dict)
    assert "ended with status: failed" in result.error


# ---------------------------------------------------------------------------
# _normalize_report
# ---------------------------------------------------------------------------


def test_normalize_report_empty() -> None:
    """_normalize_report handles empty input gracefully."""
    result = _normalize_report({}, "sample.exe")
    assert isinstance(result, dict)
    assert result["target"]["file"]["name"] == "sample.exe"
    assert result["behavior"]["processes"] == []
    assert result["ttp_tags"] == []


def test_normalize_report_skips_non_dict_tasks() -> None:
    """Tasks that are not dicts are skipped."""
    triage = {
        "sample": {"sha256": "a" * 64},
        "tasks": {"win10-1": "corrupted", "win7-1": {"ttp_tags": ["T1055"]}},
    }
    result = _normalize_report(triage, "sample.exe")
    assert "T1055" in result["ttp_tags"]


def test_normalize_report_string_sample_field() -> None:
    """If 'sample' is a string instead of dict, treat as empty."""
    triage = {
        "sample": "not_a_dict",
        "tasks": {"win10-1": {"ttp_tags": ["T1055"]}},
    }
    result = _normalize_report(triage, "sample.exe")
    assert isinstance(result, dict)
    assert result["target"]["file"]["name"] == "sample.exe"
    assert "T1055" in result["ttp_tags"]


def test_normalize_report_list_tasks_field() -> None:
    """If 'tasks' is a list instead of dict, treat as empty."""
    triage = {
        "sample": {"sha256": "a" * 64},
        "tasks": ["not_a_dict"],
    }
    result = _normalize_report(triage, "sample.exe")
    assert isinstance(result, dict)
    assert result["behavior"]["processes"] == []


def test_normalize_report_string_network_field() -> None:
    """If 'network' is a string instead of dict, treat as empty."""
    triage = {
        "sample": {"sha256": "a" * 64},
        "network": "not_a_dict",
    }
    result = _normalize_report(triage, "sample.exe")
    assert isinstance(result, dict)
    assert result["network"]["dns"] == []


def test_normalize_report_dict_signatures_field() -> None:
    """If 'signatures' is a dict instead of list, treat as empty."""
    triage = {
        "sample": {"sha256": "a" * 64},
        "signatures": {"not_a_list": True},
    }
    result = _normalize_report(triage, "sample.exe")
    assert isinstance(result, dict)
    assert result["signatures"] == []


@pytest.mark.anyio
async def test_fetch_report_string_sample_field(client: TriageClient) -> None:
    """_async_fetch_report handles 'sample' field being a string."""
    mock_resp = _mock_response(
        json_data={
            "sample": "not_a_dict",
            "tasks": {"win10-1": {"ttp_tags": ["T1055"]}},
        }
    )
    with patch.object(client, "_get_http") as mock_http_factory:
        mock_http = AsyncMock()
        mock_http.get.return_value = mock_resp
        mock_http_factory.return_value = mock_http

        result = await client._async_fetch_report("abc123")

    assert result.status == "reported"
    assert isinstance(result.report, dict)
    assert "T1055" in result.report["ttp_tags"]
