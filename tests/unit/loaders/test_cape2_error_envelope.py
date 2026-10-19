"""A CAPE answer that says it failed is a failure, never an empty detonation.

CAPE answers several refusals with HTTP 200 and a body of
``{"error": true, "error_value": "..."}``: the report API disabled, a TLP RED
task, a task with no report. Read as a report, that body is a report with no
processes, no network and no signatures: "observed, nothing happened". It is a
fetch that failed, with the reason CAPE stated, and the same holds for
``tasks/view`` and ``tasks/create/file``.

The poll also stops at once on CAPE's own failure states (``failed_analysis``,
``failed_processing``, ``failed_reporting``, ``banned``) instead of waiting out
the budget on a task that will never report.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from maljan.loaders.cape2_client import CAPEv2Client
from maljan.loaders.sandbox_client import SandboxError


def _client() -> CAPEv2Client:
    """A client whose HTTP layer is a mock: no socket is ever opened."""
    with patch("httpx.Client"):
        c = CAPEv2Client(base_url="http://cape.invalid:8000", api_token="t")
    c._http = MagicMock()
    return c


def _resp(body: Any, status_code: int = 200) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.text = "body"
    r.json.return_value = body
    return r


_DISABLED = {"error": True, "error_value": "Report download API is disabled"}


class TestTheReportEnvelope:
    def test_an_error_envelope_is_a_failed_fetch_with_its_reason(self) -> None:
        c = _client()
        c._http.get.return_value = _resp(_DISABLED)
        with pytest.raises(SandboxError, match="Report download API is disabled"):
            c.fetch_report("7")

    def test_a_tlp_red_refusal_is_a_failed_fetch(self) -> None:
        c = _client()
        c._http.get.return_value = _resp(
            {"error": True, "error_value": "Task is TLP RED, report not available"}
        )
        with pytest.raises(SandboxError, match="TLP RED"):
            c.fetch_report("7")

    def test_an_envelope_with_no_stated_reason_still_fails(self) -> None:
        c = _client()
        c._http.get.return_value = _resp({"error": True})
        with pytest.raises(SandboxError, match="no reason"):
            c.fetch_report("7")

    def test_a_body_that_is_not_a_json_object_is_a_failed_fetch(self) -> None:
        c = _client()
        c._http.get.return_value = _resp(["not", "a", "report"])
        with pytest.raises(SandboxError):
            c.fetch_report("7")

    def test_a_real_report_is_read_as_before(self) -> None:
        c = _client()
        report = {"target": {"file": {"sha256": "ab", "name": "s.exe"}}, "behavior": {}}
        c._http.get.return_value = _resp(report)
        result = c.fetch_report("7")
        assert result.report is report
        assert result.sample_sha256 == "ab"


class TestThePollStopsAtOnce:
    def test_an_error_envelope_on_the_task_view_ends_the_wait(self) -> None:
        c = _client()
        c._http.get.return_value = _resp({"error": True, "error_value": "Task not found"})
        with (
            patch("time.sleep", side_effect=AssertionError("waited")) as sleep,
            pytest.raises(SandboxError, match="Task not found"),
        ):
            c.wait_for_completion("7", timeout_seconds=1200, poll_interval_seconds=1)
        sleep.assert_not_called()
        assert c._http.get.call_count == 1

    @pytest.mark.parametrize(
        "state", ["failed_analysis", "failed_processing", "failed_reporting", "banned"]
    )
    def test_a_cape_failure_state_ends_the_wait(self, state: str) -> None:
        c = _client()
        c._http.get.return_value = _resp({"error": False, "data": {"status": state}})
        with patch("time.sleep", side_effect=AssertionError("waited")) as sleep:
            assert (
                c.wait_for_completion("7", timeout_seconds=1200, poll_interval_seconds=1) == state
            )
        sleep.assert_not_called()

    def test_a_running_task_is_still_waited_for(self) -> None:
        c = _client()
        c._http.get.side_effect = [
            _resp({"error": False, "data": {"status": "running"}}),
            _resp({"error": False, "data": {"status": "reported"}}),
        ]
        with patch("time.sleep"):
            assert (
                c.wait_for_completion("7", timeout_seconds=1200, poll_interval_seconds=1)
                == "reported"
            )


class TestTheSubmitEnvelope:
    def test_an_error_envelope_on_submit_states_its_reason(self, tmp_path) -> None:
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")
        c = _client()
        c._http.post.return_value = _resp({"error": True, "error_value": "File too big"})
        with pytest.raises(SandboxError, match="File too big"):
            c.submit(sample)


class TestThePcapEnvelope:
    def test_a_json_refusal_is_no_capture_rather_than_a_capture(self, tmp_path) -> None:
        c = _client()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"content-type": "application/json"}
        body = b'{"error": true, "error_value": "PCAP download API is disabled"}'
        resp.read.return_value = body
        resp.iter_bytes.return_value = [body]
        c._http.stream.return_value.__enter__.return_value = resp
        assert c.fetch_pcap("7", tmp_path) is None
        assert not list(tmp_path.iterdir())


class TestTheProviderFetch:
    def test_the_provider_fetch_raises_rather_than_reading_an_empty_report(self) -> None:
        from maljan.core.config import Settings
        from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider

        provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
        c = _client()
        c._http.get.return_value = _resp(_DISABLED)
        provider._client = c
        with pytest.raises(SandboxError, match="disabled"):
            provider.fetch("7")


class TestTheProbe:
    def _probe(self, monkeypatch: pytest.MonkeyPatch, body: Any, status: int = 200) -> Any:
        import asyncio

        import httpx

        from maljan.core.config import Settings
        from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, json=body)

        real = httpx.AsyncClient

        def client(*args: Any, **kwargs: Any) -> Any:
            return real(*args, transport=httpx.MockTransport(handler), **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", client)
        provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
        return asyncio.run(provider.probe())

    def test_task_not_found_still_proves_the_url_and_token(self, monkeypatch) -> None:
        r = self._probe(monkeypatch, {"error": True, "error_value": "Task not found"})
        assert r.ok is True

    def test_another_envelope_is_not_ok_with_its_reason(self, monkeypatch) -> None:
        r = self._probe(monkeypatch, {"error": True, "error_value": "API is disabled"})
        assert r.ok is False
        assert "API is disabled" in r.detail

    def test_a_task_view_is_ok(self, monkeypatch) -> None:
        r = self._probe(monkeypatch, {"error": False, "data": {"status": "reported"}})
        assert r.ok is True and r.detail == "HTTP 200"
