"""CAPEv2 polling must survive a transient sandbox, not abort on the first hiccup.

The defect this locks in, observed live on 2026-07-29: ``wait_for_completion``
was called with ``timeout_seconds=1200`` and gave up after **127 seconds** with
``Sandbox submission failed: Poll request failed: timed out``. The poll loop
re-raised any per-request exception, so one slow HTTP response ended the wait
and discarded the remaining ~18 minutes of budget.

That is precisely backwards. The loop exists to wait out a busy sandbox, and the
characteristic symptom of a busy CAPE — it is single-VM here and serialises
detonations — is exactly a slow or refused API response. The retry loop died at
the only moment it was needed, silently degrading the run to static-only.

A *permanent* error is different: a bad token or a deleted task will still be
bad in 20 minutes, so those must abort immediately rather than burn the budget.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from maljan.loaders.cape2_client import CAPEv2Client
from maljan.loaders.sandbox_client import SandboxError, SandboxTimeoutError


def _client() -> CAPEv2Client:
    """A client whose HTTP layer is a mock — no socket is ever opened."""
    with patch("httpx.Client"):
        c = CAPEv2Client(base_url="http://cape.invalid:8000", api_token="t")
    c._http = MagicMock()
    return c


def _resp(status_code: int = 200, status: str = "running") -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.text = "body"
    r.json.return_value = {"data": {"status": status}}
    return r


class TestATransientPollFailureDoesNotEndTheWait:
    def test_a_single_request_timeout_is_retried(self) -> None:
        c = _client()
        c._http.get.side_effect = [
            TimeoutError("timed out"),
            _resp(status="running"),
            _resp(status="reported"),
        ]

        with patch("time.sleep"):
            assert c.wait_for_completion("1", timeout_seconds=1200, poll_interval_seconds=1) == (
                "reported"
            )

    def test_a_burst_of_consecutive_failures_is_retried(self) -> None:
        """CAPE goes unreachable for a stretch while it processes, then returns."""
        c = _client()
        c._http.get.side_effect = [TimeoutError("timed out")] * 8 + [_resp(status="reported")]

        with patch("time.sleep"):
            assert c.wait_for_completion("1", timeout_seconds=1200, poll_interval_seconds=1) == (
                "reported"
            )

    def test_a_transient_server_error_is_retried(self) -> None:
        """A 502/503 from a loaded CAPE is a hiccup, not a verdict."""
        c = _client()
        c._http.get.side_effect = [_resp(503), _resp(502), _resp(status="reported")]

        with patch("time.sleep"):
            assert c.wait_for_completion("1", timeout_seconds=1200, poll_interval_seconds=1) == (
                "reported"
            )


class TestAPermanentErrorStillAbortsImmediately:
    """Burning a 20-minute budget on a bad token helps nobody."""

    @pytest.mark.parametrize("code", [401, 403, 404])
    def test_client_errors_abort(self, code: int) -> None:
        c = _client()
        c._http.get.return_value = _resp(code)

        with patch("time.sleep"):
            with pytest.raises(SandboxError):
                c.wait_for_completion("1", timeout_seconds=1200, poll_interval_seconds=1)
        # Aborted on the first poll — it did not retry.
        assert c._http.get.call_count == 1


class TestTheDeadlineIsStillHonoured:
    def test_unbroken_failure_eventually_times_out(self) -> None:
        """Retrying must not become waiting forever."""
        c = _client()
        c._http.get.side_effect = TimeoutError("timed out")

        clock = {"t": 0.0}

        def _mono() -> float:
            return clock["t"]

        def _sleep(s: float) -> None:
            clock["t"] += s

        with patch("time.monotonic", _mono), patch("time.sleep", _sleep):
            with pytest.raises(SandboxTimeoutError):
                c.wait_for_completion("1", timeout_seconds=60, poll_interval_seconds=10)

    def test_a_failing_poll_still_sleeps_between_attempts(self) -> None:
        """Without a sleep on the error path the retry becomes a hot spin that
        hammers an already-struggling sandbox."""
        c = _client()
        c._http.get.side_effect = [TimeoutError("x"), TimeoutError("x"), _resp(status="reported")]

        with patch("time.sleep") as slept:
            c.wait_for_completion("1", timeout_seconds=1200, poll_interval_seconds=7)

        assert slept.call_count >= 2
        assert all(call.args[0] == 7 for call in slept.call_args_list)
