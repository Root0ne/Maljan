"""Uploading a sample is not a status check and must not share its deadline.

Observed 2026-08-07: ``Sandbox submission failed: Submission request failed:
timed out``, 35 s after the submit began. ``CAPEv2Client`` applies one
``timeout`` (30 s) to every request, so the multipart upload of the sample
inherited the budget sized for ``GET /apiv2/tasks/view/<id>/`` — a few hundred
bytes of JSON. A sample is orders of magnitude larger, and the upload competes
with whatever the sandbox is already doing.

The companion fix in ``test_cape2_poll_resilience.py`` made *polling* survive a
transient failure. Submitting is deliberately **not** given the same retry:
``POST /apiv2/tasks/create/file/`` is not idempotent, a request that timed out
client-side may still have been accepted, and a blind retry would burn a second
detonation slot on a one-VM instance. The right lever here is a deadline that
fits the work, not a repeat of it.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maljan.loaders.cape2_client import CAPEv2Client
from maljan.loaders.sandbox_client import SandboxError


def _client(**kwargs: object) -> CAPEv2Client:
    with patch("httpx.Client"):
        c = CAPEv2Client(base_url="http://cape.invalid:8000", api_token="t", **kwargs)  # type: ignore[arg-type]
    c._http = MagicMock()
    return c


def _sample(tmp_path: Path) -> Path:
    p = tmp_path / "sample.exe"
    p.write_bytes(b"MZ" + b"\x00" * 4096)
    return p


def _ok_response() -> MagicMock:
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"data": {"task_ids": [17184]}}
    return r


class TestTheUploadGetsItsOwnDeadline:
    def test_submit_does_not_use_the_status_check_timeout(self, tmp_path: Path) -> None:
        c = _client()
        c._http.post.return_value = _ok_response()

        c.submit(_sample(tmp_path))

        _, kwargs = c._http.post.call_args
        assert "timeout" in kwargs, (
            "submit must pass an explicit timeout; without one it silently "
            "inherits the 30s client default sized for a JSON status check"
        )
        assert kwargs["timeout"] > 30

    def test_the_upload_deadline_is_configurable(self, tmp_path: Path) -> None:
        c = _client(upload_timeout=900)
        c._http.post.return_value = _ok_response()

        c.submit(_sample(tmp_path))

        assert c._http.post.call_args.kwargs["timeout"] == 900

    def test_a_generous_client_timeout_is_not_narrowed(self, tmp_path: Path) -> None:
        """An operator who raised the global timeout meant it."""
        c = _client(timeout=1200)
        c._http.post.return_value = _ok_response()

        c.submit(_sample(tmp_path))

        assert c._http.post.call_args.kwargs["timeout"] >= 1200


class TestSubmitStillFailsLoudlyAndOnce:
    def test_a_timeout_is_reported_not_retried(self, tmp_path: Path) -> None:
        """POST /tasks/create/file/ is not idempotent — one VM, one slot."""
        c = _client()
        c._http.post.side_effect = TimeoutError("timed out")

        with pytest.raises(SandboxError, match="Submission request failed"):
            c.submit(_sample(tmp_path))

        assert c._http.post.call_count == 1

    def test_the_task_id_is_still_returned(self, tmp_path: Path) -> None:
        c = _client()
        c._http.post.return_value = _ok_response()

        assert c.submit(_sample(tmp_path)) == "17184"
