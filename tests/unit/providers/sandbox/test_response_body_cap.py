"""A sandbox does not get to decide how much memory Maljan spends.

CORE-1 (dev audit 2026-09-06): ``rest.py`` and ``triage.py`` read a report
body with ``response.json()`` and streamed a pcap to disk with no ceiling on
either. A sandbox is a remote service under someone else's control -- often a
public one -- and a report is the one body that is legitimately large, so a
misbehaving or hostile endpoint could hand a worker a body until it ran out of
memory or filled the disk. The upload endpoint has capped its input since it
was written; these two now cap theirs the same way, and say so.
"""

from __future__ import annotations

import httpx
import pytest

from maljan.core.config import Settings
from maljan.providers.errors import ProviderError
from maljan.providers.sandbox import limits
from maljan.providers.sandbox.rest import RestSandboxProvider
from maljan.providers.sandbox.triage import TriageSandboxProvider


def _rest(handler):
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "rest"
    cfg.sandbox.rest.base_url = "https://xyz.example/api"
    cfg.sandbox.rest.report.pcap_path = "/samples/{task_id}/dump.pcap"
    provider = RestSandboxProvider.from_settings(cfg)
    provider._http = httpx.Client(
        base_url="https://xyz.example/api", transport=httpx.MockTransport(handler)
    )
    provider._sleep = lambda seconds: None
    return provider


def _triage(handler):
    from pydantic import SecretStr

    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "triage"
    cfg.sandbox.triage.api_token = SecretStr("not-a-real-token")
    provider = TriageSandboxProvider.from_settings(cfg)
    provider._http = httpx.Client(
        base_url=cfg.sandbox.triage.base_url, transport=httpx.MockTransport(handler)
    )
    return provider


@pytest.fixture(autouse=True)
def _small_cap(monkeypatch):
    """A cap small enough to test without allocating the real 64 MiB."""
    monkeypatch.setattr(limits, "MAX_RESPONSE_BYTES", 4096)


def _oversized(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=b"x" * 9000)


def test_a_rest_report_past_the_cap_is_refused_with_a_legible_error():
    with pytest.raises(ProviderError) as exc:
        _rest(_oversized).fetch("T-1")
    assert "larger than" in str(exc.value)


def test_a_triage_overview_past_the_cap_is_refused_with_a_legible_error():
    with pytest.raises(ProviderError) as exc:
        _triage(_oversized).fetch("T-1")
    assert "larger than" in str(exc.value)


def test_a_rest_pcap_past_the_cap_is_not_written_whole(tmp_path):
    """A pcap is best effort, so an over-cap capture degrades rather than raises."""
    assert _rest(_oversized).fetch_pcap("T-1", tmp_path) is None
    written = list(tmp_path.iterdir())
    assert all(f.stat().st_size <= 4096 for f in written)


def test_a_body_within_the_cap_is_still_read(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"target": {"sha256": "a" * 64}})

    run = _rest(handler).fetch("T-2")
    assert run.task_id == "T-2"
