"""Triage over httpx.MockTransport: no network, real request shapes."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from maljan.core.config import Settings
from maljan.providers.errors import ProviderError
from maljan.providers.sandbox.triage import TriageSandboxProvider

FIX = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox"


def _provider(handler, **over):
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "triage"
    cfg.sandbox.triage.api_token = __import__("pydantic").SecretStr("not-a-real-token")
    for k, v in over.items():
        setattr(cfg.sandbox.triage, k, v)
    provider = TriageSandboxProvider.from_settings(cfg)
    provider._http = httpx.Client(
        base_url=cfg.sandbox.triage.base_url, transport=httpx.MockTransport(handler)
    )
    return provider


def test_capabilities():
    cfg = Settings(_env_file=None)
    caps = TriageSandboxProvider.from_settings(cfg).capabilities
    assert caps.can_submit and caps.can_poll and caps.can_fetch_report
    assert caps.can_fetch_pcap is True
    assert caps.provides_tools is False
    assert caps.report_format == "triage"
    assert caps.degrade_on_failure is True


def test_can_fetch_pcap_tracks_the_fetch_pcap_setting():
    cfg = Settings(_env_file=None)
    cfg.sandbox.triage.fetch_pcap = False
    assert TriageSandboxProvider.from_settings(cfg).capabilities.can_fetch_pcap is False


def test_submit_posts_the_file_and_the_json_part():
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = request.content
        return httpx.Response(200, json={"id": "260904-abcdefgh1"})

    provider = _provider(handler, profile="win10")
    tmp = FIX / "triage_overview.json"  # any readable file works as the upload body
    assert provider.submit(tmp) == "260904-abcdefgh1"
    assert seen["path"].endswith("/samples")
    assert seen["auth"] == "Bearer not-a-real-token"
    assert b'"kind": "file"' in seen["body"] and b"win10" in seen["body"]


def test_submit_without_a_profile_omits_the_profiles_field():
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content
        return httpx.Response(200, json={"id": "s1"})

    provider = _provider(handler)
    provider.submit(FIX / "triage_overview.json")
    assert b'"profiles"' not in seen["body"]


def test_polling_stops_at_reported_and_backs_off():
    states = iter(["pending", "static_analysis", "running", "reported"])
    slept: list[float] = []

    def handler(request):
        return httpx.Response(200, json={"id": "s1", "status": next(states)})

    provider = _provider(handler, poll_interval_seconds=2)
    provider._sleep = slept.append
    assert provider.wait_for_completion("s1", timeout_seconds=600) == "reported"
    assert slept == [2, 3.0, 4.5], "1.5x backoff, capped at 60 s"


def test_a_retry_after_header_is_honoured():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "7"}, json={})
        return httpx.Response(200, json={"id": "s1", "status": "reported"})

    slept: list[float] = []
    provider = _provider(handler)
    provider._sleep = slept.append
    assert provider.wait_for_completion("s1", timeout_seconds=600) == "reported"
    assert slept == [7.0]


def test_a_timeout_raises_rather_than_reporting_success():
    def handler(request):
        return httpx.Response(200, json={"id": "s1", "status": "running"})

    provider = _provider(handler)
    provider._sleep = lambda _s: None
    provider._now = iter([0.0, 100.0, 100000.0]).__next__
    with pytest.raises(ProviderError) as exc:
        provider.wait_for_completion("s1", timeout_seconds=900)
    assert "did not complete" in str(exc.value)


def test_fetch_maps_overview_and_task_report_into_a_sandbox_report():
    overview = json.loads((FIX / "triage_overview.json").read_text(encoding="utf-8"))
    task = json.loads((FIX / "triage_report_behavioral1.json").read_text(encoding="utf-8"))

    def handler(request):
        if request.url.path.endswith("overview.json"):
            return httpx.Response(200, json=overview)
        if request.url.path.endswith("report_triage.json"):
            return httpx.Response(200, json=task)
        return httpx.Response(200, json={"id": "s1", "status": "reported"})

    run = _provider(handler).fetch("260904-abcdefgh1")
    report = run.report
    assert report.source_format == "triage"
    assert report.target.sha256 == overview["sample"]["sha256"]
    assert report.cti["family"] == overview["analysis"]["family"]
    assert [s.name for s in report.signatures] == [s["name"] for s in overview["signatures"]]
    assert [p.name for p in report.processes] == [
        p["procid_parent"] and p["image"] or p["image"] for p in task["processes"]
    ]
    assert sorted(report.unavailable) == ["apistats", "calls", "generic_events", "registry"]
    assert report.apistats == {}
    assert run.sample_sha256 == overview["sample"]["sha256"]


def test_the_rendered_dict_names_what_this_sandbox_cannot_provide():
    from maljan.providers.cape_view import to_cape_shaped_dict
    from maljan.schemas.sandbox_report import triage_overview_to_sandbox_report

    overview = json.loads((FIX / "triage_overview.json").read_text(encoding="utf-8"))
    rendered = to_cape_shaped_dict(triage_overview_to_sandbox_report(overview))
    assert rendered["behavior"]["apistats"] == {}
    assert "apistats" in rendered["unavailable"]


def test_pcap_is_written_only_when_it_is_a_real_capture(tmp_path):
    def handler(request):
        if request.url.path.endswith("dump.pcap"):
            return httpx.Response(200, content=b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
        return httpx.Response(404, json={})

    path = _provider(handler).fetch_pcap("260904-abcdefgh1", tmp_path)
    assert path is not None and Path(path).stat().st_size >= 24


def test_an_empty_pcap_is_not_written(tmp_path):
    def handler(request):
        return httpx.Response(200, content=b"tiny")

    assert _provider(handler).fetch_pcap("s1", tmp_path) is None


def test_pcap_is_skipped_when_disabled_in_config(tmp_path):
    def handler(request):
        raise AssertionError("fetch_pcap must not make a request when disabled")

    provider = _provider(handler, fetch_pcap=False)
    assert provider.fetch_pcap("s1", tmp_path) is None


def test_a_missing_token_fails_before_any_request():
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "triage"
    with pytest.raises(ProviderError) as exc:
        TriageSandboxProvider.from_settings(cfg).submit("/tmp/x.exe")
    assert "sandbox.triage.api_token" in str(exc.value)


@pytest.mark.asyncio
async def test_probe_reports_ok_against_the_resources_endpoint(monkeypatch):
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={})

    cfg = Settings(_env_file=None)
    cfg.sandbox.triage.api_token = __import__("pydantic").SecretStr("not-a-real-token")
    provider = TriageSandboxProvider.from_settings(cfg)

    import maljan.providers.sandbox.triage as triage_module

    real_async_client = httpx.AsyncClient

    def fake_async_client(*args, **kwargs):
        return real_async_client(transport=httpx.MockTransport(handler), timeout=10)

    monkeypatch.setattr(triage_module.httpx, "AsyncClient", fake_async_client)
    result = await provider.probe()

    assert result.ok is True
    assert seen["path"].endswith("/resources")
    assert seen["auth"] == "Bearer not-a-real-token"


@pytest.mark.asyncio
async def test_probe_without_a_token_reports_clearly_without_a_request():
    cfg = Settings(_env_file=None)
    provider = TriageSandboxProvider.from_settings(cfg)
    result = await provider.probe()
    assert result.ok is False
    assert "sandbox.triage.api_token" in result.detail
