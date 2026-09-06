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


def test_a_zero_retry_after_header_does_not_spin_the_poll_loop():
    """Regression (F10): inherited from ``rest.py`` -- ``Retry-After: 0``
    must floor the wait at the current poll interval, not skip the sleep."""
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] <= 2:
            return httpx.Response(429, headers={"Retry-After": "0"}, json={})
        return httpx.Response(200, json={"id": "s1", "status": "reported"})

    slept: list[float] = []
    provider = _provider(handler, poll_interval_seconds=2)
    provider._sleep = slept.append
    assert provider.wait_for_completion("s1", timeout_seconds=600) == "reported"
    assert slept and all(s > 0 for s in slept)


def test_a_float_retry_after_header_is_honoured():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "2.5"}, json={})
        return httpx.Response(200, json={"id": "s1", "status": "reported"})

    slept: list[float] = []
    provider = _provider(handler)
    provider._sleep = slept.append
    assert provider.wait_for_completion("s1", timeout_seconds=600) == "reported"
    assert slept == [2.5]


def test_an_http_date_retry_after_header_is_parsed_not_a_bare_valueerror():
    """RFC 9110 permits an HTTP-date as well as delta-seconds.

    I4 regression: ``float(retry_after)`` used to raise a bare ``ValueError``
    straight out of ``wait_for_completion`` on this form instead of the
    provider's own ``ProviderError``.
    """
    from datetime import UTC, datetime, timedelta
    from email.utils import format_datetime

    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            future = datetime.now(UTC) + timedelta(seconds=3)
            return httpx.Response(
                429, headers={"Retry-After": format_datetime(future, usegmt=True)}, json={}
            )
        return httpx.Response(200, json={"id": "s1", "status": "reported"})

    slept: list[float] = []
    provider = _provider(handler)
    provider._sleep = slept.append
    assert provider.wait_for_completion("s1", timeout_seconds=600) == "reported"
    assert len(slept) == 1
    assert 0 < slept[0] <= 3.5, slept


def test_an_unparseable_retry_after_header_falls_back_to_the_ordinary_backoff():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "not-a-date-or-a-number"}, json={})
        return httpx.Response(200, json={"id": "s1", "status": "reported"})

    slept: list[float] = []
    provider = _provider(handler, poll_interval_seconds=2)
    provider._sleep = slept.append
    assert provider.wait_for_completion("s1", timeout_seconds=600) == "reported"
    assert slept == [2.0], "an unparseable header must not crash the loop; it degrades to backoff"


def test_a_huge_retry_after_is_clamped_to_the_remaining_deadline():
    """A server answering ``Retry-After: 86400`` must not park the call for a day.

    The top-of-loop deadline check cannot interrupt a sleep already in
    progress, so the sleep itself must be clamped.
    """

    def handler(request):
        return httpx.Response(429, headers={"Retry-After": "86400"}, json={})

    slept: list[float] = []
    provider = _provider(handler)
    provider._sleep = slept.append
    provider._now = _Clock(step=50.0)
    with pytest.raises(ProviderError):
        provider.wait_for_completion("s1", timeout_seconds=600)
    assert slept, "the loop must still sleep, just not for the full header value"
    assert all(s <= 60.0 for s in slept), slept


class _Clock:
    """A monotonic clock that always has another value, unlike a bounded iterator.

    Used to drive ``wait_for_completion``'s deadline check without sleeping
    and without risking ``StopIteration`` if a fix changes how many times the
    loop reads the clock.
    """

    def __init__(self, step: float = 50.0) -> None:
        self._t = 0.0
        self._step = step

    def __call__(self) -> float:
        self._t += self._step
        return self._t


def test_a_permanent_rate_limit_raises_at_the_deadline_instead_of_hanging():
    """Regression: the deadline used to be checked only after a successful,
    non-terminal status read, so a server that keeps answering 429 forever
    never reached that check and the loop never returned."""

    def handler(request):
        return httpx.Response(429, headers={"Retry-After": "1"}, json={})

    provider = _provider(handler)
    provider._sleep = lambda _s: None
    provider._now = _Clock(step=50.0)
    with pytest.raises(ProviderError) as exc:
        provider.wait_for_completion("s1", timeout_seconds=600)
    assert "did not complete" in str(exc.value)


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
    assert sorted(report.unavailable) == [
        "apistats",
        "calls",
        "generic_events",
        "registry",
        "screenshots",
    ]
    assert report.apistats == {}
    assert run.sample_sha256 == overview["sample"]["sha256"]

    # The consumer shape, not Triage's own field names: a flow's combined
    # "host:port" is split, and a DNS/HTTP request is read from its
    # domain_req/domain_resp or web_req/web_resp sub-object.
    assert report.network.dns == [
        {"request": "update-relay-c9f2.net", "type": "A", "answers": [{"data": "45.33.32.23"}]}
    ]
    assert report.network.domains == ["update-relay-c9f2.net"]
    assert report.network.tcp == [{"dst": "45.33.32.23", "dport": 443}]
    assert report.network.udp == [{"dst": "10.0.2.3", "dport": 53}]
    assert {h["ip"] for h in report.network.hosts} == {"45.33.32.23", "10.0.2.3"}
    assert report.network.http == [
        {
            "host": "update-relay-c9f2.net",
            "uri": "/gate.php",
            "method": "GET",
            "status": 200,
            "port": None,
            "encrypted": True,
            "user_agent": "Mozilla/5.0 (compatible)",
        }
    ]
    assert [d["sha256"] for d in report.dropped_files] == [d["sha256"] for d in task["dumped"]]


def test_the_rendered_dict_names_what_this_sandbox_cannot_provide():
    from maljan.providers.cape_view import to_cape_shaped_dict
    from maljan.schemas.sandbox_report import triage_overview_to_sandbox_report

    overview = json.loads((FIX / "triage_overview.json").read_text(encoding="utf-8"))
    rendered = to_cape_shaped_dict(triage_overview_to_sandbox_report(overview))
    assert rendered["behavior"]["apistats"] == {}
    assert "apistats" in rendered["unavailable"]


def test_every_consumer_channel_is_populated_or_named_unavailable():
    """The mapper's own rule, enforced generically: a channel a consumer
    reads is either filled from the fixture or named in ``unavailable`` —
    never silently empty, which would read exactly like a clean sample.
    Written as a loop over the channel list so a future edit to the mapper
    cannot reintroduce a silent gap without this test catching it."""
    from maljan.schemas.sandbox_report import triage_overview_to_sandbox_report

    overview = json.loads((FIX / "triage_overview.json").read_text(encoding="utf-8"))
    task = json.loads((FIX / "triage_report_behavioral1.json").read_text(encoding="utf-8"))
    report = triage_overview_to_sandbox_report(
        overview, task_reports={"behavioral1": task}, task_id="260904-abcdefgh1"
    )
    unavailable = set(report.unavailable)
    channels: list[tuple[str, object]] = [
        ("apistats", report.apistats),
        ("calls", [c for p in report.processes for c in p.calls]),
        ("generic_events", report.generic_events),
        ("registry", report.registry),
        ("screenshots", report.screenshots),
        ("processes", report.processes),
        ("signatures", report.signatures),
        ("network.dns", report.network.dns),
        ("network.http", report.network.http),
        ("network.tcp", report.network.tcp),
        ("network.udp", report.network.udp),
        ("network.hosts", report.network.hosts),
        ("network.domains", report.network.domains),
        ("dropped_files", report.dropped_files),
    ]
    for name, value in channels:
        assert bool(value) or name in unavailable, (
            f"{name!r} is empty and not named in `unavailable`: "
            "a rendered report would read like a clean sample for it"
        )


def test_the_mapped_network_survives_the_real_parsers_not_as_na():
    """The mapping is only proven correct once real consumers, not the
    mapper's own assertions, read real domains and IPs out of it."""
    from maljan.extractors.network_extractor import build_network_iocs
    from maljan.parsers.network_parser import NetworkParser
    from maljan.providers.cape_view import to_cape_shaped_dict
    from maljan.schemas.sandbox_report import triage_overview_to_sandbox_report

    overview = json.loads((FIX / "triage_overview.json").read_text(encoding="utf-8"))
    task = json.loads((FIX / "triage_report_behavioral1.json").read_text(encoding="utf-8"))
    report = triage_overview_to_sandbox_report(
        overview, task_reports={"behavioral1": task}, task_id="260904-abcdefgh1"
    )
    rendered = to_cape_shaped_dict(report)

    parsed = NetworkParser().parse(rendered["network"])
    assert "update-relay-c9f2.net" in parsed
    assert "45.33.32.23" in parsed
    assert "N/A / N/A" not in parsed

    iocs = build_network_iocs(rendered)
    assert iocs is not None
    assert any(d.fqdn == "update-relay-c9f2.net" for d in iocs.domains)
    assert any(ip.address == "45.33.32.23" for ip in iocs.ips)


def test_pcap_is_written_only_when_it_is_a_real_capture(tmp_path):
    overview = {"tasks": [{"name": "behavioral1", "kind": "behavioral"}]}

    def handler(request):
        if request.url.path.endswith("overview.json"):
            return httpx.Response(200, json=overview)
        if request.url.path.endswith("dump.pcap"):
            return httpx.Response(200, content=b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
        return httpx.Response(404, json={})

    path = _provider(handler).fetch_pcap("260904-abcdefgh1", tmp_path)
    assert path is not None and Path(path).stat().st_size >= 24


def test_the_pcap_is_fetched_from_the_discovered_task_not_a_hardcoded_name(tmp_path):
    """Regression: the task name used to be the hardcoded literal
    "behavioral1"; a sample whose first (or only) behavioural task is named
    differently, or that ran several, must still get the right capture."""
    seen_paths: list[str] = []
    overview = {
        "tasks": [
            {"name": "static1", "kind": "static"},
            {"name": "behavioral7", "kind": "behavioral"},
            {"name": "behavioral8", "kind": "behavioral"},
        ]
    }

    def handler(request):
        seen_paths.append(request.url.path)
        if request.url.path.endswith("overview.json"):
            return httpx.Response(200, json=overview)
        if request.url.path.endswith("dump.pcap"):
            return httpx.Response(200, content=b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
        return httpx.Response(404, json={})

    path = _provider(handler).fetch_pcap("s1", tmp_path)
    assert path is not None
    assert any(p.endswith("/behavioral7/dump.pcap") for p in seen_paths)
    assert not any("behavioral8" in p or "static1" in p for p in seen_paths)


def test_a_traversal_shaped_task_id_is_sanitised_in_the_destination_path(tmp_path):
    """M12: task_id comes from Triage's own submit response, unsanitised.

    A malicious or misbehaving Triage instance answering with a task id like
    ``../../etc/passwd`` must not be able to walk the destination path out of
    ``dest_dir``.
    """
    overview = {"tasks": [{"name": "behavioral1", "kind": "behavioral"}]}

    def handler(request):
        if request.url.path.endswith("overview.json"):
            return httpx.Response(200, json=overview)
        if request.url.path.endswith("dump.pcap"):
            return httpx.Response(200, content=b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
        return httpx.Response(404, json={})

    path = _provider(handler).fetch_pcap("../../etc/passwd", tmp_path)
    assert path is not None
    written = Path(path)
    assert written.parent == tmp_path, written
    assert ".." not in written.name


def test_a_traversal_shaped_task_name_is_sanitised_in_the_request_url(tmp_path):
    seen_paths: list[str] = []
    overview = {"tasks": [{"name": "../../secrets", "kind": "behavioral"}]}

    def handler(request):
        seen_paths.append(request.url.path)
        if request.url.path.endswith("overview.json"):
            return httpx.Response(200, json=overview)
        return httpx.Response(200, content=b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)

    _provider(handler).fetch_pcap("s1", tmp_path)
    assert not any("/../" in p or p.count("..") for p in seen_paths), seen_paths


def test_no_behavioral_task_means_no_pcap_and_no_pcap_request(tmp_path):
    def handler(request):
        if request.url.path.endswith("overview.json"):
            return httpx.Response(200, json={"tasks": [{"name": "static1", "kind": "static"}]})
        raise AssertionError("must not request a PCAP with no behavioural task")

    assert _provider(handler).fetch_pcap("s1", tmp_path) is None


def test_an_empty_pcap_is_not_written(tmp_path):
    overview = {"tasks": [{"name": "behavioral1", "kind": "behavioral"}]}

    def handler(request):
        if request.url.path.endswith("overview.json"):
            return httpx.Response(200, json=overview)
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
