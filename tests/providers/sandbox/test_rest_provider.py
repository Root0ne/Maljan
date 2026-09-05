"""A sandbox Maljan has never heard of, driven from settings."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from maljan.core.config import RestMappingConfig, Settings
from maljan.providers.errors import ProviderConfigurationError, ProviderError
from maljan.providers.sandbox.rest import RestSandboxProvider

FIX = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox"
GOLDEN = Path(__file__).resolve().parents[2] / "fixtures" / "golden" / "rest_mapping"


def _cfg(**over):
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "rest"
    cfg.sandbox.rest.base_url = "https://xyz.example/api"
    for key, value in over.items():
        setattr(cfg.sandbox.rest, key, value)
    return cfg


def _provider(handler, cfg=None):
    """A provider whose HTTP client answers from ``handler`` instead of a network."""
    provider = RestSandboxProvider.from_settings(cfg or _cfg())
    provider._http = httpx.Client(
        base_url="https://xyz.example/api", transport=httpx.MockTransport(handler)
    )
    provider._sleep = lambda seconds: None
    return provider


def test_a_stray_brace_in_a_path_template_is_rejected_at_from_settings():
    """Regression (F11): ``str.format(task_id=...)`` used to raise a bare
    ``KeyError``/``IndexError`` mid-job for any other ``{...}`` in a
    configured path -- an uncaught 500 from the probe route, an unwrapped
    exception on the job path. It must instead fail loudly, and legibly, at
    configuration time."""
    cfg = _cfg()
    cfg.sandbox.rest.status.path = "/samples/{task_id}/{oops}"
    with pytest.raises(ProviderConfigurationError, match="status.path"):
        RestSandboxProvider.from_settings(cfg)


def test_a_stray_brace_in_the_report_path_is_rejected():
    cfg = _cfg()
    cfg.sandbox.rest.report.path = "/samples/{task_id}/report}"
    with pytest.raises(ProviderConfigurationError, match="report.path"):
        RestSandboxProvider.from_settings(cfg)


def test_a_stray_brace_in_the_pcap_path_is_rejected():
    cfg = _cfg()
    cfg.sandbox.rest.report.pcap_path = "/samples/{task_id}/{pcap"
    with pytest.raises(ProviderConfigurationError, match="pcap_path"):
        RestSandboxProvider.from_settings(cfg)


def test_a_well_formed_path_template_with_no_other_braces_is_accepted():
    cfg = _cfg()
    cfg.sandbox.rest.status.path = "/samples/{task_id}/status"
    RestSandboxProvider.from_settings(cfg)  # must not raise


def test_capabilities_follow_the_configuration():
    caps = RestSandboxProvider.from_settings(_cfg()).capabilities
    assert caps.can_submit and caps.can_poll and caps.can_fetch_report
    assert caps.can_fetch_pcap is False and caps.report_format == "generic"
    assert caps.accepts_uploaded_report is False and caps.provides_tools is False
    assert caps.degrade_on_failure is True

    cfg = _cfg()
    cfg.sandbox.rest.report.pcap_path = "/samples/{task_id}/dump.pcap"
    cfg.sandbox.rest.report.format = "cape2"
    caps = RestSandboxProvider.from_settings(cfg).capabilities
    assert caps.can_fetch_pcap is True and caps.report_format == "cape2"


def test_a_broken_mapping_path_is_refused_at_construction():
    cfg = _cfg()
    cfg.sandbox.rest.mapping.processes = "$[["
    with pytest.raises(ProviderConfigurationError):
        RestSandboxProvider.from_settings(cfg)


def test_submit_posts_the_configured_field_and_reads_the_task_id(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["method"] = request.method
        seen["body"] = request.content
        return httpx.Response(200, json={"id": "T-9"})

    cfg = _cfg()
    cfg.sandbox.rest.submit.file_field = "binary"
    cfg.sandbox.rest.submit.extra_fields = {"profile": "win10"}
    cfg.sandbox.rest.auth.header = "X-Api-Key"
    cfg.sandbox.rest.auth.scheme = ""
    cfg.sandbox.rest.auth.token = SecretStr("tok")
    assert _provider(handler, cfg).submit(sample) == "T-9"
    assert seen["method"] == "POST" and seen["url"].endswith("/samples")
    assert b'name="binary"' in seen["body"] and b'name="profile"' in seen["body"]


def test_a_missing_task_id_names_the_path_that_did_not_match(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ")
    provider = _provider(lambda r: httpx.Response(200, json={"other": 1}))
    with pytest.raises(ProviderError) as exc:
        provider.submit(sample)
    assert "$.id" in str(exc.value)


def test_a_non_2xx_submit_is_a_provider_error(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ")
    provider = _provider(lambda r: httpx.Response(503, text="busy"))
    with pytest.raises(ProviderError) as exc:
        provider.submit(sample)
    assert "503" in str(exc.value)


def test_polling_stops_on_a_done_value_case_insensitively():
    states = iter(["queued", "Running", "REPORTED"])
    provider = _provider(lambda r: httpx.Response(200, json={"status": next(states)}))
    assert provider.wait_for_completion("T-9") == "reported"


def test_a_failed_state_stops_the_poll_and_says_so():
    provider = _provider(lambda r: httpx.Response(200, json={"status": "error"}))
    assert provider.wait_for_completion("T-9") == "failed"


def test_the_deadline_is_honoured():
    clock = iter([0.0, 0.0, 1000.0])
    provider = _provider(lambda r: httpx.Response(200, json={"status": "running"}))
    provider._now = lambda: next(clock)
    with pytest.raises(ProviderError) as exc:
        provider.wait_for_completion("T-9", timeout_seconds=10)
    assert "did not complete" in str(exc.value)


def test_retry_after_is_honoured_and_clamped():
    slept: list[float] = []
    answers = iter(
        [
            httpx.Response(429, headers={"Retry-After": "86400"}),
            httpx.Response(200, json={"status": "reported"}),
        ]
    )
    provider = _provider(lambda r: next(answers))
    provider._sleep = slept.append
    assert provider.wait_for_completion("T-9", timeout_seconds=120) == "reported"
    assert slept and max(slept) <= 60.0


def test_retry_after_zero_does_not_spin_the_poll_loop():
    """Regression (F10): ``Retry-After: 0`` used to skip the sleep *and* the
    backoff (``parsed is not None`` suppressed both), so a server sustaining
    it hammered the endpoint until the deadline. The wait must floor at the
    current poll interval instead, same as when the header is absent."""
    slept: list[float] = []
    answers = iter(
        [
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(200, json={"status": "reported"}),
        ]
    )
    provider = _provider(lambda r: next(answers))
    provider._sleep = slept.append
    assert provider.wait_for_completion("T-9", timeout_seconds=120) == "reported"
    assert slept and all(s > 0 for s in slept), "a zero Retry-After must not skip the sleep"


def test_a_sustained_429_past_the_deadline_raises_rather_than_looping_forever():
    """The rate-limit branch is on the same clock as everything else.

    A server that keeps answering 429 with a short ``Retry-After`` forever
    must still hit the deadline check at the top of the loop rather than
    sleeping past it indefinitely.
    """
    clock = iter([0.0, 0.0, 5.0, 10.0, 1000.0])
    provider = _provider(lambda r: httpx.Response(429, headers={"Retry-After": "1"}))
    provider._now = lambda: next(clock)
    with pytest.raises(ProviderError) as exc:
        provider.wait_for_completion("T-9", timeout_seconds=10)
    assert "did not complete" in str(exc.value)


def test_fetch_maps_a_generic_report_through_the_configured_paths():
    cfg = _cfg()
    cfg.sandbox.rest.mapping.processes = "$.procs[*]"
    body = {"procs": [{"pid": 3, "name": "a.exe"}], "target": {"sha256": "ab"}}
    provider = _provider(lambda r: httpx.Response(200, json=body), cfg)
    run = provider.fetch("T-9")
    assert run.task_id == "T-9" and run.status == "reported"
    assert [p.pid for p in run.report.processes] == [3]
    assert run.report.source_format == "generic"
    assert run.raw is not None and run.report.raw == body


def test_a_cape_shaped_body_goes_through_the_cape_reader_untouched():
    cfg = _cfg()
    cfg.sandbox.rest.report.format = "cape2"
    body = {"target": {"file": {"sha256": "ab", "name": "s.bin"}}, "behavior": {"processes": []}}
    provider = _provider(lambda r: httpx.Response(200, json=body), cfg)
    run = provider.fetch("T-9")
    assert run.report.source_format == "cape2"
    from maljan.providers.cape_view import to_cape_shaped_dict

    assert to_cape_shaped_dict(run.report) is run.report.raw, "identity, as for every CAPE source"


def test_a_real_cape_fixture_goes_through_the_cape_reader_by_identity():
    """The committed/real CAPE fixture, not a hand-rolled minimal body."""
    from tests.providers._cape_fixture import first_cape_report

    cfg = _cfg()
    cfg.sandbox.rest.report.format = "cape2"
    body = first_cape_report()
    provider = _provider(lambda r: httpx.Response(200, json=body), cfg)
    run = provider.fetch("T-9")
    assert run.report.source_format == "cape2"
    from maljan.providers.cape_view import to_cape_shaped_dict

    assert to_cape_shaped_dict(run.report) is run.report.raw


def test_a_triage_shaped_body_goes_through_the_triage_reader():
    """A single-endpoint REST fetch of an overview-shaped Triage body.

    Unlike ``TriageSandboxProvider`` (which fetches an overview and each
    task's behavioural report separately and combines them), this provider
    makes one GET against ``report.path``; with ``format="triage"`` that one
    body is read by the same ``triage_overview_to_sandbox_report`` mapper,
    without per-task ``task_reports`` — so the overview-level channels
    (target identity, family, signatures) come through and the per-task ones
    (processes, network, dropped files) stay empty, exactly as they would for
    any other caller of that mapper given only an overview.
    """
    cfg = _cfg()
    cfg.sandbox.rest.report.format = "triage"
    overview = json.loads((FIX / "triage_overview.json").read_text(encoding="utf-8"))
    provider = _provider(lambda r: httpx.Response(200, json=overview), cfg)
    run = provider.fetch("260904-abcdefgh1")
    report = run.report
    assert report.source_format == "triage"
    assert report.target.sha256 == overview["sample"]["sha256"]
    assert run.sample_sha256 == overview["sample"]["sha256"]
    assert report.cti["family"] == overview["analysis"]["family"]
    assert [s.name for s in report.signatures] == [s["name"] for s in overview["signatures"]]


def test_a_generic_golden_report_names_every_unmapped_channel_unavailable():
    """Task 10's own golden fixture, mapped through the REST provider end to end."""
    xyz_mapping = RestMappingConfig(
        target_sha256="$.sample.hashes.sha256",
        processes="$.run.processes[*]",
        calls="$.run.processes[*].syscalls[*]",
        signatures="$.detections[*]",
        dns="$.net.lookups[*]",
        tcp="$.net.streams[*]",
        dropped_files="$.artifacts[*]",
        registry="$.run.registry[*]",
        field_names={
            "processes.command_line": "cmdline",
            "processes.name": "image",
            "calls.api": "syscall",
            "signatures.severity": "score",
            "signatures.ttps": "attack",
            "dns.request": "qname",
            "tcp.dst": "peer",
            "tcp.dport": "peer_port",
            "dropped_files.name": "filename",
        },
    )
    cfg = _cfg()
    cfg.sandbox.rest.mapping = xyz_mapping
    body = json.loads((GOLDEN / "xyz_report.json").read_text(encoding="utf-8"))
    provider = _provider(lambda r: httpx.Response(200, json=body), cfg)
    run = provider.fetch("xyz-1")
    report = run.report
    assert report.source_format == "generic"
    unavailable = set(report.unavailable)
    # Every channel this mapping left unpointed (http, udp, hosts, domains)
    # plus the three that never have a settings field of their own.
    for channel in ("http", "udp", "hosts", "domains", "generic_events", "screenshots"):
        assert channel in unavailable, f"{channel!r} should be named unavailable"
    # And every channel the mapping does point at produced at least one row.
    assert report.processes and report.signatures and report.network.dns
    assert report.network.tcp and report.dropped_files


def test_fetch_pcap_is_none_when_no_path_is_configured(tmp_path):
    provider = _provider(lambda r: httpx.Response(200, content=b"x" * 64))
    assert provider.fetch_pcap("T-9", tmp_path) is None


def test_fetch_pcap_streams_to_the_destination(tmp_path):
    cfg = _cfg()
    cfg.sandbox.rest.report.pcap_path = "/samples/{task_id}/dump.pcap"
    body = b"\xd4\xc3\xb2\xa1" + b"y" * 64
    provider = _provider(lambda r: httpx.Response(200, content=body), cfg)
    out = provider.fetch_pcap("T-9", tmp_path)
    assert out is not None and out.endswith("rest_T-9.pcap")


def test_verify_tls_off_is_visible_in_the_probe_detail():
    cfg = _cfg()
    cfg.sandbox.rest.verify_tls = False
    provider = RestSandboxProvider.from_settings(cfg)
    assert "TLS verification is off" in provider._tls_note()


def test_the_auth_header_is_exactly_scheme_and_token():
    cfg = _cfg()
    cfg.sandbox.rest.auth.header = "Authorization"
    cfg.sandbox.rest.auth.scheme = "Bearer"
    cfg.sandbox.rest.auth.token = SecretStr("s3cr3t")
    provider = RestSandboxProvider.from_settings(cfg)
    assert provider._auth_headers() == {"Authorization": "Bearer s3cr3t"}


def test_the_token_never_appears_in_a_log_record(caplog):
    cfg = _cfg()
    cfg.sandbox.rest.verify_tls = False
    cfg.sandbox.rest.auth.token = SecretStr("s3cr3t-token")
    with caplog.at_level("DEBUG"):
        provider = RestSandboxProvider.from_settings(cfg)
        provider._get_http()
        provider.close()
    assert all("s3cr3t-token" not in record.getMessage() for record in caplog.records)


def test_a_path_traversal_task_id_cannot_escape_the_status_url():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        return httpx.Response(200, json={"status": "reported"})

    provider = _provider(handler)
    assert provider.wait_for_completion("../../etc") == "reported"
    assert "../" not in seen["path"] and ".." not in seen["path"].split("/")


def test_a_path_traversal_task_id_cannot_escape_the_report_url():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        return httpx.Response(200, json={"target": {"sha256": "ab"}})

    provider = _provider(handler)
    provider.fetch("../../etc/passwd")
    assert "../" not in seen["path"] and ".." not in seen["path"].split("/")


def test_the_configured_token_is_redacted_out_of_an_error_body():
    """A server that echoes the request's auth header back in an error body
    (some do, for an "invalid credential" response) must not carry the
    secret into the ``ProviderError`` message a caller can log."""
    cfg = _cfg()
    cfg.sandbox.rest.auth.header = "Authorization"
    cfg.sandbox.rest.auth.scheme = "Bearer"
    cfg.sandbox.rest.auth.token = SecretStr("s3cr3t-token")
    provider = RestSandboxProvider.from_settings(cfg)

    echoed = httpx.Response(403, text="forbidden: saw header 'Bearer s3cr3t-token'")
    with pytest.raises(ProviderError) as exc:
        provider._raise_for_status(echoed, "probe")
    assert "s3cr3t-token" not in str(exc.value)
    assert "***" in str(exc.value)


def test_a_bare_token_with_no_scheme_is_also_redacted():
    cfg = _cfg()
    cfg.sandbox.rest.auth.header = "X-Api-Key"
    cfg.sandbox.rest.auth.scheme = ""
    cfg.sandbox.rest.auth.token = SecretStr("s3cr3t-token")
    provider = RestSandboxProvider.from_settings(cfg)

    echoed = httpx.Response(403, text="forbidden: key=s3cr3t-token")
    with pytest.raises(ProviderError) as exc:
        provider._raise_for_status(echoed, "probe")
    assert "s3cr3t-token" not in str(exc.value)
