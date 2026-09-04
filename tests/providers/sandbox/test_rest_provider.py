"""A sandbox Maljan has never heard of, driven from settings."""

from __future__ import annotations

import httpx
import pytest

from maljan.core.config import Settings
from maljan.providers.errors import ProviderConfigurationError, ProviderError
from maljan.providers.sandbox.rest import RestSandboxProvider


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
    cfg.sandbox.rest.auth.token = "tok"
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
    from pydantic import SecretStr

    cfg = _cfg()
    cfg.sandbox.rest.auth.header = "Authorization"
    cfg.sandbox.rest.auth.scheme = "Bearer"
    cfg.sandbox.rest.auth.token = SecretStr("s3cr3t")
    provider = RestSandboxProvider.from_settings(cfg)
    assert provider._auth_headers() == {"Authorization": "Bearer s3cr3t"}


def test_the_token_never_appears_in_a_log_record(caplog):
    from pydantic import SecretStr

    cfg = _cfg()
    cfg.sandbox.rest.verify_tls = False
    cfg.sandbox.rest.auth.token = SecretStr("s3cr3t-token")
    with caplog.at_level("DEBUG"):
        provider = RestSandboxProvider.from_settings(cfg)
        provider._get_http()
        provider.close()
    assert all("s3cr3t-token" not in record.getMessage() for record in caplog.records)
