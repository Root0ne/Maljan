"""One analysis, through a sandbox that only exists in this test."""

from __future__ import annotations

# Constructing ``MaljanApp`` lazily imports the LLM SDKs (google-genai among
# them), and one of them subclasses ``httpx.Client`` at import time. Importing
# it here, before the ``stub`` fixture below replaces ``httpx.Client`` with a
# plain function for the duration of a test, keeps that subclassing looking
# at the real class; deferring the import would have it subclass the stand-in
# instead and fail with "argument 'code' must be code, not str" on unrelated
# tests that happen to run first.
import google.genai  # noqa: F401
import pytest

from maljan.core.config import Settings
from tests.servers.rest_stub import StubState, build_stub_app


def _settings() -> Settings:
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "rest"
    rest = cfg.sandbox.rest
    rest.base_url = "http://stub"
    rest.submit.path = "/xyz/submit"
    rest.submit.file_field = "binary"
    rest.submit.task_id_path = "$.task.ref"
    rest.status.path = "/xyz/task/{task_id}"
    rest.status.state_path = "$.task.state"
    rest.status.done_values = ["finished"]
    rest.report.path = "/xyz/task/{task_id}/result"
    rest.report.pcap_path = "/xyz/task/{task_id}/capture"
    rest.poll_interval_seconds = 1
    mapping = rest.mapping
    mapping.target_sha256 = "$.sample.hashes.sha256"
    mapping.processes = "$.run.processes[*]"
    mapping.calls = "$.run.processes[*].syscalls[*]"
    mapping.signatures = "$.detections[*]"
    mapping.dns = "$.net.lookups[*]"
    mapping.tcp = "$.net.streams[*]"
    mapping.dropped_files = "$.artifacts[*]"
    mapping.registry = "$.run.registry[*]"
    mapping.field_names = {
        "processes.command_line": "cmdline",
        "processes.name": "image",
        "calls.api": "syscall",
        "signatures.severity": "score",
        "signatures.ttps": "attack",
        "dns.request": "qname",
        "tcp.dst": "peer",
        "tcp.dport": "peer_port",
        "dropped_files.name": "filename",
    }
    return cfg


@pytest.fixture()
def stub(monkeypatch):
    """Drive ``RestSandboxProvider`` at the in-process stub, no socket opened.

    ``httpx.ASGITransport`` only implements ``handle_async_request`` (it is an
    ``AsyncBaseTransport``), so a sync ``httpx.Client`` — which is what the
    provider builds — cannot use it directly: the earlier approach of handing
    it straight to ``httpx.Client(transport=...)`` fails with ``'ASGITransport'
    object has no attribute 'handle_request'`` on httpx 0.28.1. Starlette's
    ``TestClient`` is the sync bridge: it is an ``httpx.Client`` subclass whose
    transport runs the ASGI app on a background anyio portal, so every method
    the provider calls (``.request``, ``.get``, ``.stream``) works unchanged.
    """
    from starlette.testclient import TestClient

    state = StubState()
    app = build_stub_app(state)

    def client(*args, **kwargs):
        return TestClient(
            app,
            base_url=kwargs.get("base_url", "http://stub"),
            headers=kwargs.get("headers"),
        )

    monkeypatch.setattr("maljan.providers.sandbox.rest.httpx.Client", client)
    return state


@pytest.mark.asyncio
async def test_a_job_detonates_and_the_dynamic_sections_are_filled(stub, tmp_path):
    from maljan.app import MaljanApp
    from maljan.extractors.dynamic_extractor import build_dynamic_behavior
    from maljan.extractors.network_extractor import build_network_iocs

    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ" + b"\0" * 128)
    app = MaljanApp(config=_settings(), mock=False)
    container = app.container

    report = await app._submit_to_sandbox(str(sample))
    assert stub.submitted == ["s.bin"], "the stub received the sample under the configured field"
    assert report is not None
    # The synthetic xyz report's process ids, carried through the mapping and
    # into the CAPE-shaped dict every downstream extractor already reads.
    assert [p["pid"] for p in report["behavior"]["processes"]] == [100, 101]
    # Routable, non-RFC-reserved values on purpose (as the Task 10 golden
    # fixture is) — a documentation-range IP or a *.example domain is
    # filtered by the real network extractor's own suspicion rules, so this
    # is the only way to prove a mapped DNS row survives into the report a
    # job actually produces.
    assert report["network"]["dns"][0]["request"] == "telemetry-sync-71ad.net"
    assert report["network"]["tcp"][0]["dst"] == "185.220.101.42"

    # The report a job actually produces reaching the two consumers that
    # matter, not just the intermediate dict shape.
    dynamic = build_dynamic_behavior(report)
    assert dynamic is not None
    assert [p.pid for p in dynamic.process_tree] == [100]
    assert dynamic.sandbox_signatures[0].name == "persistence_run_key"

    network = build_network_iocs(report)
    assert network is not None
    assert network.domains[0].fqdn == "telemetry-sync-71ad.net"
    assert network.ips[0].address == "185.220.101.42"

    await container.aclose()


@pytest.mark.asyncio
async def test_the_unmapped_channels_are_named_rather_than_left_empty(stub, tmp_path):
    from maljan.core.container import ServiceContainer

    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ" + b"\0" * 128)
    container = ServiceContainer(config=_settings(), mock=False)
    provider = container.get_sandbox_provider()
    provider.submit(str(sample))  # the stub ignores the content; only the id it returns matters
    run = provider.fetch("XYZ-1")
    unavailable = set(run.report.unavailable)
    # The xyz mapping never populates these two; a report that quietly left
    # them empty instead of naming them would read like a clean sample.
    assert {"generic_events", "screenshots"} <= unavailable
    assert unavailable == {"domains", "generic_events", "hosts", "http", "screenshots", "udp"}
    await container.aclose()


@pytest.mark.asyncio
async def test_the_rest_provider_polls_on_its_own_budget(stub, tmp_path):
    """The app used to thread CAPE's timeout into every provider's poll loop."""
    from maljan.app import MaljanApp

    cfg = _settings()
    cfg.sandbox.rest.timeout_seconds = 42
    cfg.sandbox.rest.poll_interval_seconds = 1
    cfg.sandbox.cape2.timeout_seconds = 300
    app = MaljanApp(config=cfg, mock=False)
    assert app._poll_budget(app.container.get_sandbox_provider()) == (42, 1)
    await app.aclose()


@pytest.mark.asyncio
async def test_a_failed_job_reports_the_provider_error_without_a_traceback(stub, tmp_path, caplog):
    """A terminal ``failed`` state must degrade the run, not crash it.

    ``RestSandboxProvider.wait_for_completion`` never raises for a *terminal*
    failure — only a timeout or an HTTP error does that — it returns the
    string ``"failed"``, and ``_submit_to_sandbox`` folds that into the
    warning below via ``SubmissionResult.error``. So "the provider error" a
    caller sees for this path is that log line, not a raised
    ``ProviderError``; this test pins its exact shape rather than just the
    ``None`` return, so a future change that let a traceback leak into it (or
    dropped the state name from it) would fail here. ``_submit_to_sandbox``
    has no other channel — no run summary, no degradation-reasons list — that
    a caller could read this message from; that plumbing is filled in later,
    by graph nodes that only ever see ``sandbox_report is None``.
    """
    import logging

    from maljan.app import MaljanApp

    stub.states = ["queued", "failed"]
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ" + b"\0" * 128)
    app = MaljanApp(config=_settings(), mock=False)

    with caplog.at_level(logging.WARNING, logger="maljan"):
        report = await app._submit_to_sandbox(str(sample))
    assert report is None, "a failed sandbox task degrades the run rather than raising"

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings, "the degrade path must leave a legible trace in the logs"
    outcome = [r for r in warnings if "Sandbox task ended with status=failed" in r.getMessage()]
    assert len(outcome) == 1, [r.getMessage() for r in warnings]
    message = outcome[0].getMessage()
    # The failed state the stub returned, and the provider's own error text
    # for it, both present and readable — not swallowed into "something
    # failed".
    assert "failed" in message
    assert "Sandbox status: failed" in message
    for record in warnings:
        assert "Traceback" not in record.getMessage()
        assert record.exc_info is None
    await app.aclose()


@pytest.mark.asyncio
async def test_the_pcap_is_fetched_only_when_configured(stub, tmp_path):
    from maljan.app import MaljanApp

    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ" + b"\0" * 128)

    with_pcap = _settings()
    app_with_pcap = MaljanApp(config=with_pcap, mock=False)
    report = await app_with_pcap._submit_to_sandbox(str(sample))
    assert report is not None
    assert report["network"].get("pcap_local_path")
    await app_with_pcap.aclose()

    stub.states = ["queued", "running", "finished"]
    without_pcap = _settings()
    without_pcap.sandbox.rest.report.pcap_path = ""
    app_without_pcap = MaljanApp(config=without_pcap, mock=False)
    report = await app_without_pcap._submit_to_sandbox(str(sample))
    assert report is not None
    assert not report["network"].get("pcap_local_path")
    await app_without_pcap.aclose()
