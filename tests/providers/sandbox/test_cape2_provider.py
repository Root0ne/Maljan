"""The CAPE provider is the existing client behind the provider contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maljan.core.config import Settings
from maljan.providers.cape_view import to_cape_shaped_dict
from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider
from tests.providers._cape_fixture import first_cape_report

ROOT = Path(__file__).resolve().parents[3]


class _FakeClient:
    def __init__(self, report):
        self.report = report
        self.submitted: list[str] = []
        self.waited: list[tuple[str, int, int]] = []

    def submit(self, sample_path):
        self.submitted.append(str(sample_path))
        return "42"

    def wait_for_completion(self, task_id, timeout_seconds=300, poll_interval_seconds=10):
        self.waited.append((task_id, timeout_seconds, poll_interval_seconds))
        return "reported"

    def fetch_report(self, task_id):
        from maljan.loaders.sandbox_client import SubmissionResult

        target = self.report.get("target", {})
        # Mirrors the fixed CAPEv2Client.fetch_report: real CAPE reports nest
        # sample identity under target.file.*, never flat on target (confirmed
        # against all 97 reports under data/cape_reports/); the flat read stays
        # as a fallback for a report that genuinely has it flat.
        file_block = target.get("file") if isinstance(target.get("file"), dict) else {}
        return SubmissionResult(
            task_id=task_id,
            sample_sha256=file_block.get("sha256") or target.get("sha256", ""),
            sample_name=file_block.get("name") or target.get("name", ""),
            status="reported",
            report=self.report,
        )

    def fetch_pcap(self, task_id, dest_dir):
        return None


@pytest.fixture
def raw_report():
    return first_cape_report()


def test_capabilities(raw_report):
    # provides_tools tracks the CAPE MCP toggle, which — like every other MCP
    # server in this config (ghidra, r2, generic) — defaults to disabled; it
    # is set explicitly here so this test exercises the "enabled" branch
    # rather than asserting a truthy value against a config that defaults
    # false.
    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.mcp.enabled = True
    caps = CAPE2SandboxProvider.from_settings(cfg).capabilities
    assert caps.can_submit and caps.can_poll and caps.can_fetch_report and caps.can_fetch_pcap
    assert caps.provides_tools and caps.report_format == "cape2"
    assert caps.degrade_on_failure is True
    assert caps.accepts_uploaded_report is False


def test_fetch_keeps_the_raw_report_by_identity(raw_report):
    provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
    provider._client = _FakeClient(raw_report)
    run = provider.fetch("42")
    assert run.raw is raw_report
    assert to_cape_shaped_dict(run.report) is raw_report
    assert run.report.source_format == "cape2"
    # Real CAPE reports nest sample identity under target.file.sha256, not a
    # flat target.sha256 (empirically confirmed against data/cape_reports/;
    # target's only keys there are "category" and "file") — see the report's
    # write-up of the cape2_client.py fetch_report fix.
    assert run.sample_sha256 == raw_report["target"]["file"]["sha256"]


def test_the_configured_timeout_and_interval_reach_the_client(raw_report):
    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.timeout_seconds = 1200
    cfg.sandbox.cape2.poll_interval_seconds = 15
    provider = CAPE2SandboxProvider.from_settings(cfg)
    client = _FakeClient(raw_report)
    provider._client = client
    provider.wait_for_completion("42")
    assert client.waited == [("42", 1200, 15)]


def test_the_essential_tool_names_match_the_golden():
    golden = json.loads(
        (ROOT / "tests" / "fixtures" / "golden" / "allowlists.json").read_text(encoding="utf-8")
    )
    assert sorted(CAPE2SandboxProvider.CAPE_ESSENTIAL_TOOLS) == golden["cape_essential_tools"]


def test_notable_apis_survives_the_identity_short_circuit_for_persistence_extractor():
    """Carried finding: ``persistence_extractor`` reads ``behavior.notable_apis``
    straight off the raw sandbox dict for Linux LD_PRELOAD detection. Neither
    ``SandboxReport`` nor ``to_cape_shaped_dict``'s full render names that key —
    but this provider never takes the full-render path with a real report:
    ``fetch()`` always sets ``raw`` to the client's untouched dict and
    ``source_format="cape2"``, so ``to_cape_shaped_dict`` always short-circuits
    to ``raw`` by identity, carrying whatever ``behavior.notable_apis`` the
    sandbox emitted through byte-for-byte. Proved end to end against
    ``persistence_extractor`` rather than merely asserted in prose.
    """
    from maljan.extractors.persistence_extractor import build_persistence_list

    raw = {
        "target": {"sha256": "e" * 64, "name": "mirai"},
        "behavior": {
            "notable_apis": [{"api": "setenv", "arguments": "LD_PRELOAD=/tmp/x.so"}],
        },
    }
    provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
    provider._client = _FakeClient(raw)
    run = provider.fetch("1")

    rendered = to_cape_shaped_dict(run.report)
    assert rendered is raw

    mechanisms = build_persistence_list(rendered, sample_platform="linux")
    assert any(m.kind == "ld_preload" for m in mechanisms)


def test_dynamic_tools_are_the_thirteen_essentials():
    class _T:
        def __init__(self, name):
            self.name = name

    class _Toolkit:
        def get_tools(self):
            return [_T(n) for n in CAPE2SandboxProvider.CAPE_ESSENTIAL_TOOLS] + [_T("extra_tool")]

    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.mcp.enabled = True
    provider = CAPE2SandboxProvider.from_settings(cfg)
    provider._toolkit = _Toolkit()
    assert {t.name for t in provider.dynamic_tools()} == set(
        CAPE2SandboxProvider.CAPE_ESSENTIAL_TOOLS
    )


def test_a_disabled_cape_mcp_yields_no_tools_and_no_workflow():
    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.mcp.enabled = False
    provider = CAPE2SandboxProvider.from_settings(cfg)
    assert provider.dynamic_tools() == []
    # The prompt fragment is a property of the sandbox, not of its MCP server:
    # the workflow text is what the analyst was measured with either way.
    assert provider.dynamic_prompt_fragment() == CAPE2SandboxProvider.CAPE_PROMPT_FRAGMENT


def test_the_mock_provider_offers_no_tool_workflow():
    from maljan.providers.sandbox.mock import MockSandboxProvider

    provider = MockSandboxProvider.from_settings(Settings(_env_file=None))
    assert provider.dynamic_tools() == []
    assert provider.dynamic_prompt_fragment() == ""


def test_dynamic_tools_is_idempotent_for_a_repeat_call(monkeypatch):
    """A second call must reuse the attached toolkit rather than rebuild it.

    The static side's equivalent work (the Ghidra provider's ``open()``) found
    this the hard way: a provider that owns a client and opens it twice on a
    repeat call leaks the first transport/subprocess instead of replacing it.
    ``dynamic_tools()`` guards the same way, via ``_toolkit``.
    """
    import maljan.agents.mcp_client as mc

    class _T:
        def __init__(self, name):
            self.name = name

    constructions: list[int] = []

    class _FakeToolkit:
        def __init__(self, *args, **kwargs):
            constructions.append(1)

        async def initialize(self):
            return None

        def get_tools(self):
            return [_T(n) for n in CAPE2SandboxProvider.CAPE_ESSENTIAL_TOOLS]

    monkeypatch.setattr(mc, "MCPLangChainToolkit", _FakeToolkit)

    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.mcp.enabled = True
    provider = CAPE2SandboxProvider.from_settings(cfg)

    first = provider.dynamic_tools()
    toolkit_after_first_call = provider._toolkit
    second = provider.dynamic_tools()

    assert len(constructions) == 1, "a repeat call must not rebuild the toolkit"
    assert provider._toolkit is toolkit_after_first_call
    expected_names = set(CAPE2SandboxProvider.CAPE_ESSENTIAL_TOOLS)
    assert {t.name for t in first} == expected_names
    assert {t.name for t in second} == expected_names


def _http_toolkit_factory():
    """A stand-in ``MCPLangChainToolkit`` class recording its constructor kwargs."""
    from unittest.mock import AsyncMock, MagicMock

    instance = MagicMock()
    instance.initialize = AsyncMock(return_value=None)
    instance.get_tools = MagicMock(return_value=[])
    return MagicMock(return_value=instance)


def test_the_http_bearer_header_carries_the_real_token_not_its_mask(monkeypatch):
    """Regression, same class of bug as the generic_mcp provider's: ``mcp.auth_token``
    is a ``SecretStr``, so building the header from the field itself (rather than
    ``get_secret_value()``) would render the fixed ``**********`` mask and the
    remote CAPE MCP server could never authenticate.
    """
    import secrets

    import maljan.agents.mcp_client as mc

    token = secrets.token_hex(16)
    factory = _http_toolkit_factory()
    monkeypatch.setattr(mc, "MCPLangChainToolkit", factory)

    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.mcp.enabled = True
    cfg.sandbox.cape2.mcp.transport = "http"
    cfg.sandbox.cape2.mcp.url = "http://cape-mcp.example:9999"
    cfg.sandbox.cape2.mcp.auth_token = token
    provider = CAPE2SandboxProvider.from_settings(cfg)

    provider.dynamic_tools()

    assert factory.called
    headers = factory.call_args.kwargs["http_headers"]
    assert headers == {"Authorization": f"Bearer {token}"}
    assert "*" not in headers["Authorization"]


def test_the_http_branch_sends_no_auth_header_for_an_empty_token(monkeypatch):
    """The counterpart: an empty token must not become ``Bearer `` (or ``Bearer
    **********``); the header is omitted entirely, same as before the SecretStr
    change."""
    import maljan.agents.mcp_client as mc

    factory = _http_toolkit_factory()
    monkeypatch.setattr(mc, "MCPLangChainToolkit", factory)

    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.mcp.enabled = True
    cfg.sandbox.cape2.mcp.transport = "http"
    cfg.sandbox.cape2.mcp.url = "http://cape-mcp.example:9999"
    provider = CAPE2SandboxProvider.from_settings(cfg)

    provider.dynamic_tools()

    assert factory.called
    headers = factory.call_args.kwargs["http_headers"]
    assert headers == {}
