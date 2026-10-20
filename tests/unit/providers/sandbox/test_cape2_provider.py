"""The CAPE provider is the existing client behind the provider contract."""

from __future__ import annotations

import pytest

from maljan.core.config import Settings
from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider
from maljan.schemas.sandbox_document import sandbox_document
from tests.unit.providers._cape_fixture import first_cape_report
from tests.unit.providers._document import as_published


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
    assert as_published(sandbox_document(run.report), raw_report)
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


def test_notable_apis_survives_as_a_block_with_no_place():
    """Carried finding: ``behavior.notable_apis`` is where a Linux LD_PRELOAD
    shows up, and the neutral form has no place named for it — the CAPE reader
    keeps it under its own name (``SandboxReport.extras``) and the document
    lays it out where the report put it. Proved through the call an agent
    makes to read it rather than asserted in prose.
    """
    from maljan.providers.sandbox_tools import sandbox_report_section

    raw = {
        "target": {"sha256": "e" * 64, "name": "mirai"},
        "behavior": {
            "notable_apis": [{"api": "setenv", "arguments": "LD_PRELOAD=/tmp/x.so"}],
        },
    }
    provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
    provider._client = _FakeClient(raw)
    run = provider.fetch("1")

    rendered = sandbox_document(run.report)
    assert as_published(rendered, raw)

    behavior = sandbox_report_section(rendered, "behavior")["value"]
    assert behavior["notable_apis"] == [{"api": "setenv", "arguments": "LD_PRELOAD=/tmp/x.so"}]


class _T:
    def __init__(self, name):
        self.name = name


def _fake_toolkit(monkeypatch, names, built=None):
    """``MCPLangChainToolkit`` replaced by one offering ``names``.

    ``built`` gets each construction's keyword arguments.
    """
    import maljan.agents.mcp_client as mc

    class _FakeToolkit:
        def __init__(self, *args, **kwargs):
            if built is not None:
                built.append(kwargs)

        async def initialize(self):
            return None

        async def cleanup(self):
            return None

        def get_tools(self):
            return [_T(name) for name in names]

    monkeypatch.setattr(mc, "MCPLangChainToolkit", _FakeToolkit)


def test_dynamic_tools_are_every_tool_the_toolkit_offers(monkeypatch):
    _fake_toolkit(monkeypatch, ["submit_file", "get_task_report", "extra_tool"])
    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.mcp.enabled = True
    provider = CAPE2SandboxProvider.from_settings(cfg)
    assert {t.name for t in provider.dynamic_tools()} == {
        "submit_file",
        "get_task_report",
        "extra_tool",
    }
    provider.close()


def test_dynamic_tools_honour_the_operator_tick_list(monkeypatch):
    _fake_toolkit(monkeypatch, ["submit_file", "get_task_report", "extra_tool"])
    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.mcp.enabled = True
    cfg.sandbox.cape2.mcp.tools = ["submit_file", "not_offered"]
    provider = CAPE2SandboxProvider.from_settings(cfg)
    assert [t.name for t in provider.dynamic_tools()] == ["submit_file"]
    provider.close()


class TestTheCapeServerSharesTheServerLifecycle:
    """PS-M8: the CAPE MCP server is attached as every server is, never as a bare toolkit."""

    def test_its_calls_go_through_the_job_s_guard_with_the_block_s_budget(self, monkeypatch):
        from maljan.providers.server_guard import ServerGuard

        built: list[dict] = []
        _fake_toolkit(monkeypatch, ["get_task_report"], built)
        cfg = Settings(_env_file=None)
        cfg.sandbox.cape2.mcp.enabled = True
        cfg.sandbox.cape2.mcp.call_timeout_seconds = 42.0
        cfg.mcp.breaker.failures_to_open = 7
        provider = CAPE2SandboxProvider.from_settings(cfg)
        provider.dynamic_tools()
        guard = built[0]["guard"]
        assert isinstance(guard, ServerGuard)
        assert guard is provider.server_handle.guard
        assert guard.failures_to_open == 7
        assert guard.call_timeout_seconds == 42.0
        provider.close()

    def test_its_answers_are_held_to_the_block_s_declared_error_patterns(self, monkeypatch):
        import asyncio

        from langchain_core.tools import StructuredTool

        import maljan.agents.mcp_client as mc

        async def report(task_id: int) -> str:
            return "Task is TLP RED, report not available"

        tool = StructuredTool.from_function(
            coroutine=report, name="get_task_report", description="d"
        )

        class _FakeToolkit:
            def __init__(self, *args, **kwargs):
                pass

            async def initialize(self):
                return None

            async def cleanup(self):
                return None

            def get_tools(self):
                return [tool]

        monkeypatch.setattr(mc, "MCPLangChainToolkit", _FakeToolkit)
        cfg = Settings(_env_file=None)
        cfg.sandbox.cape2.mcp.enabled = True
        from maljan.core.tool_declarations import ErrorPattern

        cfg.sandbox.cape2.mcp.error_patterns = [ErrorPattern(match=".*TLP RED.*")]
        provider = CAPE2SandboxProvider.from_settings(cfg)
        (wrapped,) = provider.dynamic_tools()
        answer = asyncio.run(wrapped.ainvoke({"task_id": 1}))
        from maljan.tools.errors import error_parts

        assert error_parts(answer) is not None
        provider.close()

    def test_the_close_goes_through_the_handle_and_lets_go_of_it(self, monkeypatch):
        _fake_toolkit(monkeypatch, ["get_task_report"])
        cfg = Settings(_env_file=None)
        cfg.sandbox.cape2.mcp.enabled = True
        provider = CAPE2SandboxProvider.from_settings(cfg)
        provider.dynamic_tools()
        handle = provider.server_handle
        closed: list[bool] = []
        real = handle.close

        def close() -> None:
            closed.append(True)
            real()

        monkeypatch.setattr(handle, "close", close)
        provider.close()
        assert closed == [True]
        assert not handle.is_open
        assert provider.server_handle is None
        assert provider._toolkit is None

    def test_its_calls_are_recorded_under_the_provider_s_block(self, monkeypatch):
        _fake_toolkit(monkeypatch, ["get_task_report"])
        cfg = Settings(_env_file=None)
        cfg.sandbox.cape2.mcp.enabled = True
        provider = CAPE2SandboxProvider.from_settings(cfg)
        provider.dynamic_tools()
        handle = provider.server_handle
        assert handle.declared_source == "provider:cape2"
        assert handle.measures_isolation is True
        provider.close()


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
            return [_T("submit_file"), _T("get_task_report")]

    monkeypatch.setattr(mc, "MCPLangChainToolkit", _FakeToolkit)

    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.mcp.enabled = True
    provider = CAPE2SandboxProvider.from_settings(cfg)

    first = provider.dynamic_tools()
    toolkit_after_first_call = provider._toolkit
    second = provider.dynamic_tools()

    assert len(constructions) == 1, "a repeat call must not rebuild the toolkit"
    assert provider._toolkit is toolkit_after_first_call
    expected_names = {"submit_file", "get_task_report"}
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
    from pydantic import SecretStr

    cfg.sandbox.cape2.mcp.auth_token = SecretStr(token)
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


def test_the_cape_server_s_process_is_noted_under_the_job_and_cleared_with_it(monkeypatch):
    """The measurement of the CAPE MCP child lands under the job's key, never "cape2",
    and goes when the job's container closes."""
    import asyncio

    from maljan.analysis import isolation
    from maljan.core.container import ServiceContainer
    from maljan.providers.servers import ServerHandle

    _fake_toolkit(monkeypatch, ["get_task_report"])

    def child(self, before):
        self._child_pids = (424242,)

    monkeypatch.setattr(ServerHandle, "_note_child_pids", child)
    monkeypatch.setattr(isolation, "measure_tree", lambda pid, names: {"pid": pid})
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "cape2"
    cfg.sandbox.cape2.mcp.enabled = True
    container = ServiceContainer(cfg, job_id="job-aud62")
    provider = container.get_sandbox_provider()
    assert provider.job_key == "job-aud62"
    provider.dynamic_tools()
    assert "provider:cape2" in isolation.noted("job-aud62")
    assert isolation.noted("cape2") == {}
    asyncio.run(container.aclose())
    assert isolation.noted("job-aud62") == {}
