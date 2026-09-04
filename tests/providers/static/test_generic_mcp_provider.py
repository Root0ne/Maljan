"""Any MCP server attaches as a static provider through settings alone."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.core.config import MCPServerConfig, Settings
from maljan.providers.base import StaticJobContext
from maljan.providers.static.generic_mcp import GenericMCPStaticProvider


class _T:
    def __init__(self, name):
        self.name = name


def _cfg(**over):
    cfg = Settings(_env_file=None)
    cfg.static.provider = "generic_mcp"
    cfg.static.generic.enabled = True
    cfg.static.generic.command = "my-mcp"
    cfg.static.generic.args = ["--stdio"]
    for k, v in over.items():
        setattr(cfg.static.generic, k, v)
    return cfg


def test_capabilities():
    caps = GenericMCPStaticProvider.from_settings(_cfg()).capabilities
    assert caps.provides_tools and caps.supports_tool_curation and caps.needs_sample_mirror
    assert caps.degrade_on_failure is True, "an operator's own server must not fail a run"
    assert caps.provides_function_hashes is False


def test_curated_mode_without_an_allow_list_keeps_everything():
    provider = GenericMCPStaticProvider.from_settings(_cfg(tool_selection="curated"))
    tools = [_T("a"), _T("b")]
    assert len(provider.select_tools(tools)) == 2


def test_an_allow_list_narrows_the_manifest():
    provider = GenericMCPStaticProvider(
        _cfg().static.generic, label="Test MCP", allowed_tools=frozenset({"keep"})
    )
    assert [t.name for t in provider.select_tools([_T("keep"), _T("drop")])] == ["keep"]


def test_a_disabled_server_attaches_nothing():
    provider = GenericMCPStaticProvider.from_settings(_cfg(enabled=False))
    provider.open(StaticJobContext())
    assert provider.get_tools() == []


# ---------------------------------------------------------------------------
# Beyond the brief's own list: the idempotency regression the Ghidra provider
# was caught on (open() called once per chunk on one memoized instance must
# not rebuild the client each time), the degrade-vs-raise split between
# open() and the capability flag, that the stdio attach goes through
# child_env() rather than a raw os.environ copy, and the http/streamable/sse
# branch builds the toolkit with the configured transport.
# ---------------------------------------------------------------------------


def _toolkit_factory() -> MagicMock:
    """A stand-in ``MCPLangChainToolkit`` class: instances need no live MCP."""
    instance = MagicMock()
    instance.initialize = AsyncMock(return_value=None)
    instance.get_tools = MagicMock(return_value=[])
    factory = MagicMock(return_value=instance)
    return factory


def test_open_is_idempotent_for_a_repeat_call_with_an_equal_job(monkeypatch):
    """Regression for the multi-chunk leak Ghidra's provider was caught on.

    ``safe_analyze_isr_chunked`` calls the analyst once per chunk on one
    cached agent, and the container memoizes one provider per job, so a
    multi-chunk sample calls ``open()`` several times with a *fresh but
    equal* ``StaticJobContext`` (never the literal same object). Passing two
    separate, merely-``==``-equal instances is what actually exercises the
    value comparison ``open()`` relies on.
    """
    from maljan.agents import mcp_client

    constructions: list[int] = []

    class _FakeToolkit:
        def __init__(self, *args, **kwargs):
            constructions.append(1)

        async def initialize(self) -> None:
            return None

        def get_tools(self):
            return [_T("keep")]

    monkeypatch.setattr(mcp_client, "MCPLangChainToolkit", _FakeToolkit)

    provider = GenericMCPStaticProvider.from_settings(_cfg())
    job_1 = StaticJobContext(mirror_sample_path="/data/samples/.work/abc.exe")
    job_2 = StaticJobContext(mirror_sample_path="/data/samples/.work/abc.exe")
    assert job_1 == job_2 and job_1 is not job_2, "the test must exercise value equality"

    provider.open(job_1)
    toolkit_after_first_open = provider._toolkit

    provider.open(job_2)

    assert len(constructions) == 1, "a same-job repeat call must not rebuild the client"
    assert provider._toolkit is toolkit_after_first_open


def test_a_failed_attach_raises_instead_of_silently_degrading():
    """``open()`` itself still raises; degrading is the analyst's job, not the provider's.

    A nonexistent stdio command fails fast — no network, no real server — and
    proves this provider does not swallow the error itself. Whether the
    analyst then degrades is entirely the ``degrade_on_failure=True`` capability
    (see ``test_capabilities``) plus the shared, already-tested
    ``BaseAnalyst._try_initialize_mcp``.
    """
    provider = GenericMCPStaticProvider.from_settings(
        _cfg(command="definitely-not-a-real-mcp-binary-xyz")
    )
    with pytest.raises(FileNotFoundError):
        provider.open(StaticJobContext())


def test_a_failed_attach_leaves_the_analyst_running(monkeypatch):
    """End to end: the analyst survives a broken generic server without raising."""
    from maljan.agents import mcp_client
    from maljan.agents.static_analyst import StaticAnalyst

    class _BoomToolkit:
        def __init__(self, *args, **kwargs):
            pass

        async def initialize(self) -> None:
            raise RuntimeError("generic MCP server unreachable")

        def get_tools(self):
            return []

    monkeypatch.setattr(mcp_client, "MCPLangChainToolkit", _BoomToolkit)

    analyst = StaticAnalyst(llm=MagicMock(), name="static")
    container = MagicMock()
    container.get_static_provider.return_value = GenericMCPStaticProvider.from_settings(_cfg())
    analyst._container = container

    assert analyst._try_initialize_mcp() is False


def test_the_stdio_sidecar_env_carries_no_api_key(monkeypatch):
    """The generic provider must filter its subprocess env through ``child_env``.

    Same guard as the Ghidra/CAPE/network/threat-intel sidecars in
    ``tests/unit/agents/test_subprocess_env.py``: a raw ``os.environ.copy()``
    would hand an LLM or threat-intel credential to any tool server a user
    configures, including one nobody at Maljan wrote.
    """
    from maljan.agents import mcp_client

    monkeypatch.setenv("OPENAI_API_KEY", "sk-not-for-the-sidecar")
    recorder = MagicMock()
    monkeypatch.setattr("mcp.StdioServerParameters", recorder)
    monkeypatch.setattr(mcp_client, "MCPLangChainToolkit", _toolkit_factory())

    provider = GenericMCPStaticProvider.from_settings(_cfg())
    provider.open(StaticJobContext())

    assert recorder.called, "StdioServerParameters was never constructed"
    env = recorder.call_args.kwargs["env"]
    assert not any(k.endswith("_API_KEY") for k in env), f"an API key reached the sidecar: {env}"
    assert env.get("PYTHONIOENCODING") == "utf-8"


def test_http_transport_builds_the_toolkit_with_the_configured_url(monkeypatch):
    from maljan.agents import mcp_client

    factory = _toolkit_factory()
    monkeypatch.setattr(mcp_client, "MCPLangChainToolkit", factory)

    provider = GenericMCPStaticProvider.from_settings(
        _cfg(transport="http", url="http://mcp.example:9999", auth_token="tok")
    )
    provider.open(StaticJobContext())

    assert factory.called
    kwargs = factory.call_args.kwargs
    assert kwargs["transport"] == "http"
    assert kwargs["http_url"] == "http://mcp.example:9999"
    assert kwargs["http_headers"] == {"Authorization": "Bearer tok"}


def test_the_http_bearer_header_carries_the_real_token_not_its_mask(monkeypatch):
    """Regression: ``auth_token`` is a ``SecretStr``; ``f"...{token}"`` on the
    field itself (rather than ``.get_secret_value()``) renders as the fixed
    ``**********`` mask, so the sidecar would see a header it can never
    accept. Built directly from ``MCPServerConfig`` — not ``from_settings`` —
    because ``static.generic`` is only a reference to an ``mcp.servers`` key
    until Task 5 resolves it, and every ``from_settings``-based test in this
    module is red for that unrelated reason.
    """
    import secrets

    from maljan.agents import mcp_client

    token = secrets.token_hex(16)
    factory = _toolkit_factory()
    monkeypatch.setattr(mcp_client, "MCPLangChainToolkit", factory)

    cfg = MCPServerConfig(
        enabled=True,
        transport="http",
        url="http://mcp.example:9999",
        auth_token=token,
    )
    provider = GenericMCPStaticProvider(cfg, label="Test MCP")
    provider.open(StaticJobContext())

    assert factory.called
    headers = factory.call_args.kwargs["http_headers"]
    assert headers == {"Authorization": f"Bearer {token}"}
    assert "*" not in headers["Authorization"]


def test_prompt_fragment_defaults_to_a_generated_paragraph_naming_the_label():
    provider = GenericMCPStaticProvider(_cfg().static.generic, label="Test MCP")
    fragment = provider.prompt_fragment()
    assert "Test MCP" in fragment
    assert "cite a concrete artifact" in fragment


def test_prompt_fragment_text_overrides_the_generated_paragraph():
    provider = GenericMCPStaticProvider(
        _cfg().static.generic, prompt_fragment_text="Use the custom tool exactly as documented."
    )
    assert provider.prompt_fragment() == "Use the custom tool exactly as documented."


# ---------------------------------------------------------------------------
# Task 13's carried finding: close()/_close_toolkit() and open()'s different-job
# reattach branch had no direct test, only the Ghidra equivalents. A fake
# toolkit stands in so these never spawn a real subprocess.
# ---------------------------------------------------------------------------


def _fake_toolkit_class(closed: list[int], tool_names: tuple[str, ...] = ("keep",)):
    class _FakeToolkit:
        def __init__(self, *args, **kwargs):
            pass

        async def initialize(self) -> None:
            return None

        def get_tools(self):
            return [_T(n) for n in tool_names]

        async def aclose(self) -> None:
            closed.append(1)

    return _FakeToolkit


def test_opening_the_same_job_twice_is_a_no_op(monkeypatch):
    from maljan.agents import mcp_client

    constructions: list[int] = []
    closed: list[int] = []

    class _FakeToolkit:
        def __init__(self, *args, **kwargs):
            constructions.append(1)

        async def initialize(self) -> None:
            return None

        def get_tools(self):
            return [_T("keep")]

        async def aclose(self) -> None:
            closed.append(1)

    monkeypatch.setattr(mcp_client, "MCPLangChainToolkit", _FakeToolkit)

    provider = GenericMCPStaticProvider.from_settings(_cfg())
    job_1 = StaticJobContext(mirror_sample_path="/data/samples/.work/abc.exe")
    job_2 = StaticJobContext(mirror_sample_path="/data/samples/.work/abc.exe")
    assert job_1 == job_2 and job_1 is not job_2

    provider.open(job_1)
    toolkit_after_first_open = provider._toolkit
    provider.open(job_2)

    assert len(constructions) == 1, "an equal job must not rebuild the toolkit"
    assert closed == [], "a same-job repeat call must not close anything"
    assert provider._toolkit is toolkit_after_first_open


def test_opening_a_different_job_closes_the_first_toolkit_before_attaching_the_new_one(
    monkeypatch,
):
    from maljan.agents import mcp_client

    constructions: list[int] = []
    closed: list[int] = []
    _Base = _fake_toolkit_class(closed, ("keep",))

    class _CountingToolkit(_Base):
        def __init__(self, *args, **kwargs):
            constructions.append(1)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(mcp_client, "MCPLangChainToolkit", _CountingToolkit)

    provider = GenericMCPStaticProvider.from_settings(_cfg())
    provider.open(StaticJobContext(mirror_sample_path="/data/samples/.work/a.exe"))
    first_toolkit = provider._toolkit

    provider.open(StaticJobContext(mirror_sample_path="/data/samples/.work/b.exe"))

    assert len(constructions) == 2, "a genuinely different job must rebuild the toolkit"
    assert closed == [1], "the stale toolkit must be closed before the new one replaces it"
    assert provider._toolkit is not first_toolkit


def test_close_tears_down_the_toolkit_and_is_idempotent(monkeypatch):
    from maljan.agents import mcp_client

    closed: list[int] = []
    monkeypatch.setattr(mcp_client, "MCPLangChainToolkit", _fake_toolkit_class(closed, ("keep",)))

    provider = GenericMCPStaticProvider.from_settings(_cfg())
    provider.open(StaticJobContext())
    assert provider._toolkit is not None

    provider.close()
    assert provider._toolkit is None
    assert provider.get_tools() == []
    # M8 (final review): _all_tools was cleared but the curated/selected
    # subset in provider.tools was not, so a closed provider still
    # advertised tool objects whose transport was already gone.
    assert provider.tools == []
    assert closed == [1]

    provider.close()  # idempotent: nothing to tear down, no error, no second close call
    assert closed == [1]
