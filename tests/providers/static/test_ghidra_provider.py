"""The Ghidra provider is the static analyst's Ghidra code, moved."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from maljan.core.config import Settings
from maljan.providers.base import StaticJobContext
from maljan.providers.static.ghidra import GHIDRA_ALLOWED_TOOLS, GhidraStaticProvider

ROOT = Path(__file__).resolve().parents[3]


class _Tool:
    def __init__(self, name: str, description: str = "") -> None:
        self.name, self.description = name, description


def _provider(**over):
    cfg = Settings(_env_file=None)
    cfg.static.ghidra.enabled = True
    cfg.static.ghidra.transport = "http"
    cfg.static.ghidra.url = "http://ghidra.example:8089"
    for k, v in over.items():
        setattr(cfg.static.ghidra, k, v)
    return GhidraStaticProvider.from_settings(cfg)


def test_the_allow_list_is_the_golden_one():
    golden = json.loads(
        (ROOT / "tests" / "fixtures" / "golden" / "allowlists.json").read_text(encoding="utf-8")
    )
    assert sorted(GHIDRA_ALLOWED_TOOLS) == golden["ghidra_allowed_tools"]


def test_capabilities_track_the_transport():
    http = _provider().capabilities
    assert http.provides_tools and http.supports_tool_curation and http.needs_sample_mirror
    assert http.provides_function_hashes is True
    assert http.degrade_on_failure is False, "Ghidra is the static evidence; it fails loudly"
    stdio = _provider(transport="stdio").capabilities
    assert stdio.provides_function_hashes is False, "the hash pre-pass speaks the REST API"


def test_curated_mode_keeps_exactly_the_allow_list():
    provider = _provider(tool_selection="curated")
    tools = [_Tool(n) for n in sorted(GHIDRA_ALLOWED_TOOLS)] + [_Tool("unrelated_tool")]
    kept = {t.name for t in provider.select_tools(tools)}
    assert kept == set(GHIDRA_ALLOWED_TOOLS)


def test_all_mode_keeps_everything():
    provider = _provider(tool_selection="all")
    tools = [_Tool(f"t{i}") for i in range(50)]
    assert len(provider.select_tools(tools)) == 50


def test_a_failed_attach_raises_instead_of_degrading():
    """Ghidra IS the static evidence; a broken attach must not be swallowed.

    ``ghidra.example`` is an RFC 2606 domain guaranteed to never resolve, so
    this never risks a real network call — it only pins that ``open()`` lets
    the connection failure propagate, exactly like the pre-provider
    ``_initialize_mcp_client`` it was transplanted from. A provider that
    degraded quietly here would hand the ReAct loop zero tools and let the
    LLM write a confident-looking report grounded in nothing.
    """
    provider = _provider()
    with pytest.raises(httpx.HTTPError):
        provider.open(StaticJobContext())


def test_dynamic_mode_uses_the_categories_from_the_job():
    provider = _provider(tool_selection="dynamic")
    # The attach itself fails (unreachable host, see the test above) but
    # ``self._job`` is assigned before the attach is attempted, so it is
    # still set by the time the exception propagates — exercise that here
    # rather than reaching into the private attribute directly.
    with pytest.raises(httpx.HTTPError):
        provider.open(StaticJobContext(capability_categories=frozenset({"crypto"})))
    tools = [_Tool(f"filler_{i}") for i in range(80)] + [
        _Tool("detect_crypto_constants", "find AES and RC4 constants")
    ]
    names = {t.name for t in provider.select_tools(tools)}
    assert "detect_crypto_constants" in names
    assert len(names) <= 40


def test_use_all_tools_still_forces_all():
    provider = _provider(tool_selection="curated", use_all_tools=True)
    assert len(provider.select_tools([_Tool(f"t{i}") for i in range(30)])) == 30


def test_load_program_is_pinned_to_the_mirror_path():
    import asyncio

    from langchain_core.tools import StructuredTool
    from pydantic import create_model

    seen: dict[str, object] = {}

    async def inner(**kwargs):
        seen.update(kwargs)
        return "loaded"

    tool = StructuredTool.from_function(
        func=None,
        coroutine=inner,
        name="load_program",
        description="load",
        args_schema=create_model("Args", file=(str, ...)),
    )
    provider = _provider()
    # As above: the attach fails against the unreachable host, but ``_job``
    # is set first, so the pin is still exercised past the raised error.
    with pytest.raises(httpx.HTTPError):
        provider.open(StaticJobContext(mirror_sample_path="/data/samples/.work/abc.exe"))
    pinned = provider.select_tools([tool])[0]
    asyncio.run(pinned.coroutine(file="/home/user/invented.exe"))
    assert seen["file"] == "/data/samples/.work/abc.exe"


def test_mirror_spec_is_todays_work_directory():
    spec = _provider().mirror_spec()
    assert spec.work_subdir == ".work"
    assert spec.container_prefix.endswith("/samples") or spec.container_prefix == "/data/samples"


def test_a_disabled_server_yields_no_tools_and_does_not_raise():
    cfg = Settings(_env_file=None)
    cfg.static.ghidra.enabled = False
    provider = GhidraStaticProvider.from_settings(cfg)
    provider.open(StaticJobContext())
    assert provider.get_tools() == []


def test_the_analyst_asks_the_provider_for_tools(monkeypatch):
    """``_initialize_mcp_client`` resolves a provider and does nothing else."""
    from unittest.mock import MagicMock

    from maljan.agents.static_analyst import StaticAnalyst
    from maljan.providers.base import StaticCapabilities

    calls: list[str] = []

    class _Provider:
        id = "ghidra"
        capabilities = StaticCapabilities(provides_tools=True, supports_tool_curation=True)

        def open(self, job):
            calls.append("open")

        def get_tools(self):
            calls.append("get_tools")
            return [_Tool("load_program"), _Tool("list_imports")]

        def select_tools(self, tools, categories=None):
            calls.append("select_tools")
            return list(tools)

    analyst = StaticAnalyst(llm=MagicMock(), name="static")
    container = MagicMock()
    container.get_static_provider.return_value = _Provider()
    container.get_server_registry.return_value = None
    analyst._container = container
    analyst._initialize_mcp_client()
    assert calls == ["open", "get_tools", "select_tools"]
    assert [t.name for t in analyst.tools] == ["load_program", "list_imports"]


def test_a_provider_without_tools_leaves_the_analyst_toolless():
    from unittest.mock import MagicMock

    from maljan.agents.static_analyst import StaticAnalyst
    from maljan.providers.base import StaticCapabilities

    class _Evidence:
        id = "capa_yara"
        capabilities = StaticCapabilities(provides_evidence=True, degrade_on_failure=True)

        def open(self, job):
            raise AssertionError("open must not be called for a toolless provider")

    analyst = StaticAnalyst(llm=MagicMock(), name="static")
    container = MagicMock()
    container.get_static_provider.return_value = _Evidence()
    container.get_server_registry.return_value = None
    analyst._container = container
    analyst._initialize_mcp_client()
    assert analyst.tools == []


def test_static_still_fails_loudly_and_a_degrading_provider_does_not(monkeypatch):
    from unittest.mock import MagicMock

    from maljan.agents.static_analyst import StaticAnalyst
    from maljan.providers.base import StaticCapabilities

    analyst = StaticAnalyst(llm=MagicMock(), name="static")

    def boom():
        raise RuntimeError("ghidra is unreachable")

    monkeypatch.setattr(analyst, "_initialize_mcp_client", boom)
    monkeypatch.setattr(
        analyst, "_static_capabilities", lambda: StaticCapabilities(degrade_on_failure=False)
    )
    with pytest.raises(RuntimeError):
        analyst._try_initialize_mcp()

    monkeypatch.setattr(
        analyst, "_static_capabilities", lambda: StaticCapabilities(degrade_on_failure=True)
    )
    assert analyst._try_initialize_mcp() is False


def test_analyze_isr_degrades_for_a_degrading_provider_but_raises_for_ghidra():
    """I2 regression: the entry points must go through ``_try_initialize_mcp``.

    Both ``analyze`` and ``analyze_isr`` used to call the bare
    ``_initialize_mcp_client``, so ``degrade_on_failure`` was dead code on the
    static path: an unreachable r2/generic_mcp server aborted the whole
    analyst instead of the degraded-but-completed run its own capabilities
    promise. A non-existent-looking filename short-circuits ``analyze_isr``
    to an empty ISR right after the MCP attach, so this exercises the real
    entry point without needing a live LLM.
    """
    from unittest.mock import MagicMock

    from maljan.agents.static_analyst import StaticAnalyst
    from maljan.providers.base import StaticCapabilities

    missing_sample = "/nonexistent/path/does-not-exist.exe"

    class _DegradingProvider:
        id = "r2"
        capabilities = StaticCapabilities(provides_tools=True, degrade_on_failure=True)

        def open(self, job):
            raise RuntimeError("r2mcp is unreachable")

    class _LoudProvider:
        id = "ghidra"
        capabilities = StaticCapabilities(provides_tools=True, degrade_on_failure=False)

        def open(self, job):
            raise RuntimeError("ghidra is unreachable")

    degrading_analyst = StaticAnalyst(llm=MagicMock(), name="static")
    degrading_container = MagicMock()
    degrading_container.get_static_provider.return_value = _DegradingProvider()
    degrading_analyst._container = degrading_container
    isr = degrading_analyst.analyze_isr(missing_sample)
    assert isr.claims == []

    loud_analyst = StaticAnalyst(llm=MagicMock(), name="static")
    loud_container = MagicMock()
    loud_container.get_static_provider.return_value = _LoudProvider()
    loud_analyst._container = loud_container
    with pytest.raises(RuntimeError):
        loud_analyst.analyze_isr(missing_sample)


def test_open_is_idempotent_for_a_repeat_call_with_an_equal_job(monkeypatch):
    """Regression for the multi-chunk leak: chunk 2 must not rebuild chunk 1's client.

    ``safe_analyze_isr_chunked`` calls ``analyze_isr`` once per chunk on one
    cached agent, and each call derives a *fresh but equal* ``StaticJobContext``
    (same sample, same categories) — never the literal same object. Passing two
    separate, merely-``==``-equal instances is what actually exercises the
    value comparison ``open()`` relies on, rather than trivially passing an
    identity check.
    """
    from maljan.agents import ghidra_http_client

    constructions: list[int] = []

    class _FakeHTTPClient:
        def __init__(self, **kwargs):
            constructions.append(1)

        async def initialize(self) -> None:
            return None

        def get_tools(self):
            return [_Tool("load_program"), _Tool("list_imports")]

    monkeypatch.setattr(ghidra_http_client, "GhidraHTTPClient", _FakeHTTPClient)

    provider = _provider()
    job_1 = StaticJobContext(mirror_sample_path="/data/samples/.work/abc.exe")
    job_2 = StaticJobContext(mirror_sample_path="/data/samples/.work/abc.exe")
    assert job_1 == job_2 and job_1 is not job_2, "the test must exercise value equality"

    provider.open(job_1)
    toolkit_after_first_open = provider._toolkit
    tools_after_first_open = provider.get_tools()

    provider.open(job_2)

    assert len(constructions) == 1, "a same-job repeat call must not rebuild the client"
    assert provider._toolkit is toolkit_after_first_open
    assert provider.get_tools() == tools_after_first_open


def test_open_for_a_different_job_closes_the_stale_toolkit_before_reattaching(monkeypatch):
    from maljan.agents import ghidra_http_client

    constructions: list[int] = []
    closed: list[int] = []

    class _FakeHTTPClient:
        def __init__(self, **kwargs):
            constructions.append(1)

        async def initialize(self) -> None:
            return None

        def get_tools(self):
            return [_Tool("load_program")]

        async def aclose(self) -> None:
            closed.append(1)

    monkeypatch.setattr(ghidra_http_client, "GhidraHTTPClient", _FakeHTTPClient)

    provider = _provider()
    provider.open(StaticJobContext(mirror_sample_path="/data/samples/.work/a.exe"))
    first_toolkit = provider._toolkit

    provider.open(StaticJobContext(mirror_sample_path="/data/samples/.work/b.exe"))

    assert len(constructions) == 2, "a genuinely different job must rebuild"
    assert closed == [1], "the stale toolkit must be closed before the new one replaces it"
    assert provider._toolkit is not first_toolkit
