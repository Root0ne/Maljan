"""The sink-reachability pre-pass is the agent's own provider's, asked through its interface.

It used to ask the deployment's global ``static.provider``, and later the
agent's provider id against the string "ghidra". A team that puts one static
analyst on r2 and another on Ghidra, or a reverser given Ghidra's tools in a
deployment whose global provider is something else, got the pre-pass on the
wrong agents. The analysts now ask the agent's own provider object
(``providers.base.prepare_sample``): it opens the sample where it must and
gives a call graph where it can, and an agent whose provider gives none gets
no hint.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from pydantic import SecretStr

from maljan.agents.composition import ResolvedAgent
from maljan.agents.configurable_analyst import ConfigurableAnalyst
from maljan.agents.prompt_fragments import PROVIDER_FAMILY, stamp_source
from maljan.agents.static_analyst import StaticAnalyst


class _Resp:
    def __init__(self, text: str) -> None:
        self.text = text
        self.status_code = 200

    def raise_for_status(self) -> None:
        return None


class _Client:
    """Stands in for ``httpx.Client`` and records the Ghidra endpoints called."""

    def __init__(self) -> None:
        self.paths: list[str] = []
        self.timeouts: list[Any] = []

    def __call__(self, **kwargs: Any) -> _Client:
        self.timeouts.append(kwargs.get("timeout"))
        return self

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(self, url: str, json: Any = None, params: Any = None, **_kw: Any) -> _Resp:  # noqa: A002
        self.paths.append(url.rsplit("/", 1)[-1])
        if url.endswith("/load_program"):
            return _Resp('{"success": true, "program": "x.exe"}')
        return _Resp("{}")

    def get(self, url: str, params: Any = None) -> _Resp:
        self.paths.append(url.rsplit("/", 1)[-1])
        graph = {
            "nodes": [
                {"name": "entry", "address": "0x1000"},
                {"name": "CreateProcessA", "address": "EXTERNAL:1"},
            ],
            "edges": [{"from": "entry", "to": "CreateProcessA"}],
        }
        return _Resp(json.dumps(graph))


def _settings(global_provider: str) -> Any:
    class _G:
        enabled = True
        transport = "http"
        url = "http://ghidra.invalid"
        auth_token = SecretStr("")
        sample_open = None

    class _P:
        use_sink_reachability = True
        sink_reachability_max_funcs = 12

    class _S:
        class static:  # noqa: N801
            provider = global_provider
            ghidra = _G()

        preprocessing = _P()

    return _S()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> _Client:
    fake = _Client()
    monkeypatch.setattr("httpx.Client", fake)
    return fake


def _ghidra(settings: Any) -> Any:
    from maljan.providers.static.ghidra import GhidraStaticProvider

    return GhidraStaticProvider(settings.static.ghidra, settings.preprocessing, None)


def _shipped(provider_id: str) -> Any:
    from maljan.core.config import Settings
    from maljan.providers.registry import static_provider_class

    return static_provider_class(provider_id).from_settings(Settings())


def _static_analyst(provider: Any) -> Any:
    analyst = StaticAnalyst.__new__(StaticAnalyst)
    analyst.logger = logging.getLogger("test.sink_prepass")
    analyst._resolved = None
    analyst._provider = lambda: provider
    return analyst


class TestTheStaticRole:
    def test_an_analyst_on_ghidra_opens_and_reads_the_call_graph(self, client: _Client) -> None:
        provider = _ghidra(_settings("r2"))
        _static_analyst(provider)._compute_sink_priority_hint("/data/samples/x.exe")
        assert client.paths[0] == "load_program", client.paths
        assert client.paths[-1] == "get_full_call_graph", client.paths

    def test_an_analyst_on_r2_never_calls_ghidra(self, client: _Client) -> None:
        assert _static_analyst(_shipped("r2"))._compute_sink_priority_hint("/s/x.exe") == ""
        assert client.paths == []

    def test_a_switched_off_ghidra_is_not_called(self, client: _Client) -> None:
        settings = _settings("ghidra")
        settings.static.ghidra.enabled = False
        provider = _ghidra(settings)
        assert _static_analyst(provider)._compute_sink_priority_hint("/data/samples/x.exe") == ""
        assert client.paths == []

    def test_the_pre_pass_switched_off_opens_and_reads_no_graph(self, client: _Client) -> None:
        settings = _settings("ghidra")
        settings.preprocessing.use_sink_reachability = False
        provider = _ghidra(settings)
        assert _static_analyst(provider)._compute_sink_priority_hint("/data/samples/x.exe") == ""
        assert "load_program" in client.paths
        assert "get_full_call_graph" not in client.paths


class _GraphProvider:
    """A provider with a call graph and nothing else, as the analysts ask it."""

    priority_follow_up = ""

    def __init__(self) -> None:
        self.opened: list[str] = []

    def open_sample(self, path: str | None = None) -> bool:
        self.opened.append(str(path))
        return True

    def priority_functions(self, path: str) -> Any:
        from maljan.analysis.sink_reachability import CallGraph, rank_suspicious_functions

        graph = CallGraph.of_edges([("entry", "CreateProcessA")], {"entry": "0x1000"})
        return rank_suspicious_functions(graph)


class _Container:
    def __init__(self, provider: Any) -> None:
        self.provider = provider
        self.config = None

    def get_static_provider(self, provider_id: str | None = None) -> Any:
        return self.provider


def _tool(name: str) -> StructuredTool:
    return StructuredTool.from_function(func=lambda: name, name=name, description=name)


def _generic(provider: Any, *, provider_tools: bool) -> ConfigurableAnalyst:
    tools = stamp_source([_tool("decompile_function")], PROVIDER_FAMILY) if provider_tools else []
    resolved = ResolvedAgent(
        key="reverser_x",
        role="generic",
        prompt="reverse it",
        tools=tools,
        static_provider_id="acme",
        llm=None,
    )
    analyst = ConfigurableAnalyst("reverser_x", resolved, llm=None)  # type: ignore[arg-type]
    analyst._analysis_file_path = "/data/samples/.work/x.exe"
    analyst._container = _Container(provider)
    return analyst


HEAD_CHUNK = json.dumps({"analysis_file_path": "/data/samples/.work/x.exe"})


class TestAGenericAgentOnAProvider:
    def test_the_reverser_is_handed_its_provider_s_hint(self) -> None:
        provider = _GraphProvider()
        analyst = _generic(provider, provider_tools=True)

        hint = analyst._priority_hint(HEAD_CHUNK)
        assert hint.startswith("PRIORITY FUNCTIONS")
        assert "- entry (@ 0x1000) [exec] -> reaches: createprocessa (1 hop)" in hint
        assert provider.opened == ["/data/samples/.work/x.exe"]

    def test_the_hint_reaches_the_human_turn(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyst = _generic(_GraphProvider(), provider_tools=True)
        sent: list[Any] = []
        monkeypatch.setattr(analyst, "execute_tool_loop", lambda messages: sent.append(messages))

        analyst.analyze_isr(HEAD_CHUNK)

        human = sent[0][1][1]
        assert "PRIORITY FUNCTIONS" in human
        assert human.index("PRIORITY FUNCTIONS") < human.index("Sample path")

    def test_a_reverser_on_ghidra_reads_ghidra_s_graph(self, client: _Client) -> None:
        analyst = _generic(_ghidra(_settings("r2")), provider_tools=True)
        analyst._priority_hint(HEAD_CHUNK)
        assert client.paths[0] == "load_program", client.paths
        assert client.paths[-1] == "get_full_call_graph", client.paths

    @pytest.mark.parametrize(
        ("provider", "provider_tools", "data"),
        [
            ("r2", True, HEAD_CHUNK),
            ("graph", False, HEAD_CHUNK),
            ("graph", True, "a later chunk, with no path in it"),
        ],
        ids=["a-provider-with-no-call-graph", "provider-tools-not-attached", "not-the-head-chunk"],
    )
    def test_no_hint_otherwise(
        self, provider: str, provider_tools: bool, data: str, client: _Client
    ) -> None:
        held = _shipped("r2") if provider == "r2" else _GraphProvider()
        analyst = _generic(held, provider_tools=provider_tools)
        assert analyst._priority_hint(data) == ""
        assert client.paths == []


def test_the_pre_pass_waits_what_one_tool_call_may_take(
    client: _Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No fixed request timeout: the deployment's call budget, or none."""
    from maljan.providers.base import prepare_sample

    settings = _settings("ghidra")
    monkeypatch.setattr("maljan.core.config.get_settings", lambda: settings)
    prepare_sample(_ghidra(settings), "/data/samples/x.exe")

    class _Breaker:
        call_timeout_seconds = 900.0

    class _Mcp:
        breaker = _Breaker()

    settings.mcp = _Mcp()
    prepare_sample(_ghidra(settings), "/data/samples/x.exe")
    assert client.timeouts == [None, None, 900.0, 900.0]
