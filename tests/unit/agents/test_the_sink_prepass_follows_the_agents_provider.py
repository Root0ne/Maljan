"""The sink-reachability pre-pass runs for every agent on Ghidra, and for no other.

It used to ask the deployment's global ``static.provider``. A team that puts
one static analyst on r2 and another on Ghidra, or a reverser given Ghidra's
tools in a deployment whose global provider is something else, got the
pre-pass on the wrong agents: none of the Ghidra ones, and the Ghidra REST
calls against an agent that has no Ghidra at all. The question is the agent's
own provider.
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

    def post(self, url: str, json: Any = None, params: Any = None) -> _Resp:  # noqa: A002
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


def _static_analyst(provider_id: str | None) -> Any:
    analyst = StaticAnalyst.__new__(StaticAnalyst)
    analyst.logger = logging.getLogger("test.sink_prepass")
    analyst._resolved = (
        ResolvedAgent(
            key="static_x",
            role="static",
            prompt="p",
            tools=[],
            static_provider_id=provider_id,
            llm=None,
        )
        if provider_id
        else None
    )
    return analyst


class TestTheStaticRole:
    def test_a_clone_on_ghidra_runs_it_when_the_global_provider_is_r2(
        self, client: _Client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("maljan.core.config.get_settings", lambda: _settings("r2"))
        _static_analyst("ghidra")._compute_sink_priority_hint("/data/samples/x.exe")
        assert client.paths[0] == "load_program", client.paths

    def test_a_clone_on_r2_never_calls_ghidra_when_the_global_provider_is_ghidra(
        self, client: _Client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("maljan.core.config.get_settings", lambda: _settings("ghidra"))
        assert _static_analyst("r2")._compute_sink_priority_hint("/data/samples/x.exe") == ""
        assert client.paths == []

    def test_an_unresolved_analyst_still_reads_the_global_provider(
        self, client: _Client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("maljan.core.config.get_settings", lambda: _settings("ghidra"))
        _static_analyst(None)._compute_sink_priority_hint("/data/samples/x.exe")
        assert client.paths[0] == "load_program", client.paths

    def test_a_switched_off_ghidra_is_not_called(
        self, client: _Client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = _settings("ghidra")
        settings.static.ghidra.enabled = False
        monkeypatch.setattr("maljan.core.config.get_settings", lambda: settings)
        assert _static_analyst("ghidra")._compute_sink_priority_hint("/data/samples/x.exe") == ""
        assert client.paths == []


def _tool(name: str) -> StructuredTool:
    return StructuredTool.from_function(func=lambda: name, name=name, description=name)


def _generic(provider_id: str, *, provider_tools: bool) -> ConfigurableAnalyst:
    tools = stamp_source([_tool("decompile_function")], PROVIDER_FAMILY) if provider_tools else []
    resolved = ResolvedAgent(
        key="reverser_ghidra",
        role="generic",
        prompt="reverse it",
        tools=tools,
        static_provider_id=provider_id,
        llm=None,
    )
    analyst = ConfigurableAnalyst("reverser_ghidra", resolved, llm=None)  # type: ignore[arg-type]
    analyst._analysis_file_path = "/data/samples/.work/x.exe"
    return analyst


HEAD_CHUNK = json.dumps({"analysis_file_path": "/data/samples/.work/x.exe"})


class TestAGenericAgentOnGhidra:
    def test_the_reverser_on_ghidra_is_handed_the_hint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, Any] = {}

        def fake(cfg: Any, provider_id: str, path: str, log: Any = None, **_: Any) -> str:
            seen.update(provider=provider_id, path=path)
            return "PRIORITY FUNCTIONS: entry"

        monkeypatch.setattr("maljan.providers.static.ghidra.prepare_sample", fake)
        monkeypatch.setattr("maljan.core.config.get_settings", lambda: _settings("r2"))
        analyst = _generic("ghidra", provider_tools=True)

        assert analyst._priority_hint(HEAD_CHUNK) == "PRIORITY FUNCTIONS: entry\n"
        assert seen == {"provider": "ghidra", "path": "/data/samples/.work/x.exe"}

    def test_the_hint_reaches_the_human_turn(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "maljan.providers.static.ghidra.prepare_sample",
            lambda *a, **k: "PRIORITY FUNCTIONS: entry",
        )
        monkeypatch.setattr("maljan.core.config.get_settings", lambda: _settings("r2"))
        analyst = _generic("ghidra", provider_tools=True)
        sent: list[Any] = []
        monkeypatch.setattr(analyst, "execute_tool_loop", lambda messages: sent.append(messages))

        analyst.analyze_isr(HEAD_CHUNK)

        human = sent[0][1][1]
        assert "PRIORITY FUNCTIONS: entry" in human
        assert human.index("PRIORITY FUNCTIONS") < human.index("Sample path")

    @pytest.mark.parametrize(
        ("provider_id", "provider_tools", "data"),
        [
            ("r2", True, HEAD_CHUNK),
            ("ghidra", False, HEAD_CHUNK),
            ("ghidra", True, "a later chunk, with no path in it"),
        ],
        ids=["another-provider", "ghidra-tools-not-attached", "not-the-head-chunk"],
    )
    def test_no_hint_otherwise(
        self,
        provider_id: str,
        provider_tools: bool,
        data: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        called: list[bool] = []
        monkeypatch.setattr(
            "maljan.providers.static.ghidra.prepare_sample",
            lambda *a, **k: called.append(True) or "hint",
        )
        analyst = _generic(provider_id, provider_tools=provider_tools)
        assert analyst._priority_hint(data) == ""
        assert called == []


def test_the_pre_pass_waits_what_one_tool_call_may_take(
    client: _Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No fixed request timeout: the deployment's call budget, or none."""
    from maljan.providers.static.ghidra import prepare_sample

    settings = _settings("ghidra")
    prepare_sample(settings, "ghidra", "/data/samples/x.exe")

    class _Breaker:
        call_timeout_seconds = 900.0

    class _Mcp:
        breaker = _Breaker()

    settings.mcp = _Mcp()
    prepare_sample(settings, "ghidra", "/data/samples/x.exe")
    assert client.timeouts == [None, 900.0]
