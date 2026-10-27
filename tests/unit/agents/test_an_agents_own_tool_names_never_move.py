"""An agent's own tool names never move for a server an operator binds to it.

A server bound to a role by ``MCPServerConfig.agents`` is an addition to the
agents of that role. Where one of its tool names is taken by the agent's own
tools — its static provider's or sandbox's, a built-in server's, a server the
agent's definition names — it is the addition's tool that is offered as
``<server>__<tool>``: the bare name stays with the tool the agent's prompt and
workflow text were written against, and both copies stay callable, each under
its own name. The real registry runs here; only the transports are stubbed.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from langchain_core.tools import StructuredTool

from maljan.core.config import MCPServerConfig, Settings
from maljan.providers.servers import ServerHandle

# What each server offers, by key; a tool answers with its owner's name.
OFFERS: dict[str, list[str]] = {
    "analysis": ["pe_info", "strings", "identify_file"],
    "knowledge": ["attck_lookup"],
    "network": ["extract_dns"],
    "kit": ["pe_info", "strings", "attck_lookup", "extract_dns", "decompile_function", "kit_only"],
}


def _tool(name: str, owner: str) -> StructuredTool:
    def _answer(**_kw: Any) -> str:
        return owner

    return StructuredTool.from_function(func=_answer, name=name, description=f"{owner} {name}")


@pytest.fixture(autouse=True)
def _served(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _aopen(self: ServerHandle, job_id: str, **context: Any) -> None:
        return None

    monkeypatch.setattr(ServerHandle, "open", lambda self, job_id, **context: None)
    monkeypatch.setattr(ServerHandle, "aopen", _aopen)
    monkeypatch.setattr(
        ServerHandle, "tools", lambda self: [_tool(n, self.name) for n in OFFERS.get(self.name, [])]
    )
    monkeypatch.setattr(ServerHandle, "withheld_reasons", lambda self: [])


def _container(kit_roles: list[str]) -> Any:
    from maljan.core.container import ServiceContainer

    cfg = Settings(_env_file=None)
    cfg.mcp.servers["kit"] = MCPServerConfig(enabled=True, command="kit", agents=kit_roles)
    return ServiceContainer(config=cfg, mock=True)


def _wired(container: Any, name: str) -> Any:
    from unittest.mock import MagicMock

    agent = container.agent_registry.create(name, MagicMock())
    agent._container = container
    return agent


def _answers(tools: list[Any]) -> dict[str, str]:
    """Each offered name and the server whose tool runs under it."""
    return {t.name: str(t.invoke({})) for t in tools}


class _Provider:
    """A static provider whose own tools include a decompiler."""

    id = "acme"
    server_name = ""

    class capabilities:  # noqa: N801 — a stand-in for the frozen dataclass
        provides_tools = True
        degrade_on_failure = False

    def open(self, job: Any) -> None:
        return None

    def get_tools(self) -> list[Any]:
        return [_tool("decompile_function", "provider"), _tool("list_functions", "provider")]


class TestABuiltInRole:
    def test_the_definition_s_servers_keep_their_names(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent = _wired(_container(["static"]), "static")
        monkeypatch.setattr(type(agent), "_provider", lambda self: _Provider())
        agent._initialize_mcp_client()
        answers = _answers(agent.tools)
        for name in ("pe_info", "strings"):
            assert answers[name] == "analysis"
            assert answers[f"kit__{name}"] == "kit"
        assert answers["attck_lookup"] == "knowledge"
        assert answers["kit__attck_lookup"] == "kit"
        assert answers["kit_only"] == "kit"
        assert "analysis__pe_info" not in answers

    def test_the_provider_s_decompiler_is_never_shadowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent = _wired(_container(["static"]), "static")
        monkeypatch.setattr(type(agent), "_provider", lambda self: _Provider())
        agent._initialize_mcp_client()
        names = [t.name for t in agent.tools]
        assert len(names) == len(set(names)), names
        answers = _answers(agent.tools)
        assert answers["decompile_function"] == "provider"
        assert answers["kit__decompile_function"] == "kit"
        assert answers["list_functions"] == "provider"

    def test_a_built_in_server_bound_to_the_role_keeps_its_names(self) -> None:
        agent = _wired(_container(["network"]), "network")
        agent._initialize_mcp_client()
        answers = _answers(agent.tools)
        assert answers["extract_dns"] == "network"
        assert answers["kit__extract_dns"] == "kit"

    def test_without_a_collision_nothing_is_renamed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(OFFERS, "kit", ["kit_only"])
        agent = _wired(_container(["static"]), "static")
        monkeypatch.setattr(type(agent), "_provider", lambda self: _Provider())
        agent._initialize_mcp_client()
        names = [t.name for t in agent.tools]
        assert not any("__" in name for name in names), names
        assert "kit_only" in names

    @pytest.mark.asyncio
    async def test_the_judge_s_own_servers_keep_their_names(self) -> None:
        from unittest.mock import MagicMock

        from maljan.agents.judge_agent import JudgeAgent

        container = _container(["judge"])
        judge = JudgeAgent(llm=MagicMock(), config=container.config)
        judge._container = container
        await judge._initialize_mcp_client()
        # The servers' tools; the judge's in-process sandbox and ask tools
        # (T-415d) take arguments of their own and claim no server's name.
        wanted = ("attck_lookup", "kit__attck_lookup")
        answers = {t.name: str(await t.ainvoke({})) for t in judge.tools if t.name in wanted}
        assert answers["attck_lookup"] == "knowledge"
        assert answers["kit__attck_lookup"] == "kit"


class TestAGenericAgent:
    def _settings(self) -> Settings:
        cfg = Settings(
            _env_file=None,
            agents={
                "definitions": {
                    "x": {
                        "role": "generic",
                        "prompt": "p",
                        "tools": [{"kind": "mcp", "server": "analysis"}],
                    }
                },
                "profiles": {"one": {"analysts": ["x"]}},
                "profile": "one",
            },
        )
        cfg.mcp.servers["kit"] = MCPServerConfig(enabled=True, command="kit", agents=["x"])
        return cfg

    def _container(self) -> Any:
        from maljan.core.container import ServiceContainer

        return ServiceContainer(config=self._settings(), mock=True)

    def test_the_resolved_definition_keeps_its_names(self) -> None:
        from maljan.agents.composition import resolve_agent

        resolved = resolve_agent("x", self._container())
        answers = _answers(list(resolved.tools))
        assert answers["pe_info"] == "analysis"
        assert answers["kit__pe_info"] == "kit"

    def test_the_awaited_resolution_does_the_same(self) -> None:
        from maljan.agents.composition import aresolve_agent

        resolved = asyncio.run(aresolve_agent("x", self._container()))
        names = {t.name: (t.metadata or {}).get("maljan_server") for t in resolved.tools}
        assert names["pe_info"] == "analysis"
        assert names["kit__pe_info"] == "kit"


def test_many_colliding_tools_are_claimed_in_linear_time(monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    from maljan.providers.servers import ServerRegistry

    def _timed(n: int) -> float:
        names = [f"t{i}" for i in range(n)]
        own = [_tool(name, "analysis") for name in names]
        added = [_tool(name, "kit") for name in names]
        registry = ServerRegistry(Settings(_env_file=None))
        seen: dict[str, str] = {}
        tools: list[Any] = []
        start = time.perf_counter()
        registry.merge_tools("analysis", own, tools, seen)
        registry.merge_tools("kit", added, tools, seen)
        took = time.perf_counter() - start
        assert sum(1 for t in tools if t.name.startswith("kit__")) == n
        return took

    small, large = _timed(300), _timed(3000)
    assert large < max(small * 30, 0.5)
