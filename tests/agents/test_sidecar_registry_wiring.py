"""Neither sidecar is launched from a constant inside an agent any more."""

from __future__ import annotations

import inspect

import pytest

from maljan.agents import judge_agent, network_analyst


def test_no_agent_names_a_sidecar_script_any_more():
    for module in (network_analyst, judge_agent):
        source = inspect.getsource(module)
        assert "server.py" not in source, f"{module.__name__} still launches a server itself"
        assert "StdioServerParameters" not in source


def _wired(container, name: str):
    """An analyst with this container behind it, without building an LLM.

    ``container.get_agent`` needs a real model and refuses in mock mode; the
    only thing these tests need is the ``_container`` back-reference that
    ``BaseAnalyst._server_registry`` reads.
    """
    from unittest.mock import MagicMock

    agent = container.agent_registry.create(name, MagicMock())
    agent._container = container
    return agent


def test_the_network_analyst_takes_its_tools_from_the_registry(monkeypatch):
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    container = ServiceContainer(config=Settings(_env_file=None), mock=True)
    registry = container.get_server_registry()

    class _T:
        name = "extract_dns"

    monkeypatch.setattr(registry, "tools_for", lambda role, job_id, **kw: ([_T()], []))
    agent = _wired(container, "network")
    agent._initialize_mcp_client()
    assert [t.name for t in agent.tools] == ["extract_dns"]


@pytest.mark.asyncio
async def test_the_judge_takes_its_tools_from_the_registry(monkeypatch):
    from unittest.mock import MagicMock

    from maljan.agents.judge_agent import JudgeAgent
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    cfg = Settings(_env_file=None)
    container = ServiceContainer(config=cfg, mock=True)
    registry = container.get_server_registry()

    class _T:
        name = "check_ip_reputation"

    async def fake(role, job_id, **kw):
        assert role == "judge"
        return [_T()], []

    monkeypatch.setattr(registry, "atools_for", fake)
    judge = JudgeAgent(llm=MagicMock(), config=cfg)
    judge._container = container
    await judge._initialize_mcp_client()
    assert [t.name for t in judge.tools] == ["check_ip_reputation"]
    await judge.aclose()
    assert judge.tools == []
