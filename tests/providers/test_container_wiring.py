from __future__ import annotations

import pytest

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.loaders.sandbox_client import SandboxClient


def test_cape2_settings_select_the_cape2_provider():
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "cape2"
    container = ServiceContainer(config=cfg, mock=False)
    assert container.get_sandbox_provider().id == "cape2"
    assert isinstance(container.get_sandbox_client(), SandboxClient)


def test_mock_mode_overrides_the_configured_provider():
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "cape2"
    container = ServiceContainer(config=cfg, mock=True)
    assert container.get_sandbox_provider().id == "mock"


def test_providers_are_cached():
    container = ServiceContainer(config=Settings(_env_file=None), mock=True)
    assert container.get_sandbox_provider() is container.get_sandbox_provider()
    assert container.get_static_provider() is container.get_static_provider()


def test_the_default_profile_is_ghidra_plus_the_cape_equivalent():
    """The smoke test the spec's gate (6) names: today's .env, today's wiring."""
    container = ServiceContainer(config=Settings(_env_file=None), mock=False)
    assert container.get_static_provider().id == "ghidra"
    assert container.get_sandbox_provider().id == "mock"


def test_the_registry_is_built_once_per_container():
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    container = ServiceContainer(config=Settings(_env_file=None), mock=True)
    assert container.get_server_registry() is container.get_server_registry()
    assert [h.name for h in container.get_server_registry().for_agent("judge")] == ["threatintel"]


@pytest.mark.asyncio
async def test_aclose_closes_the_registry_only_when_one_was_built():
    from unittest.mock import MagicMock

    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    def _container() -> ServiceContainer:
        return ServiceContainer(config=Settings(_env_file=None), mock=True)

    container = _container()
    await container.aclose()  # never touched the registry: nothing to close

    container = _container()
    registry = container.get_server_registry()
    registry.close_all = MagicMock(return_value=[])
    await container.aclose()
    registry.close_all.assert_called_once()


@pytest.mark.asyncio
async def test_the_judge_agent_the_container_hands_out_can_reach_the_registry(monkeypatch):
    """``get_judge_agent`` must wire ``_container`` the same way ``get_agent`` does.

    Without it, ``JudgeAgent._server_registry()`` always reads ``None`` and
    the judge runs with zero threat-intel tools in production — the bug this
    regression test is here to catch stays caught only by going through the
    real ``ServiceContainer``, not a fake one built to look like it wires
    things up.

    ``mock=True`` short-circuits LLM construction (``ConfigurationError:
    Cannot build LLM in mock mode``), so this needs ``mock=False`` and a
    throwaway ``OPENAI_API_KEY`` — the default provider only needs the key to
    be present to build the client, never to make a network call.
    """
    import asyncio
    import json
    import shutil
    import sys
    from pathlib import Path

    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    if not sys.executable or not shutil.which(sys.executable):
        pytest.skip("no python interpreter available to launch the sidecar")

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")

    container = ServiceContainer(config=Settings(_env_file=None), mock=False)

    judge = container.get_judge_agent()
    await asyncio.wait_for(judge._initialize_mcp_client(), timeout=20.0)
    try:
        golden_path = (
            Path(__file__).resolve().parents[1]
            / "fixtures"
            / "golden"
            / "mcp_tools"
            / "threatintel.json"
        )
        golden = sorted(json.loads(golden_path.read_text(encoding="utf-8"))["tools"])
        assert sorted(t.name for t in judge.tools) == golden
    finally:
        await judge.aclose()

    expert = container.get_judge_agent(role="expert")
    assert expert._container is container
