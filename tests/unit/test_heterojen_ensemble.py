"""Unit tests for heterogeneous model ensemble.

Tests cover:
  - AgentLLMConfig: field validation
  - LLMConfig.agents: dict storage and lookup
  - LLMProviderRegistry.build_model_for_agent():
      no-override path (fallback to expert)
      override path (dedicated provider/model)
      unknown-provider fallback + warning
      case-insensitive agent name lookup
      temperature propagation
  - ServiceContainer.get_agent_llm():
      cache hit (same instance returned)
      mock mode raises RuntimeError
      delegates to registry
  - ServiceContainer.get_agent():
      uses get_agent_llm() not get_expert_llm()
  - Settings env var parsing (LLM__AGENTS__STATIC)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from maljan.core.config import AgentLLMConfig, LLMConfig, Settings

# ---------------------------------------------------------------------------
# AgentLLMConfig
# ---------------------------------------------------------------------------

class TestAgentLLMConfig:
    def test_required_fields(self) -> None:
        cfg = AgentLLMConfig(provider="openai", model="gpt-4o")
        assert cfg.provider == "openai"
        assert cfg.model == "gpt-4o"

    def test_temperature_default_is_none(self) -> None:
        cfg = AgentLLMConfig(provider="anthropic", model="claude-3-5-sonnet")
        assert cfg.temperature is None

    def test_temperature_override(self) -> None:
        cfg = AgentLLMConfig(provider="ollama", model="llama3.1:8b", temperature=0.2)
        assert cfg.temperature == pytest.approx(0.2)

    def test_missing_provider_rejected(self) -> None:
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            AgentLLMConfig(model="gpt-4o")  # type: ignore[call-arg]

    def test_missing_model_rejected(self) -> None:
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            AgentLLMConfig(provider="openai")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# LLMConfig.agents
# ---------------------------------------------------------------------------

class TestLLMConfigAgents:
    def test_default_agents_empty(self) -> None:
        cfg = LLMConfig()
        assert cfg.agents == {}

    def test_agents_stored(self) -> None:
        cfg = LLMConfig(
            agents={
                "static": AgentLLMConfig(provider="anthropic", model="claude-3-5-sonnet"),
                "dynamic": AgentLLMConfig(provider="openai", model="gpt-4o"),
            }
        )
        assert "static" in cfg.agents
        assert "dynamic" in cfg.agents
        assert cfg.agents["static"].provider == "anthropic"
        assert cfg.agents["dynamic"].model == "gpt-4o"

    def test_agents_dict_is_independent(self) -> None:
        cfg1 = LLMConfig()
        cfg2 = LLMConfig()
        cfg1.agents["static"] = AgentLLMConfig(provider="openai", model="gpt-4o")
        assert "static" not in cfg2.agents


# ---------------------------------------------------------------------------
# LLMProviderRegistry.build_model_for_agent()
# ---------------------------------------------------------------------------

def _make_registry(agents: dict | None = None) -> object:
    """Create a registry with mocked provider registry."""
    from maljan.llm.registry import LLMProviderRegistry

    cfg = Settings(
        llm=LLMConfig(
            provider="openai",
            agents=agents or {},
        )
    )
    registry = LLMProviderRegistry.__new__(LLMProviderRegistry)
    registry._config = cfg

    # Mock the built-in model to avoid real LLM calls
    mock_model = MagicMock()
    mock_provider_cls = MagicMock(return_value=MagicMock(
        build_model=MagicMock(return_value=mock_model)
    ))
    registry._provider_registry_patch = {
        "openai": mock_provider_cls,
        "anthropic": mock_provider_cls,
    }
    return registry, mock_model, mock_provider_cls


class TestBuildModelForAgent:
    def _make_registry_patched(self, agents: dict | None = None):
        """Create registry with _PROVIDER_REGISTRY patched."""
        from maljan.llm.registry import LLMProviderRegistry

        cfg = Settings(llm=LLMConfig(provider="openai", agents=agents or {}))
        registry = LLMProviderRegistry.__new__(LLMProviderRegistry)
        registry._config = cfg
        return registry

    def test_no_override_calls_build_model_expert(self) -> None:
        registry = self._make_registry_patched()
        with patch.object(registry, "build_model") as mock_build:
            mock_build.return_value = MagicMock()
            registry.build_model_for_agent("static")
            mock_build.assert_called_once_with(role="expert")

    def test_no_override_fallback_for_unknown_agent(self) -> None:
        registry = self._make_registry_patched()
        with patch.object(registry, "build_model") as mock_build:
            mock_build.return_value = MagicMock()
            registry.build_model_for_agent("nonexistent_agent")
            mock_build.assert_called_once_with(role="expert")

    def test_case_insensitive_agent_lookup(self) -> None:
        agents = {"static": AgentLLMConfig(provider="openai", model="gpt-4o")}
        registry = self._make_registry_patched(agents=agents)

        mock_model = MagicMock()
        mock_provider = MagicMock(build_model=MagicMock(return_value=mock_model))
        mock_cls = MagicMock(return_value=mock_provider)

        with patch("maljan.llm.registry._PROVIDER_REGISTRY", {"openai": mock_cls}):
            result = registry.build_model_for_agent("STATIC")  # uppercase
        assert result is mock_model

    def test_override_uses_agent_provider_and_model(self) -> None:
        agents = {"dynamic": AgentLLMConfig(provider="anthropic", model="claude-3-5-sonnet")}
        registry = self._make_registry_patched(agents=agents)

        mock_model = MagicMock()
        mock_provider = MagicMock(build_model=MagicMock(return_value=mock_model))
        mock_cls = MagicMock(return_value=mock_provider)

        with patch("maljan.llm.registry._PROVIDER_REGISTRY", {"anthropic": mock_cls}):
            result = registry.build_model_for_agent("dynamic")

        mock_provider.build_model.assert_called_once()
        call_kwargs = mock_provider.build_model.call_args
        assert call_kwargs.kwargs.get("model") == "claude-3-5-sonnet"
        assert result is mock_model

    def test_override_uses_agent_temperature(self) -> None:
        agents = {"network": AgentLLMConfig(provider="openai", model="gpt-4o", temperature=0.3)}
        registry = self._make_registry_patched(agents=agents)

        mock_model = MagicMock()
        mock_provider = MagicMock(build_model=MagicMock(return_value=mock_model))
        mock_cls = MagicMock(return_value=mock_provider)

        with patch("maljan.llm.registry._PROVIDER_REGISTRY", {"openai": mock_cls}):
            registry.build_model_for_agent("network")

        call_kwargs = mock_provider.build_model.call_args
        assert call_kwargs.kwargs.get("temperature") == pytest.approx(0.3)

    def test_override_no_temperature_defaults_to_01(self) -> None:
        agents = {"static": AgentLLMConfig(provider="openai", model="gpt-4o")}
        registry = self._make_registry_patched(agents=agents)

        mock_model = MagicMock()
        mock_provider = MagicMock(build_model=MagicMock(return_value=mock_model))
        mock_cls = MagicMock(return_value=mock_provider)

        with patch("maljan.llm.registry._PROVIDER_REGISTRY", {"openai": mock_cls}):
            registry.build_model_for_agent("static")

        call_kwargs = mock_provider.build_model.call_args
        assert call_kwargs.kwargs.get("temperature") == pytest.approx(0.1)

    def test_unknown_provider_in_override_falls_back(self) -> None:
        """Unknown provider in override falls back to global expert LLM with a warning."""
        agents = {"static": AgentLLMConfig(provider="nonexistent", model="foo")}
        registry = self._make_registry_patched(agents=agents)

        with patch.object(registry, "build_model") as mock_build:
            mock_build.return_value = MagicMock()
            with patch("maljan.llm.registry._PROVIDER_REGISTRY", {"openai": MagicMock()}):
                registry.build_model_for_agent("static")
            mock_build.assert_called_once_with(role="expert")


# ---------------------------------------------------------------------------
# ServiceContainer.get_agent_llm()
# ---------------------------------------------------------------------------

class TestContainerGetAgentLLM:
    def _make_container(self, agents: dict | None = None) -> object:
        from maljan.core.container import ServiceContainer
        container = ServiceContainer.__new__(ServiceContainer)
        container.config = Settings(llm=LLMConfig(agents=agents or {}))
        container.mock = False
        container._expert_llm_cache = None
        container._judge_llm_cache = None
        container._agent_llm_cache = {}
        container._agent_cache = {}
        container._data_cache = {}
        container._llm_registry = MagicMock()
        return container

    def test_delegates_to_registry(self) -> None:
        container = self._make_container()
        expected_llm = MagicMock()
        container._llm_registry.build_model_for_agent.return_value = expected_llm
        result = container.get_agent_llm("static")
        container._llm_registry.build_model_for_agent.assert_called_once_with("static")
        assert result is expected_llm

    def test_caches_result(self) -> None:
        container = self._make_container()
        expected_llm = MagicMock()
        container._llm_registry.build_model_for_agent.return_value = expected_llm

        result1 = container.get_agent_llm("dynamic")
        result2 = container.get_agent_llm("dynamic")

        # Registry called only once
        container._llm_registry.build_model_for_agent.assert_called_once()
        assert result1 is result2

    def test_different_agents_get_different_cache_entries(self) -> None:
        container = self._make_container()
        llm_static = MagicMock()
        llm_dynamic = MagicMock()
        container._llm_registry.build_model_for_agent.side_effect = [llm_static, llm_dynamic]

        r_static = container.get_agent_llm("static")
        r_dynamic = container.get_agent_llm("dynamic")

        assert r_static is llm_static
        assert r_dynamic is llm_dynamic

    def test_mock_mode_raises(self) -> None:
        from maljan.core.container import ServiceContainer
        container = ServiceContainer.__new__(ServiceContainer)
        container._llm_registry = None
        container._agent_llm_cache = {}

        with pytest.raises(RuntimeError, match="mock mode"):
            container.get_agent_llm("static")


# ---------------------------------------------------------------------------
# ServiceContainer.get_agent() uses get_agent_llm()
# ---------------------------------------------------------------------------

class TestContainerGetAgentUsesAgentLLM:
    def test_get_agent_calls_get_agent_llm_not_expert(self) -> None:
        from maljan.core.container import ServiceContainer
        container = ServiceContainer.__new__(ServiceContainer)
        container._agent_cache = {}

        dedicated_llm = MagicMock()
        container.get_agent_llm = MagicMock(return_value=dedicated_llm)
        container.get_expert_llm = MagicMock()

        mock_agent = MagicMock()
        mock_registry = MagicMock()
        mock_registry.create.return_value = mock_agent
        container.agent_registry = mock_registry

        container.get_agent("static")

        container.get_agent_llm.assert_called_once_with("static")
        container.get_expert_llm.assert_not_called()
        mock_registry.create.assert_called_once_with("static", dedicated_llm)

    def test_get_agent_cache_hit_does_not_rebuild_llm(self) -> None:
        from maljan.core.container import ServiceContainer
        container = ServiceContainer.__new__(ServiceContainer)

        cached_agent = MagicMock()
        container._agent_cache = {"static": cached_agent}
        container.get_agent_llm = MagicMock()
        container.agent_registry = MagicMock()

        result = container.get_agent("static")

        assert result is cached_agent
        container.get_agent_llm.assert_not_called()
