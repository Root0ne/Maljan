"""LLM provider registry with auto-discovery via decorator.

Usage:
    @register_provider("openai")
    class OpenAIProvider:
        name = "openai"
        def build_model(self, model, temperature, **kwargs): ...

Heterogeneous Model Ensemble:
    build_model_for_agent(agent_name) builds a model using the per-agent
    AgentLLMConfig override when one is defined, otherwise falls back to
    build_model("expert"). This allows each analysis agent to use a
    different provider/model family, reducing echo chamber risk.
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.core.config import Settings
from maljan.core.exceptions import LLMError
from maljan.core.logger import logger

# Module-level registry dict: provider_name -> class
_PROVIDER_REGISTRY: dict[str, type] = {}


def register_provider(name: str):  # type: ignore[no-untyped-def]
    """Decorator that registers an LLM provider class under the given name."""

    def decorator(cls: type) -> type:
        if name in _PROVIDER_REGISTRY:
            logger.warning(f"LLM provider '{name}' is being re-registered (overwriting).")
        _PROVIDER_REGISTRY[name] = cls
        return cls

    return decorator


def discover_providers() -> None:
    """Import all built-in provider modules to trigger @register_provider decorators."""
    import maljan.llm.anthropic_provider  # noqa: F401
    import maljan.llm.gemini_provider  # noqa: F401
    import maljan.llm.ollama_provider  # noqa: F401
    import maljan.llm.openai_provider  # noqa: F401


class LLMProviderRegistry:
    """Manages LLM provider discovery, instantiation, and model building."""

    def __init__(self, config: Settings) -> None:
        self._config = config
        discover_providers()

    def build_model(
        self,
        role: str = "expert",
        temperature: float | None = None,
        **kwargs: Any,
    ) -> BaseChatModel:
        """Build a ChatModel for the configured provider and role.

        Args:
            role: "expert" or "judge" - selects the model name.
            temperature: Override temperature. Defaults to 0.1 for expert, 0.0 for judge.
            **kwargs: Extra kwargs forwarded to the provider.

        Returns:
            A configured LangChain BaseChatModel instance.
        """
        provider_name = self._config.llm.provider
        provider_cls = _PROVIDER_REGISTRY.get(provider_name)

        if provider_cls is None:
            available = ", ".join(_PROVIDER_REGISTRY.keys()) or "(none)"
            raise LLMError(f"Unknown LLM provider: '{provider_name}'. Available: {available}")

        # Select model name based on role
        if role == "judge":
            model_name = self._config.llm.judge_model
            default_temp = 0.0
        else:
            model_name = self._config.llm.expert_model
            default_temp = 0.1

        temp = temperature if temperature is not None else default_temp

        logger.info(f"Building {provider_name}/{model_name} (role={role}, temp={temp})")
        provider = provider_cls(config=self._config)
        return provider.build_model(model=model_name, temperature=temp, **kwargs)  # type: ignore[no-any-return]

    def build_model_for_agent(
        self,
        agent_name: str,
        **kwargs: Any,
    ) -> BaseChatModel:
        """Build a ChatModel for a specific named agent.

        Looks up agent_name in LLMConfig.agents. When a per-agent
        AgentLLMConfig override exists, it builds a model using that
        agent's dedicated provider and model name — enabling heterogeneous
        model ensemble (different model families per agent).

        When no override is found, falls back to build_model("expert")
        for full backward compatibility.

        Args:
            agent_name: The agent registry key (e.g. "static", "dynamic",
                        "network"). Case-insensitive lookup.
            **kwargs:   Extra kwargs forwarded to the provider.

        Returns:
            A configured LangChain BaseChatModel instance.
        """
        agent_cfg = self._config.llm.agents.get(agent_name.lower())

        if agent_cfg is None:
            # No per-agent override — fall back to global expert LLM
            logger.debug("No per-agent LLM config for '%s', using global expert LLM.", agent_name)
            return self.build_model(role="expert", **kwargs)

        # Per-agent override found
        provider_cls = _PROVIDER_REGISTRY.get(agent_cfg.provider)
        if provider_cls is None:
            available = ", ".join(_PROVIDER_REGISTRY.keys()) or "(none)"
            logger.warning(
                "Agent '%s' specifies unknown provider '%s' (available: %s). "
                "Falling back to global expert LLM.",
                agent_name,
                agent_cfg.provider,
                available,
            )
            return self.build_model(role="expert", **kwargs)

        temp = agent_cfg.temperature if agent_cfg.temperature is not None else 0.1
        logger.info(
            "Building dedicated LLM for agent '%s': %s/%s (temp=%.2f)",
            agent_name,
            agent_cfg.provider,
            agent_cfg.model,
            temp,
        )

        # Build a temporary Settings-like config targeting the agent's provider
        # by patching _config at the provider level — clean duck-typing approach
        provider = provider_cls(config=self._config)
        return provider.build_model(  # type: ignore[no-any-return]
            model=agent_cfg.model,
            temperature=temp,
            **kwargs,
        )
