"""LLM provider registry with auto-discovery via decorator.

Usage:
    @register_provider("openai")
    class OpenAIProvider:
        name = "openai"
        def build_model(self, model, temperature, **kwargs): ...
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
    import maljan.llm.ollama_provider  # noqa: F401
    import maljan.llm.openai_provider  # noqa: F401


class LLMProviderRegistry:
    """Manages LLM provider discovery, instantiation, and model building."""

    def __init__(self, config: Settings) -> None:
        self._config = config
        discover_providers()

    def list_providers(self) -> list[str]:
        """Returns names of all registered providers."""
        return list(_PROVIDER_REGISTRY.keys())

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
            raise LLMError(
                f"Unknown LLM provider: '{provider_name}'. Available: {available}"
            )

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
