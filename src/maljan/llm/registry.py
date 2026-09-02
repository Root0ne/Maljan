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


# PORTABLE-RESPONSE-FORMAT-01 + PORTABLE-TIMEOUT-QUIRKS-01 (audit
# 2026-05-19): centralise per-provider capability flags so callers can
# branch on "does this provider support langchain ``with_structured_output``"
# / "what's the right place to set timeout?" without sniffing internal
# state. Conservative defaults match the providers we ship today.
PROVIDER_CAPABILITIES: dict[str, dict[str, Any]] = {
    "openai": {
        "supports_structured_output": True,
        # LangChain ChatOpenAI takes ``request_timeout`` as a top-level kwarg.
        "timeout_kwarg": "request_timeout",
    },
    "anthropic": {
        "supports_structured_output": True,
        "timeout_kwarg": "timeout",
    },
    "gemini": {
        "supports_structured_output": True,
        "timeout_kwarg": "request_options",  # gRPC; honoured via ``timeout`` key
    },
    "ollama": {
        # langchain-ollama exposes structured output via tool calling that
        # most Ollama-served models don't honour cleanly. Treat as
        # unsupported so callers prompt the LLM to emit JSON manually
        # instead of relying on a silent regex fallback.
        "supports_structured_output": False,
        "timeout_kwarg": "request_timeout",
    },
}


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


def structured_output_supported(config: Any | None = None, llm: Any | None = None) -> bool:
    """Whether ``with_structured_output`` is worth attempting against this endpoint.

    A property of the endpoint, not of the caller, which is why it lives here
    rather than in each of the three places that ask. Two things it decides:

    * **The provider name.** LangChain reports ``ChatOpenAI._llm_type`` as
      ``"openai-chat"``, which is absent from ``PROVIDER_CAPABILITIES``, so a
      caller that sniffed the model object got the unknown-provider default for
      *every* provider. Config wins when present; the ``-chat`` suffix is
      stripped as a backstop when it is not.

    * **A local server is not the vendor API.** ``openai`` supports structured
      output against api.openai.com. Against a local OpenAI-compatible server
      it is a different animal: measured 2026-08-07, a NarrativeAgent
      structured call against llama-server/Qwen3.6-35B hung for the full
      ``request_timeout`` of 1800 s and was about to do it twice more, with no
      log line in between, while the plain text path does the same job in
      minutes. So a custom ``base_url`` disables it.

    Never raises, and refuses when it cannot tell: knowing nothing about the
    endpoint is not a reason to gamble half an hour of a job on it.
    """
    try:
        if config is not None:
            provider_name = str(config.llm.provider)
            base_url = getattr(config.llm.openai, "base_url", None)
            if provider_name == "openai" and base_url:
                return False
        elif llm is not None:
            # "openai-chat" -> "openai"; harmless for names without a suffix.
            provider_name = str(getattr(llm, "_llm_type", "") or "").split("-")[0]
            if not provider_name:
                return False
        else:
            return False
        return bool(
            PROVIDER_CAPABILITIES.get(provider_name, {}).get("supports_structured_output", False)
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("structured-output capability check failed (%s); assuming no.", exc)
        return False


def structured_output_supported_for_llm(llm: Any) -> bool:
    """``structured_output_supported`` for callers that hold no config.

    ``NarrativeAgent`` and ``ReportComposer`` are constructed with a model and
    nothing else, but the answer depends on the configured endpoint, not on the
    model object — sniffing ``_llm_type`` alone cannot tell a local
    OpenAI-compatible server from api.openai.com. Reads the settings, and falls
    back to what the model object can say if that is unavailable.
    """
    try:
        from maljan.core.config import get_settings

        return structured_output_supported(get_settings(), llm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("structured-output settings lookup failed (%s); sniffing the model.", exc)
        return structured_output_supported(None, llm)
