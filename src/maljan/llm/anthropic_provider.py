"""Anthropic LLM provider."""

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.core.config import Settings
from maljan.core.exceptions import LLMError
from maljan.llm.registry import register_provider


@register_provider("anthropic")
class AnthropicProvider:
    """Builds LangChain ChatAnthropic instances."""

    name = "anthropic"

    def __init__(self, config: Settings) -> None:
        self._config = config

    def build_model(
        self,
        model: str,
        temperature: float,
        **kwargs: Any,
    ) -> BaseChatModel:
        from langchain_anthropic import ChatAnthropic  # type: ignore[import-untyped]

        secret = self._config.llm.anthropic.api_key
        if not secret:
            raise LLMError("ANTHROPIC_API_KEY is not set but provider is 'anthropic'.")

        from pydantic import SecretStr

        api_key = secret if isinstance(secret, SecretStr) else SecretStr(str(secret))

        return ChatAnthropic(
            model_name=model,
            api_key=api_key,
            temperature=temperature,
            **kwargs,
        )
