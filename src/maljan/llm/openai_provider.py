"""OpenAI LLM provider."""

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.core.config import Settings
from maljan.core.exceptions import LLMError
from maljan.llm.registry import register_provider


@register_provider("openai")
class OpenAIProvider:
    """Builds LangChain ChatOpenAI instances."""

    name = "openai"

    def __init__(self, config: Settings) -> None:
        self._config = config

    def build_model(
        self,
        model: str,
        temperature: float,
        **kwargs: Any,
    ) -> BaseChatModel:
        from langchain_openai import ChatOpenAI

        api_key = self._config.llm.openai.api_key
        if not api_key:
            raise LLMError("OPENAI_API_KEY is not set but provider is 'openai'.")

        return ChatOpenAI(
            model=model,
            api_key=api_key,  # type: ignore[arg-type]
            temperature=temperature,
            **kwargs,
        )
