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

        secret = self._config.llm.openai.api_key
        if not secret:
            raise LLMError("OPENAI_API_KEY is not set but provider is 'openai'.")

        from pydantic import SecretStr

        api_key = secret if isinstance(secret, SecretStr) else SecretStr(str(secret))
        build_kwargs: dict[str, Any] = {
            "model": model,
            "api_key": api_key,
            "temperature": temperature,
            **kwargs,
        }
        base_url = self._config.llm.openai.base_url
        if base_url:
            build_kwargs["base_url"] = base_url

        # Wave 5 HANG-01 (2026-05-28): explicit ``request_timeout`` and
        # ``max_retries`` so the openai SDK can't silently retry a stalled
        # request three times (3 x default 600s = 30 min). Caller-supplied
        # kwargs win. The outer ``execute_tool_loop`` / no-tools fallback
        # already enforces a daemon-thread hard cap; this aligns the inner
        # HTTP layer with that cap so we fail fast on a hung llama-server
        # instead of waiting for the SDK retry loop to give up.
        build_kwargs.setdefault("request_timeout", 300)
        build_kwargs.setdefault("max_retries", 0)

        return ChatOpenAI(**build_kwargs)
