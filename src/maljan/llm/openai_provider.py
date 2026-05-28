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

        # Wave 5 HANG-01 + Wave 7 THROUGHPUT-01 (2026-05-28): explicit
        # ``request_timeout`` and ``max_retries`` so the openai SDK can't
        # silently retry a stalled request three times (3 x default 600s
        # = 30 min). Caller-supplied kwargs win.
        # ``request_timeout`` must be >= the longest agent ``wait_for``
        # budget; otherwise the HTTP layer truncates a still-decoding
        # response before the outer wrapper's hard cap fires (live trace
        # 2026-05-28 showed static analyst dropping at exactly 300s
        # because the previous Wave 5 value was tighter than its 600s
        # ReAct budget). 900s matches the worst case of static (600s) +
        # decode headroom on a cold-cache local 35B. ``max_retries=0``
        # keeps a single attempt regardless of size — the daemon-thread
        # cap in ``execute_tool_loop`` is the only retry policy we want.
        build_kwargs.setdefault("request_timeout", 900)
        build_kwargs.setdefault("max_retries", 0)

        return ChatOpenAI(**build_kwargs)
