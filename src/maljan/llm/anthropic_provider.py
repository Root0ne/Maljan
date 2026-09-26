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

        # The same request timeout as every other provider, named rather than
        # left to the SDK's default, until the model's pace is measured; each
        # request is then sized for its own output cap.
        from maljan.llm.generation_rate import with_sized_request_timeout
        from maljan.llm.registry import PROVIDER_REQUEST_TIMEOUT_SECONDS

        kwargs.setdefault("timeout", float(PROVIDER_REQUEST_TIMEOUT_SECONDS))

        # No request sends a ``tool_use`` without its ``tool_result``, whatever
        # the history it was built from (``maljan.llm.tool_replies``).
        from maljan.llm.tool_replies import with_answered_tool_calls

        chat_class = with_answered_tool_calls(
            with_sized_request_timeout(ChatAnthropic), "anthropic"
        )
        return chat_class(  # type: ignore[no-any-return]
            model_name=model,
            api_key=api_key,
            temperature=temperature,
            **kwargs,
        )
