"""Google Gemini provider implementation."""

from __future__ import annotations

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_google_genai import ChatGoogleGenerativeAI
from pydantic import SecretStr

from maljan.core.config import Settings
from maljan.core.exceptions import LLMError
from maljan.llm.registry import register_provider


@register_provider("gemini")
class GeminiProvider:
    """Builds Gemini ChatModels via langchain-google-genai."""

    name = "gemini"

    def __init__(self, config: Settings) -> None:
        self._config = config

    def build_model(
        self,
        model: str,
        temperature: float,
        **kwargs: Any,
    ) -> BaseChatModel:
        """Builds a ChatGoogleGenerativeAI instance.

        Args:
            model: Gemini model name (e.g., 'gemini-1.5-pro').
            temperature: LLM temperature.
            **kwargs: Extra kwargs (e.g. streaming, callbacks).

        Returns:
            A ChatGoogleGenerativeAI instance.
        """
        api_key = self._config.llm.gemini.api_key
        if not api_key:
            raise LLMError(
                "Gemini API key is required but not configured. "
                "Set GOOGLE_API_KEY in your .env file."
            )

        return ChatGoogleGenerativeAI(
            model=model,
            temperature=temperature,
            google_api_key=SecretStr(api_key.get_secret_value()),
            # Auto-retry on 429 RESOURCE_EXHAUSTED with exponential backoff.
            # Free tier limit is 5 RPM; Gemini instructs "retry in ~12s".
            # 6 retries covers ~120s of rate-limit windows before giving up.
            max_retries=6,
            # Per-request HTTP timeout (seconds). Prevents silent hangs on slow responses.
            request_timeout=90,
            **kwargs,
        )
