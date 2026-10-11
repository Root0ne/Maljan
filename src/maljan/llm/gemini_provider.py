"""Google Gemini provider implementation."""

from __future__ import annotations

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_google_genai import ChatGoogleGenerativeAI
from pydantic import SecretStr

from maljan.core.config import Settings
from maljan.core.exceptions import LLMError
from maljan.llm.provider_base import (
    COMPLETION_MAX_TOKENS,
    COMPLETION_PROMPT,
    LLMProvider,
    ModelListing,
    OneTurnRequest,
)
from maljan.llm.registry import register_provider

# Google's Generative Language API, the one address Gemini is reached at.
GEMINI_API_ROOT = "https://generativelanguage.googleapis.com"


@register_provider("gemini")
class GeminiProvider(LLMProvider):
    """Builds Gemini ChatModels via langchain-google-genai."""

    name = "gemini"
    choice_order = 3
    label = "Google Gemini"
    description = "Gemini models over Google's Generative Language API."
    hosted = True
    setup_leaves = ("api_key", "expert_model", "judge_model")
    sdk_packages = frozenset({"google"})
    # The client asks again on a rate limit itself (``max_retries`` below).
    retries_inside_client = True
    llm_types = ("chat-google-generative-ai",)
    # Its request config refuses any other name for the cap.
    per_call_cap_field = "max_output_tokens"
    timeout_kwarg = "request_options"
    default_endpoint = "the Gemini API"
    concurrency = "hosted"

    @classmethod
    def supports_structured_output(cls, settings: Any) -> bool:
        return True

    @classmethod
    def model_listing(cls, settings: Any) -> ModelListing:
        return ModelListing(
            url=f"{GEMINI_API_ROOT}/v1beta/models",
            headers={"x-goog-api-key": cls.api_key(settings)},
            names=lambda payload: [m.get("name", "") for m in (payload or {}).get("models", [])],
            where=GEMINI_API_ROOT,
        )

    @classmethod
    def one_turn_request(
        cls, settings: Any, endpoint: str, model: str, effort: str | None = None
    ) -> OneTurnRequest:
        return OneTurnRequest(
            f"{GEMINI_API_ROOT}/v1beta/models/{model}:generateContent",
            {"x-goog-api-key": cls.api_key(settings)},
            {
                "contents": [{"parts": [{"text": COMPLETION_PROMPT}]}],
                "generationConfig": {"maxOutputTokens": COMPLETION_MAX_TOKENS},
            },
        )

    @classmethod
    def said_something(cls, payload: Any) -> bool:
        candidates = payload.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            return False
        parts = ((candidates[0] or {}).get("content") or {}).get("parts") or []
        return any(str(part.get("text") or "").strip() for part in parts)

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

        from maljan.llm.generation_rate import with_sized_request_timeout
        from maljan.llm.registry import PROVIDER_REQUEST_TIMEOUT_SECONDS

        # The request timeout every provider is built with, and each request
        # sized for its own output cap once the model's pace is measured. A
        # fixed 90 s used to end any answer longer than 90 s.
        kwargs.setdefault("request_timeout", float(PROVIDER_REQUEST_TIMEOUT_SECONDS))
        # No request sends a ``functionCall`` without its ``functionResponse``,
        # whatever the history it was built from (``maljan.llm.tool_replies``).
        from maljan.llm.tool_replies import with_answered_tool_calls

        chat_class = with_answered_tool_calls(
            with_sized_request_timeout(ChatGoogleGenerativeAI), "gemini"
        )
        built = chat_class(
            model=model,
            temperature=temperature,
            google_api_key=SecretStr(api_key.get_secret_value()),
            # Auto-retry on 429 RESOURCE_EXHAUSTED with exponential backoff.
            # Free tier limit is 5 RPM; Gemini instructs "retry in ~12s".
            # 6 retries covers ~120s of rate-limit windows before giving up.
            max_retries=6,
            **kwargs,
        )
        _bind_async_client_per_loop(built)
        return built  # type: ignore[no-any-return]


def _bind_async_client_per_loop(built: Any) -> None:
    """Give ``built``'s Gemini client async connections of each event loop's own.

    The google-genai client builds one httpx async client per model, and one
    model is awaited on the agent loop and on the worker's own; a pooled
    connection reused across the two fails with "bound to a different event
    loop". The client is rebuilt per loop from the arguments it was built with
    (``maljan.llm.loop_clients``); every request is still built by the original.
    A client that sends through aiohttp (per loop already) is left as it is;
    one this SDK no longer lays out this way is too, and a warning says so once.
    """
    from maljan.llm.loop_clients import layout_not_recognised, loop_bound_async_client

    api_client: Any = getattr(getattr(built, "client", None), "_api_client", None)
    if api_client is None or not (
        hasattr(api_client, "_async_httpx_client")
        and hasattr(api_client, "_async_httpx_client_args")
    ):
        layout_not_recognised("gemini", "no _api_client with an async httpx client and its args")
        return
    original = api_client._async_httpx_client
    if original is None:
        # The google-auth path, which sends through aiohttp sessions the SDK
        # already keeps one per loop.
        return
    args = api_client._async_httpx_client_args or {}
    build_class = type(original)
    try:
        api_client._async_httpx_client = loop_bound_async_client(
            lambda: build_class(**args), template=original
        )
    except TypeError as exc:
        layout_not_recognised("gemini", str(exc))
