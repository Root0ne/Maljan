"""Google Gemini provider implementation."""

from __future__ import annotations

import json
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from pydantic import SecretStr

from maljan.agents.argument_schema import _SCHEMA_KEYS, _SCHEMA_LIST_KEYS, _SCHEMA_MAP_KEYS
from maljan.core.config import GeminiConfig, Settings
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
    settings_model = GeminiConfig
    choice_order = 3
    label = "Google Gemini"
    description = "Gemini models via Google AI"
    hosted = True
    legacy_credential_keys = ("google_api_key",)
    guide_leaves = ("api_key",)
    guide_advanced_leaves = ()
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
        # Loaded here, not with the module: reading this adapter's facts (the
        # settings catalogue, a save's validation) never needs the client.
        from langchain_google_genai import ChatGoogleGenerativeAI

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
            _with_gemini_tool_schemas(with_sized_request_timeout(ChatGoogleGenerativeAI)),
            "gemini",
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


_JSON_TYPES: dict[type, str] = {bool: "boolean", int: "integer", float: "number", str: "string"}


def _gemini_schema(schema: Any) -> Any:
    """``schema`` with every form Gemini's client refuses or misreads rewritten; itself when none.

    Gemini takes only string enum values. A ``null`` among them is left out
    (it says the value may be absent); when any other value is not a string,
    the ``enum`` is left out, its ``type`` kept (or read off the values when
    they agree on one), and the values are named in the description so the
    model still reads them. A type list of one type and ``"null"``, which the
    client would read as a string, is an ``anyOf`` of that type and ``null``,
    the form the client reads as nullable. Only subschemas are read: a
    ``default``, ``examples`` or ``const`` value is data and is passed as it
    is. The tool's own argument model still checks the value.
    """
    if not isinstance(schema, dict):
        return schema
    out: dict[str, Any] = {}
    for key, value in schema.items():
        if key in _SCHEMA_LIST_KEYS and isinstance(value, list):
            items = [_gemini_schema(v) for v in value]
            same = all(a is b for a, b in zip(items, value, strict=True))
            out[key] = value if same else items
        elif key in _SCHEMA_MAP_KEYS and isinstance(value, dict):
            named = {name: _gemini_schema(v) for name, v in value.items()}
            out[key] = value if all(named[n] is value[n] for n in value) else named
        elif key in _SCHEMA_KEYS:
            out[key] = _gemini_schema(value)
        else:
            out[key] = value
    listed = schema.get("enum")
    if isinstance(listed, list) and not all(isinstance(v, str) for v in listed):
        values = [v for v in listed if v is not None]
        if values and all(isinstance(v, str) for v in values):
            out["enum"] = values
        else:
            del out["enum"]
            kinds = {_JSON_TYPES.get(type(v)) for v in values}
            if "type" not in schema and len(kinds) == 1 and None not in kinds:
                out["type"] = kinds.pop()
            if values:
                said_values = ", ".join(json.dumps(v) for v in values)
                said = str(schema.get("description") or "").strip()
                out["description"] = f"{said} One of: {said_values}.".strip()
    stated = schema.get("type")
    if isinstance(stated, list) and all(isinstance(n, str) for n in stated):
        kinds_named = [n for n in stated if n != "null"]
        if len(kinds_named) == 1 and len(kinds_named) < len(stated) and "anyOf" not in schema:
            del out["type"]
            out["anyOf"] = [{"type": kinds_named[0]}, {"type": "null"}]
        elif len(kinds_named) == 1:
            out["type"] = kinds_named[0]
    if out.keys() == schema.keys() and all(out[k] is schema[k] for k in schema):
        return schema
    return out


def gemini_tools(tools: Any) -> list[Any]:
    """``tools`` as Gemini's client can bind them; a tool that needs no change is passed as it was.

    A tool whose parameters hold a form Gemini's client refuses or misreads is
    passed in the OpenAI shape with that form rewritten
    (:func:`_gemini_schema`); anything else, Gemini's own tools included, is
    passed untouched.
    """
    from langchain_core.utils.function_calling import convert_to_openai_tool

    adapted: list[Any] = []
    for tool in tools:
        try:
            shaped = convert_to_openai_tool(tool)
        except Exception:  # noqa: BLE001 — Gemini's own tool kinds are not ours to convert
            adapted.append(tool)
            continue
        function: Any = shaped.get("function") if isinstance(shaped, dict) else None
        parameters = function.get("parameters") if isinstance(function, dict) else None
        rewritten = _gemini_schema(parameters)
        if rewritten is parameters:
            adapted.append(tool)
        else:
            adapted.append({**shaped, "function": {**function, "parameters": rewritten}})
    return adapted


_GEMINI_TOOL_CLASSES: dict[type, type] = {}


def _with_gemini_tool_schemas(chat_class: Any) -> Any:
    """``chat_class`` binding tools through :func:`gemini_tools`."""
    cached = _GEMINI_TOOL_CLASSES.get(chat_class)
    if cached is not None:
        return cached
    base: Any = chat_class

    def bind_tools(self: Any, tools: Any, *args: Any, **kwargs: Any) -> Any:
        return base.bind_tools(self, gemini_tools(tools), *args, **kwargs)

    adapted = type(chat_class.__name__, (chat_class,), {"bind_tools": bind_tools})
    adapted.__module__ = chat_class.__module__
    adapted.__qualname__ = chat_class.__qualname__
    _GEMINI_TOOL_CLASSES[chat_class] = adapted
    return adapted


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
