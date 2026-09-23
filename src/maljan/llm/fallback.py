"""An agent's ordered model list, tried in order only when a provider fails.

A local model server that times out or drops a connection used to end an
analyst's work: the model was the only one the agent had. An agent entry may
now name the models it falls back to, and :class:`FallbackChatModel` is the
one model object that holds them.

What moves a turn to the next model is a **provider failure** and nothing
else: the connection was refused or dropped, the request timed out, the server
answered 5xx or 429, it does not have the model, or it refused the request and
said so as an error. Those are facts about the provider, and another provider
may not share them.

What never moves a turn is the content of an answer. A well-formed answer the
platform's validation rejects goes back, with the feedback, to the model that
wrote it — the validation loop does that and this class is not in its way,
because it only ever sees an exception. Asking another model instead would be
the platform choosing a different answer, which is the override this platform
does not make.

Every answer says which model gave it: ``response_metadata`` carries
``maljan_model`` on every turn and ``maljan_fallback`` — the reason in words —
on a turn a fallback answered. The loop reads both into the ledger entry, the
conversation event and the run summary.
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import ConfigDict, Field

from maljan.core.logger import logger

# The keys an answer carries about the model that gave it.
MODEL_KEY = "maljan_model"
FALLBACK_KEY = "maljan_fallback"

# The statuses that describe the provider rather than the request: the server
# is failing (5xx), it is not serving now (408, 429), it does not have what
# was asked for (404), or it refused the caller (401, 403). Every other 4xx is
# about the request itself and would fail the same way on any model.
_PROVIDER_STATUSES: dict[int, str] = {
    401: "the provider refused the credential (HTTP 401)",
    403: "the provider refused the request (HTTP 403)",
    404: "the provider does not serve this model (HTTP 404)",
    408: "the provider timed out (HTTP 408)",
    429: "the provider is rate limiting (HTTP 429)",
}

# Class names a provider SDK or its transport raises for a connection that
# never answered. Matched by name because four SDKs raise four hierarchies.
_CONNECTION_NAMES = frozenset(
    {
        "APIConnectionError",
        "ConnectError",
        "ConnectTimeout",
        "RemoteProtocolError",
        "ReadError",
        "WriteError",
    }
)
_TIMEOUT_NAMES = frozenset(
    {"APITimeoutError", "ReadTimeout", "WriteTimeout", "PoolTimeout", "TimeoutException"}
)

# What a provider says when it refuses on content grounds and reports that as
# an error rather than as an answer.
_REFUSAL_CODES = ("content_filter", "content_policy", "safety", "refusal")


def _status_of(exc: BaseException) -> int | None:
    for name in ("status_code", "code", "status"):
        value = getattr(exc, name, None)
        if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599:
            return value
    return None


def _one(exc: BaseException) -> str | None:
    """The provider failure ``exc`` is, in words, or ``None``."""
    name = type(exc).__name__
    if name in _TIMEOUT_NAMES or isinstance(exc, TimeoutError):
        return "the provider timed out"
    status = _status_of(exc)
    if status is not None:
        if status >= 500:
            return f"the provider failed (HTTP {status})"
        if status in _PROVIDER_STATUSES:
            return _PROVIDER_STATUSES[status]
        if status == 400:
            code = str(getattr(exc, "code", "") or "")
            body = getattr(exc, "body", None)
            if isinstance(body, dict):
                code = f"{code} {body.get('code') or ''} {body.get('type') or ''}"
            if any(word in code.lower() for word in _REFUSAL_CODES):
                return "the provider refused the request as an error (HTTP 400)"
        return None
    if name in _CONNECTION_NAMES or isinstance(exc, ConnectionError):
        return "the provider could not be reached"
    # Ollama's client says a missing model in words and a 404 status; a
    # version without the status still says the words.
    if name == "ResponseError" and "not found" in str(exc).lower():
        return "the provider does not serve this model"
    return None


def provider_failure(exc: BaseException) -> str | None:
    """Why ``exc`` is a provider failure, in words, or ``None`` when it is not one.

    The cause chain is read too, a few links deep: a provider SDK wraps its
    transport's error, and the transport's error is the one that says what
    happened. Never raises; an exception it cannot read is not a provider
    failure, so it reaches the caller exactly as it did before.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    for _ in range(4):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        try:
            reason = _one(current)
        except Exception:  # noqa: BLE001 — unreadable is not a provider failure
            reason = None
        if reason:
            return reason
        current = current.__cause__ or current.__context__
    return None


class FallbackChatModel(BaseChatModel):
    """An agent's models, the next one asked only when the one before failed as a provider.

    Every turn starts at the first model. A server that dropped one
    connection is asked again on the next turn rather than written off for
    the rest of the job, and a fallback answers only for the turns the first
    model could not.

    Tools are bound per model at call time rather than once here, because each
    provider formats a tool its own way; what the loop binds is the
    OpenAI-shaped list every provider's own ``bind_tools`` reads.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    models: list[Any] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    agent: str = ""

    @property
    def _llm_type(self) -> str:
        return "maljan-fallback"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {"agent": self.agent, "models": list(self.labels)}

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        """Bind tools as the loop does, in the shape every provider's binder reads."""
        formatted = [convert_to_openai_tool(tool) for tool in tools]
        return self.bind(tools=formatted, **kwargs)

    @staticmethod
    def _split(kwargs: dict[str, Any]) -> tuple[Any, dict[str, Any], dict[str, Any]]:
        call = dict(kwargs)
        tools = call.pop("tools", None)
        tool_kwargs: dict[str, Any] = {}
        for key in ("tool_choice", "parallel_tool_calls", "strict"):
            if key in call:
                tool_kwargs[key] = call.pop(key)
        return tools, tool_kwargs, call

    @staticmethod
    def _runnable(model: Any, tools: Any, tool_kwargs: dict[str, Any]) -> Any:
        if tools:
            return model.bind_tools(tools, **tool_kwargs)
        return model

    def _failed(self, index: int, exc: BaseException) -> str:
        """Log one provider failure and return the sentence the answer will carry."""
        reason = provider_failure(exc) or "the provider failed"
        label = self.labels[index] if index < len(self.labels) else f"model {index + 1}"
        logger.warning(
            "%s: %s failed (%s: %s); %s.",
            self.agent or "agent",
            label,
            type(exc).__name__,
            reason,
            "trying the next model" if index + 1 < len(self.models) else "no model is left to try",
        )
        return f"{label}: {reason}"

    def _stamp(self, message: Any, index: int, failures: list[str]) -> ChatResult:
        if not isinstance(message, BaseMessage):
            message = AIMessage(content=str(getattr(message, "content", message)))
        metadata = dict(getattr(message, "response_metadata", None) or {})
        metadata[MODEL_KEY] = self.labels[index] if index < len(self.labels) else ""
        if failures:
            metadata[FALLBACK_KEY] = "; ".join(failures) + f"; answered by {metadata[MODEL_KEY]}"
        message.response_metadata = metadata
        return ChatResult(generations=[ChatGeneration(message=message)])

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        tools, tool_kwargs, call = self._split(kwargs)
        failures: list[str] = []
        for index, model in enumerate(self.models):
            try:
                answer = self._runnable(model, tools, tool_kwargs).invoke(
                    messages, stop=stop, **call
                )
            except Exception as exc:
                if provider_failure(exc) is None or index + 1 >= len(self.models):
                    if failures:
                        self._failed(index, exc)
                    raise
                failures.append(self._failed(index, exc))
                continue
            return self._stamp(answer, index, failures)
        raise RuntimeError(f"{self.agent or 'agent'} has no model to call")

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        tools, tool_kwargs, call = self._split(kwargs)
        failures: list[str] = []
        for index, model in enumerate(self.models):
            try:
                answer = await self._runnable(model, tools, tool_kwargs).ainvoke(
                    messages, stop=stop, **call
                )
            except Exception as exc:
                if provider_failure(exc) is None or index + 1 >= len(self.models):
                    if failures:
                        self._failed(index, exc)
                    raise
                failures.append(self._failed(index, exc))
                continue
            return self._stamp(answer, index, failures)
        raise RuntimeError(f"{self.agent or 'agent'} has no model to call")


def turn_model(message: Any, default: str = "") -> tuple[str, str]:
    """``(model label, fallback reason)`` for one answer.

    The reason is ``""`` on a turn the agent's first model gave.
    """
    metadata = getattr(message, "response_metadata", None)
    if not isinstance(metadata, dict):
        return default, ""
    return str(metadata.get(MODEL_KEY) or default), str(metadata.get(FALLBACK_KEY) or "")
