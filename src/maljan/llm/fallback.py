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
on the turn the list moved. The loop reads both into the ledger entry, the
conversation event and the run summary.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import threading
import time
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import ConfigDict, Field, PrivateAttr

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


# The packages whose exceptions carry an HTTP status a provider answered with.
# An integer ``.code`` on anything else says nothing about a provider: a
# library's own error code, an errno, a validator's number.
_PROVIDER_PACKAGES = frozenset({"openai", "anthropic", "httpx", "ollama", "google"})


def _status_of(exc: BaseException) -> int | None:
    package = (type(exc).__module__ or "").split(".", 1)[0]
    if package not in _PROVIDER_PACKAGES:
        return None
    candidates: list[Any] = [getattr(exc, "status_code", None), getattr(exc, "code", None)]
    response = getattr(exc, "response", None)
    candidates.append(getattr(response, "status_code", None))
    for value in candidates:
        if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599:
            return value
    return None


def _one(exc: BaseException) -> str | None:
    """The provider failure ``exc`` is, in words, or ``None``."""
    name = type(exc).__name__
    if isinstance(exc, ModelStalled):
        return str(exc)
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

    The explicit cause chain (``raise … from …``) is read too, a few links
    deep: a provider SDK wraps its transport's error that way, and the
    transport's error is the one that says what happened. The implicit
    context is not: an error raised *while handling* a provider failure — a
    parse error in an ``except`` block — is that error, not the provider's.
    Never raises; an exception it cannot read is not a provider failure, so it
    reaches the caller exactly as it did before.
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
        current = current.__cause__
    return None


# The longest ``Retry-After`` a provider may ask the same model to wait before
# the list moves on: a provider saying "in two seconds" about a model that is
# otherwise fine is answered by waiting two seconds, not by another model.
MAX_RETRY_AFTER_SECONDS = 30


class ModelStalled(TimeoutError):
    """A model on a list that did not answer within its turn deadline."""


def retry_after_seconds(exc: BaseException) -> float | None:
    """The provider's own ``Retry-After`` when it is at most thirty seconds, else ``None``."""
    headers = getattr(getattr(exc, "response", None), "headers", None)
    if headers is None:
        return None
    try:
        raw = str(headers.get("retry-after") or "").strip()
        seconds = float(raw)
    except (TypeError, ValueError, AttributeError):
        return None
    if 0 < seconds <= MAX_RETRY_AFTER_SECONDS:
        return seconds
    return None


class FallbackChatModel(BaseChatModel):
    """An agent's models, the next one asked only when the one before failed as a provider.

    **Sticky for the loop.** Once a model has failed as a provider and a later
    one has answered, the one that answered keeps answering for the rest of
    the agent's loop: a first model that stalls costs one turn deadline, not
    one per turn (forty steps at a five-minute stall is more than three hours
    of waiting no budget allows). :meth:`restart` — called where a loop
    starts — hands the next loop back to the first model. The switch is
    failure-driven only, and it is recorded once, on the turn it happened.

    **A turn deadline for every model but the last.** ``turn_deadline``
    seconds, shorter than the agent's loop budget, so a model that stops
    answering raises :class:`ModelStalled` inside this object — a provider
    failure — instead of being cancelled with the whole loop. The last model
    has nothing to fall back to and is bounded by the loop as a lone model is.

    **A short Retry-After is honoured.** A 429 or 503 that asks for at most
    thirty seconds is waited out on the same model once before the list moves
    on.

    Tools are bound per model at call time rather than once here, because each
    provider formats a tool its own way; what the loop binds is the
    OpenAI-shaped list every provider's own ``bind_tools`` reads.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    models: list[Any] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    agent: str = ""
    turn_deadline: float = 0.0

    _start: int = PrivateAttr(default=0)
    _lock: Any = PrivateAttr(default_factory=threading.Lock)

    @property
    def _llm_type(self) -> str:
        return "maljan-fallback"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {"agent": self.agent, "models": list(self.labels)}

    @property
    def answering(self) -> int:
        """The index of the model a turn starts at now."""
        with self._lock:
            return self._start

    def restart(self) -> None:
        """Start the next turn at the first model again — a new loop, a new stage."""
        with self._lock:
            self._start = 0

    def _stick(self, index: int) -> None:
        with self._lock:
            self._start = max(self._start, index)

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

    def _deadline(self, index: int) -> float | None:
        if self.turn_deadline > 0 and index + 1 < len(self.models):
            return self.turn_deadline
        return None

    def _label(self, index: int) -> str:
        return self.labels[index] if index < len(self.labels) else f"model {index + 1}"

    def _failed(self, index: int, exc: BaseException) -> str:
        """Log one provider failure and return the sentence the answer will carry."""
        reason = provider_failure(exc) or "the provider failed"
        logger.warning(
            "%s: %s failed (%s: %s); %s.",
            self.agent or "agent",
            self._label(index),
            type(exc).__name__,
            reason,
            "trying the next model" if index + 1 < len(self.models) else "no model is left to try",
        )
        return f"{self._label(index)}: {reason}"

    def _stamp(self, message: Any, index: int, failures: list[str]) -> ChatResult:
        if not isinstance(message, BaseMessage):
            message = AIMessage(content=str(getattr(message, "content", message)))
        metadata = dict(getattr(message, "response_metadata", None) or {})
        metadata[MODEL_KEY] = self._label(index) if index < len(self.labels) else ""
        if failures:
            metadata[FALLBACK_KEY] = (
                "; ".join(failures)
                + f"; answered by {metadata[MODEL_KEY]}, which answers the rest of this loop"
            )
            self._stick(index)
        message.response_metadata = metadata
        return ChatResult(generations=[ChatGeneration(message=message)])

    def _stalled(self, index: int, deadline: float) -> ModelStalled:
        return ModelStalled(
            f"{self._label(index)} did not answer within its {deadline:.0f} s turn deadline"
        )

    def _ask_sync(self, index: int, runnable: Any, messages: Any, stop: Any, call: Any) -> Any:
        deadline = self._deadline(index)
        if deadline is None:
            return runnable.invoke(messages, stop=stop, **call)
        # A thread, because a blocking call cannot be cancelled: the one left
        # behind ends at its provider's own request timeout.
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            future = pool.submit(runnable.invoke, messages, stop=stop, **call)
            try:
                return future.result(timeout=deadline)
            except concurrent.futures.TimeoutError as exc:
                raise self._stalled(index, deadline) from exc
        finally:
            pool.shutdown(wait=False)

    async def _ask_async(
        self, index: int, runnable: Any, messages: Any, stop: Any, call: Any
    ) -> Any:
        deadline = self._deadline(index)
        if deadline is None:
            return await runnable.ainvoke(messages, stop=stop, **call)
        try:
            return await asyncio.wait_for(
                runnable.ainvoke(messages, stop=stop, **call), timeout=deadline
            )
        except TimeoutError as exc:
            raise self._stalled(index, deadline) from exc

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        tools, tool_kwargs, call = self._split(kwargs)
        failures: list[str] = []
        index = self.answering
        waited = False
        while index < len(self.models):
            runnable = self._runnable(self.models[index], tools, tool_kwargs)
            try:
                answer = self._ask_sync(index, runnable, messages, stop, call)
            except Exception as exc:
                if provider_failure(exc) is None:
                    raise
                pause = None if waited else retry_after_seconds(exc)
                if pause is not None:
                    waited = True
                    time.sleep(pause)
                    continue
                failures.append(self._failed(index, exc))
                if index + 1 >= len(self.models):
                    raise
                index, waited = index + 1, False
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
        index = self.answering
        waited = False
        while index < len(self.models):
            runnable = self._runnable(self.models[index], tools, tool_kwargs)
            try:
                answer = await self._ask_async(index, runnable, messages, stop, call)
            except Exception as exc:
                if provider_failure(exc) is None:
                    raise
                pause = None if waited else retry_after_seconds(exc)
                if pause is not None:
                    waited = True
                    await asyncio.sleep(pause)
                    continue
                failures.append(self._failed(index, exc))
                if index + 1 >= len(self.models):
                    raise
                index, waited = index + 1, False
                continue
            return self._stamp(answer, index, failures)
        raise RuntimeError(f"{self.agent or 'agent'} has no model to call")


def restart_models(model: Any) -> None:
    """Hand the next loop back to the first model of a list; a no-op for any other model."""
    restart = getattr(model, "restart", None)
    if isinstance(model, FallbackChatModel) and callable(restart):
        restart()


def turn_share_seconds(cfg: Any, agent: str) -> float:
    """One model's turn deadline on a list: ``llm.fallback_turn_share`` of the agent's loop budget.

    The loop budget is read the way the loop reads it — the agent's own
    definition, then the per-agent override map, then the deployment's
    default — so the deadline is always shorter than the ``wait_for`` that
    would otherwise cancel the whole loop first.
    """
    try:
        share = float(getattr(cfg.llm, "fallback_turn_share", 0.5))
        definitions = getattr(getattr(cfg, "agents", None), "definitions", None) or {}
        definition = definitions.get(agent) if isinstance(definitions, dict) else None
        own = getattr(definition, "timeout_seconds", None)
        overrides = getattr(cfg, "react_agent_timeout_overrides", {}) or {}
        budget = own or overrides.get(agent) or getattr(cfg, "react_agent_timeout", 0)
        return max(1.0, float(budget) * share) if budget and share > 0 else 0.0
    except Exception as exc:  # noqa: BLE001 — no deadline is the lone-model behaviour
        logger.debug("fallback turn deadline not read (%s).", exc)
        return 0.0


def turn_model(message: Any, default: str = "") -> tuple[str, str]:
    """``(model label, fallback reason)`` for one answer.

    The reason is ``""`` on a turn the agent's first model gave.
    """
    metadata = getattr(message, "response_metadata", None)
    if not isinstance(metadata, dict):
        return default, ""
    return str(metadata.get(MODEL_KEY) or default), str(metadata.get(FALLBACK_KEY) or "")
