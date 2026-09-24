"""The model's measured generation rate, and the call timeouts it produces.

A configured per-call timeout is a number of seconds chosen for one model's
pace. A model a tenth as fast is given a tenth of the answer: at 3.8 tokens a
second a 600 s judge call can receive about 2,280 of its 8,192 tokens, and a
120 s composer section about 456 of its 900. So each call that has an output
budget is given the larger of its configured timeout and the time that budget
takes at the rate this job has measured for the model, times a margin. The
HTTP request carrying the call is given the same time
(:meth:`GenerationRates.request_timeout`), so a long answer at a measured pace
is not cut by the client before the wait around it ends.

The rate costs nothing to learn: every answer already says how many tokens it
generated and how long that took, and ``RateMeter`` reads it off each call as
the call returns. Where the provider reports it, the generation time is the
server's own — Ollama's ``eval_count`` and ``eval_duration``, llama.cpp's
``timings``, which the openai provider carries into the answer because the
OpenAI-compatible client would drop it (``openai_provider.with_server_timings``).
An endpoint that reports neither gives the output token count over the call's
wall clock instead; that clock includes reading the prompt, so the rate comes
out lower than the server's and the timeout longer, which is the safe side.
Until a model has answered once, no rate is known and the configured value
stands.

The same answers say how fast the model read its prompt, and that is recorded
beside the generation rate: Ollama's ``prompt_eval_count`` and
``prompt_eval_duration``, llama.cpp's ``timings.prompt_n``/``prompt_ms``. Both
count only the tokens the server actually read — a prefix it had cached is not
in them — so the rate is the reading speed itself. It is what a request that
re-sends a whole conversation to a model that must read all of it again is
sized from (``BaseAnalyst._force_final_synthesis``). Where the provider does
not report it — a hosted OpenAI-compatible API sends no ``timings`` — no
reading rate is known and nothing is sized from one.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler

from maljan.llm.registry import PROVIDER_REQUEST_TIMEOUT_SECONDS

# The time a call takes at the measured rates is multiplied by this before it
# is compared with the configured timeout. Where both of a model's rates are
# the server's own, the call's time is its prompt read plus its answer, each
# at its own rate, and the margin covers the spread between turns, which on
# the slow run went from about 70 s to 240 s around a typical 100 s. Where the
# reading rate is not measured, the answer alone is timed at the rate that
# includes the prompt read (the wall clock's, or Ollama's), as before.
TIMEOUT_MARGIN = 1.5

# The HTTP request timeout a call is sent with until its model has a measured
# rate: the one every provider builds its client with
# (``registry.PROVIDER_REQUEST_TIMEOUT_SECONDS``). httpx reads it as the
# longest silence it waits through, so it ended an answer only on a server that
# sends nothing until it has finished — a non-streaming llama.cpp server; a
# streamed answer, or DeepSeek's, which sends keep-alive lines while it
# generates, was not ended by it. Once a rate is measured a request whose
# output cap takes longer at that pace is given that time instead
# (``with_sized_request_timeout``), and the derived waits above are no longer
# held under it.
UNMEASURED_REQUEST_TIMEOUT_SECONDS = float(PROVIDER_REQUEST_TIMEOUT_SECONDS)

OLLAMA_SOURCE = "ollama eval_count/eval_duration"
LLAMA_CPP_SOURCE = "llama.cpp timings.predicted_n/predicted_ms"
WALL_CLOCK_SOURCE = "output tokens over the call's wall clock (prompt read included)"
OLLAMA_PROMPT_SOURCE = "ollama prompt_eval_count/prompt_eval_duration"
LLAMA_CPP_PROMPT_SOURCE = "llama.cpp timings.prompt_n/prompt_ms"


def measured_prompt_read(message: Any) -> tuple[int, float, str] | None:
    """``(tokens, seconds, source)`` the server spent reading one prompt, or ``None``.

    Only the server's own count and clock: a wall clock cannot tell reading
    from generating, and a rate that mixed them would size a request as if
    reading were as slow as writing.
    """
    meta = getattr(message, "response_metadata", None) or {}
    try:
        count, duration = meta.get("prompt_eval_count"), meta.get("prompt_eval_duration")
        if count and duration and int(count) > 0 and float(duration) > 0:
            return int(count), float(duration) / 1e9, OLLAMA_PROMPT_SOURCE
        timings = meta.get("timings")
        if isinstance(timings, dict):
            n, ms = timings.get("prompt_n"), timings.get("prompt_ms")
            if n and ms and int(n) > 0 and float(ms) > 0:
                return int(n), float(ms) / 1000.0, LLAMA_CPP_PROMPT_SOURCE
    except (TypeError, ValueError, AttributeError):
        return None
    return None


def measured_generation(
    message: Any, wall_seconds: float, *, server_timings: bool = True
) -> tuple[int, float, str] | None:
    """``(tokens, seconds, source)`` for one answer, or ``None`` when it says nothing.

    Read in the order of how close the number is to the generation itself:
    the server's own generation time first, the call's wall clock last.
    ``server_timings=False`` skips llama.cpp's ``timings``: the rate a timeout
    falls back on when no prompt reading rate is measured, which includes the
    prompt read.
    """
    meta = getattr(message, "response_metadata", None) or {}
    try:
        count, duration = meta.get("eval_count"), meta.get("eval_duration")
        if count and duration and int(count) > 0 and float(duration) > 0:
            return int(count), float(duration) / 1e9, OLLAMA_SOURCE
        timings = meta.get("timings") if server_timings else None
        if isinstance(timings, dict):
            n, ms = timings.get("predicted_n"), timings.get("predicted_ms")
            if n and ms and int(n) > 0 and float(ms) > 0:
                return int(n), float(ms) / 1000.0, LLAMA_CPP_SOURCE
        usage = getattr(message, "usage_metadata", None) or {}
        out = int(usage.get("output_tokens") or 0) if isinstance(usage, dict) else 0
        # An endpoint that reports no generation time lands here. The wall
        # clock includes reading the prompt, so this rate is lower than the
        # server's and every timeout sized from it longer — the safe side,
        # never a call cut short.
        if out > 0 and wall_seconds > 0:
            return out, float(wall_seconds), WALL_CLOCK_SOURCE
    except (TypeError, ValueError):
        return None
    return None


@dataclass
class _ModelRate:
    tokens: int = 0
    seconds: float = 0.0
    calls: int = 0
    sources: list[str] = field(default_factory=list)
    # The prompt the server read, measured the same way from the same answers.
    prompt_tokens: int = 0
    prompt_seconds: float = 0.0
    prompt_sources: list[str] = field(default_factory=list)
    # The same answers measured with their prompt read included: Ollama's own
    # generation rate, or the wall clock's where the server's timings are read.
    whole_tokens: int = 0
    whole_seconds: float = 0.0

    def rate(self) -> float | None:
        return self.tokens / self.seconds if self.tokens > 0 and self.seconds > 0 else None

    def prompt_rate(self) -> float | None:
        if self.prompt_tokens > 0 and self.prompt_seconds > 0:
            return self.prompt_tokens / self.prompt_seconds
        return None

    def whole_rate(self) -> float | None:
        if self.whole_tokens > 0 and self.whole_seconds > 0:
            return self.whole_tokens / self.whole_seconds
        return None


class GenerationRates:
    """Per model, the tokens generated and the time they took, for one job.

    Thread-safe: an analyst's tool loop calls its model from a worker thread
    while the graph's own loop runs another agent.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._models: dict[str, _ModelRate] = {}
        self._timeouts: dict[str, dict[str, Any]] = {}
        # Per agent, the output cap its calls were built with and how it was
        # reached, so a derived cap is printed where the timeouts it sizes are.
        self._output_caps: dict[str, dict[str, Any]] = {}

    def note_output_cap(self, agent: str, tokens: int, sentence: str) -> None:
        """Record the output cap ``agent``'s model was built with, and its derivation."""
        with self._lock:
            self._output_caps[str(agent)] = {"tokens": int(tokens), "derivation": str(sentence)}

    def observe(self, model: str, tokens: int, seconds: float, source: str) -> None:
        if tokens <= 0 or seconds <= 0:
            return
        with self._lock:
            row = self._models.setdefault(str(model), _ModelRate())
            row.tokens += int(tokens)
            row.seconds += float(seconds)
            row.calls += 1
            if source not in row.sources:
                row.sources.append(source)

    def observe_whole(self, model: str, tokens: int, seconds: float) -> None:
        """One answer measured with its prompt read included."""
        if tokens <= 0 or seconds <= 0:
            return
        with self._lock:
            row = self._models.setdefault(str(model), _ModelRate())
            row.whole_tokens += int(tokens)
            row.whole_seconds += float(seconds)

    def observe_prompt(self, model: str, tokens: int, seconds: float, source: str) -> None:
        """One prompt the server read: how many tokens, and how long it took."""
        if tokens <= 0 or seconds <= 0:
            return
        with self._lock:
            row = self._models.setdefault(str(model), _ModelRate())
            row.prompt_tokens += int(tokens)
            row.prompt_seconds += float(seconds)
            if source not in row.prompt_sources:
                row.prompt_sources.append(source)

    def rate(self, model: str) -> float | None:
        """Tokens a second over every measured answer of ``model``, or ``None``."""
        with self._lock:
            row = self._models.get(str(model))
            return row.rate() if row is not None else None

    def rate_source(self, model: str) -> list[str]:
        """Where ``model``'s generation rate was read from, in the order first seen."""
        with self._lock:
            row = self._models.get(str(model))
            return list(row.sources) if row is not None else []

    def prompt_rate(self, model: str) -> float | None:
        """Prompt tokens read a second over every measured answer of ``model``, or ``None``."""
        with self._lock:
            row = self._models.get(str(model))
            return row.prompt_rate() if row is not None else None

    def call_timeout(
        self,
        call: str,
        model: str,
        configured: float,
        max_tokens: int,
        *,
        budget: str = "",
        prompt_tokens: int = 0,
    ) -> float:
        """The seconds one call of ``call`` waits, and a record of how it was reached.

        With both of the model's server rates measured and the call's prompt
        size given: ``(prompt_tokens / prompt_rate + max_tokens / rate) ×
        TIMEOUT_MARGIN``. Otherwise ``max_tokens / whole_rate × TIMEOUT_MARGIN``,
        the rate that includes the prompt read (the server's rate where no
        whole one was measured). Never shorter than configured. With no rate
        or no output budget the configured value stands. ``budget`` is how the
        caller reached ``max_tokens``, kept with the row so the record says
        where both numbers came from.
        """
        configured = float(configured)
        tokens = int(max_tokens or 0)
        prompt = int(prompt_tokens or 0)
        derived, used_rate, read_rate = self._derived(model, tokens, prompt)
        applied = configured if derived is None else max(configured, derived)
        with self._lock:
            record: dict[str, Any] = {
                "model": str(model),
                "configured_s": configured,
                "max_tokens": tokens,
                "tokens_per_second": None if used_rate is None else round(used_rate, 3),
                "derived_s": None if derived is None else round(derived, 1),
                "applied_s": round(applied, 1),
            }
            if read_rate is not None:
                record["prompt_tokens"] = prompt
                record["prompt_tokens_per_second"] = round(read_rate, 3)
            self._timeouts[call] = record
            if budget:
                self._timeouts[call]["budget"] = budget
        return applied

    def _derived(
        self, model: str, tokens: int, prompt: int
    ) -> tuple[float | None, float | None, float | None]:
        """``(seconds, generation rate used, reading rate used)`` for one call, or no seconds.

        With both of the model's server rates measured and the prompt size
        given, the prompt read and the answer each at its own rate; otherwise
        the answer at the rate that includes the prompt read. ``None`` seconds
        with no rate measured or no output budget.
        """
        with self._lock:
            row = self._models.get(str(model))
            rate = row.rate() if row is not None else None
            prompt_rate = row.prompt_rate() if row is not None else None
            whole = row.whole_rate() if row is not None else None
        if rate is None or tokens <= 0:
            return None, rate, None
        if prompt > 0 and prompt_rate is not None:
            return (prompt / prompt_rate + tokens / rate) * TIMEOUT_MARGIN, rate, prompt_rate
        used = whole or rate
        return tokens / used * TIMEOUT_MARGIN, used, None

    def request_timeout(self, model: str, max_tokens: int, prompt_tokens: int = 0) -> float:
        """The HTTP request timeout one call of ``model`` is sent with, in seconds.

        The larger of :data:`UNMEASURED_REQUEST_TIMEOUT_SECONDS` and the time
        the call's output cap takes at the model's measured pace, by the same
        arithmetic and margin as :meth:`call_timeout`: a request is never cut
        before the wait around it would end. With no rate measured yet, or no
        output cap, the unmeasured timeout.
        """
        derived, _rate, _read = self._derived(model, int(max_tokens or 0), int(prompt_tokens or 0))
        if derived is None:
            return UNMEASURED_REQUEST_TIMEOUT_SECONDS
        return max(UNMEASURED_REQUEST_TIMEOUT_SECONDS, derived)

    def snapshot(self) -> dict[str, Any]:
        """Every measured rate and every timeout it produced, with the stated constants."""
        with self._lock:
            return {
                "margin": TIMEOUT_MARGIN,
                "unmeasured_request_timeout_s": UNMEASURED_REQUEST_TIMEOUT_SECONDS,
                "models": {
                    name: {
                        "tokens_per_second": (
                            None if row.rate() is None else round(row.rate() or 0.0, 3)
                        ),
                        "tokens": row.tokens,
                        "seconds": round(row.seconds, 3),
                        "calls": row.calls,
                        "sources": list(row.sources),
                        "prompt_tokens_per_second": (
                            None
                            if row.prompt_rate() is None
                            else round(row.prompt_rate() or 0.0, 3)
                        ),
                        "prompt_tokens": row.prompt_tokens,
                        "prompt_seconds": round(row.prompt_seconds, 3),
                        "prompt_sources": list(row.prompt_sources),
                    }
                    for name, row in sorted(self._models.items())
                },
                "timeouts": {call: dict(row) for call, row in sorted(self._timeouts.items())},
                **(
                    {"output_caps": {a: dict(r) for a, r in sorted(self._output_caps.items())}}
                    if self._output_caps
                    else {}
                ),
            }


class RateMeter(BaseCallbackHandler):
    """Reads each answer's generation count and time as the call returns.

    Attached to a built model, so every call on it — an analyst's turn, the
    mediator, the judge, the report stage — is measured without any call site
    having to remember to, and without a request of its own.
    """

    def __init__(self, rates: GenerationRates, model: str) -> None:
        self.rates = rates
        self.model = model
        self._started: dict[UUID, float] = {}
        self._lock = threading.Lock()

    def on_chat_model_start(
        self, serialized: dict[str, Any], messages: Any, *, run_id: UUID, **kwargs: Any
    ) -> None:
        with self._lock:
            self._started[run_id] = time.monotonic()

    def on_llm_start(
        self, serialized: dict[str, Any], prompts: Any, *, run_id: UUID, **kwargs: Any
    ) -> None:
        with self._lock:
            self._started[run_id] = time.monotonic()

    def on_llm_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        with self._lock:
            self._started.pop(run_id, None)

    def on_llm_end(self, response: Any, *, run_id: UUID, **kwargs: Any) -> None:
        with self._lock:
            started = self._started.pop(run_id, None)
        wall = time.monotonic() - started if started is not None else 0.0
        try:
            generation = response.generations[0][0]
        except (AttributeError, IndexError, TypeError):
            return
        message = getattr(generation, "message", None)
        measured = measured_generation(message, wall)
        info = getattr(generation, "generation_info", None)
        if measured is None and isinstance(info, dict):
            # The server's counts as the provider handed them over, for a path
            # that did not fold them into the message.
            measured = measured_generation(
                SimpleNamespace(
                    response_metadata=info,
                    usage_metadata=getattr(message, "usage_metadata", None),
                ),
                wall,
            )
        if measured is not None:
            self.rates.observe(self.model, *measured)
        whole = measured_generation(message, wall, server_timings=False)
        if whole is not None:
            self.rates.observe_whole(self.model, whole[0], whole[1])
        read = measured_prompt_read(message)
        if read is None and isinstance(info, dict):
            read = measured_prompt_read(SimpleNamespace(response_metadata=info))
        if read is not None:
            self.rates.observe_prompt(self.model, *read)


def _fallback_list(llm: Any) -> list[Any] | None:
    """The models of an agent's fallback list, or ``None`` for a single model."""
    models = getattr(llm, "models", None)
    if isinstance(models, list) and models and hasattr(llm, "answering"):
        return models
    return None


def model_name_of(llm: Any) -> str:
    """The model a chat model object calls, as the rates are keyed.

    For an agent's fallback list it is the model a turn starts at now — the
    one that will answer unless it fails as a provider.
    """
    models = _fallback_list(llm)
    if models is not None:
        try:
            return model_name_of(models[min(int(llm.answering), len(models) - 1)])
        except Exception:  # noqa: BLE001 — a name is a label, never a failure
            return model_name_of(models[0])
    name = type(llm).__name__
    for attr in ("model_name", "model"):
        value = getattr(llm, attr, None)
        if isinstance(value, str) and value:
            name = value
            break
    # Keyed by the server too: one tag served by a local and a remote Ollama is
    # two paces. The label keeps scheme and host only, never a credential.
    endpoint = _endpoint_of(llm)
    return f"{name} @ {endpoint}" if endpoint else name


def _endpoint_of(llm: Any) -> str:
    for attr in ("openai_api_base", "base_url", "anthropic_api_url"):
        value = getattr(llm, attr, None)
        if isinstance(value, str) and value:
            from maljan.core.model_assignments import endpoint_label

            return endpoint_label(value)
    return ""


def attach_rate_meter(llm: Any, rates: GenerationRates | None, model: str | None = None) -> Any:
    """Add a ``RateMeter`` to ``llm``'s callbacks, once; returns ``llm``.

    An agent's fallback list is metered model by model rather than as the
    list, so each answer is counted against the model that actually gave it.
    Never raises: a model object that takes no callbacks is left as it is and
    its calls keep the configured timeouts.
    """
    if rates is None or llm is None:
        return llm
    models = _fallback_list(llm)
    if models is not None:
        for inner in models:
            attach_rate_meter(inner, rates)
        return llm
    try:
        existing = list(getattr(llm, "callbacks", None) or [])
        if any(isinstance(cb, RateMeter) for cb in existing):
            return llm
        meter = RateMeter(rates, model or model_name_of(llm))
        object.__setattr__(llm, "callbacks", [*existing, meter])
    except Exception:  # noqa: BLE001 — measurement must never break a model
        return llm
    return llm


# The payload fields an output cap is sent under, in the order they are read:
# chat completions' two and the Responses API's.
_PAYLOAD_CAP_KEYS = ("max_completion_tokens", "max_tokens", "max_output_tokens")

# Where a built model keeps the request timeout its client was given.
_CLIENT_TIMEOUT_ATTRS = ("request_timeout", "default_request_timeout", "timeout")


def _meter_of(llm: Any) -> RateMeter | None:
    """The ``RateMeter`` attached to ``llm``, or ``None``."""
    return next(
        (cb for cb in (getattr(llm, "callbacks", None) or []) if isinstance(cb, RateMeter)),
        None,
    )


def carry_rate_meter(source: Any, target: Any) -> Any:
    """Attach ``source``'s meter to ``target`` as well, when it has one; returns ``target``.

    For a model rebuilt in place of another — the llama.cpp self-heal — so the
    replacement's answers are measured, and its requests sized, as the
    original's were.
    """
    meter = _meter_of(source)
    if meter is None:
        return target
    return attach_rate_meter(target, meter.rates, meter.model)


def _client_timeout(llm: Any) -> float:
    """The request timeout ``llm``'s client was built with, or the unmeasured one."""
    for attr in _CLIENT_TIMEOUT_ATTRS:
        value = getattr(llm, attr, None)
        if isinstance(value, int | float) and not isinstance(value, bool) and value > 0:
            return float(value)
    return UNMEASURED_REQUEST_TIMEOUT_SECONDS


def sized_request_timeout(llm: Any, cap: int, prompt_chars: int = 0) -> float | None:
    """The timeout one request of ``llm`` needs beyond its client's, or ``None``.

    The time the request's output cap takes at the model's measured pace, by
    :meth:`GenerationRates.request_timeout`'s arithmetic, with its prompt at
    ``CHARS_PER_TOKEN`` characters a token. ``None`` — the client's own timeout
    stands — for a model with no meter, no measured rate yet, a request with no
    cap, or one whose derived time is within what its client already allows.
    Never raises.
    """
    try:
        meter = _meter_of(llm)
        if meter is None or int(cap or 0) <= 0:
            return None
        if meter.rates.rate(meter.model) is None:
            return None
        from maljan.llm.context_window import CHARS_PER_TOKEN

        seconds = meter.rates.request_timeout(
            meter.model, int(cap), -(-max(0, int(prompt_chars)) // CHARS_PER_TOKEN)
        )
        return seconds if seconds > _client_timeout(llm) else None
    except Exception:  # noqa: BLE001 — a timeout that cannot be sized keeps the client's
        return None


def _content_chars(entries: Any) -> int:
    """The characters of a request's messages (chat completions) or input items (Responses)."""
    if isinstance(entries, str):
        return len(entries)
    total = 0
    for entry in entries or []:
        if isinstance(entry, dict):
            total += len(str(entry.get("content") or ""))
        else:
            total += len(str(getattr(entry, "content", "") or ""))
    return total


def request_timeout_for(llm: Any, payload: dict[str, Any]) -> float | None:
    """The HTTP request timeout one request of ``llm`` is sent with, or ``None``.

    Read from the request itself: its output cap (``max_completion_tokens``,
    ``max_tokens`` or the Responses API's ``max_output_tokens``) and its prompt
    (``messages``, or the Responses API's ``input``), sized by
    :func:`sized_request_timeout`. Never raises.
    """
    try:
        cap = 0
        for key in _PAYLOAD_CAP_KEYS:
            value = payload.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                cap = value
                break
        chars = _content_chars(payload.get("messages")) + _content_chars(payload.get("input"))
        return sized_request_timeout(llm, cap, chars)
    except Exception:  # noqa: BLE001 — a timeout that cannot be sized keeps the client's
        return None


# One subclass per chat class seen, so pydantic builds each schema once.
_SIZED_CLASSES: dict[type, type] = {}


def with_sized_request_timeout(chat_class: Any) -> Any:
    """``chat_class`` sending each request with a timeout sized for its answer.

    The client is built with ``PROVIDER_REQUEST_TIMEOUT_SECONDS``. httpx reads
    that as the longest silence it waits through, not as a deadline for the
    whole answer, so it ended a request only where the server sent nothing
    until it had finished — a non-streaming llama.cpp server, which kept a
    long answer to about 1,800 s of generation. Each request now carries its
    own ``timeout`` where the model's pace is measured and its output cap takes
    longer than the client allows: the SDK's per-request option, which
    overrides the client's (:func:`request_timeout_for`). Anything else is sent
    as it was.

    Chat classes that build an OpenAI-style payload (``_get_request_payload``)
    get the timeout in the payload; Gemini's (``_prepare_request``) gets it as
    the ``timeout`` argument that method reads.
    """
    if not isinstance(chat_class, type):
        return chat_class
    cached = _SIZED_CLASSES.get(chat_class)
    if cached is not None:
        return cached
    base: Any = chat_class
    members: dict[str, Any] = {}

    if hasattr(chat_class, "_get_request_payload"):

        def _get_request_payload(self: Any, input_: Any, *, stop: Any = None, **kwargs: Any) -> Any:
            payload = base._get_request_payload(self, input_, stop=stop, **kwargs)
            if isinstance(payload, dict) and "timeout" not in payload:
                seconds = request_timeout_for(self, payload)
                if seconds is not None:
                    payload["timeout"] = seconds
            return payload

        members["_get_request_payload"] = _get_request_payload
    elif hasattr(chat_class, "_prepare_request"):

        def _prepare_request(self: Any, messages: Any, **kwargs: Any) -> Any:
            if kwargs.get("timeout") is None:
                cap = kwargs.get("max_output_tokens") or getattr(self, "max_output_tokens", 0)
                seconds = sized_request_timeout(self, int(cap or 0), _content_chars(messages))
                if seconds is not None:
                    kwargs["timeout"] = seconds
            return base._prepare_request(self, messages, **kwargs)

        members["_prepare_request"] = _prepare_request
    else:
        return chat_class

    sized = type(chat_class.__name__, (chat_class,), members)
    _SIZED_CLASSES[chat_class] = sized
    return sized
