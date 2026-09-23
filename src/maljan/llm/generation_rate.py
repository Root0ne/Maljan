"""The model's measured generation rate, and the call timeouts it produces.

A configured per-call timeout is a number of seconds chosen for one model's
pace. A model a tenth as fast is given a tenth of the answer: at 3.8 tokens a
second a 600 s judge call can receive about 2,280 of its 8,192 tokens, and a
120 s composer section about 456 of its 900. So each call that has an output
budget is given the larger of its configured timeout and the time that budget
takes at the rate this job has measured for the model, times a margin, never
above a ceiling.

The rate costs nothing to learn: every answer already says how many tokens it
generated and how long that took, and ``RateMeter`` reads it off each call as
the call returns. Where the provider reports it, the generation time is the
server's own — Ollama's ``eval_count`` and ``eval_duration``, llama.cpp's
``timings``. The OpenAI-compatible client drops llama.cpp's ``timings`` before
the answer reaches this code, so there the output token count is divided by the
call's wall clock instead; that clock includes reading the prompt, so the rate
comes out lower than the server's and the timeout longer, which is the safe
side. Until a model has answered once, no rate is known and the configured
value stands.

The same answers say how fast the model read its prompt, and that is recorded
beside the generation rate: Ollama's ``prompt_eval_count`` and
``prompt_eval_duration``, llama.cpp's ``timings.prompt_n``/``prompt_ms``. Both
count only the tokens the server actually read — a prefix it had cached is not
in them — so the rate is the reading speed itself. It is what a request that
re-sends a whole conversation to a model that must read all of it again is
sized from (``BaseAnalyst._force_final_synthesis``). Where the provider does
not report it — the OpenAI-compatible client drops llama.cpp's ``timings`` — no
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

# The time a budget takes at the measured rate is multiplied by this before it
# is compared with the configured timeout. It covers what the rate leaves out
# — the prompt read before the first token, which on the slow run's 27–36K
# character prompts is not small — and the spread between turns, which on that
# run went from about 70 s to 240 s around a typical 100 s.
TIMEOUT_MARGIN = 1.5

# No derived timeout goes above this. It is the HTTP request timeout every
# provider builds its client with (``registry.PROVIDER_REQUEST_TIMEOUT_SECONDS``,
# 1,800 s), because a wait longer than that is cut by the client before this
# one would fire. At 3.8 tokens a second the judge's 8,192-token budget needs
# 8,192 / 3.8 × 1.5 ≈ 3,234 s; held at 1,800 s it receives about 6,840 tokens,
# against the 2,280 its configured 600 s allowed. A configured value above the
# ceiling is the operator's and is kept.
TIMEOUT_CEILING_SECONDS = float(PROVIDER_REQUEST_TIMEOUT_SECONDS)

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


def measured_generation(message: Any, wall_seconds: float) -> tuple[int, float, str] | None:
    """``(tokens, seconds, source)`` for one answer, or ``None`` when it says nothing.

    Read in the order of how close the number is to the generation itself:
    the server's own generation time first, the call's wall clock last.
    """
    meta = getattr(message, "response_metadata", None) or {}
    try:
        count, duration = meta.get("eval_count"), meta.get("eval_duration")
        if count and duration and int(count) > 0 and float(duration) > 0:
            return int(count), float(duration) / 1e9, OLLAMA_SOURCE
        timings = meta.get("timings")
        if isinstance(timings, dict):
            n, ms = timings.get("predicted_n"), timings.get("predicted_ms")
            if n and ms and int(n) > 0 and float(ms) > 0:
                return int(n), float(ms) / 1000.0, LLAMA_CPP_SOURCE
        usage = getattr(message, "usage_metadata", None) or {}
        out = int(usage.get("output_tokens") or 0) if isinstance(usage, dict) else 0
        # The llama.cpp path lands here: its ``timings`` do not survive the
        # OpenAI-compatible client. The wall clock includes reading the prompt,
        # so this rate is lower than the server's and every timeout sized from
        # it longer — the safe side, never a call cut short.
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

    def rate(self) -> float | None:
        return self.tokens / self.seconds if self.tokens > 0 and self.seconds > 0 else None

    def prompt_rate(self) -> float | None:
        if self.prompt_tokens > 0 and self.prompt_seconds > 0:
            return self.prompt_tokens / self.prompt_seconds
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

    def call_timeout(self, call: str, model: str, configured: float, max_tokens: int) -> float:
        """The seconds one call of ``call`` waits, and a record of how it was reached.

        ``max(configured, min(max_tokens / rate × TIMEOUT_MARGIN, ceiling))``:
        never shorter than configured, never raised past the ceiling. With no
        rate or no output budget the configured value stands.
        """
        configured = float(configured)
        rate = self.rate(model)
        derived: float | None = None
        applied = configured
        if rate is not None and int(max_tokens or 0) > 0:
            derived = int(max_tokens) / rate * TIMEOUT_MARGIN
            applied = max(configured, min(derived, TIMEOUT_CEILING_SECONDS))
        with self._lock:
            self._timeouts[call] = {
                "model": str(model),
                "configured_s": configured,
                "max_tokens": int(max_tokens or 0),
                "tokens_per_second": None if rate is None else round(rate, 3),
                "derived_s": None if derived is None else round(derived, 1),
                "applied_s": round(applied, 1),
            }
        return applied

    def snapshot(self) -> dict[str, Any]:
        """Every measured rate and every timeout it produced, with the stated constants."""
        with self._lock:
            return {
                "margin": TIMEOUT_MARGIN,
                "ceiling_s": TIMEOUT_CEILING_SECONDS,
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
