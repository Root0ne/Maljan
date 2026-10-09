"""What one run spent on its models, in the provider's own figures.

LangChain responses carry ``usage_metadata`` (``input_tokens`` /
``output_tokens``) when the provider reported usage, and an OpenAI-compatible
router may report what the call cost as well. ``TokenLedger`` is a thread-safe
accumulator of exactly that: one instance lives on the ``ServiceContainer`` (one
per analysis run), every model call adds its usage to it under the agent that
made the call and the model that answered, and the judge node snapshots it into
the ``RunSummary``.

A call whose provider reported no usage is counted as a call and as **not
reported** — never as an estimate — and recorded by the agent that made it,
the call it was and the model that answered, so a run summary that says "not
reported for one call" can also say which one. A figure printed as a count is a count the
provider gave; where it gave none, the report says so. The same rule holds for
cost: there is no price table here, and a cost appears only where the provider
reported one. Recording never raises — telemetry must not break analysis.

Three parts of a call are recorded where the provider reports them, and only
there: the input tokens it read from its prompt cache, the input tokens it
wrote to it (Anthropic's ``cache_creation_input_tokens``), and the output
tokens its model spent reasoning. Each is a part of the input or output count,
not an addition to it — a provider that bills cached or cache-written input at
its own rate, or counts reasoning inside the output, is read off the same
figures. A call that did not report a part is not counted as a zero for it:
each part carries the number of calls that reported it.

Every call also says which model answered it, so the ledger is where a run's
per-agent model count comes from, and a fallback — a turn another model
answered because the first one failed as a provider — is kept with its reason.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from typing import Any


def estimate_tokens(text: str) -> int:
    """Cheap, dependency-free token estimate (~4 chars/token).

    For a spending *ceiling* checked before a call is made, where nothing has
    been reported yet. Never used for a figure the run reports as spent.
    """
    if not text:
        return 0
    return max(1, len(text) // 4)


def _cost_of(response: Any) -> float | None:
    """The cost the provider reported for this call, or ``None`` when it reported none."""
    metadata = getattr(response, "response_metadata", None)
    if not isinstance(metadata, dict):
        return None
    for holder in (metadata.get("token_usage"), metadata.get("usage"), metadata):
        if isinstance(holder, dict):
            value = holder.get("cost")
            if isinstance(value, int | float) and not isinstance(value, bool) and value >= 0:
                return float(value)
    return None


def _count(value: Any) -> int | None:
    """``value`` as a token count, or ``None`` when it is not one."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return max(0, int(value))


def _raw_usage(response: Any) -> dict[str, Any]:
    """The usage block as the provider sent it, where the client kept it."""
    metadata = getattr(response, "response_metadata", None)
    if not isinstance(metadata, dict):
        return {}
    raw = metadata.get("token_usage") or metadata.get("usage")
    return raw if isinstance(raw, dict) else {}


def _cached_input_of(usage: dict[str, Any], raw: dict[str, Any]) -> int | None:
    """The input tokens the provider read from its prompt cache, or ``None`` unreported.

    LangChain's ``input_token_details.cache_read`` first — every client fills
    it from its provider's own field (OpenAI's and DeepSeek's
    ``prompt_tokens_details.cached_tokens``, Anthropic's cache reads) — and
    DeepSeek's ``prompt_cache_hit_tokens`` where only that was sent.
    """
    details = usage.get("input_token_details")
    if isinstance(details, dict):
        found = _count(details.get("cache_read"))
        if found is not None:
            return found
    return _count(raw.get("prompt_cache_hit_tokens"))


def _cache_writes_of(usage: dict[str, Any]) -> tuple[int, int] | None:
    """``(input tokens written to the prompt cache, of them for an hour)``, or ``None`` unreported.

    LangChain's ``input_token_details`` as langchain-anthropic fills it from
    Anthropic's usage: ``cache_creation`` (``cache_creation_input_tokens``),
    or, where Anthropic splits the writes by lifetime, its
    ``ephemeral_5m_input_tokens`` and ``ephemeral_1h_input_tokens`` with
    ``cache_creation`` set to zero so the two are not counted twice. No other
    provider reports a cache write.
    """
    details = usage.get("input_token_details")
    if not isinstance(details, dict):
        return None
    whole = _count(details.get("cache_creation"))
    five = _count(details.get("ephemeral_5m_input_tokens"))
    hour = _count(details.get("ephemeral_1h_input_tokens"))
    if whole is None and five is None and hour is None:
        return None
    split = (five or 0) + (hour or 0)
    return max(whole or 0, split), min(hour or 0, max(whole or 0, split))


def _reasoning_of(usage: dict[str, Any], raw: dict[str, Any]) -> int | None:
    """The output tokens the model spent reasoning, or ``None`` unreported.

    ``output_token_details.reasoning`` first, the provider's own
    ``completion_tokens_details.reasoning_tokens`` where the client left it.
    """
    details = usage.get("output_token_details")
    if isinstance(details, dict):
        found = _count(details.get("reasoning"))
        if found is not None:
            return found
    completion = raw.get("completion_tokens_details")
    if isinstance(completion, dict):
        return _count(completion.get("reasoning_tokens"))
    return None


def turn_usage(response: Any) -> dict[str, Any] | None:
    """One answer's reported usage, or ``None``.

    ``{input_tokens, output_tokens[, cached_input_tokens][, cache_write_input_tokens
    [, cache_write_1h_input_tokens]][, reasoning_tokens][, cost][, sent_at]}``: the
    optional keys are there only when the provider reported them (``sent_at``
    when the client stamped the request's send time). ``None``
    is the provider having reported nothing, which the caller says in words
    rather than as a zero.
    """
    usage = getattr(response, "usage_metadata", None)
    if not isinstance(usage, dict) or usage.get("input_tokens") is None:
        return None
    out: dict[str, Any] = {
        "input_tokens": max(0, int(usage.get("input_tokens") or 0)),
        "output_tokens": max(0, int(usage.get("output_tokens") or 0)),
    }
    raw = _raw_usage(response)
    cached = _cached_input_of(usage, raw)
    if cached is not None:
        out["cached_input_tokens"] = min(cached, out["input_tokens"])
    writes = _cache_writes_of(usage)
    if writes is not None:
        room = out["input_tokens"] - out.get("cached_input_tokens", 0)
        written = min(writes[0], room)
        out["cache_write_input_tokens"] = written
        if writes[1]:
            out["cache_write_1h_input_tokens"] = min(writes[1], written)
    reasoning = _reasoning_of(usage, raw)
    if reasoning is not None:
        out["reasoning_tokens"] = min(reasoning, out["output_tokens"])
    cost = _cost_of(response)
    if cost is not None:
        out["cost"] = cost
    # When the request was sent, where the model's client stamped it: the
    # spend ceiling prices a call at the rate in force then. Not a usage
    # figure, and no tally reads it.
    metadata = getattr(response, "response_metadata", None)
    sent = metadata.get("sent_at") if isinstance(metadata, dict) else None
    if isinstance(sent, int | float) and not isinstance(sent, bool) and sent > 0:
        out["sent_at"] = float(sent)
    return out


class _Tally:
    """One agent's calls: the reported figures, and the calls that reported none."""

    __slots__ = (
        "cache_write_calls",
        "cache_write_input_tokens",
        "cached_calls",
        "cached_input_tokens",
        "calls",
        "cost",
        "cost_calls",
        "input_tokens",
        "models",
        "output_tokens",
        "reasoning_calls",
        "reasoning_tokens",
        "unreported",
    )

    def __init__(self) -> None:
        self.calls = 0
        self.unreported = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.cached_input_tokens = 0
        self.cached_calls = 0
        self.cache_write_input_tokens = 0
        self.cache_write_calls = 0
        self.reasoning_tokens = 0
        self.reasoning_calls = 0
        self.cost = 0.0
        self.cost_calls = 0
        self.models: dict[str, int] = {}

    def as_dict(self) -> dict[str, Any]:
        return {
            "llm_calls": self.calls,
            "unreported_calls": self.unreported,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.input_tokens + self.output_tokens,
            # The two parts, each with the calls that reported it, and absent
            # when none did — for the reason the cost below is.
            **(
                {
                    "cached_input_tokens": self.cached_input_tokens,
                    "cached_calls": self.cached_calls,
                }
                if self.cached_calls
                else {}
            ),
            **(
                {
                    "cache_write_input_tokens": self.cache_write_input_tokens,
                    "cache_write_calls": self.cache_write_calls,
                }
                if self.cache_write_calls
                else {}
            ),
            **(
                {"reasoning_tokens": self.reasoning_tokens, "reasoning_calls": self.reasoning_calls}
                if self.reasoning_calls
                else {}
            ),
            # Absent rather than zero when no call reported a cost: zero is a
            # figure a provider can report, and "reported nothing" is not it.
            **(
                {"cost": round(self.cost, 6), "cost_calls": self.cost_calls}
                if self.cost_calls
                else {}
            ),
            "models": dict(sorted(self.models.items())),
        }


# The parts of a call's usage a durable record of it carries, where the
# provider reported them.
_CALL_PARTS: tuple[str, ...] = (
    "input_tokens",
    "output_tokens",
    "cached_input_tokens",
    "cache_write_input_tokens",
    "reasoning_tokens",
    "cost",
)


def call_record(
    usage: dict[str, Any] | None, *, agent: str = "", model: str = "", call: str = ""
) -> dict[str, Any]:
    """One call as the ledger recorded it: who made it, which model answered, what it reported.

    ``reported`` is false for a call whose provider reported no usage, and the
    record then carries no figure: an absent figure is not a zero. A part the
    provider did not report is left out for the same reason.
    """
    row: dict[str, Any] = {
        "agent": str(agent),
        "model": str(model),
        "call": str(call),
        "reported": usage is not None,
    }
    if usage is None:
        return row
    for part in _CALL_PARTS:
        value = usage.get(part)
        if isinstance(value, int | float) and not isinstance(value, bool):
            row[part] = float(value) if part == "cost" else int(value)
    return row


class TokenLedger:
    """Thread-safe tally of what one run's model calls spent, per agent and per model."""

    def __init__(self, spend: Any = None) -> None:
        self._lock = threading.Lock()
        # The job's spend meter (``core.spend.SpendMeter``), handed every
        # recorded call; ``None`` where nothing prices the run.
        self.spend = spend
        self._total = _Tally()
        self._agents: dict[str, _Tally] = {}
        self._fallbacks: list[dict[str, str]] = []
        # One row per failed attempt a provider was asked again after
        # (``maljan.llm.transient``), filed under the call that then answered.
        self._retries: list[dict[str, str]] = []
        self._unreported: list[dict[str, str]] = []
        # Told of every recorded call as it is recorded, with the call's own
        # figures (``call_record``): the worker commits each one to the job's
        # event record once its loop runs the publish, so what a run spent is
        # known call by call even when its process dies before any summary is
        # built (all but a call recorded in the last moments before the kill).
        # ``None`` where nothing listens.
        self.on_call: Callable[[dict[str, Any]], None] | None = None

    def add(
        self,
        usage: dict[str, Any] | None,
        *,
        agent: str = "",
        model: str = "",
        fallback: str = "",
        call: str = "",
        estimated: dict[str, Any] | None = None,
        retries: Sequence[str] = (),
    ) -> None:
        """One call: its reported usage, or ``None`` when the provider reported none.

        ``call`` names what the call was — a tool-loop turn, the verdict, a
        report section — and is recorded for a call that reported no usage.
        ``estimated`` is a stated estimate of a call that reported none (an
        answer ended while it streamed): it is handed to the spend meter only,
        and the call stays one that reported no usage here. ``retries`` are
        the failed attempts made before this call answered, one line each.
        """
        with self._lock:
            if usage is None:
                self._unreported.append({"agent": agent, "call": call, "model": model})
            tallies = [self._total]
            if agent:
                tallies.append(self._agents.setdefault(agent, _Tally()))
            for tally in tallies:
                tally.calls += 1
                if model:
                    tally.models[model] = tally.models.get(model, 0) + 1
                if usage is None:
                    tally.unreported += 1
                    continue
                tally.input_tokens += int(usage.get("input_tokens") or 0)
                tally.output_tokens += int(usage.get("output_tokens") or 0)
                if "cached_input_tokens" in usage:
                    tally.cached_input_tokens += int(usage["cached_input_tokens"] or 0)
                    tally.cached_calls += 1
                if "cache_write_input_tokens" in usage:
                    tally.cache_write_input_tokens += int(usage["cache_write_input_tokens"] or 0)
                    tally.cache_write_calls += 1
                if "reasoning_tokens" in usage:
                    tally.reasoning_tokens += int(usage["reasoning_tokens"] or 0)
                    tally.reasoning_calls += 1
                if "cost" in usage:
                    tally.cost += float(usage["cost"])
                    tally.cost_calls += 1
            if fallback:
                self._fallbacks.append({"agent": agent, "model": model, "reason": fallback})
            for reason in retries:
                self._retries.append({"agent": agent, "model": model, "reason": str(reason)})
        if self.spend is not None:
            self.spend.settle(usage, model, call, estimated=estimated)
        listener = self.on_call
        if listener is not None:
            try:
                listener(call_record(usage, agent=agent, model=model, call=call))
            except Exception:  # noqa: BLE001 — recording never raises
                pass

    @property
    def input_tokens(self) -> int:
        return self._total.input_tokens

    @property
    def output_tokens(self) -> int:
        return self._total.output_tokens

    @property
    def calls(self) -> int:
        return self._total.calls

    @property
    def total_tokens(self) -> int:
        return self._total.input_tokens + self._total.output_tokens

    def snapshot(self) -> dict[str, Any]:
        """A plain-dict copy for handing to the RunSummary builder."""
        with self._lock:
            out = self._total.as_dict()
            out.pop("models", None)
            out["agents"] = {name: tally.as_dict() for name, tally in sorted(self._agents.items())}
            out["fallbacks"] = [dict(row) for row in self._fallbacks]
            # Present only when a provider was asked again, so a run without
            # one reads as it always did.
            if self._retries:
                out["retries"] = [dict(row) for row in self._retries]
            # Which calls reported no usage, one row each, present only when
            # one did: ``unreported_calls`` is their count.
            if self._unreported:
                out["unreported"] = [dict(row) for row in self._unreported]
            return out


def record_response_usage(
    ledger: TokenLedger | None,
    response: Any,
    *,
    agent: str = "",
    model: str = "",
    call: str = "",
) -> None:
    """Add one model answer to ``ledger`` (no-op if ledger is None). Never raises.

    ``model`` is the label of the model the caller asked; an answer that says
    which model gave it — a fallback list stamps every answer — wins over it.
    ``call`` names what the call was, for a call that reported no usage.
    """
    if ledger is None:
        return
    try:
        from maljan.llm.fallback import turn_model
        from maljan.llm.stream_watch import estimated_usage
        from maljan.llm.transient import retries_of

        answered_by, fallback = turn_model(response, model)
        usage = turn_usage(response)
        ledger.add(
            usage,
            agent=agent,
            model=answered_by,
            fallback=fallback,
            call=call,
            # An answer ended while it streamed reported nothing, and carries a
            # stated estimate for the spend ceiling; the reported figures stay
            # absent.
            estimated=None if usage is not None else estimated_usage(response),
            retries=retries_of(response),
        )
    except Exception:  # noqa: BLE001 — telemetry must never break analysis
        return


def structured_answer(
    answer: Any,
    ledger: TokenLedger | None,
    *,
    agent: str = "",
    model: str = "",
    call: str = "",
) -> Any:
    """The parsed value of a ``with_structured_output(..., include_raw=True)`` answer.

    The raw turn is recorded on ``ledger`` first: the parser hides the usage,
    and a structured call the ledger never sees is a call the run's total
    leaves out. A parse that failed raises its error, as the structured call
    would have without ``include_raw``, so a caller's fallback still runs. An
    answer in any other shape — a stand-in that ignores ``include_raw`` — is
    handed back as it is.
    """
    if not (isinstance(answer, dict) and "raw" in answer and "parsed" in answer):
        return answer
    record_response_usage(ledger, answer.get("raw"), agent=agent, model=model, call=call)
    error = answer.get("parsing_error")
    if answer.get("parsed") is None and error is not None:
        raise error if isinstance(error, BaseException) else ValueError(str(error))
    return answer.get("parsed")
