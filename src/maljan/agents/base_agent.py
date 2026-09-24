"""Abstract base class for all domain expert analyst agents.

Subclasses implement ``analyze`` / ``revise`` for raw text and may also
override the ``analyze_isr`` / ``revise_isr`` pair to produce richer
structured output (``AgentISR``). The safe wrappers add token truncation
and exception translation so callers see a uniform ``AnalystError`` API.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import itertools
import json
import re
import sys
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Mapping, Sequence
from concurrent.futures import CancelledError as _FuturesCancelled
from concurrent.futures import Future as _ConcurrentFuture
from concurrent.futures import TimeoutError as _FuturesTimeout
from dataclasses import replace
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, cast

import tiktoken
from langchain_core.language_models.chat_models import BaseChatModel

if TYPE_CHECKING:
    from langchain_core.messages import BaseMessage

from maljan.agents.prompt_fragments import CLAIM_FORMAT_FRAGMENT
from maljan.core.config import get_settings
from maljan.core.exceptions import AgentLoopCancelled, AnalystError
from maljan.core.logger import logger
from maljan.core.token_ledger import TokenLedger, record_response_usage
from maljan.llm.context_window import (
    CHARS_PER_TOKEN,
    NO_ROOM_RUN_STATE,
    tool_definition_chars,
    window_full_error,
)
from maljan.pipeline.validation import (
    ABSENCE_CLAIM_CODE,
    ALIGNMENT_MARGIN,
    ANALYST_CUT_CODE,
    CLAIM_DOES_NOT_DESCRIBE_CODE,
    VALIDITY_CODE,
    ValidationTally,
    Violation,
    analyst_cut_violation,
    mark_invalid_technique_ids,
    parse_violations,
    retry_with_feedback_sync,
    validate_isr,
    validity_check_available,
)
from maljan.schemas.evidence import ENTRY_ID_RE, EvidenceCounter, LedgerEntry, apply_budget
from maljan.schemas.isr_models import AgentISR, Artifact, ClaimEvidence, Finding
from maljan.schemas.tool_evidence import CapturedToolOutput
from maljan.utils.marked_cut import CUT_MARK

# Regex: matches MITRE ATT&CK technique IDs like T1055 or T1055.001.
_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")

# Regex: the ReAct stop message emitted when an agent exhausts its
# ``recursion_limit`` while still tool-calling (it never wrote a final answer).
# The static analyst's Ghidra loop hits this after spending its whole step
# budget gathering evidence; matching it lets ``execute_tool_loop`` salvage that
# gathered tool output with a forced-synthesis call instead of discarding it and
# returning a useless "need more steps" non-answer. (Phrase observed across
# live runs; it is not a maljan/langchain in-tree literal.)
_RECURSION_STOP_RE = re.compile(r"need more steps to process", re.IGNORECASE)
# What the loop writes down for itself when the graph's own limit stopped it
# before langgraph could say so. Worded so ``_RECURSION_STOP_RE`` reads it, and
# so the salvage path that follows treats it the way it treats langgraph's.
RECURSION_STOP_TEXT = "Sorry, need more steps to process this request."

# The mark on an assistant turn this code wrote itself rather than a model:
# the step-cap stop appended after a recursion error. No model served it, so
# it is not a call on the token ledger.
SYNTHETIC_TURN_KEY = "maljan_synthetic_turn"


def is_model_turn(message: Any) -> bool:
    """Whether ``message`` is an assistant turn a model answered, and so a call to count."""
    if getattr(message, "type", "") != "ai":
        return False
    metadata = getattr(message, "response_metadata", None)
    return not (isinstance(metadata, dict) and metadata.get(SYNTHETIC_TURN_KEY))


def is_the_graph_s_step_stop(message: Any) -> bool:
    """Whether ``message`` is langgraph's step-limit sentence rather than a model turn."""
    return (
        getattr(message, "type", "") == "ai"
        and not getattr(message, "tool_calls", None)
        and bool(_RECURSION_STOP_RE.search(str(getattr(message, "content", "") or "")))
    )


# Bounds for the forced-synthesis salvage (see ``_force_final_synthesis``).
#
# Below this many seconds the salvage is skipped rather than attempted: a call
# that cannot finish still consumes the time it was given, and starting one with
# nothing left is precisely how the hard cap came to fire on 2026-08-11.
_SYNTHESIS_MIN_SECONDS = 60

# What the salvage tells the model before the ids it can still cite.
_SYNTHESIS_DIRECTIVE = (
    "You have gathered enough tool output above. Do NOT request or "
    "call any more tools. Using ONLY the evidence already collected "
    "in this conversation, write your FINAL answer now in the exact "
    "format the system prompt requested. Where the evidence is "
    "genuinely insufficient for a point, state that briefly instead "
    "of asking for more steps. "
)

# The floor under the character budget for the conversation re-sent to the
# model. The measured failure re-sent 19 tool outputs — the guardrail caps each
# at 6,000 chars, so ~114,000 characters before the system prompt. Prefilling
# that and generating a full structured answer did not finish in 25 minutes on
# the local 35B.
#
# A floor rather than the budget, because 16,000 characters is a number chosen
# against one deployment's model: it cut 21 of 41 messages on a run whose
# analyst then wrote "no malicious strings were visible in ev_0007 (referenced
# but not displayed)". Where the server's context window is known the budget is
# derived from it instead; where it is not, this is what holds.
_SYNTHESIS_MIN_CHARS = 16_000

# How much of the window the salvage conversation may fill, and how many
# characters a token is worth. Four characters per token is the usual English
# ratio, and two fifths of the window leaves room for the system prompt this
# does not measure and for the answer the model still has to generate.
_SYNTHESIS_CONTEXT_SHARE = 0.4
_CHARS_PER_TOKEN = 4


def _model_context_tokens(cfg: Any, agent_name: str) -> int:
    """The context window of the model this agent runs on, or ``0``.

    The per-agent entry decides which *provider* is asked, so an agent on
    Ollama reads the Ollama window even when the run is otherwise OpenAI. It
    does not carry a window of its own: an agent pointed at its own
    OpenAI-compatible endpoint therefore reads ``llm.openai.context_size``,
    which describes the global one. That is a known limit of this lookup and
    not a claim about that agent's server; the floor below is what protects it.

    An agent that may fall back to another model reads the smallest window
    any of its models declares: the salvage is re-sent to whichever model is
    answering, and a conversation sized for the roomiest would overflow the
    tightest.

    Zero means nothing declared it, and the caller falls back to the floor.
    """
    try:
        entry = (getattr(cfg.llm, "agents", None) or {}).get(agent_name)
        chain: list[Any] = entry.chain() if entry is not None else [None]
        windows: list[int] = []
        for choice in chain:
            provider = str(getattr(choice, "provider", "") or cfg.llm.provider)
            if provider == "ollama":
                windows.append(int(cfg.llm.ollama.num_ctx))
            else:
                windows.append(int(getattr(cfg.llm.openai, "context_size", 0) or 0))
        declared = [window for window in windows if window > 0]
        return min(declared) if declared else 0
    except Exception as exc:  # noqa: BLE001 — a budget is never worth a lost salvage
        logger.debug("synthesis budget: the context size could not be read (%s).", exc)
        return 0


def synthesis_budget_chars(cfg: Any, agent_name: str, window_tokens: int = 0) -> int:
    """How many characters of conversation the salvage may re-send.

    ``window_tokens`` is the window the job's context budget counts on — the
    smaller of the declared and the probed one. The salvage is sized from the
    smaller of it and every window this agent's models declare: a declaration
    left larger than the served window sized a salvage after a server-reported
    full window at close to the conversation the server had just refused, and
    a fallback model with a smaller window must still be able to read it.
    """
    windows = [
        t for t in (int(window_tokens or 0), _model_context_tokens(cfg, agent_name)) if t > 0
    ]
    tokens = min(windows) if windows else 0
    if tokens <= 0:
        return _SYNTHESIS_MIN_CHARS
    return max(_SYNTHESIS_MIN_CHARS, int(tokens * _CHARS_PER_TOKEN * _SYNTHESIS_CONTEXT_SHARE))


def salvage_chars_at_pace(
    seconds: float,
    *,
    generation_rate: float | None,
    prompt_rate: float | None,
    chars_per_token: int,
    answer_tokens: int | None = None,
) -> int | None:
    """Characters of conversation a no-tools salvage can send and still finish in ``seconds``.

    The salvage re-sends the conversation without the loop's tools, so the
    server cannot reuse what it had cached for the loop and reads the whole
    request again, then writes the final answer. At the model's measured
    rates that takes ``sent / chars_per_token / prompt_rate`` plus
    ``answer_tokens / generation_rate`` seconds, and the two together, times
    ``TIMEOUT_MARGIN`` for the spread between turns, must fit in what is left.
    ``answer_tokens`` defaults to ``FINAL_ANSWER_EXPECTED_TOKENS``, the answer
    the loop's own time reserve was sized for.

    ``None`` when either rate is unmeasured: nothing is sized from a rate
    nobody measured, and the window alone then bounds the request. ``0`` when
    the answer alone does not fit.

    The slow run's numbers are why: 393 s left, a 50,000-character
    conversation read at 110–240 tokens a second and an answer written at 5.5,
    and the call ran into its hard cap on all three PE samples.
    """
    from maljan.llm.generation_rate import TIMEOUT_MARGIN

    if not generation_rate or not prompt_rate or generation_rate <= 0 or prompt_rate <= 0:
        return None
    tokens = FINAL_ANSWER_EXPECTED_TOKENS if answer_tokens is None else int(answer_tokens)
    reading = float(seconds) / TIMEOUT_MARGIN - tokens / float(generation_rate)
    if reading <= 0:
        return 0
    return int(reading * float(prompt_rate) * max(1, int(chars_per_token)))


def ledger_ids_in(msgs: Sequence[Any]) -> list[str]:
    """Every ledger id still readable in this window, in the order they appear.

    Wherever it appears in a message, not only where the recorder stamped it:
    what the caller needs is the set of ids the model can still read, and one
    written into prose is one it can read.
    """
    seen: list[str] = []
    for message in msgs:
        for found in ENTRY_ID_RE.findall(str(getattr(message, "content", "") or "")):
            if found.lower() not in seen:
                seen.append(found.lower())
    return seen


def _message_chars(m: object) -> int:
    """Size of a message **as the server will see it**, not just its text.

    An assistant turn that requests tools carries ``content == ""`` and puts the
    whole request in ``tool_calls``, so measuring ``content`` alone reports zero
    for exactly the messages a ReAct transcript is made of. A first cut of the
    trim below did that and undercounted by roughly 4x: it dropped one message
    from a conversation the server then reported at 38,868 tokens.
    """
    total = len(str(getattr(m, "content", "") or ""))
    calls = getattr(m, "tool_calls", None)
    if calls:
        total += len(str(calls))
    return total


def _reported_request_chars(messages: list, per_token: int) -> int:
    """What the server said the conversation weighs, in the budget's characters.

    The last assistant turn that carries usage is the answer to a request the
    server counted in full: ``input_tokens`` is everything before that turn,
    tool definitions and template included. That count converted at the
    budget's rate, plus the measured size of that turn and of everything after
    it, is what the next request weighs as far as anything reported can say.
    Zero where no turn carries a count, and the measure alone then answers.
    """
    for index in range(len(messages) - 1, -1, -1):
        message = messages[index]
        if getattr(message, "type", "") != "ai":
            continue
        usage = getattr(message, "usage_metadata", None) or {}
        try:
            prompt = int(usage.get("input_tokens") or 0)
        except (AttributeError, TypeError, ValueError):
            prompt = 0
        if prompt > 0:
            return prompt * max(1, per_token) + sum(_message_chars(m) for m in messages[index:])
    return 0


def request_chars(messages: list, definition_chars: int, per_token: int) -> int:
    """What a tool loop's next request weighs, in the budget's characters.

    The messages as the server will see them, plus the definitions of the
    loop's tools, which go with every request; and never less than what the
    server itself reported for the last request plus what came after it. One
    rule for every loop that sizes itself against the window — the analysts'
    and the judge's.
    """
    measured = sum(_message_chars(m) for m in messages) + max(0, int(definition_chars))
    return max(measured, _reported_request_chars(messages, per_token))


def counted_window_tokens(budget: Any) -> int:
    """The window a job's context budget derives from, or ``0`` where it derives nothing."""
    from maljan.llm.context_window import ContextBudget

    if isinstance(budget, ContextBudget) and budget.derives:
        return int(budget.window.tokens)
    return 0


def _conversation_units(msgs: list) -> list[list]:
    """The conversation as the things that can be dropped whole.

    A tool call and the results it produced are one unit: dropping a result
    while keeping the call that referenced it is what left an analyst writing
    "no malicious strings were visible in ev_0007 (referenced but not
    displayed)" — a sentence about evidence it had been shown the name of and
    not the content. Everything else is a unit of one.
    """
    units: list[list] = []
    for message in msgs:
        is_result = type(message).__name__ == "ToolMessage"
        if is_result and units and getattr(units[-1][0], "tool_calls", None):
            units[-1].append(message)
            continue
        units.append([message])
    return units


def _is_a_tool_pair(unit: list) -> bool:
    """Whether this unit is a tool call with its results."""
    return bool(getattr(unit[0], "tool_calls", None))


def _framing_of(msgs: list) -> list:
    """The leading framing a trimmed salvage always keeps: at most two turns before a tool result."""
    head: list = []
    for message in msgs:
        if len(head) >= 2 or type(message).__name__ == "ToolMessage":
            break
        head.append(message)
    return head


def _trim_for_synthesis(msgs: list, budget: int) -> list:
    """Fit a ReAct conversation into ``budget`` characters, framing first.

    Keeps the leading framing — the system prompt and the first human turn,
    which carry the task and the output format — and then drops whole units
    until the rest fits: assistant prose that called no tool goes before any
    tool call does, and after that the oldest tool call goes with its results.
    Late tool calls are the ones the model chose after reading the early ones,
    so when evidence has to go, the oldest goes first — and a call never
    outlives its result or the other way round.

    The budget exists because of what long context costs *this* server, not for
    tidiness: on the hybrid recurrent model a ~39k-token conversation drove
    llama.cpp to write and erase a **63 MiB recurrent-state checkpoint every few
    hundred tokens**, which is what turned a salvage call into a 25-minute one.

    Returns ``msgs`` unchanged when it already fits, so the common case is
    untouched and only a conversation that would not finish is altered.
    """
    if sum(_message_chars(m) for m in msgs) <= budget:
        return msgs

    head: list = []
    rest: list = list(msgs)
    # The framing is whatever precedes the first tool result, capped at two
    # turns so a long opening cannot itself exhaust the budget.
    while rest and len(head) < 2 and type(rest[0]).__name__ != "ToolMessage":
        head.append(rest.pop(0))

    units = _conversation_units(rest)
    used = sum(_message_chars(m) for m in head) + sum(
        _message_chars(m) for unit in units for m in unit
    )

    # Prose first, oldest first: an assistant turn that called no tool is the
    # model's own commentary, and the evidence is what the salvage is for.
    for index, unit in enumerate(units):
        if used <= budget:
            break
        if _is_a_tool_pair(unit):
            continue
        used -= sum(_message_chars(m) for m in unit)
        units[index] = []

    for index, unit in enumerate(units):
        if used <= budget:
            break
        if not unit:
            continue
        used -= sum(_message_chars(m) for m in unit)
        units[index] = []

    return [*head, *[m for unit in units for m in unit]]


def steps_used(messages: list) -> int:
    """The graph steps a conversation has spent, counted the way langgraph counts.

    An assistant turn is one node execution, and a turn that called tools
    costs a second for the tool node; the framing and the tool results cost
    nothing.
    """
    ai_turns = [m for m in messages if getattr(m, "type", "") == "ai"]
    tool_rounds = sum(1 for m in ai_turns if getattr(m, "tool_calls", None))
    return len(ai_turns) + tool_rounds


def model_turns_left(max_steps: int, messages: list) -> int:
    """How many model turns the loop still has, counted the way langgraph counts.

    ``max_steps`` is handed to langgraph as ``recursion_limit``, and langgraph
    counts node executions: an assistant turn is one, and a turn that called
    tools costs a second for the tool node. So the budget in model turns is
    half the steps, rounded up, less what the transcript already spent — one
    per assistant turn plus one per tool round. What the model is told is a
    number it can act on; the graph's own step count is not.
    """
    return max(0, (int(max_steps) - steps_used(messages) + 1) // 2)


class LoopBudget:
    """One tool loop's steps and seconds.

    The loop's own turns are counted from its conversation, refreshed on every
    model turn. What an agent it asked spends is *not* taken off this: an ask
    carries its own step budget (``agents.delegation_steps``), because a
    caller and its specialists doing different work out of one step count
    starved both — the live proof watched a lead's third ask refused with
    three steps left while the first callee had already died at a recursion
    limit of five. The wall clock is the one thing they really share, and it
    needs no charging: a delegated call runs inside the caller's own timeout.
    """

    def __init__(self, max_steps: int, timeout: float, started: float | None = None) -> None:
        self.max_steps = int(max_steps)
        self.timeout = float(timeout)
        self.started = time.monotonic() if started is None else float(started)
        self.own_steps = 0
        self.delegated_steps = 0

    def note_turns(self, messages: list) -> None:
        """Record what the loop's own conversation has spent so far."""
        self.own_steps = steps_used(messages)

    def note_delegated(self, steps: int) -> None:
        """Record what an agent this loop asked spent, for the meter only.

        Not charged. The number is here so a budget row can say the caller's
        loop had work done under it, and so the meter's two sides add up; it
        does not shorten the caller's own budget in either dimension.
        """
        self.delegated_steps += max(0, int(steps))

    def steps_left(self) -> int:
        return max(0, self.max_steps - self.own_steps)

    def turns_left(self, messages: list) -> int:
        """The budget line's number: model turns this loop has left."""
        return model_turns_left(self.max_steps, messages)

    def seconds_left(self) -> float:
        return max(0.0, self.timeout - (time.monotonic() - self.started))


class BudgetCeiling:
    """What one delegated loop gets: the delegation's own budget, not a share.

    ``steps`` is ``agents.delegation_steps`` and replaces whatever the callee
    would otherwise have had — a specialist answering an ask is doing one
    focused job, not its own stage. ``seconds`` is the per-ask timeout already
    cut down to what the caller has left, because the caller is waiting inside
    its own wall clock.

    ``wall`` is that remainder, kept separately so the hard cap can put its
    grace inside it: clamping the abort to ``seconds`` fired it at exactly the
    soft timeout and gave a callee none of the thirty seconds every other loop
    gets to come back in. It defaults to ``seconds`` for a ceiling built
    without one.
    """

    def __init__(self, steps: int, seconds: float, wall: float | None = None) -> None:
        self.steps = int(steps)
        self.seconds = float(seconds)
        self.wall = float(seconds if wall is None else wall)


# The class-level stand-ins for two pieces of per-agent state, for an analyst
# built without ``__init__``. The mapping is read-only so one of them cannot
# become every stand-in's; the lock is deliberately shared, because a set of
# stand-ins asking each other is one conversation and serialising it is the
# same answer the real agents get.
_NO_PATH_CHOICES: Mapping[str, Any] = MappingProxyType({})
_SHARED_STAND_IN_LOCK = threading.RLock()
# Reentrant, unlike a real agent's: a set of stand-ins shares this one object,
# so a plain lock would make a stand-in asking through another stand-in block
# on itself and be refused rather than nesting.
_SHARED_STAND_IN_ASKS_LOCK = threading.RLock()


# How long past its own timeout a loop is left alone before it is aborted
# outright. The soft timeout ends the model's turn; this one ends the thread
# that would not come back from it.
HARD_CAP_GRACE = 30.0


# How long a final answer is expected to run, in tokens, when the reserve is
# sized from the model's measured rate. The slow run's two final-answer-sized
# calls took 222 s (the judge's verdict) and 158 s (the narrative) at 3.8
# tokens a second: about 840 and 600 tokens. A structured report of a loop's
# findings is of that size, so the reserve holds a thousand tokens at the
# model's own pace — and never less than its longest measured turn allows.
FINAL_ANSWER_EXPECTED_TOKENS = 1000


class TurnPace:
    """How long this loop's turns take, per answering model, and whether the time left fits one.

    A loop that reaches its time budget mid-turn has nothing to write its
    answer with: the thirty seconds of grace are a tenth of one turn of a model
    that takes a hundred. So the loop measures its own turns and ends its tool
    phase while what is left still holds the next turn and the final-answer
    turn after it.

    A turn runs from one model answer to the next: the tools the model asked
    for and the model's next call, which is what "one more turn" costs. Turns
    are kept per answering model, and the turn on which a model list moved to
    its next model is not measured at all: it holds the dead model's deadline,
    which says nothing about the pace of the model that answered.

    The final turn is given ``TIMEOUT_MARGIN`` (``llm.generation_rate``) times
    the larger of the longest turn seen and, where the model's generation rate
    is measured, ``FINAL_ANSWER_EXPECTED_TOKENS`` at that rate — and never less
    than the salvage's own minimum. Nothing is decided before the answering
    model has taken a measured turn.
    """

    def __init__(self, rate_of: Callable[[], float | None] | None = None) -> None:
        self._last_answer = time.monotonic()
        self._rate_of = rate_of
        self.turns: dict[str, list[float]] = {}
        self.current = ""

    def note(self, snapshot: Any, default_model: str = "") -> None:
        """Record one step of the graph; a step that ends on a model answer closes a turn."""
        now = time.monotonic()
        messages = (snapshot or {}).get("messages") if isinstance(snapshot, dict) else None
        last = messages[-1] if messages else None
        if getattr(last, "type", "") != "ai":
            return
        from maljan.llm.fallback import turn_model

        model, switched = turn_model(last, default_model)
        self.current = model
        if not switched:
            self.turns.setdefault(model, []).append(now - self._last_answer)
        self._last_answer = now

    def longest(self) -> float:
        return max(self.turns.get(self.current) or [0.0])

    def reserve(self) -> float:
        """The seconds kept for the final-answer turn."""
        from maljan.llm.generation_rate import TIMEOUT_MARGIN

        needed = self.longest()
        rate = self._rate_of() if self._rate_of is not None else None
        if rate:
            needed = max(needed, FINAL_ANSWER_EXPECTED_TOKENS / rate)
        return max(needed * TIMEOUT_MARGIN, float(_SYNTHESIS_MIN_SECONDS))

    def leaves_no_room_for(self, seconds_left: float) -> bool:
        """Whether another turn would eat into the final answer's reserve."""
        if not self.turns.get(self.current):
            return False
        return seconds_left < self.longest() + self.reserve()


def without_unanswered_calls(messages: list) -> tuple[list, int]:
    """The conversation with every tool call nothing answered taken off its turn.

    A loop the clock ended right after a model turn holds that turn's calls
    with no answer to them, and Anthropic, OpenAI and Gemini refuse such a
    transcript outright. The model's own text of that turn stays; only the
    calls that never ran go. Returns the conversation and how many calls went.

    A call is carried in more places than ``tool_calls``, and each provider's
    formatter reads its own: OpenAI's (and llama.cpp's) falls back to
    ``additional_kwargs["tool_calls"]`` once ``tool_calls`` is empty,
    Anthropic's re-emits a ``tool_use`` block from the content list, Gemini's
    sends ``additional_kwargs["function_call"]``. Every one of them goes for a
    call that never ran.
    """
    answered = {
        str(getattr(message, "tool_call_id", "") or "")
        for message in messages
        if getattr(message, "type", "") == "tool"
    }
    kept: list = []
    dropped = 0
    for message in messages:
        calls = list(getattr(message, "tool_calls", None) or [])
        if getattr(message, "type", "") != "ai" or not calls:
            kept.append(message)
            continue
        ran = [call for call in calls if str(call.get("id") or "") in answered]
        if len(ran) == len(calls):
            kept.append(message)
            continue
        dropped += len(calls) - len(ran)
        unrun = {str(call.get("id") or "") for call in calls} - answered
        kept.append(
            message.model_copy(
                update={
                    "tool_calls": ran,
                    "invalid_tool_calls": [],
                    "additional_kwargs": _kwargs_without(message, unrun, bool(ran)),
                    "content": _content_without(message.content, unrun, bool(ran)),
                }
            )
        )
    return kept, dropped


# The content-block types a provider writes a call as.
_CALL_BLOCK_TYPES = frozenset({"tool_use", "tool_call", "function_call", "server_tool_use"})


def _kwargs_without(message: Any, unrun: set[str], any_ran: bool) -> dict[str, Any]:
    """``additional_kwargs`` with the provider-shaped copies of unrun calls gone."""
    extra = dict(getattr(message, "additional_kwargs", None) or {})
    raw_calls = extra.get("tool_calls")
    if isinstance(raw_calls, list):
        kept = [
            c for c in raw_calls if not (isinstance(c, dict) and str(c.get("id") or "") in unrun)
        ]
        if kept:
            extra["tool_calls"] = kept
        else:
            extra.pop("tool_calls", None)
    # Gemini's single ``function_call`` carries no id: it is one of the turn's
    # calls, and it goes when none of them ran.
    if not any_ran:
        extra.pop("function_call", None)
    return extra


def _content_without(content: Any, unrun: set[str], any_ran: bool) -> Any:
    """The turn's content with the blocks of unrun calls gone and its text kept."""
    if not isinstance(content, list):
        return content
    kept: list = []
    for block in content:
        if isinstance(block, dict) and block.get("type") in _CALL_BLOCK_TYPES:
            block_id = str(block.get("id") or "")
            if block_id in unrun or (not block_id and not any_ran):
                continue
        kept.append(block)
    return kept


def _model_label(llm: Any) -> str:
    """The answering model's name, for a turn that does not carry its own."""
    from maljan.llm.generation_rate import model_name_of

    return model_name_of(llm)


def _model_that_closes_off_truncated_calls(llm: Any, tools: list, repair: Any) -> Any:
    """``llm`` with the repair appended, or ``llm`` when it cannot be appended to.

    The repair has to sit between the model and the tool node and cost
    nothing. A node would cost a superstep of every turn; binding the tools
    here and piping the answer through the repair costs none, because
    langgraph sees the same one runnable it always saw.

    It is appended only when binding produced a ``RunnableBinding`` — what a
    real provider returns, and what langgraph checks for before deciding to
    bind the tools itself. A model that binds some other way is handed back
    untouched, because a sequence langgraph then tries to bind again would
    fail for every loop rather than for the rare truncated call this exists
    to rescue.
    """
    from langchain_core.runnables import RunnableBinding, RunnableLambda

    binder = getattr(llm, "bind_tools", None)
    if not callable(binder):
        return llm
    names = [str(getattr(tool, "name", "")) for tool in tools]
    if len(set(names)) != len(names):
        # Two tools of one name: langgraph would keep one of them and then
        # refuse the bound list for not matching. Nothing here is worth a loop
        # that will not start.
        logger.debug("tool argument repair not attached: two tools share a name.")
        return llm
    try:
        bound = binder(tools)
    except Exception as exc:  # noqa: BLE001 — the loop binds them the ordinary way
        logger.debug("tool argument repair not attached (%s).", exc)
        return llm
    if not isinstance(bound, RunnableBinding):
        return llm
    return bound | RunnableLambda(repair)


def lock_for(agent: Any) -> Any:
    """The lock that serialises everything driving one agent, or nothing.

    An ask of an agent, a second ask of it and its own stage run all take it,
    because all three drive the same buffers, the same budget and the same
    call chain. A duck-typed stand-in that borrows one of these wrappers and
    is never asked by anyone has no lock and needs none, so it gets a context
    that does nothing rather than an attribute error.
    """
    lock = getattr(agent, "delegation_lock", None)
    return lock if lock is not None else contextlib.nullcontext()


def _turn_key(message: Any, index: int) -> str:
    """What identifies one model turn, for publishing it exactly once.

    Not ``id(message)``: CPython reuses an address after collection, so a turn
    that had been collected could suppress a later one, and a graph that
    copied its state between snapshots — a checkpointer, a serialising reducer
    — would make every turn look new on every snapshot and republish the whole
    conversation each time.

    langchain gives a message its own id. A message without one is keyed on
    its place in the conversation *and* on what it says: the place alone
    cannot survive a conversation being replayed from the first message, which
    a connection error does, and the text alone would swallow a turn a model
    genuinely repeated — the degenerate loop this codebase guards against
    elsewhere, where the interesting thing is precisely that it said the same
    thing again.
    """
    own = getattr(message, "id", None)
    if own:
        return f"id:{own}"
    return f"turn:{index}:{hash(str(getattr(message, 'content', '') or ''))}"


def _steps_this_loop_spent(ledger: LoopBudget, messages: list) -> int:
    """What *this* loop has used, from the conversation or from the budget itself.

    A loop that ended at its wall clock has no conversation to hand over: the
    thread it was running on did not come back, and the record was written
    with an empty list — so the one run the meter exists to explain, the
    analyst that spent twenty-five minutes and thirty tool calls and was cut
    off, landed in the summary as zero steps. The refresher counted the
    conversation before every model turn, so the budget itself holds the last
    figure anyone saw.

    Its own turns and nothing else. What a specialist spent is filed under the
    specialist, and it comes out of the specialist's cap, not this one: adding
    it here counted the same steps in two rows and made ``steps_used`` a number
    that could exceed ``max_steps`` — a lead that made six asks of twelve steps
    would read 82 of 40. The row carries ``delegated_steps`` beside this, for a
    reader who wants the other number.
    """
    return int(steps_used(messages) if messages else ledger.own_steps)


def hard_cap(timeout: float, ceiling: BudgetCeiling | None = None) -> float:
    """The wall a loop is aborted at, never later than a caller is waiting for.

    A delegated loop runs on a tool thread that cannot be cancelled, so the
    grace it is normally given is the time it can outlive the caller by: the
    caller's own wait fires, its node fails and drains it, and a callee still
    running writes its ledger onto an agent that has finished. The ceiling
    carries what the caller had left, and the grace goes inside that rather
    than being clipped away against the ask's own timeout — a callee whose
    abort fires at the same second as its soft timeout never gets to write up
    what it gathered.
    """
    wall = float(timeout) + HARD_CAP_GRACE
    if ceiling is not None:
        wall = min(wall, float(ceiling.wall))
    return max(1.0, wall)


def a_budget(value: Any) -> int | None:
    """``value`` as a budget, or ``None`` when it is not one.

    A whole number of at least one. ``True`` is an ``int`` to Python and is a
    budget to nobody, so it is refused by name. Everything a budget is read
    from goes through this: the definition's own fields, which the settings
    model already holds to the same rule, and the two deprecated override
    maps, which are plain ``dict[str, int]`` and hold anything an admin typed.
    A loop given a zero or a negative recursion limit does not run at all, so
    the fallback is the deployment's number rather than the stored one.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def _definition_budget(cfg: Any, agent_name: str) -> tuple[int | None, int | None]:
    """``(timeout_seconds, max_steps)`` this agent's definition sets, if any.

    Read defensively: a settings stand-in may carry no definition map at all,
    and a budget is not worth an exception on the path that starts every loop.
    """
    definitions = getattr(getattr(cfg, "agents", None), "definitions", None)
    if not isinstance(definitions, dict):
        return None, None
    definition = definitions.get(agent_name)
    return (
        a_budget(getattr(definition, "timeout_seconds", None)),
        a_budget(getattr(definition, "max_steps", None)),
    )


def slowest_call(entries: Any) -> str:
    """`, slowest <tool> 12.3s`, or `""` when nothing in the loop was timed.

    The loop's own elapsed time says a run was slow; it does not say whether
    the model or a tool was. The ledger's per-call clock does, and the slowest
    call is the one an operator looks for first. A clause rather than a line of
    its own, so the three existing lines keep their shape.
    """
    slowest = None
    for entry in entries or []:
        try:
            ms = int(getattr(entry, "duration_ms", 0) or 0)
        except (TypeError, ValueError):
            continue
        if ms > 0 and (slowest is None or ms > slowest[0]):
            slowest = (ms, str(getattr(entry, "tool", "") or ""))
    if slowest is None or not slowest[1]:
        return ""
    return f", slowest {slowest[1]} {slowest[0] / 1000.0:.1f}s"


def loop_limits(agent_name: str, ceiling: BudgetCeiling | None = None) -> tuple[int, int]:
    """``(timeout, max_steps)`` for one loop of ``agent_name``.

    The agent's own definition first, then the deprecated per-agent override
    maps — each held to what a budget can be — then the deployment's defaults.
    A budget is a property of the agent
    — an operator cloning a team gets the definition, and used to get none of
    its budget — so the definition wins over a map keyed by agent name
    somewhere else in the settings. A ceiling replaces both: an agent
    answering an ask spends the delegation's budget, not its stage's and not a
    leftover of its caller's. A module function rather than only a method, so
    a duck-typed analyst that borrows one method reads the same numbers.
    """
    cfg = get_settings()
    own_timeout, own_steps = _definition_budget(cfg, agent_name)
    overrides = getattr(cfg, "react_agent_timeout_overrides", {}) or {}
    step_overrides = getattr(cfg, "react_agent_max_steps_overrides", {}) or {}
    timeout = own_timeout or a_budget(overrides.get(agent_name)) or int(cfg.react_agent_timeout)
    max_steps = (
        own_steps or a_budget(step_overrides.get(agent_name)) or int(cfg.react_agent_max_steps)
    )
    if ceiling is not None:
        max_steps = max(2, int(ceiling.steps))
        timeout = max(1, int(ceiling.seconds))
    return timeout, max_steps


# The one human turn a tool loop gets when its last message is neither a
# structured report nor a findings block. Exactly one: a model that will not
# answer after being told it did not answer will not answer on the third ask
# either, and each ask is another full model turn.
# No tool half to the sentence: the nudge invokes the bare model, with no tools
# bound to that turn, so a model that took that branch answered with an empty
# message and the run's one extra step bought nothing.
FINAL_ANSWER_NUDGE = "Your last message was not a final report. Return your final ISR now."

# What the analyst reports for itself when even the nudge produced no report.
# Not ``no_data``: the analyst had data, read it, and stopped mid-thought.
NO_STRUCTURED_REPORT_STATUS = "no_claims"
NO_STRUCTURED_REPORT_REASON = "the model ended without a structured report"

# What an analyst reports for itself when it answered in prose the parser could
# not read a single claim out of, after it was asked once for the claim
# format. The prose is the analyst's report and is kept as written; nothing is
# made a claim of, because a claim carries a confidence the analyst stated and
# prose states none.
UNPARSED_ANSWER_REASON = "the answer did not parse into claims; its prose is kept as the report"


def unparsed_answers_reason(names: Sequence[str]) -> str:
    """The run's degradation reason for analysts whose answer stayed prose."""
    return (
        "analyst answers kept as prose, with no claim read from them after one "
        f"question about the claim format: {', '.join(names)}"
    )


def answer_is_isr(text: str) -> bool:
    """Whether an answer carries a report at all.

    The two shapes an analyst may answer in: the ``CLAIM:`` block every ISR
    prompt asks for, and the optional fenced ``maljan-findings`` channel. Prose
    that is neither is not a report — it may be a fine paragraph, but nothing
    downstream can read a finding out of it without inventing one.
    """
    from maljan.agents.findings_block import has_findings_block

    if not text or not text.strip():
        return False
    return "CLAIM:" in text or has_findings_block(text)


def nudge_turns(msgs: list) -> tuple[list, bool]:
    """The conversation as it can be sent back to the server, and whether it changed.

    An assistant turn that carried a tool call whose arguments never parsed
    ends the loop: no tool ran, and nothing answered it. Sent back as it is,
    the server has to render that call into its template and fails on the
    same arguments, which is the 500 a live nudge got ("Failed to parse tool
    call arguments as JSON"). The call is dropped, the turn's text kept, and
    the answer the nudge asks for is what the model says next.
    """
    from langchain_core.messages import AIMessage

    out: list = []
    changed = False
    for message in msgs:
        invalid = getattr(message, "invalid_tool_calls", None) or []
        if isinstance(message, AIMessage) and invalid:
            changed = True
            kept_calls = list(getattr(message, "tool_calls", None) or [])
            content = message.content if isinstance(message.content, str) else ""
            # A turn that was nothing but the call it could not make is left
            # out rather than sent as an empty assistant turn, which some
            # templates render as nothing and a few reject.
            if not content.strip() and not kept_calls:
                continue
            out.append(AIMessage(content=message.content, tool_calls=kept_calls))
            continue
        out.append(message)
    return out, changed


def cause_chain(exc: BaseException, limit: int = 4) -> str:
    """``exc``'s causes, innermost last, as one line.

    ``str(APIConnectionError)`` is the words "Connection error." whatever
    produced it: a refused socket, a TLS failure, and an httpx pool being used
    from an event loop other than the one it was opened on all read the same.
    The last of those is a bug in this process rather than a blip on the wire
    — it cost a full retry on the judge's first verdict request of every run
    and nothing in the log could tell it from a flaky server. The chain is
    where the difference is, so the chain is what gets logged.
    """
    parts: list[str] = []
    seen: set[int] = {id(exc)}
    cause: BaseException | None = exc.__cause__ or exc.__context__
    while cause is not None and len(parts) < limit and id(cause) not in seen:
        parts.append(repr(cause))
        seen.add(id(cause))
        cause = cause.__cause__ or cause.__context__
    return " <- ".join(parts) if parts else "no cause recorded"


# The statuses that mean "not now" rather than "no". A provider answering any
# of these is describing its own state, and a second attempt a couple of
# seconds later is the difference between a thin run and a lost one. Every
# other 4xx is a refusal about the request itself and is answered once.
RETRYABLE_STATUSES: frozenset[int] = frozenset({408, 409, 429, 500, 502, 503, 504})

# The longest delay a provider's ``Retry-After`` may impose on us. Beyond this
# the caller's own budget is the shorter answer, so the backoff below is used
# instead and the run degrades rather than parking on one request.
_MAX_RETRY_AFTER_SECONDS = 30


def _provider_fault(exc: BaseException) -> str:
    """One bounded line about a provider failure, safe to put in a log.

    The class and, for a status error, the status. Deliberately not the body:
    a provider that quotes the offending request back has quoted a credential
    back, and this line is written to a log file that outlives the run.
    """
    note_a_window_that_moved(exc)
    status = getattr(exc, "status_code", None)
    return f"{type(exc).__name__}" + (f" {status}" if status else "")


def note_a_window_that_moved(exc: BaseException) -> None:
    """Retire the learned windows when a server says a request did not fit.

    The learned window is believed for a while, so a server restarted with a
    smaller one is sized against the figure it used to serve — and the room
    check cannot catch that, because the room check measures against the
    believed window. The server itself says so the first time a request
    overflows, and that sentence is the only free correction there is.

    The message is read here and nowhere else it could leak: what is taken
    from it is a yes or a no, and nothing of it is logged or stored.
    """
    from maljan.llm.context_window import note_provider_error

    with contextlib.suppress(Exception):
        note_provider_error(str(exc))


def _retry_after(exc: BaseException, default: int) -> int:
    """The provider's own ``Retry-After``, when it sent a usable one.

    Both forms RFC 9110 allows: delta-seconds, and an HTTP-date, which several
    hosted providers send on 429 and 503. Either way the answer is clamped —
    a provider asking for an hour is asking for longer than the caller has.
    """
    headers = getattr(getattr(exc, "response", None), "headers", None)
    raw = ""
    if headers is not None:
        with contextlib.suppress(Exception):
            raw = str(headers.get("retry-after") or "").strip()
    if not raw:
        return default
    try:
        seconds = int(float(raw))
    except (TypeError, ValueError):
        seconds = _seconds_until(raw)
    if 0 < seconds <= _MAX_RETRY_AFTER_SECONDS:
        return seconds
    return default


def _seconds_until(http_date: str) -> int:
    """An HTTP-date as seconds from now, or ``0`` when it is not one."""
    from datetime import UTC, datetime
    from email.utils import parsedate_to_datetime

    try:
        when = parsedate_to_datetime(http_date)
    except (TypeError, ValueError):
        return 0
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return int((when - datetime.now(UTC)).total_seconds())


async def retry_on_connection_error(
    make_awaitable: Callable[[], Awaitable[Any]],
    *,
    attempts: int = 3,
    what: str = "LLM call",
    log: Any = None,
) -> Any:
    """Await ``make_awaitable()``, retrying only a transient connection error.

    ``openai_provider`` sets ``max_retries=0`` process-wide, deliberately: the
    SDK's own retries would storm a *stalled* request three times its 1800 s
    timeout. The comment there says the ReAct loop's cap "is the only retry
    policy we want" — but that retry only ever wrapped the ReAct executor, so
    every other call in the system was left with exactly one attempt against a
    client configured never to retry.

    That is not a theoretical gap. The judge's verdict, the mediator's fast
    path and the entire reporting layer were all single-attempt, and a local
    llama-server dropping an idle socket during a long tool-call gap is a
    routine event here. One blip degraded a whole run to "Suspicious", or
    silently dropped a report section.

    Narrow on purpose, preserving the original anti-storm intent: a transport
    failure, and the handful of statuses a provider uses to say "not now".
    Hosted endpoints answer 500 "Internal server error" and 503 "Service
    temporarily overloaded" for a second at a time, and a single attempt
    against them cost a live run its static analyst, its negotiation, its
    verdict and every composer section within twelve seconds. A refusal —
    401, 402, 403, 404, 422 and the rest of the 400 family — is answered once,
    because asking again cannot change it. A stall surfaces as ``TimeoutError``
    from the caller's ``wait_for`` and is never retried. Backoff is 1 s then
    2 s, or the provider's own ``Retry-After`` when it sends one that fits
    inside the budget.

    Takes a *factory* rather than an awaitable because a coroutine cannot be
    awaited twice.
    """
    from openai import APIConnectionError, APIStatusError

    emit = log or logger
    for attempt in range(attempts):
        try:
            return await make_awaitable()
        except (APIConnectionError, APIStatusError) as exc:
            status = getattr(exc, "status_code", None)
            if isinstance(exc, APIStatusError) and status not in RETRYABLE_STATUSES:
                raise
            kind = f"HTTP {status}" if isinstance(exc, APIStatusError) else "connection error"
            # The cause chain is what tells a dropped socket from this
            # process using a pool on the wrong loop, and it is worth having
            # for a transport failure. A status error has no such ambiguity
            # and its chain can carry the provider's own body, which is where
            # a credential quoted back would be — so that branch says the
            # status and stops, rather than reporting an absence of causes as
            # though something had named itself.
            cause_args: tuple[str, ...] = ()
            cause_clause = ""
            if not isinstance(exc, APIStatusError):
                cause_clause, cause_args = " (caused by %s)", (cause_chain(exc),)
            if attempt >= attempts - 1:
                emit.error(
                    "%s: %s after %d attempts: %r" + cause_clause,
                    what,
                    kind,
                    attempts,
                    _provider_fault(exc),
                    *cause_args,
                )
                raise
            wait = _retry_after(exc, 2**attempt)
            emit.warning(
                "%s: %s (attempt %d/%d): %r" + cause_clause + " — retrying in %ds.",
                what,
                kind,
                attempt + 1,
                attempts,
                _provider_fault(exc),
                *cause_args,
                wait,
            )
            await asyncio.sleep(wait)
    raise AssertionError("unreachable")  # pragma: no cover


def describe_exception_for_log(exc: BaseException) -> str:
    """Return a non-empty, diagnosable description of ``exc``, for the log.

    For the log and for nothing else, which is what the name says: it keeps
    the exception's *message*, and a message names the host path an ``OSError``
    could not read, the URL a transport error was given and the credential a
    base URL was configured with. That is the operator's to read, on the
    operator's host. What a published event may say about a failure is
    ``maljan.pipeline.events.describe_exception``, which never carries one.

    Analyst failures were logged as
    ``"dynamic ISR analysis failed: "`` — an empty tail — because several
    exceptions raised on the MCP path carry no message (bare ``Exception``,
    ``ExceptionGroup``, ``anyio`` cancellation wrappers). The operator was left
    with a failure and zero information about it. Always fall back to the
    exception's class name, and unwrap ``ExceptionGroup`` sub-exceptions so an
    MCP connection error inside a task group is still visible.
    """
    text = str(exc).strip()
    inner = getattr(exc, "exceptions", None)
    if not text and isinstance(inner, list | tuple) and inner:
        parts = [describe_exception_for_log(sub) for sub in inner[:3]]
        return f"{type(exc).__name__}({'; '.join(p for p in parts if p)})"
    if text:
        return f"{type(exc).__name__}: {text}"
    # 2026-07-26: the class name alone was still ambiguous for the one that
    # mattered most. ``concurrent.futures.CancelledError`` and
    # ``asyncio.CancelledError`` are *different classes* that print the same
    # bare word, and only the first is an ``Exception`` — which is precisely
    # why it slipped through every handler and reached the log as the
    # uninformative ``ISR analysis failed: CancelledError``. Qualify it.
    module = type(exc).__module__
    if module and module not in ("builtins", "__main__"):
        return f"{module}.{type(exc).__name__}"
    return type(exc).__name__


# Structured CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE block parsing, used by the
# view- and tier-decomposition paths whose prompts explicitly demand that shape.
_BLOCK_SPLIT_RE = re.compile(r"(?:^|\r?\n)\s*-{3,}\s*(?:\r?\n|$)", flags=re.MULTILINE)
_BLOCK_CLAIM_RE = re.compile(
    r"CLAIM:\s*(.+?)(?=\s*\n\s*(?:EVIDENCE|CONFIDENCE|TECHNIQUE):|\Z)", re.DOTALL
)
_BLOCK_EVIDENCE_RE = re.compile(
    r"EVIDENCE:\s*(.+?)(?=\s*\n\s*(?:CONFIDENCE|TECHNIQUE):|\Z)", re.DOTALL
)
_BLOCK_CONFIDENCE_RE = re.compile(r"CONFIDENCE:\s*([\d.]+)")
_BLOCK_TECHNIQUE_RE = re.compile(r"TECHNIQUE:\s*(T\d{4}(?:\.\d{3})?|NONE)", re.IGNORECASE)


# Model tool-call scaffolding, which is not prose and is never a finding.
# A local model that emits its tool calls into the
# assistant channel -- rather than through the API's own tool-call field --
# leaves these blocks in the text the ISR extraction reads, and a live
# ``static_r2`` run put them in front of an operator as claims.
#
# Closing tags are optional on purpose: a generation cut off mid-call leaves an
# opening tag and a half-written argument object, which is exactly the shape
# most likely to survive into a claim.
_SCAFFOLD_TAGS = ("tool_call", "function_call", "tool_use", "tool_response")
_SCAFFOLD_BLOCK_RE = re.compile(
    r"<(?P<tag>" + "|".join(_SCAFFOLD_TAGS) + r")\b[^>]*>.*?(?:</(?P=tag)\s*>|\Z)",
    re.DOTALL | re.IGNORECASE,
)
# A fenced block is stripped only when what it fences is a tool invocation: a
# name plus its arguments. A model quoting real JSON evidence (an import list,
# a config blob) is citing an artifact, and that has to survive.
_FENCED_JSON_RE = re.compile(r"```(?:json|tool_code)?\s*(\{.*?\})\s*```", re.DOTALL)
_INVOCATION_KEYS = ({"name", "arguments"}, {"name", "parameters"}, {"tool", "arguments"})


def _is_tool_invocation(payload: str) -> bool:
    try:
        parsed = json.loads(payload)
    except ValueError:
        return False
    if not isinstance(parsed, dict):
        return False
    keys = set(parsed)
    return any(required <= keys for required in _INVOCATION_KEYS)


def strip_tool_call_scaffolding(text: str) -> str:
    """Remove tool-call scaffolding from model output, leaving the prose.

    Applied before claims are derived, by both claim parsers and by the
    free-text path, so no analyst can turn a tool call into a finding. Text
    with no scaffolding in it comes back byte for byte.
    """
    if not text:
        return text
    cleaned = _SCAFFOLD_BLOCK_RE.sub("", text)
    cleaned = _FENCED_JSON_RE.sub(
        lambda m: "" if _is_tool_invocation(m.group(1)) else m.group(0), cleaned
    )
    if cleaned == text:
        return text
    # Only the blank lines the removals themselves left behind.
    return re.sub(r"\n{3,}", "\n\n", cleaned).strip()


def evidence_ref_width() -> int:
    """How much of one claim's evidence line the ISR stores: what the window allows one answer.

    The line feeds prompts — the ISR text the mediator and the peer revision
    rounds read, the claims the report composer is handed, the judge's
    memory query — as well as the report. So it is sized the way one tool
    answer is: the largest share of the served window one answer may take
    (``context_window.derive_tool_output_chars`` over an empty conversation),
    and the documented 6,000 characters where no window is known. It used to
    be a fixed 200 characters, which cut an analyst's own citation mid-sentence
    on every window. Where the cut still lands, it is marked where the kept
    text ends.
    """
    from maljan.llm.context_window import (
        FALLBACK,
        UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS,
        derive_tool_output_chars,
        window_for_settings,
    )

    try:
        fact = window_for_settings(get_settings(), [], probe=False)
    except Exception:  # noqa: BLE001 — an unknown window is the documented fallback
        return UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS
    if fact.source == FALLBACK or fact.tokens <= 0:
        return UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS
    return derive_tool_output_chars(window_tokens=int(fact.tokens)) or (
        UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS
    )


# How many dropped ids are written back after the evidence field's cut.
_EVIDENCE_REF_IDS = 3

# The start of an id the cut sliced through, at the end of the kept text: any
# prefix of ``[ev_NNNN``, from the bare bracket up to a whole id whose closing
# bracket was cut, and the space before it. The whole id is written back.
_PARTIAL_ID_AT_END_RE = re.compile(r"\s*(?:\[(?:e(?:v(?:_\d{0,4})?)?)?)?$", re.IGNORECASE)


def evidence_ref_text(evidence_text: str) -> str:
    """The evidence line as the ISR stores it, with its ledger ids kept.

    The field is cut to the width the window allows one answer
    (``evidence_ref_width``), and the claim format asks for the id at
    the end of a line whose front is prose, so on a long line the cut lands on
    the one part the run can check. Any id the cut dropped is written back
    after it, in the order the model wrote it, up to a few: the field is what
    the report prints and what long-term memory embeds, and the width should
    bound it. An id the cut sliced through is removed from
    the kept text, since the whole id follows.

    The cut is marked (``utils.marked_cut.CUT_MARK``) where the kept text ends.
    Unmarked, "… This suggests" was printed in a report, and copied into a
    section's prose, as the model's own finished sentence.
    """
    kept = evidence_text[: evidence_ref_width()]
    if len(kept) == len(evidence_text):
        return kept
    kept = _PARTIAL_ID_AT_END_RE.sub("", kept).rstrip() + CUT_MARK
    still_there = {found.lower() for found in ENTRY_ID_RE.findall(kept)}
    dropped = [
        found
        for found in dict.fromkeys(f.lower() for f in ENTRY_ID_RE.findall(evidence_text))
        if found not in still_there
    ][:_EVIDENCE_REF_IDS]
    if not dropped:
        return kept
    return f"{kept} {' '.join(f'[{found}]' for found in dropped)}"


def parse_structured_claims(text: str) -> list[ClaimEvidence]:
    """Parse ``CLAIM:``-delimited blocks, tolerating a missing ``EVIDENCE:`` line.

    The claims alone; ``parse_structured_claims_counted`` also says how many
    blocks were not claims for want of a confidence.
    """
    return parse_structured_claims_counted(text)[0]


def parse_structured_claims_counted(text: str) -> tuple[list[ClaimEvidence], int]:
    """``(claims, blocks that stated no confidence)`` for the ``CLAIM:`` blocks in ``text``.

    The view/tier decomposition prompts (``_VIEW_SYSTEM``)
    require this exact format; the parsed output used to be handed to a
    free-text sentence splitter, which has no notion of a ``TECHNIQUE:`` line,
    so every technique ID produced through those paths was dropped and the raw
    "CLAIM: ..." prefix leaked into the claim text.

    More lenient than the static analyst's strict variant about the citation:
    a block without ``EVIDENCE:`` is still a finding, recorded as unsourced.
    Not about the confidence. A block that states none, or one that cannot be
    read as a number, is not a claim: the confidence on a claim is the
    analyst's own statement, and this parser used to write 0.5 where the
    analyst wrote nothing. Such blocks are counted instead, and the count is
    what the validation turn asks the analyst about.
    """
    claims: list[ClaimEvidence] = []
    without_confidence = 0
    # Stripped per field rather than over the whole text: removing a block
    # that sat between ``CLAIM:`` and ``EVIDENCE:`` would leave the claim
    # marker with nothing after it, and the next line would slide up into the
    # claim. A block whose claim is nothing but scaffolding is dropped below.
    for raw_block in _BLOCK_SPLIT_RE.split(text):
        block = raw_block.strip()
        if not block or "CLAIM:" not in block:
            continue
        claim_match = _BLOCK_CLAIM_RE.search(block)
        if not claim_match:
            continue
        claim_text = strip_tool_call_scaffolding(claim_match.group(1)).strip()
        if not claim_text:
            # C1: the whole claim was a tool call. An empty finding is worse
            # than none at all -- it reaches the operator as a blank row.
            continue

        # The citation is model output too, and a model that writes a tool
        # call while it is naming an artifact puts the block here rather than
        # in the claim. Cleaned to nothing it means what a missing EVIDENCE
        # line already means to this lenient parser: a finding worth keeping,
        # recorded as unsourced.
        evidence_match = _BLOCK_EVIDENCE_RE.search(block)
        evidence_text = (
            strip_tool_call_scaffolding(evidence_match.group(1)).strip() if evidence_match else ""
        )
        confidence_match = _BLOCK_CONFIDENCE_RE.search(block)
        technique_match = _BLOCK_TECHNIQUE_RE.search(block)

        confidence = _stated_confidence(confidence_match)
        if confidence is None:
            without_confidence += 1
            continue

        technique_id: str | None = None
        if technique_match:
            raw_tid = technique_match.group(1).upper()
            # Kept as written. Whether the id is real, retired or a
            # placeholder is ``attck.unknown_id``'s question, asked with
            # feedback and recorded; a parser that dropped it here would be
            # the silent rewrite this pipeline does not do.
            if raw_tid != "NONE":
                technique_id = raw_tid

        claims.append(
            ClaimEvidence(
                claim=claim_text[:300],
                evidence_ref=evidence_ref_text(evidence_text),
                confidence=confidence,
                technique_id=technique_id,
            )
        )
    return claims, without_confidence


def _stated_confidence(match: re.Match[str] | None) -> float | None:
    """The confidence a ``CONFIDENCE:`` line states, or ``None`` when it states none.

    A number above one or below zero is still the analyst's number, held to
    the range the schema carries; a line that is not a number states nothing.
    """
    if match is None:
        return None
    try:
        return max(0.0, min(1.0, float(match.group(1))))
    except ValueError:
        return None


def _extract_technique_ids(text: str) -> list[str]:
    """Every distinct technique id mentioned in the text, in order, as written."""
    return list(dict.fromkeys(_TECHNIQUE_RE.findall(text)))


# ---------------------------------------------------------------------------
# View-decomposition (findings-log §3.6) — text-path only.
# Each "view" is a focused sub-prompt over the SAME evidence (AppPoet-style),
# not a content split. Views run concurrently and merge via merge_chunk_isrs.
# ---------------------------------------------------------------------------

# Generic, tools-free system prompt for a single view. Renders the same claim
# format the analysts are given, so ``parse_structured_claims`` reads it and
# the format is written in one place, and carries the "cite an artifact, do
# not invent" rule the §3.2 study needs.
_VIEW_SYSTEM = (
    "You are an expert malware analyst examining one focused facet of a sample. "
    "Analyse ONLY the aspect named in the instruction; ignore everything else. "
    "For EVERY claim you MUST cite a concrete artifact (API/import, string, path, "
    "registry key, host/domain). DO NOT invent capabilities or technique IDs — if "
    "the evidence does not support a claim, omit it. Cite MITRE ATT&CK technique "
    "IDs in the form Txxxx or Txxxx.yyy only when the evidence supports them.\n"
    + CLAIM_FORMAT_FRAGMENT
)

# Per-domain ordered facets. ``_view_specs`` returns the first N (N=2 -> the first
# two; N=4 -> all four). Each entry: (key, focused instruction).
_DOMAIN_FACETS: dict[str, list[tuple[str, str]]] = {
    "static": [
        (
            "code",
            "Focus only on executable behaviour: imported APIs, suspicious "
            "call sequences, and control-flow (e.g. injection, native API use).",
        ),
        (
            "artifacts",
            "Focus only on static artifacts: hardcoded strings, embedded "
            "resources, configuration blobs, and file/path indicators.",
        ),
        (
            "crypto",
            "Focus only on cryptography and obfuscation: crypto constants, "
            "packing/entropy signs, and de/obfuscation routines.",
        ),
        (
            "evasion",
            "Focus only on anti-analysis and evasion: anti-debug, anti-VM, "
            "timing checks, and sandbox-detection logic.",
        ),
    ],
    "dynamic": [
        (
            "behaviour",
            "Focus only on runtime behaviour: API call sequences, process "
            "creation/injection, and command execution.",
        ),
        (
            "artifacts",
            "Focus only on dropped artifacts: files written, registry keys "
            "set, mutexes, and configuration/IOCs.",
        ),
        (
            "persistence",
            "Focus only on persistence: autostart, services, scheduled "
            "tasks, WMI, and COM/registry run keys.",
        ),
        (
            "network",
            "Focus only on network/C2 behaviour observed at runtime: "
            "connections, beaconing, and exfiltration.",
        ),
    ],
    "network": [
        (
            "dns",
            "Focus only on DNS and beaconing: queries, DGA-like domains, and "
            "periodic callback patterns.",
        ),
        (
            "web",
            "Focus only on HTTP/TLS: request patterns, headers, SNI, and certificate anomalies.",
        ),
        (
            "tunnel",
            "Focus only on tunneling and non-standard channels: unusual "
            "ports, protocol mismatches, and covert transport.",
        ),
        (
            "exfil",
            "Focus only on exfiltration: large/odd outbound transfers and "
            "data-staging destinations.",
        ),
    ],
}


def _view_specs(domain: str, n_views: int) -> list[tuple[str, str]]:
    """Return ``n_views`` focused (key, instruction) facets for ``domain``.

    Draws from the per-domain ordered facet list; for N beyond the table it
    pads with generic numbered facets so the eval harness can try any N>=2.
    """
    facets = _DOMAIN_FACETS.get(domain, _DOMAIN_FACETS["static"])
    if n_views <= len(facets):
        return facets[:n_views]
    out = list(facets)
    for i in range(len(facets), n_views):
        out.append((f"facet{i}", f"Focus only on analysis facet #{i + 1} of the evidence."))
    return out


# ---------------------------------------------------------------------------
# Tier-wise (vertical) reasoning (findings-log §4 Item 3, LAMD). Where view
# decomposition is *horizontal* (independent facets over the SAME evidence, run
# concurrently), tier reasoning is *vertical*: foundational facts -> behaviour
# synthesis -> ATT&CK semantics, each tier consuming the previous tier's
# findings as added context. Tiers run SEQUENTIALLY and share the §3.6
# equal-budget split and the tools-free ``_invoke_view`` text path.
# ---------------------------------------------------------------------------

_TIER_SPECS: list[tuple[str, str]] = [
    (
        "facts",
        "Reasoning tier 1 of 3 (foundational facts). Extract ONLY concrete, "
        "low-level artifacts present in the evidence: specific imported APIs, "
        "strings, file paths, registry keys, mutexes, hosts/domains/IPs. Do NOT "
        "interpret intent or assign technique IDs yet — just enumerate what is "
        "verifiably present, each with its artifact citation.",
    ),
    (
        "behaviour",
        "Reasoning tier 2 of 3 (behaviour synthesis). Using ONLY the foundational "
        "facts established by the previous tier, synthesize the concrete "
        "behaviours they implement (e.g. process injection, persistence, C2 "
        "beaconing, credential theft, file encryption). Cite the specific "
        "artifact supporting each behaviour; do NOT introduce artifacts the "
        "previous tier did not establish.",
    ),
    (
        "semantics",
        "Reasoning tier 3 of 3 (ATT&CK semantics). Using ONLY the behaviours "
        "established by the previous tier, map each to its MITRE ATT&CK technique "
        "and assess overall malicious intent. Cite the supporting behaviour and "
        "artifact for every technique; omit any technique the evidence does not "
        "support.",
    ),
]


def _tier_specs(n_tiers: int) -> list[tuple[str, str]]:
    """Return ``n_tiers`` ordered (key, instruction) reasoning tiers.

    Draws from the fixed LAMD-style facts->behaviour->semantics ladder (the
    canonical depth is 3); for N beyond the table it pads with generic numbered
    tiers so the eval harness can probe any N>=2.
    """
    if n_tiers <= len(_TIER_SPECS):
        return _TIER_SPECS[:n_tiers]
    out = list(_TIER_SPECS)
    for i in range(len(_TIER_SPECS), n_tiers):
        out.append(
            (
                f"tier{i}",
                f"Reasoning tier {i + 1}: build further on the findings of the "
                "previous tier, adding only what the evidence supports.",
            )
        )
    return out


# ---------------------------------------------------------------------------
# Inline consistency gate (findings-log §4 Item 4, LAMD). LAMD verifies factual
# consistency at the foundational tier *before* claims propagate; Maljan's
# fp_linter is post-hoc/structural. This adds an optional, claim-level grounding
# filter (applied in the analyst safe_* wrappers): a claim survives only when
# the artifact / technique it cites actually appears in the source evidence.
# Gated off by default (PreprocessingConfig.use_claim_consistency_gate).
# ---------------------------------------------------------------------------

# Generic words that must not, on their own, make a claim look "grounded".
_GROUNDING_STOPWORDS: frozenset[str] = frozenset(
    {
        "this",
        "that",
        "with",
        "from",
        "uses",
        "using",
        "which",
        "their",
        "there",
        "into",
        "when",
        "then",
        "also",
        "does",
        "while",
        "these",
        "those",
        "such",
        "have",
        "been",
        "will",
        "would",
        "could",
        "should",
        "about",
        "they",
        "them",
        "between",
        "across",
        "through",
        "based",
        "appears",
        "likely",
        "suggests",
        "indicates",
        "behaviour",
        "behavior",
        "sample",
        "malware",
        "analysis",
        "report",
        "finding",
        "claim",
    }
)

# Minimum fraction of a claim's substantive tokens that must overlap the source
# evidence for the claim to count as grounded (the text-fallback path).
_GROUNDING_MIN_OVERLAP: float = 0.34

# The synthetic evidence_ref ``_text_to_isr`` emits — must never be treated as a
# real, auto-grounding artifact reference.
_SYNTHETIC_REF_PREFIX = "text-extracted"


def _significant_tokens(text: str) -> list[str]:
    """Lowercase alphanumeric tokens of length>=4 that are not generic filler."""
    return [
        t
        for t in re.split(r"[^a-z0-9]+", text.lower())
        if len(t) >= 4 and t not in _GROUNDING_STOPWORDS
    ]


def _claim_grounded_in_evidence(
    claim_text: str, evidence_ref: str, technique_id: str | None, evidence: str
) -> bool:
    """Return True when a claim is supported by the source evidence.

    Grounded when (a) the cited technique id literally appears in the evidence,
    (b) the claim carries a *real* artifact reference (not the synthetic
    text-extraction placeholder) whose substantive token appears in the
    evidence, or (c) a sufficient fraction of the claim text's substantive
    tokens overlap the evidence. Extends the grounding idiom from
    ``eval_view_decomposition._grounding_rate`` to the production claim shapes
    (structured real refs + text-fallback claims).
    """
    ev_lower = evidence.lower()
    tid = (technique_id or "").upper().strip()
    if tid and tid in evidence.upper():
        return True
    ref = evidence_ref or ""
    if ref and not ref.lower().startswith(_SYNTHETIC_REF_PREFIX):
        if any(t in ev_lower for t in _significant_tokens(ref)):
            return True
    claim_tokens = set(_significant_tokens(claim_text))
    if not claim_tokens:
        return False
    hits = sum(1 for t in claim_tokens if t in ev_lower)
    return hits / len(claim_tokens) >= _GROUNDING_MIN_OVERLAP


# Strip control characters except whitespace (\t \n \r) before sending
# untrusted data into a prompt. This neutralises common prompt-injection
# tricks such as embedded ANSI escape sequences or rogue BOMs.


# ---------------------------------------------------------------------------
# A single process-wide agent event loop.
#
# Every agent ReAct / no-tools LLM call used to spin up a throwaway
# ``asyncio.new_event_loop()`` in its own thread and ``close()`` it afterwards.
# The openai SDK lazily builds an httpx ASYNC connection pool bound to whatever
# loop first awaits it; once that per-call loop closed, the pooled connections
# were orphaned and their later cleanup ran ``loop.call_soon`` on the CLOSED
# loop -> ``RuntimeError: Event loop is closed`` (Windows ProactorEventLoop),
# surfaced to the SDK as a bogus ``APIConnectionError`` that aborted the
# negotiation + mediator phases. A per-invocation FRESH client (an earlier
# attempt) removed the cross-loop reuse but introduced a pipeline hang.
#
# The root fix is to stop churning loops at all: one long-lived loop in a
# daemon thread serves every agent coroutine via ``run_coroutine_threadsafe``.
# Async clients are created once on that loop and reused on the SAME loop for
# the process lifetime, so the cross-loop reuse is structurally impossible and
# there is no per-call client rebuild to hang on. The hard wall-clock cap is
# preserved via ``future.result(timeout=...)`` (mirrors the old ``t.join``).
_AGENT_LOOP: asyncio.AbstractEventLoop | None = None
_AGENT_LOOP_LOCK = threading.Lock()


# How long a cancelled agent coroutine has to actually end before the loop it
# runs on is treated as wedged. Cancelling is a request: a task that never
# awaits again — anyio delivering into a shielded child-process wait is the
# case seen live — never receives it, and anyio re-arms the delivery with
# ``call_soon`` on every iteration, which turns the loop thread into a 100 %
# CPU spin that nothing ends. Ten seconds is far longer than any teardown that
# is going to succeed and far shorter than the 80 minutes that spin ran for.
#
# It is measured against the *shielded* teardown budgets in
# ``providers/servers.py``, which are the only work allowed to continue after a
# cancel: ``CHILD_TERM_GRACE`` 2s and ``REAP_BUDGET`` 4s, both far inside this.
# The unshielded ones there are larger than this grace on purpose —
# ``CLEANUP_TIMEOUT`` 12s, plus ``CROSS_LOOP_GRACE`` 14s routed, and
# ``SYNC_CLOSE_TIMEOUT`` 20s — but a cancel is only ever watched *after* one of
# those fences has already fired, so they are never in flight here. Raising a
# shielded budget in that module past this value would start retiring healthy
# loops, so the two are changed together.
CANCEL_DELIVERY_GRACE = 10.0

# Callbacks fired when a loop is retired, so whatever was bound to it can be
# dropped before anything tries to use it on the fresh loop (see
# ``_retire_wedged_loop``). Registered by ``providers.servers`` and
# ``core.container``; called on the watchdog thread, so a hook does the least
# work that makes its own state unusable and never blocks for long.
_LOOP_RETIREMENT_HOOKS: list[Callable[[asyncio.AbstractEventLoop], None]] = []
_LOOP_HOOKS_LOCK = threading.Lock()
# The thread serving each live agent loop, so a loop that refuses to stop can
# be named in the log rather than described. Keyed by ``id`` because a loop is
# only ever compared by identity here.
_LOOP_THREADS: dict[int, threading.Thread] = {}
_LOOP_SEQUENCE = itertools.count(1)


def on_agent_loop_retired(hook: Callable[[asyncio.AbstractEventLoop], None]) -> None:
    """Register ``hook`` to run when an agent loop is retired. Never unregisters."""
    with _LOOP_HOOKS_LOCK:
        if hook not in _LOOP_RETIREMENT_HOOKS:
            _LOOP_RETIREMENT_HOOKS.append(hook)


def _invalidate_loop_bound_state(loop: asyncio.AbstractEventLoop) -> None:
    """Tell every registered owner that ``loop`` is gone. Never raises."""
    with _LOOP_HOOKS_LOCK:
        hooks = list(_LOOP_RETIREMENT_HOOKS)
    for hook in hooks:
        try:
            hook(loop)
        except Exception as exc:  # noqa: BLE001 — one owner must not stop the rest
            logger.warning("agent-loop retirement hook failed (non-fatal): %s", exc)


def _serve_agent_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Run ``loop`` until it is stopped, then close it.

    ``run_forever`` only returns after a retirement posted ``stop()``, so the
    close is reached exactly once per retired loop and never for a healthy one.
    Closing frees the selector and the self-pipe, which otherwise stayed open
    for the life of the process — one pair of descriptors per retirement.
    """
    try:
        loop.run_forever()
    finally:
        with contextlib.suppress(Exception):
            loop.close()


def _get_agent_loop() -> asyncio.AbstractEventLoop:
    """Return the process-wide agent event loop, starting it on first use."""
    global _AGENT_LOOP
    with _AGENT_LOOP_LOCK:
        loop = _AGENT_LOOP
        # ``is_running()`` is deliberately not consulted: a loop whose thread
        # has been started but has not yet entered ``run_forever`` would look
        # dead to a second caller and get replaced, orphaning the first. A
        # retired loop is signalled by ``_retire_wedged_loop`` clearing this
        # global instead.
        if loop is None or loop.is_closed():
            loop = asyncio.new_event_loop()
            thread = threading.Thread(
                target=_serve_agent_loop,
                args=(loop,),
                name=f"maljan-agent-loop-{next(_LOOP_SEQUENCE)}",
                daemon=True,
            )
            _LOOP_THREADS[id(loop)] = thread
            thread.start()
            _AGENT_LOOP = loop
        return loop


# Once the interpreter has begun finalising, a daemon thread has nothing
# useful left to do and several harmful things it can still attempt. Logging is
# the sharpest: the streams a handler writes to are closed by then, which
# ``logging`` reports as an error and swallows, and holding the stderr buffer
# lock while the runtime tears itself down is a ``Fatal Python error`` and a
# non-zero exit on a process that had already finished its work. The children
# this thread would reap are the operating system's to collect a moment later
# in any case, so standing down costs nothing.
def _the_interpreter_is_going() -> bool:
    """True once this process has begun shutting down. Never raises."""
    try:
        return bool(sys.is_finalizing())
    except Exception:  # noqa: BLE001 — a shutdown check may not fail a shutdown
        return True


def _retire_wedged_loop(loop: asyncio.AbstractEventLoop, what: str) -> None:
    """Stop ``loop``, verify it stopped, and let the next caller start a fresh one.

    Only ever reached from the watchdog below, and only for a loop that is
    already unusable: it carries a task that refused a cancellation, or it is
    not servicing callbacks at all, so everything queued behind it is starved
    anyway.

    ``stop()`` is a request too. It is honoured at the end of a ``_run_once``
    iteration, which is exactly what the anyio cancel-delivery spin does reach
    — but a coroutine blocked in synchronous code never returns to the loop, so
    the stop is never seen. Claiming the loop was retired in that case would be
    a lie: the global is cleared either way (nothing may be handed this loop
    again), and if the loop is still running after the grace this says so
    loudly, names the thread, and leaves it abandoned.

    The stop is posted before anything bound to the loop is invalidated. A
    spinning loop honours ``stop()`` at the end of its current iteration, so
    posting it first ends the spin at once; the invalidation that follows
    reaps every child the loop's handles spawned, each with its own grace
    period, and a loop left spinning through those reaps would starve the
    rest of the process for exactly that long (BUG 13 showed six abandoned
    handles queued behind one retirement). Nothing is handed this loop in the
    meantime: the global was cleared before either step, and a cached toolkit
    or async client created on this loop would only park on a future nobody
    will ever complete, which is what the invalidation exists to prevent.
    """
    if _the_interpreter_is_going():
        return
    global _AGENT_LOOP
    with _AGENT_LOOP_LOCK:
        if _AGENT_LOOP is loop:
            _AGENT_LOOP = None
    thread = _LOOP_THREADS.pop(id(loop), None)
    logger.error(
        "%s ignored its cancellation for %.0fs; the agent loop is being retired and "
        "a fresh one will be started for the next call.",
        what,
        CANCEL_DELIVERY_GRACE,
    )
    with contextlib.suppress(RuntimeError):
        loop.call_soon_threadsafe(loop.stop)
    _invalidate_loop_bound_state(loop)

    deadline = time.monotonic() + CANCEL_DELIVERY_GRACE
    while time.monotonic() < deadline:
        if loop.is_closed() or not loop.is_running():
            return
        time.sleep(0.1)
    if _the_interpreter_is_going():
        return
    logger.error(
        "the retired agent loop did not stop within %.0fs either: thread %r is abandoned "
        "and keeps running whatever blocked it until this process exits. Everything that "
        "was bound to that loop has been dropped, so the work itself continues on the "
        "fresh loop; the cost is one wedged thread.",
        CANCEL_DELIVERY_GRACE,
        thread.name if thread is not None else "maljan-agent-loop",
    )


def _on_agent_loop_thread(loop: asyncio.AbstractEventLoop) -> bool:
    """True when the calling thread is the one serving ``loop``.

    Read from the recorded thread rather than from ``get_running_loop``: the
    callers that matter are *synchronous* functions reached from a coroutine
    running on the agent loop, and those have no running loop of their own to
    ask.
    """
    thread = _LOOP_THREADS.get(id(loop))
    return thread is not None and thread.ident == threading.get_ident()


def _submit_to_agent_loop(
    coro: Any, loop: asyncio.AbstractEventLoop
) -> tuple[_ConcurrentFuture[Any], list[asyncio.Task[Any]]]:
    """Schedule ``coro`` on ``loop``, keeping the task it actually runs as.

    ``run_coroutine_threadsafe`` hands back a ``concurrent.futures.Future``
    that is marked cancelled the moment ``cancel()`` is called, whether or not
    the asyncio task ever ends — so the future says nothing about whether a
    cancellation was delivered. The task does, and this is the only way to
    hold one: the wrapper records itself before awaiting.
    """
    running: list[asyncio.Task[Any]] = []

    async def _tracked() -> Any:
        task = asyncio.current_task()
        if task is not None:
            running.append(task)
        return await coro

    return asyncio.run_coroutine_threadsafe(_tracked(), loop), running


def _cancel_and_watch(
    loop: asyncio.AbstractEventLoop,
    future: _ConcurrentFuture[Any],
    running: list[asyncio.Task[Any]],
    what: str,
) -> None:
    """Cancel ``future`` and make sure the cancellation is actually delivered.

    ``future.cancel()`` on its own is fire-and-forget: the live hang of
    2026-09-07 was a teardown whose cancellation could not be delivered, after
    which the loop thread spun at 100 % CPU for 80 minutes, starved the
    worker's own thread of the GIL and stopped the job's heartbeat. The
    watchdog is a daemon thread rather than a wait here, so no caller is
    delayed by a task that is going to end normally.
    """
    future.cancel()
    # An empty ``running`` is ambiguous: the coroutine may have been cancelled
    # before the loop gave it a turn (a healthy loop, nothing to do), or the
    # loop may already be wedged by an *earlier* task so this one never
    # started — the state the whole fix exists for. A callback posted now tells
    # the two apart: a loop that still services callbacks is healthy, a loop
    # that never runs this one is not servicing anything.
    servicing = threading.Event()
    with contextlib.suppress(RuntimeError):
        loop.call_soon_threadsafe(servicing.set)

    def _watch() -> None:
        deadline = time.monotonic() + CANCEL_DELIVERY_GRACE
        while time.monotonic() < deadline:
            if running and running[0].done():
                return
            if _the_interpreter_is_going():
                return
            time.sleep(0.05)
        if _the_interpreter_is_going():
            return
        if running:
            if not running[0].done():
                _retire_wedged_loop(loop, what)
            return
        if not servicing.is_set():
            _retire_wedged_loop(loop, f"{what} (never started: the loop is not running work)")

    def _watch_quietly() -> None:
        """``_watch``, with nothing able to leave the thread.

        A daemon thread has nobody to report to. An exception out of one is a
        traceback printed at shutdown, on streams that may be gone, which is
        the failure this whole guard exists to stop — and a watchdog that
        cannot finish its own job has nothing to say that is worth ending a
        finished process over.
        """
        try:
            _watch()
        except BaseException:  # noqa: BLE001 — a watchdog never becomes the failure
            if not _the_interpreter_is_going():
                with contextlib.suppress(Exception):
                    logger.debug("the cancel watchdog stopped early.", exc_info=True)

    threading.Thread(target=_watch_quietly, name="maljan-agent-loop-watchdog", daemon=True).start()


def _job_s_cancellation(coro: Any, what: str) -> Any | None:
    """The cancellation of the job this call runs for; a cancelled job's call is not started."""
    from maljan.core.cancellation import JobCancelled, current

    job = current()
    if job is not None:
        try:
            job.check(f"before {what}")
        except JobCancelled:
            coro.close()
            raise
    return job


def _in_flight(
    job: Any | None,
    loop: asyncio.AbstractEventLoop,
    future: _ConcurrentFuture[Any],
    running: list[asyncio.Task[Any]],
    what: str,
) -> Callable[[], None]:
    """Register a call on the agent loop with its job, so a cancel stops it; the unregister."""
    if job is None:
        return lambda: None
    return cast(
        "Callable[[], None]",
        job.track(lambda: _cancel_and_watch(loop, future, running, f"{what} (job cancelled)")),
    )


def _run_coro_blocking(coro: Any, hard_timeout: float, label: str = "") -> Any:
    """Submit ``coro`` to the shared agent loop and block until done / timeout.

    Mirrors the old daemon-thread + ``t.join(timeout)`` contract: on the hard
    wall-clock cap we cancel the scheduled task and raise ``TimeoutError`` so the
    caller surfaces a degraded analyst instead of hanging. Any exception raised
    inside the coroutine (including the inner ``asyncio.wait_for`` stall) is
    re-raised here unchanged.

    ``label`` names what is being run ("cape-mcp-init", "react:static") and is
    the difference between a diagnosable failure and a shrug. Pass it.

    Two ways a coroutine can end without a result, and they mean opposite
    things — see ``AgentLoopCancelled``. The second branch existed nowhere
    before 2026-07-26, which is how every dynamic-analyst failure in the
    database came to say ``CancelledError`` and nothing else.
    """
    loop = _get_agent_loop()
    what = label or "agent coroutine"
    # Blocking the agent loop's *own* thread on work the agent loop has to run
    # is a deadlock by construction: ``future.result`` holds that thread, so the
    # coroutine it waits for never gets a turn and the loop is dead underneath
    # it for the whole hard cap — the "blocked in synchronous code" case
    # ``_retire_wedged_loop`` can only report, never end. Refusing names the
    # caller, which is the one thing a stack trace of a wedged loop cannot.
    if _on_agent_loop_thread(loop):
        coro.close()
        raise RuntimeError(
            f"{what} was submitted with a blocking wait from the agent loop's own "
            "thread, which cannot serve it: await it there instead, or move the "
            "synchronous caller to asyncio.to_thread"
        )
    job = _job_s_cancellation(coro, what)
    future, running = _submit_to_agent_loop(coro, loop)
    # A cancelled job stops this call where it is: the task on the agent loop
    # is cancelled, which cancels the model request it is awaiting.
    forget = _in_flight(job, loop, future, running, what)
    try:
        return future.result(timeout=hard_timeout)
    except _FuturesTimeout:
        # We cancelled it: it ran out of wall clock. Whether that cancellation
        # is ever *delivered* is a separate question, and one the watchdog
        # answers rather than assuming.
        _cancel_and_watch(loop, future, running, what)
        raise TimeoutError(f"{what} exceeded hard cap of {int(hard_timeout)}s") from None
    except _FuturesCancelled as exc:
        if job is not None and job.is_cancelled:
            job.check(f"while {what} was in flight")
        # It cancelled itself. ``concurrent.futures.CancelledError`` is an
        # ``Exception`` whose ``str()`` is empty, so left alone it reaches the
        # operator as one uninformative word.
        raise AgentLoopCancelled(
            f"{what} was cancelled from inside — the underlying service closed the "
            f"connection or its task group aborted (no timeout was reached)"
        ) from exc
    finally:
        forget()


# Public alias: callers outside this module (the sandbox/static providers)
# import a name that isn't theirs to treat as private. The leading-underscore
# name stays for the tests and call sites within this module.
run_coro_blocking = _run_coro_blocking


# How long any single toolkit close may take before it is abandoned. Teardown
# runs after the analysis has already succeeded, so the only thing at stake is
# reclaiming a subprocess and a socket — never worth holding a finished job
# open for. See ``BaseAnalyst.close_tools``.
CLOSE_TOOLS_TIMEOUT = 15.0


async def run_on_agent_loop(coro: Any, hard_timeout: float, label: str = "") -> Any:
    """Await ``coro`` on the shared agent loop from a *different* running loop.

    The async sibling of ``_run_coro_blocking``, and the other half of the
    shared-loop fix above. That fix moved every *analyst* call onto one long-lived
    loop, but the graph's own coroutine nodes still awaited their agent calls
    on the worker's loop — and the openai SDK's httpx pool is bound to the loop
    that first awaited it, which by then is always the agent loop. Building a
    brand-new ``ChatOpenAI`` does not help: the pool is shared process-wide, so
    the second loop inherits the first loop's connections and every call dies
    instantly with ``RuntimeError: ... bound to a different event loop``, which
    the SDK reports as a bare ``APIConnectionError("Connection error.")``.

    Live evidence (2026-07-26): *every* run in the database recorded
    ``Mediation failed: Connection error.`` — the negotiation had never once
    completed in this deployment, and the graph's fault-isolation boundary
    degraded it to "no consensus" so quietly that nothing ever surfaced it.
    The judge escaped only because it calls the *sync* client via
    ``asyncio.to_thread``, which binds no loop at all.
    """
    loop = _get_agent_loop()
    what = label or "agent coroutine"
    job = _job_s_cancellation(coro, what)
    future, running = _submit_to_agent_loop(coro, loop)
    forget = _in_flight(job, loop, future, running, what)
    try:
        return await asyncio.wait_for(asyncio.wrap_future(future), hard_timeout)
    except TimeoutError:
        _cancel_and_watch(loop, future, running, what)
        raise TimeoutError(f"{what} exceeded hard cap of {int(hard_timeout)}s") from None
    except (asyncio.CancelledError, _FuturesCancelled) as exc:
        # The caller itself being cancelled is not the call failing: the
        # cancellation goes on up, and the call on the agent loop is stopped
        # with it. This branch used to turn it into ``AgentLoopCancelled``, an
        # ordinary error: a cancelled job's mediation was then caught as a
        # failed one, and the graph went on to the judge and the report.
        task = asyncio.current_task()
        if task is not None and task.cancelling():
            _cancel_and_watch(loop, future, running, what)
            raise
        future.cancel()
        if job is not None and job.is_cancelled:
            job.check(f"while {what} was in flight")
        # Same distinction as ``_run_coro_blocking``, and here the old code was
        # actively misleading: it folded cancellation into ``TimeoutError``, so
        # a transport that died in milliseconds was reported as having "exceeded
        # a hard cap" of several minutes. This is the mediator and judge path.
        raise AgentLoopCancelled(
            f"{what} was cancelled from inside — the underlying service closed the "
            f"connection or its task group aborted (no timeout was reached)"
        ) from exc
    finally:
        forget()


# The negotiation-round instructions the ISR revision path appends to whatever
# system prompt its agent carries. Lifted verbatim out of
# ``NetworkAnalyst.revise_isr``; ``tests/unit/agents/test_revision_prompt_golden.py``
# holds it to the byte.
_REVISION_ISR_FRAMING = (
    "You are in a negotiation round. You MUST:\n"
    "1. List any peer claims you still DISPUTE in a DISPUTES section.\n"
    "2. Revise your own claims based on new evidence.\n"
    "3. If you have NO disputes, write 'DISPUTES: NONE' to signal convergence."
)


def prompt_to_messages(prompt_messages: list[tuple[str, str]]) -> list[BaseMessage]:
    """``(role, text)`` pairs as LangChain messages, with no templating step.

    The same construction ``execute_tool_loop`` does inline, and for the same
    reason: a ``ChatPromptTemplate`` would read a literal ``{...}`` inside a
    report — JSON, a decompiled struct — as an f-string variable and raise on
    content the pipeline routinely produces. An unknown role is dropped rather
    than guessed at.
    """
    from langchain_core.messages import HumanMessage, SystemMessage

    built: list[BaseMessage] = []
    for role, content in prompt_messages:
        if role == "system":
            built.append(SystemMessage(content=content))
        elif role == "human":
            built.append(HumanMessage(content=content))
    return built


def frame_messages(
    messages: list[BaseMessage], *, facts_block: str = "", run_state: str = ""
) -> list[BaseMessage]:
    """The conversation with the run's two standing blocks in their places.

    ``facts_block`` goes at the head of the first human turn, once: it is the
    triage pack, and the human turn is where the task and the data are.
    ``run_state`` goes into the first system turn between its markers,
    replacing the block already there — the same conversation framed twice
    carries one block, the newer one. Empty blocks change nothing, so an
    agent outside a staged run sends exactly what it always sent.
    """
    from langchain_core.messages import HumanMessage, SystemMessage

    from maljan.pipeline.run_state import RUN_STATE_BEGIN, with_run_state
    from maljan.pipeline.triage_pack import PACK_HEADING

    out: list[BaseMessage] = list(messages)
    if run_state or any(
        isinstance(m, SystemMessage) and RUN_STATE_BEGIN in str(m.content) for m in out
    ):
        for index, message in enumerate(out):
            if isinstance(message, SystemMessage):
                out[index] = SystemMessage(content=with_run_state(str(message.content), run_state))
                break
    if facts_block:
        for index, message in enumerate(out):
            if isinstance(message, HumanMessage):
                content = str(message.content)
                if PACK_HEADING not in content:
                    out[index] = HumanMessage(content=f"{facts_block}\n\n{content}")
                break
    return out


def revision_messages(
    system_prompt: str,
    original_data: str,
    own_report: str,
    peer_reports: dict[str, str],
    mediator_feedback: str,
    *,
    isr: bool = False,
    revision_round: int = 1,
) -> list[tuple[str, str]]:
    """The revision prompt every analyst sends, as ``(role, text)`` pairs.

    Extracted from ``NetworkAnalyst`` so the configurable analyst sends the
    same framing rather than a second copy of it that drifts. The two paths it
    covers are the two that exist: ``isr=False`` is the plain text revision,
    which passes ``system_prompt`` through untouched; ``isr=True`` is the
    negotiation round, which appends ``_REVISION_ISR_FRAMING`` and asks for the
    CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE plus DISPUTES shape the ISR parsers
    read. Everything here — the labels, the order of the blocks, the closing
    sentence — is byte-for-byte what the network analyst sent before.

    ``revision_round`` is not interpolated into the prompt (it never was); it
    is carried so a caller's log line and the returned ISR agree about which
    round produced which text.
    """
    logger.debug(
        "Building revision prompt (isr=%s, round=%d, peers=%d).",
        isr,
        revision_round,
        len(peer_reports),
    )
    if isr:
        peer_section = (
            "\n\n".join(
                f"{name.upper()} REPORT:\n{report}" for name, report in peer_reports.items()
            )
            or "No peer reports available."
        )
        return [
            ("system", system_prompt + "\n\n" + _REVISION_ISR_FRAMING),
            (
                "human",
                f"YOUR ORIGINAL REPORT:\n{own_report}\n\n"
                f"PEER REPORTS:\n{peer_section}\n\n"
                f"MEDIATOR FEEDBACK:\n{mediator_feedback}\n\n"
                f"RAW DATA:\n{original_data}\n\n"
                "Format your response as structured claims (CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE)\n"
                "followed by a DISPUTES section listing peer claims you reject.\n"
                "Example:\n"
                "CLAIM: ...\nEVIDENCE: ...\nCONFIDENCE: 0.8\nTECHNIQUE: T1071\n---\n"
                "DISPUTES:\n- Static analyst says no C2 strings but PCAP shows beaconing.\n",
            ),
        ]

    peer_section = (
        "\n\n".join(
            f"{name.upper()} ANALYST REPORT:\n{report}" for name, report in peer_reports.items()
        )
        or "No peer reports available."
    )
    return [
        ("system", system_prompt),
        (
            "human",
            f"YOUR ORIGINAL REPORT:\n{own_report}\n\n"
            f"PEER ANALYST REPORTS:\n{peer_section}\n\n"
            f"MEDIATOR CONTRADICTIONS:\n{mediator_feedback}\n\n"
            f"ORIGINAL RAW DATA:\n{original_data}\n\n"
            "Revise your analysis addressing the contradictions above.",
        ),
    ]


def analyst_output_cap(agent: str = "") -> int:
    """The output cap an analyst's calls are built with, in tokens.

    ``llm.expert_max_tokens`` when the operator set it, and otherwise the cap
    derived from the window the analyst's model serves
    (``context_window.output_cap_for``), as the container binds it. Read,
    never raised: the cut question names the cap in force.
    """
    try:
        from maljan.llm.context_window import output_cap_for

        return output_cap_for(get_settings(), "expert_max_tokens", agent).tokens
    except Exception:  # noqa: BLE001 — an unreadable setting names no cap
        return 0


def answer_cut_at_cap(response: Any, cap: int) -> tuple[int, str] | None:
    """``(cap, text)`` when the output cap ended ``response``, else ``None``.

    By the server's word or by its count: ik_llama.cpp reports ``stop`` for an
    answer it cut at ``n_predict``, so a count equal to the cap is the signal
    that holds (``core.truncation_ledger.record_judge_response``).
    """
    from maljan.core.truncation_ledger import completion_tokens_of, hit_length_cap

    text = str(getattr(response, "content", "") or "")
    if not text.strip():
        return None
    produced = completion_tokens_of(response)
    if hit_length_cap(response) or (cap > 0 and produced is not None and produced >= cap):
        return (cap or int(produced or 0), text)
    return None


class _PriorAnswer:
    """The answer the analyst already gave, in the shape the retry loop reads.

    ``retry_with_feedback_sync`` runs its callable once before validating, and
    the analyst has already run. Handing the loop the finished ISR back on the
    first call keeps one implementation of the feedback turn instead of a
    second copy that drifts.
    """

    def __init__(self, isr: AgentISR) -> None:
        self.isr = isr
        # An answer that parsed into nothing is shown back as the prose it was,
        # so the question about its format is asked over what was written.
        self.content = isr.unparsed_answer or isr.to_text_summary()


def alignment_gate(knowledge: Any, cfg_validation: Any, log: Any, name: str) -> Any | None:
    """The alignment gate for one validation turn, or ``None`` when it does not run.

    ``auto`` runs it only on a worker whose ATT&CK index is already built;
    with ``alignment_gate_build`` the first run that wanted it starts the
    build on a thread and goes without, so no analyst's validation turn ever
    pays for the build. ``off`` never runs it. A knowledge module without the
    question — a stub — has no gate. A function rather than a method so a
    duck-typed analyst that borrows ``_validate_isr`` alone still gets it.
    """
    mode = str(getattr(cfg_validation, "alignment_gate", "auto") or "auto")
    if mode != "auto":
        return None
    warm = getattr(knowledge, "index_is_warm", None)
    gate = getattr(knowledge, "technique_alignment", None)
    if warm is None or gate is None:
        return None
    try:
        if warm():
            return gate
        if bool(getattr(cfg_validation, "alignment_gate_build", False)):
            started = getattr(knowledge, "warm_index_in_background", lambda: False)()
            if started:
                log.info(
                    "%s: the ATT&CK index is being built for the alignment gate; "
                    "this run goes without it.",
                    name,
                )
    except Exception as exc:  # noqa: BLE001 — a gate that cannot start is no gate
        log.debug("%s: alignment gate unavailable (%s).", name, exc)
    return None


class BudgetMeter:
    """What one loop spent, announced as it runs and written down when it ends.

    A mixin rather than a method on the analyst, because the judge runs a tool
    loop too: it binds servers by role, its ledger entries carry its name, and
    the console draws it as a step of the pipeline. One implementation is what
    keeps its rows the same shape as an analyst's, and what keeps the two from
    drifting the next time the meter grows a field.
    """

    name: str
    logger: Any
    pipeline_stage: str
    _container: Any = None
    # Read-only, so an agent built without ``__init__`` — a stand-in, a script
    # — cannot drain another one's rows out of a list they all share.
    _budget_records: Sequence[dict[str, Any]] = ()

    # Which global model an agent with no entry of its own runs on: the
    # analysts take the expert model, the judge its own.
    _model_role: str = "expert"

    def _model_label(self) -> str:
        """The label of the model this agent calls first, or ``""`` outside a job."""
        config = getattr(getattr(self, "_container", None), "config", None)
        name = str(getattr(self, "name", "") or "")
        if config is None or not name:
            return ""
        from maljan.core.model_assignments import model_label_for

        return model_label_for(config, name, role=self._model_role)

    def _turn_share(self) -> float | None:
        """``llm.fallback_turn_share`` from the job's settings, or ``None`` for the process's."""
        llm = getattr(getattr(getattr(self, "_container", None), "config", None), "llm", None)
        share = getattr(llm, "fallback_turn_share", None)
        return float(share) if isinstance(share, int | float) else None

    def _record_usage(self, response: Any, *, announce: bool = True) -> None:
        """One model answer onto the run's ledger, under this agent and the model that gave it.

        ``announce`` publishes the switch when this answer is the one a
        fallback gave; the tool loop announces its turns as they happen and
        records them afterwards, so it passes ``False`` here.
        """
        record_response_usage(
            getattr(self, "token_ledger", None),
            response,
            agent=str(getattr(self, "name", "") or ""),
            model=self._model_label(),
        )
        # Whether this answer ended at the output cap, kept for the validation
        # turn: the last model answer recorded is the one the turn checks.
        self._last_answer_cut = answer_cut_at_cap(
            response, analyst_output_cap(str(getattr(self, "name", "") or ""))
        )
        if announce:
            self._announce_fallback(response)

    def _record_turns_taken(self, latest: Mapping[str, Any], sent: int) -> None:
        """The model turns of a loop that did not come back, onto the run's ledger.

        ``latest`` is the conversation as the stream last left it and ``sent``
        how many of its messages the loop started with. A loop the hard cap
        stopped, or one that failed, was still answered for every turn it
        took; a finished loop records its turns from its result instead.
        """
        for message in list(latest.get("messages") or [])[sent:]:
            if is_model_turn(message):
                self._record_usage(message, announce=False)

    def _announce_fallback(self, message: Any) -> None:
        """Publish ``model_fallback`` when ``message`` is the turn its model list moved on.

        Published whatever ``core.events.stream_deltas`` says: the switch is a
        fact about the run a reader of the conversation has to see, not part
        of the text being streamed. Once per switch, because a list that moved
        stays moved for the loop and only the turn that moved it carries the
        reason. Never raises.
        """
        from maljan.pipeline.events import announce_model_fallback

        announce_model_fallback(
            self._event_sink(),
            message,
            agent=str(getattr(self, "name", "") or ""),
            stage=str(getattr(self, "pipeline_stage", "") or "analysis"),
        )

    def _event_sink(self) -> Any:
        """The job's event sink, or ``None`` for an agent outside a job."""
        return getattr(getattr(self, "_container", None), "event_sink", None)

    def _publish_deltas(self, snapshot: Any, already: set[str]) -> None:
        """Publish what this agent has newly said, once per turn it says it in.

        The loop reads its graph as a stream of whole states, so the smallest
        thing there is to publish is one model turn's text — not a token. That
        is still the difference between a reader watching an analyst work and
        a reader watching a dot for half an hour, which is what this is for.

        A turn is identified by what the model said rather than counted, so a
        state yielded twice publishes nothing twice. Never raises, and silent
        when ``core.events.stream_deltas`` is off or there is no sink.
        """
        sink = self._event_sink()
        if sink is None:
            return
        try:
            from maljan.core.token_ledger import turn_usage
            from maljan.llm.fallback import turn_model
            from maljan.pipeline.events import emit_agent_message_delta, scrub

            # The job's settings, not the process's: a switch this job was
            # submitted under is the one that decides what this job publishes.
            config = getattr(getattr(self, "_container", None), "config", None)
            if not bool(getattr(getattr(config, "events", None), "stream_deltas", True)):
                return
            messages = snapshot.get("messages") if isinstance(snapshot, dict) else None
            default_model = self._model_label()
            for index, message in enumerate(list(messages or [])):
                if getattr(message, "type", "") != "ai":
                    continue
                # The graph's own sentence at its step limit, not the agent's:
                # the ``stage_ended_at_cap`` event is what says the loop ended.
                if is_the_graph_s_step_stop(message):
                    continue
                marker = _turn_key(message, index)
                if marker in already:
                    continue
                already.add(marker)
                model, _reason = turn_model(message, default_model)
                emit_agent_message_delta(
                    sink,
                    stage=str(getattr(self, "pipeline_stage", "") or "analysis"),
                    agent=str(self.name),
                    text_delta=scrub(str(getattr(message, "content", "") or "")),
                    model=model,
                    tokens=turn_usage(message),
                )
        except Exception as exc:  # noqa: BLE001 — a delta never costs a turn
            self.logger.debug("%s: delta not published (%s).", self.name, exc)

    def _budget_tick(
        self, ledger: LoopBudget, messages: list, *, final: bool = False, ledger_entries: int = 0
    ) -> None:
        """One ``budget_tick`` for this loop as it stands. Never raises."""
        from maljan.pipeline.events import emit_budget_tick

        try:
            emit_budget_tick(
                self._event_sink(),
                agent=str(self.name),
                stage=str(getattr(self, "pipeline_stage", "") or "analysis"),
                steps_used=_steps_this_loop_spent(ledger, messages),
                max_steps=ledger.max_steps,
                elapsed_s=time.monotonic() - ledger.started,
                timeout_s=ledger.timeout,
                prompt_chars=sum(_message_chars(m) for m in messages),
                ledger_entries=ledger_entries,
                final=final,
                tool_definition_chars=self._definitions_sent(),
            )
        except Exception as exc:  # noqa: BLE001 — the meter never costs a turn
            self.logger.debug("%s: budget tick skipped (%s).", self.name, exc)

    def _record_budget(
        self, ledger: LoopBudget, messages: list, cap: str | None, *, detail: str = ""
    ) -> None:
        """Write this loop's spend down, and announce the cap that ended it, if one did."""
        from maljan.pipeline.events import emit_stage_ended_at_cap

        stage = str(getattr(self, "pipeline_stage", "") or "analysis")
        record: dict[str, Any] = {
            "stage": stage,
            "steps_used": _steps_this_loop_spent(ledger, messages),
            "max_steps": ledger.max_steps,
            "elapsed_s": round(time.monotonic() - ledger.started, 1),
            "timeout_s": round(ledger.timeout, 1),
            "delegated_steps": ledger.delegated_steps,
            "tool_definition_chars": self._definitions_sent(),
            "cap": cap,
        }
        self._note_budget(record)
        if cap:
            emit_stage_ended_at_cap(
                self._event_sink(), stage=stage, agent=str(self.name), cap=cap, detail=detail
            )

    def _definitions_sent(self) -> int:
        """What this agent's tool definitions weigh with each request of its loop, or 0."""
        try:
            return max(0, int(getattr(self, "_tool_definition_chars", 0) or 0))
        except (TypeError, ValueError):
            return 0

    def _note_budget(self, record: dict[str, Any]) -> None:
        """Keep one loop's record, on this instance rather than on the class.

        Under the meter's lock: the rebinding is a read-modify-write, and a
        delegated hand-over runs it from an executor thread while this agent's
        own loop may be recording one of its own.
        """
        with self._the_meter_s_lock():
            self._budget_records = [*self._budget_records, record]

    def _the_meter_s_lock(self) -> Any:
        """This agent's lock for its read-modify-write counters, or nothing.

        A duck-typed stand-in that borrows one of these methods and is never
        driven from two threads has none and needs none.
        """
        return getattr(self, "_meter_lock", None) or contextlib.nullcontext()

    def drain_budget_records(self) -> list[dict[str, Any]]:
        """Every loop's budget record since the last drain, handing over ownership."""
        with self._the_meter_s_lock():
            records = list(self._budget_records)
            self._budget_records = []
        return records


class BaseAnalyst(BudgetMeter, ABC):
    """Abstract base class for expert agents."""

    def __init__(self, llm: BaseChatModel, name: str, tools: list | None = None) -> None:
        self.llm = llm
        self.name = name
        self.tools = tools or []
        self.logger = logger.getChild(self.name.lower())
        # What the pipeline established before this agent started, rendered
        # for a prompt, and the ids of the entries it may cite for it. Set by
        # the node on every run, empty for an agent outside a staged run.
        self.facts_block: str = ""
        self.pack_ledger_ids: list[str] = []
        # The run-state block's body, derived from the state by the node and
        # regenerated with the remaining budget on every turn of a tool loop.
        self.run_state_block: str = ""
        # Per-run token ledger (findings-log §4 Item 1). The container attaches
        # the shared ledger in get_agent(); None when an agent runs standalone.
        self.token_ledger: TokenLedger | None = None
        # Which stage of the active team this agent is running as, set by the
        # node before it works. Read by the evidence recorder, so a ledger
        # entry says which step of the team made the call.
        self.pipeline_stage: str = "analysis"
        # The job this agent serves, set by the container that built it. Every
        # attach asks for it, so two agents in one job share their handles.
        self._job_id: str = ""
        # Per-run truncation ledger (pitfall P6, findings-log §2.0). Same
        # lifecycle as token_ledger; None disables counting.
        self.truncation_ledger: Any | None = None
        # Durable capture of the ReAct tool loop's
        # ToolMessages (decompile/crypto/emulate/dataflow) so the report
        # Composer can ground deep sections instead of hallucinating. Populated
        # Every tool call this agent has made since the last drain, with the id
        # the model was shown, the timing, the outcome and the parsed result.
        # It accumulates across loops on purpose: a chunked analysis re-enters
        # the loop once per chunk, and the node that writes the ledger reads it
        # once at the end. The node drains it — reading without clearing is how
        # a revision that made no calls re-emits the analysis round's.
        self._evidence_entries: list[LedgerEntry] = []
        # Bytes of tool output this agent has already kept. The budget is the
        # agent's, not the loop's: a chunked analysis re-enters the loop once
        # per chunk and would otherwise be handed the whole budget again on
        # each of them.
        self._evidence_bytes_spent = 0
        # The per-job id source, attached by the container next to the token
        # and truncation ledgers. None outside a job: the recorder then counts
        # within its own loop.
        self.evidence_counter: EvidenceCounter | None = None
        # The run's record of what its tools answered, handed down by the
        # container. ``None`` for an agent built outside a job.
        self.evidence_corpus: Any = None
        # What the optional ``maljan-findings`` block carried, accumulated as
        # the loop answers and drained onto the ISR the analyst returns. A
        # buffer rather than a return value because the block arrives with the
        # model's prose, several turns before the ISR is assembled, and on a
        # chunked run it arrives once per chunk.
        self._findings_buffer: list[Finding] = []
        self._artifacts_buffer: list[Artifact] = []
        # The answers of the asks this agent made, as the specialists' own
        # ISRs. A lead's report is the only channel its chunk has out of a
        # stage, so a lead whose loop died with six answered asks behind it
        # took those answers down with it: the ledger held 52 entries and the
        # stage merged nothing. They are kept here, labelled with the agent
        # that produced them, and they are what the salvage below and the
        # stage's merge fall back to.
        self._delegated_isrs: list[AgentISR] = []
        # How many of them a salvage turn has already been shown. The buffer
        # itself is never drained: the stage promotes every answered ask, and
        # a chunked lead's later salvage would otherwise re-read the first
        # chunk's answers as if they were its own.
        self._asks_already_synthesised = 0
        # Declared here rather than only in the subclasses that populate them,
        # because ``close_tools`` below has to be able to release them for any
        # analyst. ``toolkit`` is an MCP toolkit or a Ghidra HTTP client
        # depending on transport; ``_container`` is the per-job container that
        # created this agent, so the static analyst can reuse it instead of
        # building a new one per chunk.
        self.toolkit: Any = None
        self._container: Any = None
        # The path this agent's tools must be given, and the per-server
        # override for a tool server that was handed the sample somewhere else
        # (``agents.sample_staging``). Both are assigned per sample — by
        # ``pipeline.nodes._pin_sample_path`` and by resolution respectively —
        # and both are inert while unset, which is what keeps an analyst built
        # in a test or a script exactly what it was.
        self._analysis_file_path: str | None = None
        self._path_by_server: dict[str, str] = {}
        # The ``ResolvedAgent`` the container built this agent from — its own
        # prompt, tools and static provider id, so a clone never has to
        # re-derive what it already knows about itself.
        self._resolved: Any = None
        # Reasons this agent's own tool-server attachment degraded, filled in
        # by ``_attach_registry_tools``/subclasses. A per-instance list, not a
        # mutable class attribute: the run summary reads
        # ``container.server_degradation_reasons()`` instead (the registry is
        # the source of truth across every agent in a job), so this exists
        # only for an agent inspected directly (tests, scripts).
        self.degradation_reasons: list[str] = []
        # What this analyst was told was wrong with its answer and did not fix,
        # after its one retry, and how many retries the run spent on it. Drained
        # by the analyst node onto the state's validation channels.
        self.validation_findings: list[Violation] = []
        self.validation_retries: int = 0
        # The checks that could not run on this analyst's answers — the
        # validity check on a box with no catalogue — by code, once each.
        # Drained by the node like the findings are.
        self.validation_not_run: list[str] = []
        # The routed ``(file_type, platform)`` of the sample this agent is
        # working on, set by the node; the platform check reads it.
        self.sample_format: tuple[str, str] = ("unknown", "unknown")
        # Every violation this analyst was *shown*, by code. A violation the
        # retry fixed leaves no other trace, and a run summary that counts only
        # the leftovers cannot say what the retry was for.
        self.validation_fed_back: dict[str, int] = {}
        # Whether the last tool loop ended on something that was not a report,
        # after its one nudge. Read by ``_text_to_isr`` so the ISR says why it
        # is empty instead of leaving the reader to infer it from a claim list.
        self._answer_unstructured: bool = False
        # How the last final-answer nudge had to be sent when the plain way
        # would not do, or ``None``. The node reads it into the run summary.
        self._nudge_retry_mode: str | None = None
        # Delegation state (``agents.delegation``). ``call_chain`` names the
        # agents whose asks this one is answering, outermost first; empty for
        # an agent running its own stage. ``loop_budget`` is the running
        # loop's, so an ask made from inside it can read what is left and
        # charge what the callee spent; ``_budget_ceiling`` is what a caller
        # allows this agent when it is the callee. ``steps_spent`` counts every
        # graph step this agent's loops have used, so a caller can charge the
        # difference. ``current_round`` is the debate round the agent is
        # working in, so an ask carries it. ``sample_path_choices`` is what the
        # node pinned, which an ask reads to choose the callee's own mirror.
        #
        # The lock is this agent's for the whole job — the container caches one
        # instance per key — and everything that drives the agent takes it: an
        # ask of it, and its own stage. Two callers asking it at once, or an
        # ask arriving while its own loop runs, would share one set of buffers,
        # one budget and one call chain. Reentrant, because a chunked stage run
        # enters through two of the wrappers that take it.
        self.call_chain: tuple[str, ...] = ()
        self.loop_budget: LoopBudget | None = None
        self._budget_ceiling: BudgetCeiling | None = None
        self.steps_spent: int = 0
        self.current_round: int = 0
        self.sample_path_choices = {}
        self.delegation_lock = threading.RLock()
        # The caller's side of the same rule: this agent's own asks run one
        # after another, whether or not they name the same callee. A model
        # that emits two ``ask_*`` calls in one turn has them gathered
        # concurrently, and two nested loops against one llama-server slot
        # clobber its recurrent state. A different object from the lock above,
        # so an ask made from inside an ask still nests.
        self.asks_lock = threading.Lock()
        # Held while the meter's rows and the validation counters are read,
        # changed and written back: those are read-modify-write, and a
        # hand-over from a delegation runs on an executor thread.
        self._meter_lock = threading.Lock()
        # The budget meter's record of every loop this agent ran since the
        # node last drained it: steps against the cap, seconds against the
        # limit, and the cap that ended it when one did. The node writes it
        # to the state and the judge reads it into ``run_summary.budget``.
        self._budget_records: Sequence[dict[str, Any]] = []

    def _system_prompt(self, fallback: str | Callable[[], str]) -> str:
        """This analyst's system turn for the job it is actually running.

        The container resolves an agent once per job — its prompt already
        carries the sample's format fragment, the agent's own static provider
        fragment and any prompt the operator set on the definition — and hands
        it over as ``_resolved``. Reading it here is what makes that resolution
        the prompt a built-in analyst sends, rather than a value only the
        settings probe ever saw.

        ``fallback`` is the module constant (or a callable that assembles it),
        used by an analyst constructed outside a container: a test, a script,
        the CLI. It is the neutral assembly, which is the honest answer when
        nothing has said what the sample is.
        """
        resolved = getattr(self, "_resolved", None)
        prompt = getattr(resolved, "prompt", "") if resolved is not None else ""
        if prompt:
            return str(prompt)
        return fallback() if callable(fallback) else fallback

    def _initialize_mcp_client(self) -> None:
        """Attach this analyst's MCP toolkit. Subclasses that have one override."""
        return None

    async def close_tools(self) -> None:
        """Release this analyst's MCP toolkit and any HTTP client it holds.

        Whoever caches a toolkit closes it, and nobody did. ``cleanup()`` had a
        single caller in the whole repository — its own failure branch — so
        every successful run abandoned an ``AsyncExitStack``, its anyio task
        group and, for stdio transports, an unreaped MCP server subprocess.
        They accumulated on the process-wide agent loop, which by design never
        closes, for the life of the worker.

        Cleanup is dispatched to ``_AGENT_LOOP`` because that is the loop the
        stack was *entered* on; closing it from anywhere else is what makes
        anyio raise "Attempted to exit cancel scope in a different task". Even
        so this is best-effort — a cancelled scope can refuse to unwind — which
        is why the worker also carries a hard memory backstop.

        **Bounded, and awaited rather than blocked on.** The first cut of this
        used the blocking ``_run_coro_blocking`` from inside the job's
        coroutine, which does two bad things at once: it pins the worker's
        event loop while it waits, and it inherits whatever the underlying
        close decides to do. A live run showed exactly why that matters — the
        analysis finished, the report was written, and then teardown hung for
        42 minutes until SIGTERM, with arq still reporting ``j_ongoing=1``. An
        ``mcp`` stdio transport's exit stack waits on its child process, and a
        child that does not exit waits forever. With ``max_jobs = 1`` that one
        stuck teardown blocks every later analysis.

        Total and idempotent: called from a job-end ``finally``, so it must not
        be able to turn a finished analysis into a failed one — nor keep it
        from finishing.
        """
        # ``toolkit`` is an MCPLangChainToolkit (``cleanup``) for the stdio and
        # streamable-http analysts, or a client exposing ``aclose`` directly.
        # The static analyst no longer sets ``self.toolkit`` at all: its
        # provider owns the client/subprocess and closes it itself
        # (``ServiceContainer.aclose`` calls ``get_static_provider().close()``
        # alongside this loop), so this being a no-op for it is by design, not
        # a gap. Both closer shapes can leak on a hang; accept either name.
        toolkit = getattr(self, "toolkit", None)
        closers: list[Any] = []
        for closer_name in ("cleanup", "aclose"):
            closer = getattr(toolkit, closer_name, None)
            if callable(closer):
                closers.append(closer())
                break

        for coro in closers:
            try:
                await run_on_agent_loop(
                    coro, hard_timeout=CLOSE_TOOLS_TIMEOUT, label=f"close-tools:{self.name}"
                )
            except Exception as exc:  # noqa: BLE001 — teardown never propagates
                self.logger.warning(
                    "Tool cleanup for %s failed (non-fatal): %s",
                    self.name,
                    describe_exception_for_log(exc),
                )

        # Drop the references regardless, so a retained agent cannot keep a
        # half-closed session — or its captured tool output — alive.
        self.toolkit = None
        self.tools = []
        self._evidence_entries = []

    def _try_initialize_mcp(self) -> bool:
        """Attach the MCP toolkit, returning False instead of raising.

        Lifted from the network analyst, where it was the only place this
        pattern existed. Everywhere else called ``_initialize_mcp_client()``
        bare, and the dynamic analyst paid for it: with the CAPE forward
        half-dead, an unreachable toolkit aborted the whole analyst on every
        single run rather than falling back to the evidence it already had.

        Whether degrading is *right* is a per-analyst judgement, not a
        default — ``_static_capabilities()`` is where an analyst with a
        provider says so; one without a provider keeps the old universal
        degrade-and-continue behaviour.
        """
        capabilities = self._static_capabilities()
        try:
            self._initialize_mcp_client()
            return bool(self.tools)
        except Exception as exc:
            if capabilities is not None and not capabilities.degrade_on_failure:
                # Ghidra IS the static evidence: a toolless run would produce a
                # confident-looking report grounded in nothing. Fail loudly.
                raise
            self.logger.warning(
                "%s MCP initialization failed (graceful degradation, continuing without tools): %s",
                self.name,
                describe_exception_for_log(exc),
            )
            return False

    def _static_capabilities(self) -> Any | None:
        """The provider's degrade policy, or None for an analyst without one."""
        return None

    def _server_registry(self) -> Any | None:
        """The job's tool-server registry, or None when this agent runs bare."""
        container = getattr(self, "_container", None)
        if container is None:
            return None
        return container.get_server_registry()

    def _context_budget(self) -> Any | None:
        """The job's context budget, or None when this agent runs bare.

        What the tool paths ask how many characters of an answer this model may
        read now, and what this loop reports its own conversation size to.
        """
        container = getattr(self, "_container", None)
        if container is None:
            return None
        try:
            return container.get_context_budget()
        except Exception as exc:  # noqa: BLE001 — a budget is never worth a lost loop
            self.logger.debug("%s: the context budget is unavailable (%s).", self.name, exc)
            return None

    def _note_conversation(self, messages: list) -> None:
        """Tell the job's budget what this loop's next request will weigh.

        Called from the run-state refresher, which already runs before every
        model turn and already holds the messages. Measured with
        ``_message_chars``, the same rule the salvage trim uses: an assistant
        turn that requests tools carries its whole request outside ``content``,
        and counting the text alone under-reported a ReAct transcript fourfold.

        Two things a request carries that the messages do not show are added.
        The definitions of the loop's tools go with every request; left out,
        a static analyst with 35 tools was over a quarter of its tool budget
        fuller than it believed, and the server refused with the budget still saying
        there was room. And where the server reported what the last request
        really weighed, that figure — converted at the budget's own rate, plus
        what the conversation gained since — is a floor under the measure:
        content that tokenises worse than the rate assumes, and the template
        the server wraps every message in, are in the server's count and in
        nobody else's.
        """
        budget = self._context_budget()
        if budget is None:
            return
        try:
            budget.note_conversation(
                self.name,
                request_chars(
                    messages,
                    int(getattr(self, "_tool_definition_chars", 0) or 0),
                    int(getattr(budget, "chars_per_token", CHARS_PER_TOKEN) or CHARS_PER_TOKEN),
                ),
            )
        except Exception as exc:  # noqa: BLE001 — a budget is never worth a lost loop
            self.logger.debug("%s: the conversation size was not recorded (%s).", self.name, exc)

    def _forget_conversation(self) -> None:
        """Let go of this loop's size, so a finished loop stops binding the cap."""
        budget = self._context_budget()
        if budget is None:
            return
        try:
            budget.forget_conversation(self.name)
        except Exception as exc:  # noqa: BLE001 — a budget is never worth a lost loop
            self.logger.debug("%s: the conversation size was not released (%s).", self.name, exc)

    def _job_key(self) -> str:
        """A per-job identity for the handles' same-job short circuit."""
        return self._job_id or "job"

    def _definition_tool_refs(self) -> list[Any]:
        """This agent definition's ``ToolRef``s, under the active profile.

        The built-in analysts attach their own tools rather than reading the
        ``ResolvedAgent`` the container built for them, so without this the
        ``tools`` list on a definition would bind nothing and the two tool
        sidecars — which carry ``agents=[]`` precisely so the definition is
        the only binding — would never reach an analyst.
        """
        container = getattr(self, "_container", None)
        if container is None:
            return []
        from maljan.agents.composition import mcp_refs_for

        return list(mcp_refs_for(container.config, self.name))

    def _definition_sandbox_tools(self) -> list[Any]:
        """The job's sandbox-report tools, when this definition asks for them.

        ``ToolRef(kind="sandbox")`` is the one in-process tool source, so there
        is nothing to open and nothing that can hang — the report is already on
        the container. Withheld by a profile that sets
        ``exclude_sandbox_tools``, which is how the measurement baseline stays
        tool-free without the definitions having to change.
        """
        container = getattr(self, "_container", None)
        if container is None:
            return []
        definition = container.config.agents.definitions.get(self.name)
        if definition is None or not any(ref.kind == "sandbox" for ref in definition.tools):
            return []
        from maljan.agents.composition import active_profile

        if active_profile(container.config).exclude_sandbox_tools:
            return []
        from maljan.providers.sandbox_tools import sandbox_tools

        return list(sandbox_tools(container))

    def _profile_excluded_servers(self) -> str:
        """The servers the active profile withholds, as ``for_agent``'s argument."""
        container = getattr(self, "_container", None)
        if container is None:
            return ""
        from maljan.agents.composition import _excluded_servers

        return _excluded_servers(container.config, self.name)

    def _attach_registry_tools(self, role: str, *, exclude: str = "", **context: Any) -> list[Any]:
        """Tools from every server this agent is bound to, minus one it owns.

        Two bindings, the same two resolution composes: servers bound to
        ``role`` by ``MCPServerConfig.agents``, then the servers the agent's
        own definition names by ``ToolRef``. One ``seen`` map spans both, so
        the collision rule holds across them and a server named twice
        contributes one copy.

        ``exclude`` is the static provider's own server: a ``generic_mcp``
        provider driving ``mcp.servers["mine"]`` and an ``agents: ["static"]``
        binding on that same entry are two ways of saying the same thing, and
        attaching it twice would show the model two copies of every tool. The
        active profile's own exclusions are added to it, which is how the
        ``measurement`` baseline runs these analysts with no tools at all.

        A failure here never raises. Whether a *provider* failure degrades or
        fails is the provider's capability flag; a registry server is always
        an addition, so it always degrades, and the reason travels to the run
        summary through ``degradation_reasons``.
        """
        registry = self._server_registry()
        if registry is None:
            return []
        withheld = ",".join(x for x in (exclude, self._profile_excluded_servers()) if x)
        seen: dict[str, str] = {}
        tools, reasons = registry.tools_for(
            role, self._job_key(), exclude=withheld, seen=seen, **context
        )
        for ref in self._definition_tool_refs():
            if str(ref.server) == exclude:
                continue
            picked, ref_reasons = registry.tools_for_ref(ref, self._job_key(), seen=seen, **context)
            tools.extend(picked)
            reasons.extend(ref_reasons)
        if reasons:
            self.degradation_reasons = [*self.degradation_reasons, *reasons]
        return list(tools)

    def pinned_tools(self) -> list[Any]:
        """This agent's tools, each guarded against the bare-filename call.

        See ``agents.tool_pinning`` for what the guard does and why it is this
        narrow. With no pinned path the resolved tools come back unwrapped.
        """
        from maljan.agents.tool_pinning import pin_paths

        return pin_paths(
            list(self.tools),
            default_path=self._analysis_file_path,
            path_by_server=self._path_by_server,
            agent_name=self.name,
        )

    def _run_state_body(self, steps_left: int | None, seconds_left: float | None) -> str:
        """The node's run-state lines plus this loop's remaining budget.

        Once the conversation has no room left for a tool answer the block
        says so. Regenerated rather than appended, like the rest of it, so the
        fact costs the same whether the loop reads it once or forty times —
        which is what makes telling the model cheaper than refusing its calls.
        """
        body = str(getattr(self, "run_state_block", "") or "").rstrip()
        if not body:
            return ""
        budget = []
        if steps_left is not None:
            budget.append(f"{max(0, int(steps_left))} model turns")
        if seconds_left is not None:
            budget.append(f"{max(0, int(seconds_left))} s")
        if budget:
            body = f"{body}\nbudget remaining: {', '.join(budget)}"
        return f"{body}\n{NO_ROOM_RUN_STATE}" if self._says_no_room() else body

    def _says_no_room(self) -> bool:
        """Whether this loop's run-state block carries the no-room line.

        Asked of the budget rather than derived from ``_out_of_room``: the line
        is charged when the room runs out, and only when there was room to
        charge it, so the block adds nothing that was not paid for.
        """
        from maljan.llm.context_window import ContextBudget

        budget = self._context_budget()
        try:
            return isinstance(budget, ContextBudget) and budget.says_no_room(self.name)
        except Exception:  # noqa: BLE001 — a budget is never worth a lost loop
            return False

    def _out_of_room(self) -> bool:
        """Whether this agent's tool phase has ended for want of room.

        The type is checked rather than the attribute: a stand-in container
        answers every question with something truthy, and a loop that reported
        itself out of room because a test handed it a mock would end early for
        a reason that never happened.
        """
        from maljan.llm.context_window import ContextBudget

        budget = self._context_budget()
        try:
            return isinstance(budget, ContextBudget) and budget.out_of_room(self.name)
        except Exception:  # noqa: BLE001 — a budget is never worth a lost loop
            return False

    def frame_messages(
        self,
        messages: list[BaseMessage],
        *,
        steps_left: int | None = None,
        seconds_left: float | None = None,
    ) -> list[BaseMessage]:
        """``messages`` with this agent's facts block and run-state block in place."""
        return frame_messages(
            messages,
            facts_block=str(getattr(self, "facts_block", "") or ""),
            run_state=self._run_state_body(steps_left, seconds_left),
        )

    def _loop_limits(self) -> tuple[int, int]:
        """This agent's ``(timeout, max_steps)`` for one loop; see ``loop_limits``."""
        return loop_limits(self.name, getattr(self, "_budget_ceiling", None))

    def _run_state_refresher(
        self,
        max_steps: int,
        timeout: float,
        started: float,
        budget: LoopBudget | None = None,
        recorder: Any = None,
    ) -> Any:
        """The per-turn hook that regenerates the run-state block's budget line.

        Handed to the ReAct executor as its prompt: every model turn goes
        through it, so the block the model reads says how many steps and
        seconds this loop has left as of that turn. Nothing accumulates — the
        block is replaced, not appended — and a loop with no block returns
        the conversation untouched.

        ``budget`` is the loop's own when the loop made one; the arguments
        describe a fresh one otherwise, so a caller with only the three
        numbers reads the same line. ``recorder`` is what the tick counts its
        ledger entries from — without it every tick but the last published a
        zero that meant "nobody asked" rather than "no calls yet".
        """
        ledger = budget if budget is not None else LoopBudget(max_steps, timeout, started)
        from maljan.pipeline.events import BUDGET_TICK_EVERY

        ticked: list[int] = [0]

        def refresh(state: Any) -> list[BaseMessage]:
            messages = state.get("messages") if isinstance(state, dict) else None
            if messages is None:
                messages = getattr(state, "messages", None) or []
            messages = list(messages)
            # Counted on every turn whether or not there is a block to show
            # it in: the budget is what an ask from inside this loop reads.
            ledger.note_turns(messages)
            # And what the conversation weighs, which is what the next tool
            # answer's cap is measured against.
            self._note_conversation(messages)
            # The meter, every few steps: a tick per turn would be a stream
            # of near-identical events on a forty-step loop.
            used = steps_used(messages)
            if budget is not None and used and used // BUDGET_TICK_EVERY > ticked[0]:
                ticked[0] = used // BUDGET_TICK_EVERY
                self._budget_tick(
                    ledger,
                    messages,
                    ledger_entries=len(getattr(recorder, "entries", None) or []),
                )
            if not str(getattr(self, "run_state_block", "") or ""):
                return messages
            # The budget is stated in model turns (``model_turns_left``): the
            # framing and the tool results cost nothing, an assistant turn
            # costs one and a tool round costs one more, which is how the
            # graph's recursion limit is spent.
            try:
                return self.frame_messages(
                    messages,
                    steps_left=ledger.turns_left(messages),
                    seconds_left=ledger.seconds_left(),
                )
            except Exception as exc:  # noqa: BLE001 — the block never costs a turn
                self.logger.debug("%s: run-state refresh skipped (%s).", self.name, exc)
                return messages

        return refresh

    def execute_tool_loop(self, prompt_messages: list) -> str:
        """Executes a tool-calling ReAct loop if tools are available.

        The loop runs against ``pinned_tools()``; ``self.tools`` keeps the
        resolved objects, so what an agent reports it has is what resolution
        gave it and only the loop sees the wrappers.

        Runs the async ReAct agent in a dedicated **daemon** thread with its own
        event loop. This avoids the nest_asyncio + anyio cancel scope
        incompatibility that caused 'Attempted to exit cancel scope in a
        different task' RuntimeErrors when the agent was invoked from within an
        already-running asyncio loop (e.g. ARQ worker).

        Phase A fix (daemon thread + bulletproof cleanup):
          - ThreadPoolExecutor replaced with threading.Thread(daemon=True) so
            zombie threads cannot block the worker process.
          - Cleanup is wrapped in broad exception handlers so loop.close()
            always succeeds even when pending tasks refuse cancellation.
          - If the thread refuses to die within the timeout, we log a critical
            warning and raise TimeoutError. The daemon flag ensures the OS will
            reap the thread when the worker process eventually exits.

        The no-tools fallback path used to
        call ``self.llm.invoke(prebuilt)`` synchronously with no timeout, so
        when an analyst with no MCP tools (e.g. dynamic analyst with CAPE
        disabled) hit a slow / queued llama-server, the worker hung
        indefinitely — the openai SDK's default 600s ``request_timeout``
        combined with the default ``max_retries=2`` produced ~30 min of
        silent waiting before raising. The fallback now runs inside the same
        daemon-thread + hard-cap-timeout machinery as the tools path, so the
        analyst is killed at the configured ``react_agent_timeout`` budget
        regardless of which path it takes.
        """
        from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

        # Build BaseMessages directly so literal `{...}` substrings in the
        # report content (e.g. JSON like {"programs": [...]}) are not parsed
        # as ChatPromptTemplate f-string variables.
        prebuilt: list[BaseMessage] = []
        for role, content in prompt_messages:
            if role == "system":
                prebuilt.append(SystemMessage(content=content))
            elif role == "human":
                prebuilt.append(HumanMessage(content=content))

        # Per-agent timeout override: the static analyst with 31 Ghidra tools
        # never finishes inside 180 s on commodity hardware, so it gets the
        # operator-configured headroom. Per-agent recursion-step override: its
        # Ghidra loop needs far more than the default ~4-tool-call budget, and
        # without it the loop hit the step cap and LangGraph returned the
        # "need more steps" stop message instead of real claims. Both are
        # capped by a caller's ceiling when this loop answers an ask.
        timeout, max_steps = self._loop_limits()

        # A model list that moved on in an earlier loop starts this one at its
        # first model again — the switch is sticky for a loop, not for the job
        # — and its turn deadline is a share of *this* loop's budget, which
        # inside an ask is the ask's, not the agent's own.
        from maljan.llm.fallback import restart_models

        restart_models(self.llm, loop_seconds=float(timeout), share=self._turn_share())

        # The two standing blocks: the pack at the head of the task, the run
        # state in the system turn with this loop's whole budget still ahead.
        prebuilt = self.frame_messages(
            prebuilt, steps_left=model_turns_left(max_steps, []), seconds_left=float(timeout)
        )

        if not self.tools:
            plain = LoopBudget(int(max_steps), float(timeout))
            self._last_loop_deadline = plain.started + float(timeout)
            try:
                answer = self._invoke_llm_with_timeout(prebuilt, timeout)
            except TimeoutError:
                self._record_budget(plain, [], "time", detail="the model did not answer in time")
                raise
            self.steps_spent += 1
            self._record_budget(plain, [], None)
            return self._capture_findings(answer)

        from langgraph.errors import GraphRecursionError
        from langgraph.prebuilt import create_react_agent

        self.logger.info("Starting ReAct agent loop with %d tools...", len(self.tools))

        # The recorder fills its own list as the loop runs, rather than the
        # loop reconstructing one from the message stream afterwards — that is
        # what gives each call its timing, its outcome and the id the model was
        # shown. What it gathered is appended to the agent's buffer at the end;
        # nothing is reset here, because this may be the second of ten chunks.
        from maljan.agents.evidence_recorder import (
            ArgumentRepairs,
            EvidenceRecorder,
            RepeatGuard,
            record_tools,
            repair_invalid_tool_calls,
        )

        # An agent built outside a container has no counter attached, and one
        # per loop would issue ``ev_0001`` twice to the same buffer. It keeps
        # its own from the first loop on.
        if self.evidence_counter is None:
            self.evidence_counter = EvidenceCounter()
        recorder = EvidenceRecorder(
            self.name,
            counter=self.evidence_counter,
            # The stage the node set on this agent, so a ledger entry says
            # which step of the team made the call rather than the constant
            # "analysis" every entry carried when there was only one.
            stage=str(getattr(self, "pipeline_stage", "") or "analysis"),
            sink=self._event_sink(),
            # What the run saw, before the byte budget trims what it keeps.
            corpus=getattr(self, "evidence_corpus", None),
            # The model a call is filed under until a turn names another.
            model=self._model_label(),
        )
        # The repeat guard is per loop, like the recorder: a second chunk is a
        # new conversation and the model has not seen the first one's answers.
        repeats = RepeatGuard()
        # The arguments this loop had to close off, so the ledger entry for
        # such a call says so and keeps what the model actually wrote.
        repairs = ArgumentRepairs()

        messages = prebuilt

        # The loop's budget, readable by an ask made from inside it and
        # charged by the delegation when the callee returns.
        budget = LoopBudget(int(max_steps), float(timeout))
        # When this loop's time runs out: the validation turn that follows it
        # is held to what is left, not given a fresh budget.
        self._last_loop_deadline = budget.started + float(timeout)
        self.loop_budget = budget

        # The run-state block is regenerated on every model turn with the
        # budget this loop has left, which is why the executor's prompt is a
        # callable rather than the fixed messages.
        # The per-turn refresher rides ``create_react_agent(prompt=...)``, which
        # langgraph 1.x deprecates in favour of ``langchain.agents.create_agent``
        # and its middleware hook. The contract this loop needs is one call
        # before every model turn that can replace the system message; that is
        # what moves when the helper does.
        def _close_off_truncated_calls(answer: Any) -> Any:
            """The model's turn with a call it ran out of room to finish made good.

            Appended to the model rather than added as a node: a node is a
            superstep, and a seam that cost one would quietly take a third of
            every loop's tool rounds away. Here the loop's shape is exactly
            what it was — langgraph sees one message from the model, and what
            it sees is the message with the call in ``tool_calls`` where the
            arguments could be closed off, and untouched where they could not.
            """
            # The calls this turn asks for are this turn's model's, and a turn
            # a fallback gave is said in the conversation as it happens.
            recorder.note_turn(answer)
            self._announce_fallback(answer)
            try:
                repaired = repair_invalid_tool_calls(answer, repairs)
            except Exception as exc:  # noqa: BLE001 — a repair never costs a loop
                self.logger.debug("tool argument repair skipped (%s).", exc)
                return answer
            return repaired if repaired is not None else answer

        recorded = record_tools(
            self.pinned_tools(),
            recorder,
            repeats,
            repairs,
            self._context_budget(),
            on_question=self._count_question,
        )
        # Sent with every request of this loop, so counted with its conversation.
        self._tool_definition_chars = tool_definition_chars(recorded)
        self.ended_out_of_room = False
        agent_executor = create_react_agent(
            _model_that_closes_off_truncated_calls(self.llm, recorded, _close_off_truncated_calls),
            recorded,
            prompt=self._run_state_refresher(
                int(max_steps),
                float(timeout),
                budget.started,
                budget=budget,
                recorder=recorder,
            ),
        )

        # Whether the server, rather than the budget, said the window was full.
        window_full = False
        # Whether the time budget ended the tool phase, and the sentence saying
        # how: the loop's own turn times against what was left.
        time_capped = False
        time_detail = ""
        # The time kept for the final answer when the clock ended the phase,
        # and whether the budget ran out with nothing gathered.
        final_reserve = 0.0
        budget_ran_out_empty = False

        def _rate_of_the_answering_model() -> float | None:
            rates_of = getattr(getattr(self, "_container", None), "get_generation_rates", None)
            if not callable(rates_of):
                return None
            try:
                from maljan.llm.generation_rate import model_name_of

                rate = rates_of().rate(model_name_of(self.llm))
            except Exception:  # noqa: BLE001 — a missing rate leaves the turn floor
                return None
            return rate if isinstance(rate, int | float) else None

        # The conversation as the stream last left it. Out here rather than in
        # the coroutine so a loop the hard cap stops still hands over the turns
        # it took: they were answered and spent.
        latest: dict = {"messages": list(messages)}

        # Run the ReAct coroutine on the shared, never-closing agent
        # loop (see ``_get_agent_loop``) instead of a throwaway per-call loop.
        async def _invoke() -> dict:
            self.logger.info(
                "Invoking ReAct agent (timeout=%ds, tools=%d)...",
                timeout,
                len(self.tools),
            )
            # The provider sets
            # ``max_retries=0`` on purpose to stop the openai SDK from
            # retry-storming a *stalled* request (3 x request_timeout).
            # But a transient ``APIConnectionError`` — the local
            # llama-server briefly dropping an idle socket during a long
            # Ghidra tool-call gap — is NOT a stall, and with zero
            # retries it aborted the entire (most-important) static
            # analyst on a single blip (observed: static ReAct died at
            # 86s, no watchdog hang). Retry ONLY APIConnectionError, a
            # few times with short backoff. A genuine stall surfaces as
            # asyncio.TimeoutError from the wait_for below and is NOT
            # retried — the anti-storm intent is preserved.
            from openai import APIConnectionError

            async def _until_it_answers_or_repeats() -> dict:
                """The ReAct loop, ended early once it is only repeating itself.

                Streamed rather than awaited whole for one reason: a loop that
                has spent three turns re-asking for answers it already has is
                not going to spend the fourth differently, and ending it needs
                the conversation as it stands. ``stream_mode="values"`` yields
                the state after each step, so the last one is what ``ainvoke``
                would have returned.

                Closed explicitly on the way out. Breaking out of an ``async
                for`` leaves the generator suspended and the graph behind it
                alive until the loop's finalizer gets to it, and on a box with
                one llama-server slot a run that is still alive is not free.
                """
                nonlocal time_capped, time_detail, final_reserve
                stream: Any = agent_executor.astream(
                    {"messages": messages},
                    {"recursion_limit": max_steps},
                    stream_mode="values",
                )
                spoken: set[str] = set()
                pace = TurnPace(_rate_of_the_answering_model)
                # Kept past the loop: what one turn and a final answer cost at
                # this model's pace is what the stage asks before it gives
                # this analyst a second loop.
                self._last_pace = pace
                async with contextlib.aclosing(stream) as snapshots:
                    try:
                        async for snapshot in snapshots:
                            latest.update(snapshot)
                            self._publish_deltas(snapshot, spoken)
                            if repeats.ending_the_loop():
                                self.logger.warning(
                                    "%s ReAct loop ended after %d repeated tool call(s); "
                                    "synthesising from what it gathered.",
                                    self.name,
                                    repeats.served_repeats,
                                )
                                break
                            # The same end for a conversation with no room
                            # left. The guardrail marked this agent when it
                            # told the model so, and every call after that is
                            # refused without running a tool — so a model that
                            # asks anyway is spending the step budget on
                            # refusals, which is what ran a live loop from its
                            # sixteenth step to its fortieth.
                            if self._out_of_room():
                                self.logger.warning(
                                    "%s ReAct loop ended: the conversation has no room "
                                    "left for a tool answer; synthesising from what it "
                                    "gathered.",
                                    self.name,
                                )
                                break
                            # And the same end for the clock, early enough for
                            # the answer: once what is left cannot hold another
                            # turn at this model's own pace and the final-answer
                            # turn after it, the tool phase ends here and the
                            # salvage below writes up what was gathered. At the
                            # time budget itself there is no turn left to write.
                            pace.note(snapshot, _model_label(self.llm))
                            left = budget.seconds_left()
                            if pace.leaves_no_room_for(left):
                                time_capped = True
                                final_reserve = pace.reserve()
                                time_detail = (
                                    f"{left:.0f}s of {float(timeout):.0f}s left; the longest "
                                    f"turn of {pace.current} (its tools and its next "
                                    f"answer) took {pace.longest():.0f}s, and "
                                    f"{final_reserve:.0f}s are kept for the final answer"
                                )
                                self.logger.warning(
                                    "%s ReAct loop ended on its time budget: %s; "
                                    "synthesising from what it gathered.",
                                    self.name,
                                    time_detail,
                                )
                                break
                    except GraphRecursionError:
                        # The step cap, reached without langgraph's own
                        # "need more steps" turn — which it only takes when
                        # the model asks for a tool with fewer than two steps
                        # left, and never when the cap is small. The
                        # conversation up to here is what the loop gathered,
                        # and the salvage below turns it into claims: an
                        # agent at its cap writes up what it has, and a
                        # recursion error is not something a model can read.
                        self.logger.warning(
                            "%s ReAct loop reached its %d-step cap; "
                            "synthesising from what it gathered.",
                            self.name,
                            max_steps,
                        )
                        latest["messages"] = [
                            *list(latest.get("messages") or []),
                            AIMessage(
                                content=RECURSION_STOP_TEXT,
                                response_metadata={SYNTHETIC_TURN_KEY: True},
                            ),
                        ]
                    except Exception as exc:
                        # The server saying the window is full is this
                        # conversation out of room, whatever the budget
                        # believed: the tool phase ends the way it does when
                        # the budget sees it first, and what was gathered is
                        # salvaged rather than lost with the analyst. Only
                        # then. A failure that is not a provider's full-window
                        # answer, or one met before any tool ran — the framing
                        # alone does not fit, which is a configuration fault —
                        # has nothing to salvage and fails the agent as it
                        # always did.
                        if not (window_full_error(exc) and recorder.entries):
                            raise
                        nonlocal window_full
                        window_full = True
                        note_a_window_that_moved(exc)
                        self.logger.warning(
                            "%s ReAct loop ended: the model server reported its context "
                            "window full (%s); synthesising from what it gathered.",
                            self.name,
                            type(exc).__name__,
                        )
                return dict(latest)

            last_conn_exc: Exception | None = None
            for _attempt in range(3):
                # A replayed conversation is a fresh loop as far as the model
                # is concerned: it is about to re-make the calls it made before
                # the connection dropped, and counting those as repeats ends an
                # analyst for a blip the retry exists to absorb.
                repeats.reset()
                try:
                    result = await asyncio.wait_for(
                        _until_it_answers_or_repeats(),
                        timeout=float(timeout),
                    )
                    msg_count = len(result.get("messages", []))
                    self.logger.info(
                        "ReAct loop completed: %d messages in conversation.",
                        msg_count,
                    )
                    return result
                except TimeoutError:
                    # The time budget itself, reached inside one turn or one
                    # tool call longer than any the loop had seen. What was
                    # gathered is kept and handed on rather than dropped with
                    # the analyst; the salvage gets whatever time is left,
                    # which may be none. Any other timeout is not this one.
                    nonlocal time_capped, time_detail, budget_ran_out_empty
                    if budget.seconds_left() > 1.0:
                        raise
                    if not recorder.entries:
                        budget_ran_out_empty = True
                        raise
                    time_capped = True
                    time_detail = (
                        f"the loop reached its {float(timeout):.0f}s budget inside a "
                        "turn longer than any it had measured"
                    )
                    self.logger.warning(
                        "%s ReAct loop reached its %ds time budget mid-turn; keeping "
                        "what it gathered.",
                        self.name,
                        timeout,
                    )
                    return dict(latest)
                except APIConnectionError as conn_exc:
                    last_conn_exc = conn_exc
                    if _attempt < 2:
                        # The abandoned attempt's turns were answered; the
                        # replay starts from the loop's first messages, so what
                        # it records next is its own.
                        self._record_turns_taken(latest, len(messages))
                        latest.clear()
                        latest["messages"] = list(messages)
                        _wait = 2**_attempt
                        self.logger.warning(
                            "ReAct LLM connection error (attempt %d/3): %s — retrying in %ds.",
                            _attempt + 1,
                            conn_exc,
                            _wait,
                        )
                        await asyncio.sleep(_wait)
                        continue
                    raise
            # Unreachable: the loop always returns on success or re-raises
            # on the final attempt. Kept as a typed fallback so mypy sees
            # a BaseException (last_conn_exc is Exception | None).
            raise last_conn_exc or RuntimeError(  # pragma: no cover
                "ReAct retry loop exited without result"
            )

        # Instrument the
        # outer execute_tool_loop window so operators can correlate slow
        # analysts with token / tool-call counts without sprinkling timers
        # across the codebase. Minimal-viable implementation: wall-clock,
        # message count, tool-call count.
        import time as _time

        _t0 = _time.monotonic()
        hard_timeout = hard_cap(timeout, getattr(self, "_budget_ceiling", None))
        try:
            try:
                thread_result: dict | None = _run_coro_blocking(
                    _invoke(), hard_timeout, label=f"react:{self.name}"
                )
            except TimeoutError:
                # Two different walls. The soft budget with nothing gathered
                # is not the hard cap, and is not said to be.
                if budget_ran_out_empty:
                    self.logger.critical(
                        "%s ReAct agent reached its %ds budget with nothing gathered; "
                        "aborting this analyst.",
                        self.name,
                        timeout,
                    )
                    detail = f"the loop reached its {int(timeout)}s budget with nothing gathered"
                else:
                    self.logger.critical(
                        "%s ReAct agent exceeded the %ds hard cap; aborting this analyst.",
                        self.name,
                        hard_timeout,
                    )
                    detail = f"the loop exceeded its {int(hard_timeout)}s hard cap"
                self._record_budget(budget, [], "time", detail=detail)
                self._record_turns_taken(latest, len(messages))
                raise
            except AnalystError:
                self._record_turns_taken(latest, len(messages))
                raise
            except Exception as exc:
                self._record_turns_taken(latest, len(messages))
                # A server that refused the request for its length is telling
                # us the window it serves is not the one we learned; the
                # learned figure is dropped so the next question is asked.
                note_a_window_that_moved(exc)
                self.logger.error("ReAct agent failed: %s (%s)", type(exc).__name__, exc)
                raise AnalystError(f"{self.name} ReAct agent failed: {exc}") from exc
        finally:
            # In a ``finally`` because the run whose evidence is worth the most
            # is the one that died: an analyst that hit the hard cap after
            # thirty Ghidra calls made thirty calls, and losing all of them
            # because the last one timed out is the opposite of a ledger.
            self._finish_evidence(recorder)
            self.loop_budget = None
            # Read before the conversation is forgotten: forgetting it clears
            # the mark, so a question asked afterwards is always answered no
            # and a loop that ran out of room recorded the step cap instead.
            no_room = self._out_of_room()
            # The loop is over and its conversation is gone, so it stops
            # deciding how much of an answer the next one may read. In the same
            # ``finally`` and for the same reason: a loop that died still held
            # a conversation, and leaving its size behind would shrink every
            # later stage's answers against a window nothing is using.
            self._forget_conversation()

        if thread_result is None:
            raise AnalystError(f"{self.name} ReAct agent returned no result")

        msgs = thread_result.get("messages", []) or []
        # What this loop cost: its own turns. What it asked for is the
        # callee's own budget and is counted under the callee.
        self.steps_spent += steps_used(msgs)
        # Tool calls are AIMessage instances whose ``tool_calls`` attribute
        # is a non-empty list. Counting them is cheap and the most useful
        # single metric for "did this analyst overspend on Ghidra".
        tool_call_count = sum(len(getattr(m, "tool_calls", None) or []) for m in msgs)
        # The ReAct tool-loop's LLM calls happen INSIDE
        # langgraph's ``create_react_agent`` executor, so they never passed
        # through ``_invoke_llm_with_timeout`` where token usage is tallied.
        # Only the no-tools fallback and view paths recorded usage, so the
        # per-run TokenLedger reported ~1 call for a multi-call ReAct run.
        # Record every AI turn the executor produced (each carries its own
        # ``usage_metadata``) so the ledger reflects real LLM spend.
        for _m in msgs:
            if is_model_turn(_m):
                self._record_usage(_m, announce=False)
        elapsed = _time.monotonic() - _t0
        # A loop that overran is a slow model or a slow tool, and the loop's
        # own elapsed time cannot tell them apart. Every ledger entry carries
        # the clock of its own round trip, so the line names the single
        # slowest call and the tool that answered it; the run summary carries
        # the same three numbers per agent (``tool_latency``), and the ledger
        # itself has every call.
        slowest = slowest_call(recorder.entries)
        cfg_obj = get_settings()
        _budget = getattr(cfg_obj, "react_agent_tool_call_budget", 20)
        if tool_call_count > _budget:
            self.logger.warning(
                "%s ReAct loop spent %d tool calls (budget=%d, elapsed=%.1fs)%s.",
                self.name,
                tool_call_count,
                _budget,
                elapsed,
                slowest,
            )
        elif elapsed > 0.9 * float(timeout):
            self.logger.warning(
                "%s ReAct loop close to timeout: elapsed=%.1fs, "
                "timeout=%ds, tool_calls=%d, messages=%d%s.",
                self.name,
                elapsed,
                timeout,
                tool_call_count,
                len(msgs),
                slowest,
            )
        else:
            self.logger.info(
                "%s ReAct loop: elapsed=%.1fs, tool_calls=%d, messages=%d%s.",
                self.name,
                elapsed,
                tool_call_count,
                len(msgs),
                slowest,
            )

        final_message = msgs[-1]
        content = str(final_message.content)
        # Forced synthesis: a tool-using ReAct loop
        # that spends its whole step budget gathering evidence ends with
        # LangGraph's "need more steps" stop message (or an empty final turn),
        # silently discarding every tool result it collected. The static
        # analyst's Ghidra loop did exactly this (19 tool calls -> 41 messages
        # -> recursion limit -> zero claims). When it happens, re-invoke the
        # model once on the accumulated conversation with a directive to stop
        # tool-calling and synthesise now, so the gathered evidence becomes real
        # claims instead of a useless "need more steps" non-answer.
        hit_step_cap = bool(_RECURSION_STOP_RE.search(content))
        # A loop ended for repeating itself, or for running out of room to
        # read another answer, is in the same place as one that spent its
        # steps: it has evidence and no answer, and the salvage is what turns
        # the first into the second.
        ended_early = repeats.ending_the_loop() or no_room or window_full or time_capped
        self._record_react_loop(hit_step_cap=hit_step_cap)
        if repeats.ending_the_loop():
            cap, why = "repeats", f"{repeats.served_repeats} repeated tool call(s)"
        elif no_room:
            cap, why = "no_room", "the conversation had no room left for a tool answer"
        elif window_full:
            cap, why = "no_room", "the model server reported its context window full"
        elif time_capped:
            cap, why = "time", time_detail
        elif hit_step_cap:
            cap, why = "steps", ""
        else:
            cap, why = None, ""
        # A turn the loop ended before its calls ran — the clock breaks right
        # after the model answers — leaves calls nothing answered, which a
        # hosted provider refuses to be sent. They go; the turn's text stays,
        # and the record says they did not run.
        msgs, unrun = without_unanswered_calls(msgs)
        if unrun:
            note = f"{unrun} tool call(s) of the last turn were not run"
            why = f"{why}; {note}" if why else note
            self.logger.warning("%s: %s.", self.name, note)
        self._record_budget(budget, msgs, cap, detail=why)
        self._budget_tick(budget, msgs, final=True, ledger_entries=len(recorder.entries))
        # Counted above, where it cost a step; not sent back to a model, which
        # would read the graph's sentence as its own last turn.
        msgs = [message for message in msgs if not is_the_graph_s_step_stop(message)]
        answered = False
        if tool_call_count > 0 and (not content.strip() or hit_step_cap or ended_early):
            self.logger.warning(
                "%s ReAct loop ended without a final answer after %d tool calls "
                "(messages=%d); forcing synthesis from gathered tool output.",
                self.name,
                tool_call_count,
                len(msgs),
            )
            # `elapsed` is not decoration: without it the salvage receives a
            # fresh copy of the full budget, and loop + salvage together overrun
            # the hard cap the loop was already inside. Measured 2026-08-11:
            # 109.5 s loop + a fresh 1,500 s synthesis = 1,677 s against a
            # 1,530 s cap, and zero techniques out the other side.
            if time_capped:
                self._give_the_final_turn(final_reserve, float(timeout) - elapsed)
            synthesized = self._force_final_synthesis(msgs, timeout, elapsed)
            if synthesized.strip() and not _RECURSION_STOP_RE.search(synthesized):
                content = synthesized
                msgs = [*msgs, AIMessage(content=synthesized)]
                answered = True
        # A loop a cap ended ends on the graph's sentence or on a tool's
        # notice, and neither is what the agent said. Where the salvage wrote
        # nothing the agent has no answer, and says nothing: why the loop
        # ended is on the budget record and the ``stage_ended_at_cap`` event,
        # in the platform's own voice, not in the agent's.
        if cap is not None and not answered:
            content = ""
        self.ended_out_of_room = cap == "no_room"

        # A final message that is neither a structured report nor a findings
        # block is not an answer. The loop's own stop condition cannot see that
        # — LangGraph stops as soon as the model emits no tool call — so a model
        # that narrated its next step and then fell silent used to reach
        # ``_text_to_isr`` as prose, and the sentence splitter made a claim out
        # of "Let me search for more specific strings related to malware
        # indicators:" at 0.5. Say so once, in the same conversation, and give
        # it the step to answer in.
        if window_full:
            # The nudge re-sends the conversation the server has just refused,
            # so it cannot fit and would only occupy the model's one slot for a
            # full prefill to learn that again. After the platform's own budget
            # ended the phase the conversation is inside the tool budget with
            # the reply reserve whole, and the nudge below still has room.
            self._answer_unstructured = not answer_is_isr(content)
            return self._capture_findings(content)
        # What is left *after* the final-answer turn, not before it: handed the
        # loop's own elapsed time, the nudge was given a second full remainder
        # and the two together ran past the budget.
        elapsed = _time.monotonic() - _t0
        return self._capture_findings(
            self._settle_final_answer(content, msgs, timeout, elapsed, max_steps)
        )

    def _count_question(self, code: str) -> None:
        """Count one question a tool call was answered with, where the run summary reads it."""
        with self._the_meter_s_lock():
            fed_back = dict(getattr(self, "validation_fed_back", None) or {})
            fed_back[code] = fed_back.get(code, 0) + 1
            self.validation_fed_back = fed_back

    def _give_the_final_turn(self, reserve: float, remaining: float) -> None:
        """Hold a model list's per-turn deadline at the final answer's reserve.

        Inside the loop a list's turn deadline is a share of what is left, and
        at the time cap that share is below the reserve the final answer was
        given — a model writing its own answer would be declared stalled. The
        list is not restarted: the model answering now keeps answering.
        """
        enter = getattr(self.llm, "enter_loop", None)
        if not callable(enter) or remaining <= 0 or reserve <= 0:
            return
        try:
            enter(float(remaining), min(1.0, float(reserve) / float(remaining)))
        except Exception as exc:  # noqa: BLE001 — a deadline is never worth a turn
            self.logger.debug("final-turn deadline not set (%s).", exc)

    def _settle_final_answer(
        self, content: str, msgs: list, timeout: int, elapsed: float, max_steps: int
    ) -> str:
        """The loop's answer, nudged once if it was not a report, and judged.

        Sets ``_answer_unstructured``, which is what makes the analyst report
        ``no_claims`` rather than an empty ISR that reads like an analyst with
        nothing to say.
        """
        self._answer_unstructured = False
        if answer_is_isr(content):
            return content
        nudged = self._nudge_for_final_answer(msgs, timeout, elapsed, max_steps)
        # Only when the nudge answered the question. Taking any non-empty text
        # would let a second non-report — often shorter than the first —
        # replace what the loop actually produced.
        if nudged is not None and answer_is_isr(nudged):
            return nudged
        self.logger.warning(
            "%s: the loop ended without a structured report even after the nudge; reporting %s.",
            self.name,
            NO_STRUCTURED_REPORT_STATUS,
        )
        self._answer_unstructured = True
        return content

    def _nudge_for_final_answer(
        self, msgs: list, timeout: int, elapsed: float, max_steps: int
    ) -> str | None:
        """Ask once for the report the loop did not produce; ``None`` on failure.

        Bounded in both dimensions, like ``_force_final_synthesis``: the extra
        turn counts against ``max_steps`` (the conversation already spent
        ``len(msgs)`` of them, and a loop with nothing left gets no nudge) and
        against the time the loop has already used. Never raises — a nudge that
        cannot run leaves the answer exactly as the loop left it.
        """
        from langchain_core.messages import HumanMessage

        remaining_steps = model_turns_left(max_steps, list(msgs))
        if remaining_steps < 1:
            self.logger.info(
                "%s: no step budget left for the final-answer nudge.",
                self.name,
            )
            return None
        remaining_time = float(timeout) - elapsed
        if remaining_time <= 1.0:
            self.logger.info("%s: no time budget left for the final-answer nudge.", self.name)
            return None

        self.logger.warning(
            "%s: the loop's last message was not a final report; asking once for one.",
            self.name,
        )
        sendable, dropped = nudge_turns(msgs)
        modes: list[str] = ["invalid_tool_calls_dropped"] if dropped else []
        if dropped:
            self.logger.warning(
                "%s: the nudge leaves out a tool call whose arguments never parsed.", self.name
            )
        turns = [*sendable, HumanMessage(content=FINAL_ANSWER_NUDGE)]
        budget = min(remaining_time, float(timeout))

        def _ask_with(model: Any, label: str) -> Any:
            async def _ask() -> Any:
                return await asyncio.wait_for(model.ainvoke(turns), timeout=budget)

            return _run_coro_blocking(_ask(), budget + 5, label=label)

        try:
            answer = _ask_with(self.llm, f"nudge:{self.name}")
        except Exception as exc:  # noqa: BLE001 — a nudge that fails is asked one other way
            self.logger.warning("%s: the final-answer nudge failed (%s).", self.name, exc)
            # The other shape the server accepts: the loop's own tools bound
            # and forbidden, so the transcript renders as the loop rendered
            # it and the model still has to answer in prose.
            withheld = self._llm_with_tools_withheld()
            if withheld is None:
                self._nudge_retry_mode = "+".join(modes) or None
                return None
            try:
                answer = _ask_with(withheld, f"nudge-tools-none:{self.name}")
            except Exception as again:  # noqa: BLE001 — changes nothing
                self.logger.warning(
                    "%s: the final-answer nudge failed with tools withheld too (%s).",
                    self.name,
                    again,
                )
                self._nudge_retry_mode = "+".join(modes) or None
                return None
            modes.append("tool_choice_none")
        self._nudge_retry_mode = "+".join(modes) or None
        self._record_usage(answer)
        text = str(getattr(answer, "content", "") or "")
        return text or None

    def _llm_with_tools_withheld(self) -> Any | None:
        """This agent's model with its tools bound and ``tool_choice="none"``, or ``None``.

        ``None`` when the agent has no tools or the model cannot bind them;
        the caller then has no second way to ask.
        """
        tools = list(getattr(self, "tools", None) or [])
        bind = getattr(self.llm, "bind_tools", None)
        if not tools or bind is None:
            return None
        # The same tools the loop was run with, guards included, so the
        # server sees the tool list the transcript was produced against. An
        # agent that cannot pin — one built outside a job — binds them bare.
        try:
            pinned = self.pinned_tools()
        except Exception as exc:  # noqa: BLE001 — the bare tools are the fallback's fallback
            self.logger.debug("%s: tools bound unpinned for the nudge (%s).", self.name, exc)
            pinned = tools
        try:
            return bind(pinned, tool_choice="none")
        except Exception as exc:  # noqa: BLE001 — a model that cannot bind has no fallback
            self.logger.debug("%s: tools could not be bound for the nudge (%s).", self.name, exc)
            return None

    def _record_react_loop(self, *, hit_step_cap: bool) -> None:
        """Count one ReAct loop and whether it exhausted its step budget.

        Pitfall P6 asks for truncation *frequency*, so every loop is counted,
        not only the ones that hit the cap. Never raises — telemetry must not
        break an analysis.
        """
        ledger = getattr(self, "truncation_ledger", None)
        if ledger is None:
            return
        try:
            ledger.record_react_loop(hit_step_cap=hit_step_cap)
        except Exception:  # noqa: BLE001
            return

    def _finish_evidence(self, recorder: Any) -> None:
        """Close this loop's ledger: apply the byte budget, then publish it.

        Best-effort in every branch. A ledger that cannot be closed is a
        report with less to cite, never an analysis that failed.
        """
        try:
            entries = list(recorder.entries)
            budget = int(getattr(get_settings().reporting, "evidence_budget_bytes", 0) or 0)
            trimmed, self._evidence_bytes_spent = apply_budget(
                entries, budget, already_spent=self._evidence_bytes_spent
            )
            if trimmed:
                self.logger.warning(
                    "%s: %d of %d evidence entries exceeded the %d-byte budget and "
                    "kept only their call record.",
                    self.name,
                    trimmed,
                    len(entries),
                    budget,
                )
            ledger = getattr(self, "truncation_ledger", None)
            if ledger is not None:
                try:
                    ledger.record_evidence_budget(entries=len(entries), trimmed=trimmed)
                except Exception:  # noqa: BLE001 — telemetry never breaks a run
                    pass
            self._evidence_entries.extend(entries)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("evidence ledger not published: %s", exc)

    def _capture_findings(self, content: str) -> str:
        """Take the structured block out of an answer and keep what it carried.

        The prose comes back without the block, so the ISR parser, the
        transcript and the report all see what a person would read. Never
        raises: an agent that emitted a malformed block still wrote an answer.
        """
        try:
            from maljan.agents.findings_block import parse_findings_block

            block = parse_findings_block(content)
            if not block:
                return content
            self._findings_buffer.extend(block.findings)
            self._artifacts_buffer.extend(block.artifacts)
            self.logger.info(
                "%s: findings block carried %d finding(s) and %d artifact(s).",
                self.name,
                len(block.findings),
                len(block.artifacts),
            )
            return block.prose
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("findings block not read: %s", exc)
            return content

    def _drain_findings(self, isr: AgentISR) -> AgentISR:
        """Move the buffered structured channel onto ``isr`` and clear it."""
        if self._findings_buffer:
            isr.findings = list(self._findings_buffer)
        if self._artifacts_buffer:
            isr.artifacts = list(self._artifacts_buffer)
        self._findings_buffer = []
        self._artifacts_buffer = []
        return isr

    def drain_evidence_entries(self) -> list[LedgerEntry]:
        """Every entry gathered since the last drain, handing over ownership.

        Draining rather than reading is the contract, and it is the contract
        because both halves of the alternative are wrong: a node that reads
        without clearing re-emits the previous round's calls onto an
        append-only channel, and a loop that clears on entry throws away the
        chunks before the last one. Exactly one node drains each agent, after
        the work that node is responsible for.
        """
        entries = self._evidence_entries
        self._evidence_entries = []
        return entries

    def get_last_tool_evidence(self) -> list[CapturedToolOutput]:
        """The same calls in the previous capture shape, for readers not yet moved.

        A peek, not a drain: this view is derived and nothing writes it to the
        state on its own.
        """
        return [entry.to_captured() for entry in self._evidence_entries]

    def _force_final_synthesis(self, msgs: list, timeout: int, elapsed: float = 0.0) -> str:
        """Salvage a ReAct loop that hit its step budget without answering.

        LangGraph returns a "...need more steps..." stop message when the agent
        exhausts ``recursion_limit`` while still tool-calling, discarding every
        tool result it gathered. Re-invoke the model once on the accumulated
        conversation with a hard directive to stop calling tools and write its
        final answer now, in the format the original system prompt requested.

        **Bounded in both dimensions, and it was neither before.** Measured
        2026-08-11 on a real binary: the loop spent its 40 steps in 109 s, this
        method was handed the whole 41-message conversation and a *fresh* copy
        of the full 1,500 s timeout, ran 25 minutes, hit the 1,530 s hard cap,
        and the analysis produced zero techniques. Two bounds composed into
        nothing — exceeding the step cap guaranteed an attempt at the time cap,
        and on a rich binary that attempt could not finish.

        So: synthesis gets what is *left* of the budget (a salvage that overruns
        the deadline it was called to respect is not a salvage), skips entirely
        when too little remains to be worth starting, and re-sends a conversation
        trimmed to a character budget — the model cannot synthesise from context
        it never finishes reading. The budget is the smaller of what the window
        allows and, where this model's reading and writing rates are measured,
        what the time left can be read and answered in
        (``salvage_chars_at_pace``); the framing — the task and the pack — is
        always kept, and the oldest tool calls go first. When even the framing
        cannot be read and answered in the time left, the salvage is not sent.
        Either way what it sent and how it ended is on the loop's budget record
        under ``salvage``.

        Best-effort throughout: on any failure it returns "" so the caller keeps
        the original content.
        """
        from langchain_core.messages import HumanMessage

        # Not truncated to whole seconds: at the time cap a second is a large
        # share of what the final answer was kept.
        remaining = max(0.0, float(timeout) - elapsed)
        generation_rate, prompt_rate = self._measured_rates()
        paced_unknown = generation_rate is None or prompt_rate is None
        if paced_unknown and remaining < _SYNTHESIS_MIN_SECONDS:
            self.logger.warning(
                "%s skipping forced synthesis: only %ds of the %ds budget left "
                "(minimum %ds) — starting it is how the hard cap fires.",
                self.name,
                remaining,
                timeout,
                _SYNTHESIS_MIN_SECONDS,
            )
            self._note_salvage(
                seconds_left=remaining,
                outcome="not sent",
                detail=(
                    f"{remaining:.0f}s were left, under the {_SYNTHESIS_MIN_SECONDS}s a salvage "
                    "is started with when no rate of this model is measured"
                ),
            )
            return ""

        window_budget = synthesis_budget_chars(
            get_settings(), self.name, counted_window_tokens(self._context_budget())
        )
        # What the time left can hold at this model's measured pace, when both
        # of its rates are known; the window's bound applies either way.
        paced = salvage_chars_at_pace(
            remaining,
            generation_rate=generation_rate,
            prompt_rate=prompt_rate,
            chars_per_token=self._chars_per_token(),
        )
        budget = window_budget if paced is None else min(window_budget, paced)
        # The same transcript rule the nudge follows: a tool call whose
        # arguments never parsed is not sent back to the server.
        sendable, _dropped = nudge_turns(msgs)
        conversation = sum(_message_chars(m) for m in sendable)
        framing = sum(_message_chars(m) for m in _framing_of(sendable))
        rates = self._rates_sentence(generation_rate, prompt_rate)
        if paced is not None and paced < framing + len(_SYNTHESIS_DIRECTIVE):
            # Not even the task and the pack can be read and answered in the
            # time left at this pace. Starting anyway is a call that runs into
            # its hard cap and keeps the model busy past it.
            detail = (
                f"{remaining:.0f}s were left; at {rates} they hold {max(0, paced)} characters "
                f"of request, and the task alone is {framing}"
            )
            self.logger.warning("%s skipping forced synthesis: %s.", self.name, detail)
            self._note_salvage(
                seconds_left=remaining,
                conversation_chars=conversation,
                budget_chars=max(0, paced),
                sized_by="pace",
                outcome="not sent",
                detail=detail,
            )
            return ""

        trimmed = _trim_for_synthesis(sendable, budget)
        sent = sum(_message_chars(m) for m in trimmed)
        if len(trimmed) < len(msgs):
            self.logger.warning(
                "%s forced synthesis: trimmed %d of %d messages to fit %d chars%s.",
                self.name,
                len(msgs) - len(trimmed),
                len(msgs),
                budget,
                f" ({remaining:.0f}s left at {rates})" if paced is not None else "",
            )
        # What the model can still see, named for it. Trimming drops whole
        # tool calls, so an id that was in the conversation a moment ago may
        # not be any more, and an analyst citing one it can no longer read is
        # how "referenced but not displayed" got into a report.
        visible = ledger_ids_in(trimmed)
        citable = (
            "The evidence still in front of you is " + ", ".join(visible) + ". Cite only these ids."
            if visible
            else "Cite only evidence ids that appear above."
        )
        directive = HumanMessage(content=_SYNTHESIS_DIRECTIVE + citable)
        record = {
            "seconds_left": remaining,
            "conversation_chars": conversation,
            "sent_chars": sent,
            "budget_chars": budget,
            "sized_by": "window" if paced is None or window_budget <= paced else "pace",
        }
        try:
            answer = self._invoke_llm_with_timeout([*trimmed, directive], remaining)
        except Exception as exc:  # noqa: BLE001 - best-effort salvage
            self.logger.error(
                "%s forced synthesis failed: %s (%s)",
                self.name,
                type(exc).__name__,
                exc,
            )
            self._note_salvage(**record, outcome="failed", detail=type(exc).__name__)
            return ""
        self._note_salvage(**record, outcome="answered")
        return answer

    def _measured_rates(self) -> tuple[float | None, float | None]:
        """``(generation, prompt reading)`` tokens a second of this agent's model, as measured."""
        rates_of = getattr(getattr(self, "_container", None), "get_generation_rates", None)
        if not callable(rates_of):
            return None, None
        try:
            from maljan.llm.generation_rate import model_name_of

            rates = rates_of()
            model = model_name_of(self.llm)
            generation, reading = rates.rate(model), rates.prompt_rate(model)
        except Exception:  # noqa: BLE001 — an unmeasured model sizes nothing from a rate
            return None, None
        return (
            generation if isinstance(generation, int | float) else None,
            reading if isinstance(reading, int | float) else None,
        )

    @staticmethod
    def _rates_sentence(generation: float | None, reading: float | None) -> str:
        if generation is None or reading is None:
            return "no measured rate"
        return f"{reading:.0f} tokens/s read and {generation:.1f} tokens/s written"

    def _chars_per_token(self) -> int:
        """Characters a token of this run's requests holds, as the context budget counts them."""
        from maljan.llm.context_window import CHARS_PER_TOKEN

        budget = self._context_budget()
        return int(getattr(budget, "chars_per_token", 0) or CHARS_PER_TOKEN)

    def _note_salvage(self, **record: Any) -> None:
        """Put what the salvage sent and how it ended on this loop's budget record.

        On the last record, which is the loop the salvage belongs to: it is
        written before the salvage starts. Never raises.
        """
        row = {
            key: round(value, 1) if isinstance(value, float) else value
            for key, value in record.items()
        }
        self._note_on_last_loop("salvage", row)

    def ask_the_model(self, messages: list, *, model: Any = None, what: str = "turn") -> str:
        """One tools-free model call outside a tool loop, cancellable in flight.

        The revision rounds, the view and tier decomposition turns and the
        other single calls an analyst makes used ``invoke`` on a thread: a
        cancelled job refused the next such call but left the one on the wire
        generating on the model server until the provider's request timeout,
        with the next job queued behind it. This goes through
        ``_invoke_llm_with_timeout``: the model's own async call on the agent
        loop, registered with the job's cancellation, held to this agent's
        loop budget.
        """
        timeout, _steps = loop_limits(self.name, getattr(self, "_budget_ceiling", None))
        return self._invoke_llm_with_timeout(messages, float(timeout), model=model, what=what)

    def _invoke_llm_with_timeout(
        self,
        messages: list,
        timeout: float,
        *,
        model: Any = None,
        what: str = "no-tools fallback",
    ) -> str:
        """Run ``model.ainvoke(messages)`` (``self.llm`` by default) with a hard wall-clock timeout.

        Used by ``execute_tool_loop`` when
        the agent has no tools registered, by the salvage, by the validation
        turn and by ``ask_the_model``. Runs on the shared agent loop so a
        stalled / queued llama-server cannot freeze the worker, and a timeout
        or a cancelled job cancels the request itself.
        """
        import time as _time

        from maljan.core.exceptions import AnalystError

        # Run on the shared agent loop (see ``_get_agent_loop``)
        # rather than a throwaway per-call loop, so no openai async client is
        # ever orphaned on a closed loop.
        llm: Any = self.llm if model is None else model

        async def _invoke() -> str:
            # ``what`` goes into the format itself so the timeout stays the
            # line's first argument, as log readers of this line expect.
            self.logger.info(f"Invoking LLM ({what}, timeout=%ds)...", timeout)  # noqa: G004
            # The model's own async call where it has one, so the timeout and
            # a cancelled job cancel the request itself: the connection closes
            # and the server stops generating. A synchronous ``invoke`` in a
            # thread cannot be cancelled — the slow run's salvage timed out on
            # the worker's side and went on generating on the server's, and
            # the next loop's first turn queued behind it for 908 s. A stand-in
            # that stubs only ``invoke`` is still run in a thread.
            ask = getattr(type(llm), "ainvoke", None)
            call = (
                llm.ainvoke(messages)
                if inspect.iscoroutinefunction(ask)
                else asyncio.to_thread(llm.invoke, messages)
            )
            response = await asyncio.wait_for(call, timeout=float(timeout))
            self._record_usage(response)
            return str(response.content)

        _t0 = _time.monotonic()
        hard_timeout = hard_cap(timeout, getattr(self, "_budget_ceiling", None))
        try:
            content = _run_coro_blocking(_invoke(), hard_timeout, label=f"llm:{self.name}")
        except TimeoutError:
            self.logger.critical(
                "%s %s exceeded the %ds hard cap.",
                self.name,
                what,
                hard_timeout,
            )
            raise
        except AnalystError:
            raise
        except Exception as exc:
            self.logger.error("LLM %s failed: %s (%s)", what, type(exc).__name__, exc)
            raise AnalystError(f"{self.name} {what} failed: {exc}") from exc

        elapsed = _time.monotonic() - _t0
        self.logger.info(
            "%s %s: elapsed=%.1fs, timeout=%ds.",
            self.name,
            what,
            elapsed,
            timeout,
        )
        return str(content)

    # ------------------------------------------------------------------
    # Abstract text interface (must be implemented by subclasses)
    # ------------------------------------------------------------------

    @abstractmethod
    def analyze(self, data: str) -> str:
        """Core analysis logic that translates raw data into a first-pass report."""
        pass

    @abstractmethod
    def revise(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        """Revise the agent's own report based on peer reports and mediator feedback."""
        pass

    # ------------------------------------------------------------------
    # ISR interface (subclasses may override for richer output)
    # ------------------------------------------------------------------

    def analyze_isr(self, data: str) -> AgentISR:
        """Return a structured AgentISR from initial analysis.

        Default: calls analyze() and wraps the text output into a minimal ISR.
        Subclasses should override to extract proper ClaimEvidence objects.
        """
        report_text = self.analyze(data)
        return self._text_to_isr(report_text, revision_round=0)

    def revise_isr(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
        revision_round: int = 1,
    ) -> tuple[str, AgentISR]:
        """Return (revised_text, AgentISR) from a revision round.

        Default: calls revise() and wraps the text into a minimal ISR.
        Subclasses should override to extract dissent_items from the LLM response.
        """
        revised_text = self.revise(original_data, own_report, peer_reports, mediator_feedback)
        isr = self._text_to_isr(revised_text, revision_round=revision_round)
        return revised_text, isr

    def answer_task(self, task: str) -> tuple[str, AgentISR]:
        """Work on one task another agent handed over, and answer with claims.

        The delegated path (``agents.delegation``): the agent's own system
        prompt, the task as the human turn — framed like every other first
        turn, with the pack in front and the run state in the system turn —
        the tool loop, the parse into claims, and the same checks an answer to
        a stage gets: the consistency gate and the technique check, in this
        agent's own conversation. Returns the loop's text and the checked ISR.

        The evidence the gate and the check read is the task plus what this
        loop's own tool calls returned: a delegated answer rests on what the
        agent went and looked at, not on a data chunk it was handed.

        Raises whatever the loop raises. A caller reads the failure as a tool
        error, which is the honest answer to an ask that could not be done.
        """
        self._try_initialize_mcp()
        before = len(self._evidence_entries)
        text = self.execute_tool_loop([("system", self._system_prompt("")), ("human", task)])
        gathered = "\n".join(
            str(getattr(entry, "output", "") or "") for entry in self._evidence_entries[before:]
        )
        evidence = f"{task}\n{gathered}" if gathered else task
        isr = self._text_to_isr(text, revision_round=int(self.current_round))
        isr = self._validate_isr(self._apply_consistency_gate(isr, evidence), evidence)
        return text, self._drain_findings(isr)

    # ------------------------------------------------------------------
    # Safe wrappers (error handling + token protection)
    # ------------------------------------------------------------------

    def safe_analyze(self, data: str) -> str:
        """Wrapper around analyze() with error handling and token protection."""
        try:
            truncated = self._truncate_input(data)
            return self.analyze(truncated)
        except AnalystError:
            raise
        except Exception as e:
            self.logger.error("Analysis failed: %s", e)
            raise AnalystError(f"{self.name} analysis failed: {e}") from e

    def safe_analyze_isr(self, data: str) -> AgentISR:
        """Wrapper around analyze_isr() with error handling and token protection.

        Under this agent's delegation lock, so an ask of it waits while its own
        stage runs and its own stage waits while it is answering one: both
        drive the same buffers, the same budget and the same call chain.
        """
        self.current_round = 0
        with lock_for(self):
            return self._analyze_isr_guarded(data)

    def safe_analyze_isr_within(self, data: str, seconds: float) -> AgentISR:
        """``safe_analyze_isr`` with the loop held to ``seconds``, what the stage has left.

        The ceiling a delegated ask uses, with this agent's own step budget:
        the loop's budget, its hard cap and its salvage are all sized from
        what is left, not from a fresh copy of the stage's whole time.
        """
        self.current_round = 0
        _timeout, max_steps = loop_limits(self.name)
        with lock_for(self):
            before = getattr(self, "_budget_ceiling", None)
            self._budget_ceiling = BudgetCeiling(max_steps, max(1.0, float(seconds)))
            try:
                return self._analyze_isr_guarded(data)
            finally:
                self._budget_ceiling = before

    def seconds_an_answer_needs(self) -> float:
        """One answer at the pace this agent's last loop measured: the loop's final-answer reserve.

        ``TurnPace.reserve``: the longest turn, or a 1,000-token answer at the
        measured rate where that is longer, times the margin, and at least the
        salvage's minimum. A loop that measured nothing needs that minimum.
        """
        pace = getattr(self, "_last_pace", None)
        if not isinstance(pace, TurnPace):
            return float(_SYNTHESIS_MIN_SECONDS)
        return pace.reserve()

    def _seconds_the_last_loop_left(self, fallback: float) -> float:
        """What is left of the last loop's time, or ``fallback`` when no loop has run."""
        deadline = getattr(self, "_last_loop_deadline", None)
        if not isinstance(deadline, int | float):
            return float(fallback)
        return float(deadline) - time.monotonic()

    def _note_on_last_loop(self, key: str, value: Any) -> None:
        """Put one fact on the last loop's budget record. Never raises."""
        try:
            lock = getattr(self, "_meter_lock", None) or contextlib.nullcontext()
            with lock:
                records = list(getattr(self, "_budget_records", None) or [])
                if not records:
                    return
                records[-1] = {**records[-1], key: value}
                self._budget_records = records
        except Exception as exc:  # noqa: BLE001 — a record never costs an answer
            self.logger.debug("%s: %s was not recorded (%s).", self.name, key, exc)

    def seconds_a_loop_needs(self) -> float:
        """One turn and the final answer after it, at the pace this agent's last loop measured.

        The longest turn of the model that answered last, plus the reserve the
        loop keeps for a final answer (``TurnPace.reserve``). A loop that
        measured no turn needs at least the salvage's own minimum.
        """
        pace = getattr(self, "_last_pace", None)
        if not isinstance(pace, TurnPace):
            return float(_SYNTHESIS_MIN_SECONDS)
        return pace.longest() + pace.reserve()

    def _analyze_isr_guarded(self, data: str) -> AgentISR:
        # Whatever the loop is given, kept where the handlers below can reach
        # it: the salvage needs the same text the analysis had, and asking for
        # it again inside a handler is how a failing truncate would raise out
        # of the branch that is reporting a different failure.
        truncated = data
        try:
            truncated = self._truncate_input(data)
            isr = self.analyze_isr(truncated)
            if not isr.claims:
                # An analyst whose loop ended without a report answers with an
                # empty ISR rather than raising, so the salvage belongs here as
                # much as on the failure path below: a lead's cap arrives as
                # "no claims" and takes every answered ask with it.
                salvaged = self._synthesise_from_answered_asks()
                if salvaged is not None and salvaged.claims:
                    isr = salvaged
            return self._validate_isr(self._apply_consistency_gate(isr, truncated), truncated)
        except AnalystError:
            salvaged = self._salvaged_isr(truncated)
            if salvaged is not None:
                return salvaged
            raise
        except Exception as e:
            self.logger.error("ISR analysis failed: %s", describe_exception_for_log(e))
            salvaged = self._salvaged_isr(truncated)
            if salvaged is not None:
                return salvaged
            raise AnalystError(
                f"{self.name} ISR analysis failed: {describe_exception_for_log(e)}"
            ) from e

    def _salvaged_isr(self, evidence: str) -> AgentISR | None:
        """A report written from the answered asks, checked like any other.

        Through the same gate and the same validation the ordinary path takes:
        a salvaged report that cites what it cannot see is the failure mode
        the gate exists for, and it is the report most likely to.

        ``evidence`` is the text the analysis was given, already truncated by
        the caller. Nothing here may raise: this runs inside the handler that
        is reporting the original failure, and a salvage that threw would
        replace that failure with its own.
        """
        try:
            salvaged = self._synthesise_from_answered_asks()
            if salvaged is None:
                return None
            return self._validate_isr(self._apply_consistency_gate(salvaged, evidence), evidence)
        except Exception as exc:  # noqa: BLE001 — the original failure is the one to report
            self.logger.error(
                "%s: the salvaged report could not be checked: %s",
                self.name,
                describe_exception_for_log(exc),
            )
            return None

    def answered_asks(self) -> list[AgentISR]:
        """The specialists' own ISRs, for the asks this agent got answers to.

        A peek rather than a drain: the stage node reads it when a lead's own
        report never arrived, and it is the lead's loop that owns the buffer.
        """
        return list(getattr(self, "_delegated_isrs", None) or [])

    def remember_answered_ask(self, isr: AgentISR) -> None:
        """Keep a specialist's answer where the salvage and the stage can find it."""
        if isr is None:
            return
        buffer = getattr(self, "_delegated_isrs", None)
        if isinstance(buffer, list):
            buffer.append(isr)

    def _synthesise_from_answered_asks(self) -> AgentISR | None:
        """One bounded turn that writes a lead's report from the asks it got back.

        A lead delegates, and its own report is the only way its stage hears
        about the answers. When the loop dies — the wall-clock cap, most of
        all, which is what an 1,800 s lead chunk hits — the transcript it died
        in is gone and the answers go with it. They do not have to: the
        specialists' ISRs are on this agent, and one turn over them produces
        the report the loop was about to write.

        ``None`` when there is nothing to synthesise from or the turn itself
        failed, and then the caller's own failure stands: the stage promotes
        the specialists' answers instead, which loses the lead's synthesis but
        no completed ask.
        """
        answers = self.answered_asks()[self._asks_already_synthesised :]
        if not answers:
            return None
        # A chunked lead re-enters this loop once per chunk, and the answers it
        # got in the first chunk are not answers to the second chunk's asks.
        # The buffer keeps all of them — the stage promotes every one — and
        # each salvage turn is shown only what came in since the last.
        self._asks_already_synthesised = len(self.answered_asks())
        self.logger.warning(
            "%s: the loop ended without a report and %d ask(s) had been answered; "
            "synthesising from those answers.",
            self.name,
            len(answers),
        )
        from langchain_core.messages import HumanMessage, SystemMessage

        blocks = [
            f"ANSWER FROM {isr.agent_id}:\n{isr.to_text_summary()}"
            for isr in answers
            if isr is not None
        ]
        prompt = self._system_prompt("")
        messages: list[Any] = []
        if prompt:
            messages.append(SystemMessage(content=prompt))
        messages.append(
            HumanMessage(
                content=(
                    "Your own analysis turn ended before you wrote your report, and the "
                    "specialists you asked have answered. Using ONLY those answers, write "
                    "your FINAL answer now in the exact format the system prompt "
                    "requested. Do not call any tools. Cite the evidence ids the answers "
                    "cite, and attribute each point to the specialist that made it.\n\n"
                    + "\n\n".join(blocks)
                )
            )
        )
        try:
            text = self._invoke_llm_with_timeout(messages, _SYNTHESIS_MIN_SECONDS)
        except Exception as exc:  # noqa: BLE001 — a salvage that fails leaves the failure
            self.logger.error(
                "%s: synthesis from the answered asks failed: %s",
                self.name,
                describe_exception_for_log(exc),
            )
            return None
        if not answer_is_isr(text):
            return None
        return self._text_to_isr(self._capture_findings(text), 0)

    def safe_analyze_isr_chunked(self, chunks: list) -> AgentISR:
        """Analyze a list of TextChunk objects, merging their ISRs.

        Each chunk's loop runs under this agent's delegation lock, the same one
        a single-chunk run and an ask of it take, so nothing else drives the
        agent while one of its chunks is in flight.

        Raises:
            AnalystError: If the chunk list is empty or analysis fails on all
                chunks. An empty chunk list is treated as a hard input error
                rather than a silent "no findings" success.
        """
        from maljan.analysis.chunk_merger import merge_chunk_isrs

        if not chunks:
            raise AnalystError(f"{self.name} received an empty chunk list — no data to analyse.")

        if len(chunks) == 1:
            return self.safe_analyze_isr(chunks[0].content)

        self.logger.info("Chunked analysis: %d chunks for agent='%s'.", len(chunks), self.name)

        chunk_isrs: list[AgentISR] = []
        errors: list[str] = []

        for chunk in chunks:
            prompt_text = f"{chunk.to_prompt_header()}\n\n{chunk.content}"
            try:
                # Each chunk's loop under this agent's lock, so an ask of it
                # cannot run inside one: an ask drives the same buffers, the
                # same budget and the same call chain this loop is using.
                with lock_for(self):
                    isr = self.analyze_isr(prompt_text)
                chunk_isrs.append(isr)
                self.logger.debug(
                    "Chunk %d/%d analyzed: %d claims.",
                    chunk.index + 1,
                    chunk.total,
                    len(isr.claims),
                )
            except Exception as exc:
                errors.append(f"chunk {chunk.index + 1}: {exc}")
                self.logger.warning("Chunk %d/%d failed: %s.", chunk.index + 1, chunk.total, exc)

        if not chunk_isrs:
            raise AnalystError(
                f"{self.name} chunked analysis failed on all chunks: {'; '.join(errors)}"
            )

        if errors:
            self.logger.warning(
                "%d/%d chunks failed for '%s'. Merging %d successful results.",
                len(errors),
                len(chunks),
                self.name,
                len(chunk_isrs),
            )

        merged = merge_chunk_isrs(chunk_isrs)
        # Item 4 consistency gate: ground the merged claims against the full
        # multi-chunk evidence (a claim from one chunk grounded by another is
        # still grounded in the sample). No-op when the gate is off.
        evidence = "\n".join(c.content for c in chunks)
        return self._validate_isr(self._apply_consistency_gate(merged, evidence), evidence)

    # ------------------------------------------------------------------
    # View-decomposition (findings-log §3.6) — text path only
    # ------------------------------------------------------------------

    def _invoke_view(self, instruction: str, data: str, max_tokens: int | None) -> str:
        """One tools-free, focused LLM call for a single view. Returns raw text.

        ``max_tokens`` (the equal-budget per-view cap) is bound onto the model
        when set; binding failures degrade to an unbound call so a provider that
        rejects the kwarg never breaks the pilot.
        """
        from langchain_core.messages import HumanMessage, SystemMessage

        messages = [
            SystemMessage(content=_VIEW_SYSTEM),
            HumanMessage(content=f"{instruction}\n\n{data}"),
        ]
        # ``bind`` returns a Runnable, not a BaseChatModel; widen to Any so the
        # equal-budget cap can be attached without a type clash.
        llm: Any = self.llm
        if max_tokens and max_tokens > 0:
            try:
                llm = self.llm.bind(max_tokens=max_tokens)
            except Exception:  # noqa: BLE001 — provider may not accept the kwarg
                llm = self.llm
        return self.ask_the_model(messages, model=llm, what="view")

    def analyze_isr_views(
        self,
        data: str,
        n_views: int,
        *,
        total_max_tokens: int | None = None,
    ) -> AgentISR:
        """View-decomposition: run ``n_views`` focused sub-prompts over the SAME
        evidence concurrently, then merge the per-view ISRs.

        Equal-budget (the control §3.2 lacked): each view is capped at
        ``total_max_tokens // n_views`` so total generation budget matches the
        monolithic arm. A view that errors is dropped (fault isolation), as in
        ``safe_analyze_isr_chunked``. Tools-free text path only.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        from maljan.analysis.chunk_merger import merge_chunk_isrs

        if n_views < 2:
            return self.analyze_isr(data)

        domain = self._infer_domain()
        specs = _view_specs(domain, n_views)
        per_view_budget = (total_max_tokens // n_views) if total_max_tokens else None

        view_isrs: list[AgentISR] = []
        errors: list[str] = []

        def _run(spec: tuple[str, str]) -> AgentISR:
            text = self._invoke_view(spec[1], data, per_view_budget)
            return self._text_to_isr(text, revision_round=0)

        with ThreadPoolExecutor(max_workers=len(specs)) as pool:
            futures = {pool.submit(_run, spec): spec[0] for spec in specs}
            for fut in as_completed(futures):
                key = futures[fut]
                try:
                    view_isrs.append(fut.result())
                except Exception as exc:  # noqa: BLE001 — fault isolation
                    errors.append(f"view '{key}': {exc}")
                    self.logger.warning("View '%s' failed: %s.", key, exc)

        if not view_isrs:
            raise AnalystError(
                f"{self.name} view-decomposition failed on all {n_views} views: {'; '.join(errors)}"
            )
        if errors:
            self.logger.warning(
                "%d/%d views failed for '%s'; merging %d successful view(s).",
                len(errors),
                n_views,
                self.name,
                len(view_isrs),
            )
        self.logger.info(
            "View-decomposition: %d views -> merged ISR for agent='%s'.",
            len(view_isrs),
            self.name,
        )
        return merge_chunk_isrs(view_isrs)

    def safe_analyze_isr_views(
        self,
        data: str,
        n_views: int,
        *,
        total_max_tokens: int | None = None,
    ) -> AgentISR:
        """Wrapper around ``analyze_isr_views`` with truncation + error handling."""
        try:
            truncated = self._truncate_input(data)
            isr = self.analyze_isr_views(truncated, n_views, total_max_tokens=total_max_tokens)
            return self._apply_consistency_gate(isr, truncated)
        except AnalystError:
            raise
        except Exception as e:
            self.logger.error(
                "View-decomposition ISR analysis failed: %s", describe_exception_for_log(e)
            )
            raise AnalystError(
                f"{self.name} view-decomposition failed: {describe_exception_for_log(e)}"
            ) from e

    # ------------------------------------------------------------------
    # Tier-wise (vertical) reasoning (findings-log §4 Item 3) — text path
    # ------------------------------------------------------------------

    def analyze_isr_tiered(
        self,
        data: str,
        n_tiers: int,
        *,
        total_max_tokens: int | None = None,
    ) -> AgentISR:
        """Tier-wise (vertical) reasoning (findings-log §4 Item 3, LAMD).

        Runs ``n_tiers`` SEQUENTIAL focused sub-prompts over the same evidence,
        each tier receiving the previous tier's findings as added context
        (facts -> behaviour -> ATT&CK semantics). Equal-budget: each tier is
        capped at ``total_max_tokens // n_tiers`` so total generation budget
        matches the monolithic arm. A tier that errors is skipped and the chain
        continues from the last good context (fault isolation). Per-tier ISRs
        are merged (``merge_chunk_isrs`` dedups the claims tiers naturally
        repeat). Tools-free text path only.
        """
        from maljan.analysis.chunk_merger import merge_chunk_isrs

        if n_tiers < 2:
            return self.analyze_isr(data)

        specs = _tier_specs(n_tiers)
        per_tier_budget = (total_max_tokens // n_tiers) if total_max_tokens else None

        tier_isrs: list[AgentISR] = []
        errors: list[str] = []
        prior_text = ""

        for key, instruction in specs:
            if prior_text:
                tier_input = (
                    f"{data}\n\n"
                    "--- Findings established by the previous reasoning tier "
                    "(build on these; do not contradict or ignore them) ---\n"
                    f"{prior_text}"
                )
            else:
                tier_input = data
            try:
                text = self._invoke_view(instruction, tier_input, per_tier_budget)
            except Exception as exc:  # noqa: BLE001 — fault isolation
                errors.append(f"tier '{key}': {exc}")
                self.logger.warning("Reasoning tier '%s' failed: %s.", key, exc)
                continue
            prior_text = text
            tier_isrs.append(self._text_to_isr(text, revision_round=0))

        if not tier_isrs:
            raise AnalystError(
                f"{self.name} tier-wise reasoning failed on all {n_tiers} tiers: "
                f"{'; '.join(errors)}"
            )
        if errors:
            self.logger.warning(
                "%d/%d reasoning tiers failed for '%s'; merging %d successful tier(s).",
                len(errors),
                n_tiers,
                self.name,
                len(tier_isrs),
            )
        self.logger.info(
            "Tier-wise reasoning: %d tiers -> merged ISR for agent='%s'.",
            len(tier_isrs),
            self.name,
        )
        return merge_chunk_isrs(tier_isrs)

    def safe_analyze_isr_tiered(
        self,
        data: str,
        n_tiers: int,
        *,
        total_max_tokens: int | None = None,
    ) -> AgentISR:
        """Wrapper around ``analyze_isr_tiered`` with truncation + error handling."""
        try:
            truncated = self._truncate_input(data)
            isr = self.analyze_isr_tiered(truncated, n_tiers, total_max_tokens=total_max_tokens)
            return self._apply_consistency_gate(isr, truncated)
        except AnalystError:
            raise
        except Exception as e:
            self.logger.error(
                "Tier-wise reasoning ISR analysis failed: %s", describe_exception_for_log(e)
            )
            raise AnalystError(
                f"{self.name} tier-wise reasoning failed: {describe_exception_for_log(e)}"
            ) from e

    # ------------------------------------------------------------------
    # Inline consistency gate (findings-log §4 Item 4)
    # ------------------------------------------------------------------

    def _validate_isr(self, isr: AgentISR, evidence: str) -> AgentISR:
        """Tell the analyst what is wrong with its own answer, once.

        The ATT&CK check that used to run in the judge node, as a pass that
        rewrote each claim's ``technique_id`` against a TF-IDF index, runs here
        instead — as feedback, in this analyst's own conversation, with one
        turn to fix it. An id that survives that turn keeps the analyst's
        spelling and is flagged ``technique_id_valid=False``; the report and
        the FP linter read the flag, and nothing substitutes an id.

        Never raises: a validation loop that could fail a run would be a worse
        failure mode than the one it replaces.
        """
        try:
            from maljan.tools import knowledge
        except Exception as exc:  # noqa: BLE001 — no catalogue, no check
            self.logger.debug("Validation skipped, the knowledge tools are unavailable: %s", exc)
            return isr

        # What this analyst may cite: its own ledger as it stands when the
        # answer is checked, and the triage pack's entries, which every agent
        # was shown. It decides whether a technique claim that cites nothing
        # is a violation: an analyst with neither has nothing to cite.
        ledger_ids = [
            str(getattr(entry, "id", ""))
            for entry in (getattr(self, "_evidence_entries", None) or [])
            if getattr(entry, "id", "")
        ]
        ledger_ids.extend(
            str(i) for i in (getattr(self, "pack_ledger_ids", None) or []) if str(i).strip()
        )

        # The validity check answers from the vendored id universe; a box
        # without it cannot check anything, and says so in the run summary
        # instead of reporting every id as fine.
        if not validity_check_available(knowledge):
            not_run = getattr(self, "validation_not_run", None)
            if not_run is None:
                not_run = []
                self.validation_not_run = not_run
            if VALIDITY_CODE not in not_run:
                not_run.append(VALIDITY_CODE)
            self.logger.warning(
                "%s: the ATT&CK catalogue is unavailable; technique ids are not checked.",
                self.name,
            )

        file_type, platform = getattr(self, "sample_format", ("unknown", "unknown"))
        sample = {"file_type": file_type, "platform": platform}
        cfg_validation = getattr(get_settings(), "validation", None)
        gate = alignment_gate(knowledge, cfg_validation, self.logger, self.name)
        threshold = float(getattr(cfg_validation, "alignment_threshold", 0.05) or 0.05)
        margin = float(getattr(cfg_validation, "alignment_margin", ALIGNMENT_MARGIN))
        challenges = bool(getattr(cfg_validation, "weak_alignment", False))
        # One weak-alignment batch per turn. The ranking is recorded on every
        # claim every time; what is bounded is the asking, because a second
        # batch would spend another full model turn on a check whose first
        # batch the analyst has already answered.
        asked: list[bool] = []

        # An answer the loop already asked once for a report — the nudge — is
        # not asked again for the claim format: that was the question. What it
        # left unread is recorded instead of asked.
        nudged = bool(getattr(self, "_answer_unstructured", False))

        # Whether the answer being checked ended at the output cap: the loop's
        # own answer first, then each retry's. A cut answer is asked for a
        # whole shorter one (``analyst_cut_violation``) and is not sent back;
        # the question describes it.
        # Keyed by the parsed answer, because the loop checks the kept answer
        # again after choosing it, and that may be the first one.
        cuts: dict[int, tuple[int, str] | None] = {id(isr): getattr(self, "_last_answer_cut", None)}
        # Read once: the next model call records its own.
        self._last_answer_cut = None

        def _validator(candidate: AgentISR) -> list[Violation]:
            first = not asked
            asked.append(True)
            unread = [] if nudged else parse_violations(candidate)
            cut = cuts.get(id(candidate))
            return [
                *([analyst_cut_violation(*cut)] if cut is not None else []),
                *unread,
                *validate_isr(
                    candidate,
                    attck=knowledge,
                    ledger_ids=ledger_ids,
                    sample=sample,
                    alignment=gate,
                    alignment_threshold=threshold,
                    alignment_margin=margin,
                    weak_alignment_challenges=challenges and first,
                ),
            ]

        if nudged:
            self.validation_findings.extend(parse_violations(isr))

        try:
            initial = _validator(isr)
        except Exception as exc:  # noqa: BLE001
            self.logger.warning("Validation skipped (%s).", exc)
            return isr
        if not initial:
            return isr

        # The turn gets what the loop it follows left, and is not asked at all
        # when that cannot hold an answer at this model's pace: a question after
        # a loop that ended at its time cap used to be handed the whole budget
        # again, and after a second loop the whole of what that loop was given.
        timeout, _steps = loop_limits(self.name, getattr(self, "_budget_ceiling", None))
        # Through the class's functions, so a duck-typed analyst that borrows
        # this method alone is held to the same rule.
        left = BaseAnalyst._seconds_the_last_loop_left(self, float(timeout))  # type: ignore[arg-type]
        needs = BaseAnalyst.seconds_an_answer_needs(self)  # type: ignore[arg-type]
        if left < needs:
            detail = (
                f"not asked: {max(0.0, left):.0f}s of the loop's time were left, and an answer "
                f"needs {needs:.0f}s at the pace this agent's loop measured"
            )
            self.logger.warning("%s: validation turn %s.", self.name, detail)
            # An unknown id is a catalogue fact and is marked whether or not it
            # was asked. An absence reading, and a claim whose sentence does not
            # describe its technique, are questions for the analyst, and one
            # never sent notes nothing on the claim: the finding is recorded
            # saying it was not asked, and the technique goes through as claimed.
            unasked = [
                replace(
                    v,
                    message=f"{v.message} {detail[:1].upper()}{detail[1:]}.",
                    sentence="",
                    asked=False,
                )
                if v.code in (ABSENCE_CLAIM_CODE, CLAIM_DOES_NOT_DESCRIBE_CODE, ANALYST_CUT_CODE)
                else v
                for v in initial
            ]
            mark_invalid_technique_ids(isr, [v for v in unasked if v.code != ABSENCE_CLAIM_CODE])
            self.validation_findings.extend(unasked)
            BaseAnalyst._note_on_last_loop(self, "validation", detail)  # type: ignore[arg-type]
            return isr

        from langchain_core.messages import HumanMessage, SystemMessage

        prompt = self._system_prompt("")
        messages: list[BaseMessage] = []
        if prompt:
            messages.append(SystemMessage(content=prompt))
        messages.append(HumanMessage(content=self._truncate_input(evidence)))
        # Framed like every other turn: the feedback asks the analyst to cite
        # ledger ids, and the pack is where the ids it can cite are written.
        # Through the module function, so a duck-typed analyst that borrows
        # this method alone is framed too.
        messages = frame_messages(
            messages,
            facts_block=str(getattr(self, "facts_block", "") or ""),
            run_state=str(getattr(self, "run_state_block", "") or ""),
        )

        first: list[Any] = [_PriorAnswer(isr)]

        # A retry that asks for a whole new answer is sent only when the
        # conversation it sends leaves the cap free in the window. Every other
        # question keeps the answer and asks for a fix to it, as it always did.
        loop_cut = cuts.get(id(isr))
        if loop_cut is not None and not BaseAnalyst._fits_the_window(  # type: ignore[arg-type]
            self, messages, loop_cut[0]
        ):
            detail = (
                "not asked: the conversation the question is sent in and the "
                f"{loop_cut[0]}-token answer it asks for do not fit this model's window"
            )
            self.logger.warning("%s: the cut-at-cap question was %s.", self.name, detail)
            unasked_cut = analyst_cut_violation(*loop_cut)
            self.validation_findings.append(
                replace(
                    unasked_cut,
                    message=f"{unasked_cut.message} {detail[:1].upper()}{detail[1:]}.",
                    asked=False,
                )
            )
            cuts[id(isr)] = None

        def _run(turns: list[Any]) -> Any:
            if first:
                return first.pop()
            return self._invoke_llm_with_timeout(turns, left)

        def _parse(answer: Any) -> AgentISR:
            if isinstance(answer, _PriorAnswer):
                return answer.isr
            text = str(getattr(answer, "content", answer))
            parsed = self._text_to_isr(self._capture_findings(text), isr.revision_round)
            cuts[id(parsed)] = getattr(self, "_last_answer_cut", None)
            self._last_answer_cut = None
            return parsed

        def _keep(first_answer: AgentISR, retried: AgentISR) -> AgentISR:
            # A retry that came back with fewer claims than it started with
            # lost work. ``_text_to_isr`` over a garbled second answer parses
            # to an empty ISR just as happily as over a good one, and taking it
            # would delete the analyst's original findings with nothing
            # recording that it happened. The first answer is kept and what is
            # wrong with it is recorded — and published: the loop checks the
            # kept answer again before it says what became of each finding.
            # An answer that is still prose after being asked keeps the loop's
            # own prose, which is what the analyst wrote from everything it
            # gathered; the retry was asked over the evidence text alone.
            if not retried.claims and first_answer.unparsed_answer:
                return first_answer
            # Asked for a whole shorter answer because the first was cut, and
            # given one that ended on its own: that answer is the analyst's,
            # fewer claims and all. The cut one it replaces was never whole.
            if (
                cuts.get(id(first_answer)) is not None
                and cuts.get(id(retried)) is None
                and retried.claims
            ):
                return retried
            if len(retried.claims) < len(first_answer.claims):
                self.logger.warning(
                    "Validation: the retry for '%s' returned %d claim(s) against %d; "
                    "keeping the first answer and recording what is wrong with it.",
                    self.name,
                    len(retried.claims),
                    len(first_answer.claims),
                )
                return first_answer
            return retried

        try:
            tally = ValidationTally()
            revised, violations, retries = retry_with_feedback_sync(
                _run,
                messages,
                [_validator],
                parse=_parse,
                on_feedback=tally.count,
                sink=self._event_sink(),
                agent=str(self.name),
                stage=str(getattr(self, "pipeline_stage", "") or "analysis"),
                keep=_keep,
                drop_answer_for=frozenset({ANALYST_CUT_CODE}),
            )
        except Exception as exc:  # noqa: BLE001 — a retry that fails keeps the first answer
            self.logger.warning("Validation retry failed (%s); keeping the first answer.", exc)
            return isr

        self.validation_retries += retries
        for code, count in tally.by_code.items():
            self.validation_fed_back[code] = self.validation_fed_back.get(code, 0) + count

        if violations:
            mark_invalid_technique_ids(revised, violations)
            self.validation_findings.extend(violations)
            self.logger.info(
                "Validation: %d finding(s) survived the retry for '%s' (%s).",
                len(violations),
                self.name,
                ", ".join(sorted({v.code for v in violations})),
            )
        return revised

    def _fits_the_window(self, messages: list[Any], cap: int) -> bool:
        """Whether ``messages`` and an answer of ``cap`` tokens fit this model's window.

        Measured against the job's learned window, in the budget's own
        characters per token. With no window learned there is nothing to
        measure against, and the question is asked.
        """
        budget = BaseAnalyst._context_budget(self)  # type: ignore[arg-type]
        if budget is None or not getattr(budget, "derives", False):
            return True
        try:
            per_token = float(budget.chars_per_token)
            room = (int(budget.window.tokens) - int(cap)) * per_token
        except Exception:  # noqa: BLE001 — a budget that cannot say leaves the question asked
            return True
        sent = sum(len(str(getattr(m, "content", m) or "")) for m in messages)
        return sent <= room

    def drain_nudge_retry_mode(self) -> str | None:
        """How the last nudge had to be sent, handed over once."""
        mode = getattr(self, "_nudge_retry_mode", None)
        self._nudge_retry_mode = None
        return str(mode) if mode else None

    def drain_validation_not_run(self) -> list[str]:
        """The checks that could not run, handed over once."""
        codes = list(getattr(self, "validation_not_run", None) or [])
        self.validation_not_run = []
        return codes

    def drain_validation_findings(self) -> tuple[list[dict[str, str]], int, dict[str, int]]:
        """What this analyst was told, what it did not fix, and what that cost.

        Three values, not two: the leftovers, the retry count, and every code
        the analyst was fed back — including the ones it went on to fix, which
        are exactly the ones nothing else in the run records.
        """
        rows = [v.to_dict() for v in self.validation_findings]
        retries = self.validation_retries
        fed_back = dict(self.validation_fed_back)
        self.validation_findings = []
        self.validation_retries = 0
        self.validation_fed_back = {}
        return rows, retries, fed_back

    def _apply_consistency_gate(self, isr: AgentISR, evidence: str) -> AgentISR:
        """LAMD foundational-tier consistency gate (findings-log §4 Item 4).

        When ``PreprocessingConfig.use_claim_consistency_gate`` is on, drop
        claims whose cited artifact / technique is absent from the source
        evidence — catching hallucinated claims at parse time, complementing the
        post-hoc fp_linter. No-op when the gate is off, the ISR has no claims,
        or no evidence is available. Never raises (a gate failure must not lose
        the run).
        """
        self._drain_findings(isr)
        try:
            if not get_settings().preprocessing.use_claim_consistency_gate:
                return isr
            if not isr.claims or not evidence:
                return isr
            kept = [
                c
                for c in isr.claims
                if _claim_grounded_in_evidence(c.claim, c.evidence_ref, c.technique_id, evidence)
            ]
            dropped = len(isr.claims) - len(kept)
            if dropped:
                self.logger.info(
                    "Consistency gate dropped %d/%d ungrounded claim(s) for '%s'.",
                    dropped,
                    len(isr.claims),
                    self.name,
                )
            return isr.model_copy(update={"claims": kept})
        except Exception as exc:  # noqa: BLE001 — gate must never break the run
            self.logger.warning("Consistency gate skipped (%s).", exc)
            return isr

    def safe_revise_isr(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
        revision_round: int = 1,
    ) -> tuple[str, AgentISR]:
        """Wrapper around revise_isr() with error handling.

        Under this agent's delegation lock, for the reason ``safe_analyze_isr``
        takes it: a revision round is this agent's own loop.
        """
        self.current_round = int(revision_round)
        with lock_for(self):
            try:
                truncated = self._truncate_input(original_data)
                text, isr = self.revise_isr(
                    truncated, own_report, peer_reports, mediator_feedback, revision_round
                )
                return text, self._drain_findings(isr)
            except AnalystError:
                raise
            except Exception as e:
                self.logger.error("ISR revision failed: %s", e)
                raise AnalystError(f"{self.name} ISR revision failed: {e}") from e

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Sentence-extraction helpers
    # ------------------------------------------------------------------

    # Sentence terminator regex: handles CRLF, full-width Unicode punctuation,
    # and Asian-language end markers in addition to ASCII .!?.
    _SENTENCE_SPLIT_RE = re.compile(
        r"(?<=[.!?。！？])[\s\r\n]+",
        flags=re.UNICODE,
    )

    # Recognise meta-claim text so the judge, the corroboration count and the
    # long-term-memory gate all read it as "no real claims" rather than as a
    # finding the analyst stated at 1.0 confidence. The fallback
    # strings come from ``file_loader.py:107`` ("No * data available for
    # sample ...") and from analyst LLM fallbacks that copy that wording.
    # Widened beyond the bare file_loader
    # placeholder to also catch the DEFEATIST re-wordings a small model emits
    # when it parrots a "No <x> data available" raw-data slot — e.g. "Static
    # analysis could not be performed due to missing binary data" (confidence
    # 1.0). Those parse as well-formed CLAIM blocks and would otherwise inflate
    # the verdict with a fake high-confidence "I couldn't analyse" claim instead
    # of honestly collapsing to a zero-claim, degraded-flagged ISR. Kept tight
    # (requires "be performed/completed/conducted") so a genuine partial finding
    # like "Static analysis could not confirm RC4 but ..." is NOT swallowed.
    _META_CLAIM_RE = re.compile(
        r"^\s*(?:"
        r"no\s+[a-z_]+\s+data\s+(?:available|was\s+available|provided|found)"
        r"|(?:static|dynamic|network)\s+analysis\s+"
        r"(?:could\s+not|cannot|can\s*not|was\s+not\s+able\s+to)\s+"
        r"be\s+(?:performed|completed|conducted)"
        r"|(?:missing|no)\s+binary\s+data"
        r")",
        flags=re.IGNORECASE,
    )

    # What a model writes on its way to a tool call rather than in a report:
    # "Let me search for more specific strings related to malware indicators:".
    # A live static analyst ended its loop on exactly that sentence and the
    # free-text splitter turned it into the run's only claim, at 0.5. An
    # intention is not a finding, whatever the loop did with it afterwards.
    _INTENTION_CLAIM_RE = re.compile(
        r"^\s*(?:let\s+me\b|let's\b|let\s+us\b|i\s+will\b|i'll\b|i\s+need\s+to\b"
        r"|i\s+am\s+going\s+to\b|i'm\s+going\s+to\b|next,|now\s+i\b"
        r"|first,\s+(?:let|i)\b)",
        flags=re.IGNORECASE,
    )

    def _is_meta_claim_text(self, text: str) -> bool:
        """True when ``text`` is a placeholder or an intention, not real analysis."""
        if not text:
            return True
        # Match the placeholder anywhere near the start of the text — analysts
        # sometimes prepend a one-line header (e.g. "CLAIM:") before parroting
        # the fallback, so probe both the raw first line and the same line with
        # a leading ``CLAIM:``/``EVIDENCE:`` label stripped.
        stripped = text.strip()
        first = stripped.splitlines()[0] if stripped else ""
        unlabelled = re.sub(r"^\s*(?:claim|evidence)\s*:\s*", "", first, flags=re.IGNORECASE)
        if self._META_CLAIM_RE.match(first) or self._META_CLAIM_RE.match(unlabelled):
            return True
        announces = bool(
            self._INTENTION_CLAIM_RE.match(first)
            or self._INTENTION_CLAIM_RE.match(unlabelled)
            # A sentence that ends in a colon announces what comes next; it
            # states nothing itself.
            or stripped.endswith(":")
        )
        # Only when that is the whole of it. A report may open by narrating its
        # next step and then say something real, and the sentence splitter drops
        # the opening sentence on its own — zeroing the whole answer for its
        # first line would throw away the findings that followed.
        return announces and len(self._SENTENCE_SPLIT_RE.split(stripped)) == 1

    def _drop_meta_claims(self, claims: list[ClaimEvidence]) -> list[ClaimEvidence]:
        """Strip parsed claims that are really "I could not analyse" meta-claims.

        ``_text_to_isr`` neutralises the placeholder on the
        text-fallback path, but a defeatist claim that parses as a well-formed
        ``CLAIM/EVIDENCE/CONFIDENCE`` block bypasses it. Filtering the parsed list
        here makes a no-real-finding analyst collapse to a zero-claim ISR so the
        downstream confidence cap honestly marks the run degraded instead of
        crediting a fake high-confidence claim.
        """
        return [c for c in claims if not self._is_meta_claim_text(c.claim)]

    def _parsed_isr(
        self, claims: list[ClaimEvidence], content: str, domain: str, revision_round: int = 0
    ) -> AgentISR:
        """The ISR for claims a strict parser read out of ``content``.

        With the count of CLAIM blocks the strict parser passed over for
        stating no confidence, which the validation turn asks about: a strict
        parser that drops a block says nothing, and the analyst wrote it.
        """
        isr = AgentISR(
            agent_id=self.name,
            domain=domain,
            claims=claims,
            dissent_items=[],
            revision_round=revision_round,
        )
        isr.note_parse(blocks_without_confidence=parse_structured_claims_counted(content)[1])
        return isr

    def _text_to_isr(self, text: str, revision_round: int) -> AgentISR:
        """Convert a free-text report into a minimal AgentISR."""
        domain = self._infer_domain()

        # A model that writes its tool calls into
        # the assistant channel leaves them here -- a live static_r2 run put
        # raw ``<tool_call>`` blocks in front of an operator as findings.
        # Removed before anything reads the text, so neither a claim nor the
        # kept prose carries scaffolding; a report that is nothing else yields
        # no claims at all, which is what the meta-claim branch already does
        # for the placeholder case.
        text = strip_tool_call_scaffolding(text)

        # When the agent returned only the placeholder
        # ("No static data available for sample ..."), emit a *zero-claim*
        # ISR rather than one with a meta-sentence. Every consumer already
        # skips an empty-claim ISR, so this is the single tightest place to
        # stop "I had nothing to read" being counted as a finding.
        if self._is_meta_claim_text(text):
            self.logger.info(
                "%s: meta-claim text detected; emitting zero-claim ISR.",
                self.name,
            )
            return self._with_answer_status(
                AgentISR(
                    agent_id=self.name,
                    domain=domain,
                    claims=[],
                    dissent_items=[],
                    revision_round=revision_round,
                )
            )

        # Structured output first, and only. Several prompts —
        # notably the view/tier decomposition ones — mandate the
        # CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE block format, and every ISR
        # prompt asks for it.
        structured: list[ClaimEvidence] = []
        without_confidence = 0
        if "CLAIM:" in text:
            structured, without_confidence = parse_structured_claims_counted(text)
        if structured:
            isr = AgentISR(
                agent_id=self.name,
                domain=domain,
                claims=structured,
                dissent_items=[],
                revision_round=revision_round,
            )
            isr.note_parse(blocks_without_confidence=without_confidence)
            return isr

        # An answer with no claim this parser can read is prose, and prose is
        # kept as the analyst's report rather than cut into claims. The
        # sentence splitter that stood here made a claim of every sentence
        # longer than twenty characters, Markdown headings included, at a flat
        # 0.50 nobody stated. The validation turn asks once for the claim
        # format; what survives that is recorded, and the stage keeps the prose.
        isr = AgentISR(
            agent_id=self.name,
            domain=domain,
            claims=[],
            dissent_items=[],
            revision_round=revision_round,
        )
        isr.note_parse(unparsed_answer=text.strip(), blocks_without_confidence=without_confidence)
        isr.status = NO_STRUCTURED_REPORT_STATUS
        isr.status_reason = UNPARSED_ANSWER_REASON
        return isr

    # Class-level default so an analyst built without ``__init__`` — a test
    # stand-in, a script — still answers the question the parser asks it.
    _answer_unstructured: bool = False
    # The same, for the delegation state the loop reads and writes: a
    # stand-in that never asks anyone and is never asked still runs a loop.
    call_chain: tuple[str, ...] = ()
    loop_budget: LoopBudget | None = None
    # What the definitions of the running loop's tools weigh in a request.
    _tool_definition_chars: int = 0
    # Whether this agent's last loop ended for want of room. A caller that
    # would run the agent again on the same material asks this first: a
    # second loop meets the same full window.
    ended_out_of_room: bool = False
    _budget_ceiling: BudgetCeiling | None = None
    # When the last loop's time ran out, on the monotonic clock; ``None``
    # before any loop.
    _last_loop_deadline: float | None = None
    steps_spent: int = 0
    current_round: int = 0
    # The lock included: ``delegation.ask`` takes it on the callee, and a
    # stand-in that a real agent is allowed to ask must have one to take.
    delegation_lock: Any = _SHARED_STAND_IN_LOCK
    asks_lock: Any = _SHARED_STAND_IN_ASKS_LOCK
    # Read-only, because one dict here would be one dict for every analyst
    # built without ``__init__``, and the node writes a whole new mapping
    # rather than into this one.
    sample_path_choices: Mapping[str, Any] = _NO_PATH_CHOICES

    def _with_answer_status(self, isr: AgentISR) -> AgentISR:
        """Say on the ISR that the loop never produced a report, when it did not.

        Only when there is nothing else to say: an answer that was not a report
        but still yielded claims has already said more than the status would.
        """
        if self._answer_unstructured and not isr.claims:
            isr.status = NO_STRUCTURED_REPORT_STATUS
            isr.status_reason = NO_STRUCTURED_REPORT_REASON
        return isr

    _DOMAIN_KEYWORDS: dict[str, Literal["static", "dynamic", "network"]] = {
        "static": "static",
        "dynamic": "dynamic",
        "network": "network",
    }

    def _infer_domain(self) -> str:
        """Infer the ISR domain from the agent's registered name.

        Falls back to a clearly-marked default and emits a warning rather than
        silently mislabelling unknown agents. The previous behaviour silently
        mapped *any* unrecognised name to "network", so a new agent kind was
        reported under a domain it had nothing to do with.

        Returns ``str`` rather than a three-way Literal:
        a custom analyst's domain is its own definition key, and ``AgentISR``
        has always accepted a free string there.
        """
        name_lower = self.name.lower()
        for keyword, domain in self._DOMAIN_KEYWORDS.items():
            if keyword in name_lower:
                return domain
        self.logger.warning(
            "Could not infer ISR domain from agent name '%s'; defaulting to 'static'. "
            "Override _infer_domain in your agent for a correct value.",
            self.name,
        )
        return "static"

    def _truncate_input(self, text: str) -> str:
        """Truncate input text to stay within the configured token limit."""
        limit = get_settings().max_token_limit
        try:
            enc = tiktoken.get_encoding("cl100k_base")
            tokens = enc.encode(text)
            if len(tokens) > limit:
                self.logger.warning("Input truncated from %d to %d tokens", len(tokens), limit)
                return enc.decode(tokens[:limit])
        except (KeyError, OSError, ValueError) as exc:
            msg = "tiktoken truncation failed (%s); using char-based fallback."
            self.logger.debug(msg, exc)  # nosemgrep
            char_limit = limit * 4
            if len(text) > char_limit:
                self.logger.warning("Input truncated (fallback) to ~%d tokens", limit)
                return text[:char_limit]
        return text
