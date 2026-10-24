"""What one job has spent on its models, in US dollars, against the operator's ceiling.

``llm.max_spend_usd_per_job`` is the ceiling and has no default: a deployment
that sets none has none. It is a hard bound against the platform's own measure
of a prompt (characters over ``CHARS_PER_TOKEN``): nothing is sent that could
take the job past it by that measure.

**What a call costs.** The cost a provider reports in its answer, where it
reports one. Otherwise the usage it reported — the input tokens it read from
its prompt cache, those it wrote to it, the other input tokens, and the output
tokens — at the prices of the model that answered *in force when the request
was sent*, and at the vendor's prices for a prompt of its length where the
vendor prices a long prompt otherwise (a row's ``tiers``: Anthropic prices
Claude Haiku 5.5 higher for a prompt over 100,000 tokens, the prompt counted
whole, cache reads and writes included).
Prices come from the operator's ``llm.model_prices`` first, then from a
``prices`` row of the vendored model table, which carries a vendor's
documented prices as data, with the page they were read from. A row may carry
time windows (UTC, optionally some weekdays only) with their own prices and
source — DeepSeek's peak hours are such windows — and a call is priced at the
window its send time falls in, or at the row's own prices outside every
window.

Nothing is guessed. A call whose model has no price and whose provider
reported no cost adds nothing it could be wrong about: it is named, once in the
log and in the run summary, and the spend the ceiling is compared against is
then what the priced calls cost — a figure the job has spent at least. A call
whose provider reported no usage is the token ledger's ``unreported`` row, and
adds nothing here either.

**Before a call** (:meth:`SpendMeter.admit`). A call is admitted with its
output cap held to what the spend it may use pays for at its model's output
price, after its prompt priced as uncached input (or as written to the prompt
cache, where that costs more), both at the price tier of its prompt's length
and at the highest rate in
force between now and the call's deadline (a call sent across a window's edge
is never settled above what it reserved). It is refused only when that does
not pay for the smallest answer the call can give: for a tool-loop turn the
largest turn this job has measured of the model, for a report call the answer
planned for it (below), for any other call the largest single-shot or
verdict/report answer measured of it, and with nothing measured the call's own
configured output cap. A call whose model takes no cap of its own per call is
admitted only at its whole configured cap. Every admitted call reserves its
worst case — its prompt and its held cap — until it returns and its cost is on
the ledger, so calls running at the same time never spend the same remainder
twice.

**One refusal is not the end of the job.** A call that does not fit only
because other calls in flight hold their worst case waits for them to settle
(they usually settle far below it), for as long as its own deadline allows. A
refused call is recorded and its caller takes its salvage path; the spend is
exhausted only when the ceiling is reached, or when, with no call in flight,
no call of any kind made since the latest stage began
(:meth:`SpendMeter.begin_stage`) — each at the smallest prompt it was sent
with and its own cap — would still be admitted.

**The reserve for the verdict and the report.** A job plans its verdict call
and its report calls (:meth:`SpendMeter.plan_tail`) and keeps aside, for each
of them, what its admission will demand: its prompt as uncached input and the
answer planned for it, at the rates in force. That is never below what the
tail needs to be made, and it is sized from this job's own calls rather than
from the window:

* a planned call's prompt is the largest prompt of its own kind once one was
  sent; before that the largest single-shot prompt this job has sent (a
  revision's prompt carries the same reports), else the largest opening prompt
  of a conversation (a tool loop's first turn), bounded by what the window
  accounting allows that kind of call; the window allowance alone only while no
  prompt was sent at all; a tool loop's conversation is never used;
* the verdict's answer is what its admission demands: the largest single-shot
  answer measured of its model (its configured cap until one is);
* a report call's answer is the mean answer of the report calls measured of
  its model once one returned, and before that the mean answer of its other
  single-shot calls (the verdict left out), else its largest tool-loop turn;
  with no answer measured the reserve is not sized;
* each kind keeps its validation retries (a retry is a call made inside
  :func:`validation_retry`): one per planned call until a call of the kind
  is made, then ``(retries + 1) / (calls + 1)`` of this job's own count for
  the kind, each planned with the answer it corrects in its prompt.

Each row of the derivation also carries its expected charge: the first call of
a kind with its prompt uncached and the ones after it at this job's measured
cache-hit share for the model. Calls that are not the verdict or the report
spend only above the whole reserve; a verdict or report call spends above the
reserve of the other planned calls.

A tool loop's turns reach the token ledger when the loop ends, so a running
loop also reports the turns it has taken so far (:meth:`SpendMeter.note_loop`)
and the meter counts them until the ledger has them. A loop's turn keeps room
for the loop's closing answer: it is admitted only when what is left after it
still pays for the smallest answer.

When the spend is exhausted — nothing more fits, or the ceiling reached —
every running tool loop ends its tool phase the way it does at its step cap:
its agent writes its answer from what it gathered, and only the verdict and
the report run after it, on the reserve kept for them.
"""

from __future__ import annotations

import contextlib
import json
import math
import re
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from maljan.core.context_reset import reset_in_own_context
from maljan.core.logger import logger

MILLION = 1_000_000

# How much larger a prompt is counted when its price tier is chosen before the
# call, over the platform's measure (``CHARS_PER_TOKEN``, three characters a
# token). Anthropic documents its current tokenizer at about 2.5 characters a
# token (the models overview: 1M tokens is roughly 2.5M characters), so a
# prompt measured at three is short of what the API counts; the tier is chosen
# as if each token were two characters, below either, so a call whose prompt
# the API may count past a tier's threshold is admitted at that tier. Only the
# tier is chosen so; the tokens priced are the measure's. A row without tiers
# is admitted exactly as before.
TIER_COUNT_MARGIN = 1.5

# The cap name a loop the ceiling ended records, beside ``steps``, ``time``,
# ``repeats`` and ``no_room``.
SPEND_CAP = "spend"

# The calls that spend the reserve kept for them: the verdict and a report
# section (or the narrative round). Every other call spends above it.
TAIL_KINDS = frozenset({"verdict", "report"})

# The planned calls, in the order a job makes them.
_TAIL_ORDER = ("verdict", "report")

# The calls still made once the spend is exhausted, when they fit what is
# left: the verdict and the report, and the answer a tool loop the ceiling
# ended writes from what it gathered (its salvage, or the nudge for it).
AFTER_EXHAUSTION_KINDS = TAIL_KINDS | {"salvage", "final-answer nudge"}

# The calls that are turns of a tool loop, whose prompts are the loop's whole
# conversation.
LOOP_KINDS = frozenset({"loop turn", "mediation turn"})

# What the token ledger names a tool-loop turn it records.
LOOP_TURN_CALL = "tool loop turn"

# The kinds of call a stage is known to make, by the stage's kind, beyond the
# ones that are made after exhaustion too: counted as planned from the stage's
# start (:meth:`SpendMeter.begin_stage`).
STAGE_CALL_KINDS: dict[str, tuple[str, ...]] = {
    "analysis": ("loop turn",),
    "debate": ("revision", "mediation turn"),
}

# What the token ledger names a verdict or report call, and the planned kind
# each one is.
TAIL_CALLS = {
    "verdict": "verdict",
    "report section": "report",
    "narrative": "report",
    # The report's question round (``reporting.question_round.QUESTION_CALL``).
    "questions": "report",
    # A follow-up question asked of a finished run (``reporting.follow_up.FOLLOW_UP_CALL``).
    "follow-up": "report",
}

# Set on a stated estimate whose prompt is to be priced at the share of the
# model's input this job measured read from the provider's cache.
AT_CACHED_SHARE = "at_cached_share"

# Set on a stated estimate of a call's output alone, handed beside the usage
# its provider did report (a stream broken after its prompt usage arrived):
# the call is priced on both, and only the output's part is an estimate.
OUTPUT_ESTIMATED = "output_estimated"

# What a charge says was estimated (``estimated_part`` on its record).
ESTIMATED_WHOLE = "input and output"
ESTIMATED_OUTPUT = "output"

# What the run summary names a price the provider reported with its answer.
PROVIDER_REPORTED = "provider-reported"

_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_HHMM = re.compile(r"\A([01]\d|2[0-3]):([0-5]\d)\Z")


class SpendCeilingStop(Exception):
    """A model call the operator's spend ceiling does not admit, in the words the run records."""


class AgentCeilingStop(SpendCeilingStop):
    """A model call one agent's own ceiling does not admit (``llm.agents.<key>.max_spend_usd``).

    A :class:`SpendCeilingStop`, so every caller takes the salvage path it takes
    for the job's ceiling; the job's spend is not exhausted by it, and no other
    agent's call is refused.
    """

    def __init__(self, said: str, agent: str) -> None:
        super().__init__(said)
        self.agent = agent


# What the call feed names the record of an agent stopped at its own ceiling
# (``token_ledger.TokenLedger.on_call``): not a call, and no count moves.
AGENT_CEILING_RECORD = "agent ceiling"


# Set while a validation loop sends its correction turn: the call admitted
# then is a retry of the call before it, counted apart from first calls.
_RETRYING: ContextVar[bool] = ContextVar("maljan_spend_retrying", default=False)

# How long a call waiting for other calls' reservations to settle sleeps
# between looks, at most; a settling call wakes it sooner.
_WAIT_SLICE_SECONDS = 1.0


@contextlib.contextmanager
def validation_retry() -> Iterator[None]:
    """Mark the calls made inside the block as a validation loop's retry."""
    token = _RETRYING.set(True)
    try:
        yield
    finally:
        _RETRYING.reset(token)


class Admission:
    """What one admitted call was admitted as, for the fallback attempts made in its place.

    The kind of call, the prompt it was measured over and the slot its worst
    case is reserved under. A model list that moves to its next model asks the
    meter again under the same slot, at that model's own price and output cap
    (``llm.fallback``). Copying one gives the same object: it names a
    reservation of the meter and is never a value of its own.
    """

    __slots__ = ("kind", "meter", "prompt_chars", "slot")

    def __init__(self, meter: SpendMeter, kind: str, prompt_chars: int, slot: Any) -> None:
        self.meter = meter
        self.kind = kind
        self.prompt_chars = prompt_chars
        self.slot = slot

    def __copy__(self) -> Admission:
        return self

    def __deepcopy__(self, memo: Any) -> Admission:
        return self

    def held(self) -> bool:
        """Whether its reservation is still held, so a later call may use its slot."""
        return self.meter.holds(self.slot)


# The admission of the call being made, per task and thread: set by the admission
# itself, carried across the hop to the agent loop with the stream rule
# (``agents.base_agent._submit_to_agent_loop``), and ignored once its slot is
# released, so a call nobody admitted never borrows an earlier one's.
_ADMISSION: ContextVar[Admission | None] = ContextVar("maljan_spend_admission", default=None)


def current_admission() -> Admission | None:
    """The admission of the call this task is making, while its reservation is held."""
    found = _ADMISSION.get()
    return found if found is not None and found.held() else None


@contextlib.contextmanager
def carrying(admission: Admission | None) -> Iterator[None]:
    """Make ``admission`` the one of the calls made inside the block."""
    token = _ADMISSION.set(admission)
    try:
        yield
    finally:
        reset_in_own_context(_ADMISSION, token)


def _meter_of(ledger: Any) -> SpendMeter | None:
    meter = getattr(ledger, "spend", None)
    return meter if isinstance(meter, SpendMeter) else None


def spend_ceiling_set(ledger: Any) -> bool:
    """Whether the job ``ledger`` records has a spend ceiling. Never raises."""
    meter = _meter_of(ledger)
    return meter is not None and meter.ceiling_usd is not None


def usd_said(amount: float) -> str:
    """A US-dollar amount as written to a reader: to six places, trailing zeros dropped."""
    text = f"{float(amount):.6f}".rstrip("0").rstrip(".")
    return text or "0"


def agent_ceiling_set(ledger: Any, agent: str) -> bool:
    """Whether ``agent`` (its ``llm.agents`` key) sets a ceiling of its own. Never raises."""
    meter = _meter_of(ledger)
    return meter is not None and meter.agent_ceiling(agent) is not None


def call_deadline_of(llm: Any, messages: Any = None) -> float | None:
    """How long one request of ``llm`` may run: its sized whole-call deadline, or ``None``.

    The request timeout the model's client sends it with — its output cap at
    the model's measured pace where one is measured, the client's own timeout
    otherwise (``generation_rate.call_deadline``). The horizon a call is
    priced over at admission.
    """
    try:
        from maljan.llm.generation_rate import call_deadline

        return float(call_deadline(llm, messages or [], {}))
    except Exception:  # noqa: BLE001 — a deadline that cannot be sized is the default one
        return None


def _holdable(llm: Any) -> bool:
    from maljan.llm.context_window import accepts_output_bound

    try:
        return bool(accepts_output_bound(llm))
    except Exception:  # noqa: BLE001 — a model that cannot say takes no cap
        return False


def spend_bound(
    ledger: Any, llm: Any, prompt_chars: int, cap_tokens: int, slot: Any = None
) -> int | None:
    """A report call's output cap under the spend ceiling, or ``None`` for its own.

    Raises :class:`SpendCeilingStop` when the call is not to be made. With
    ``slot`` the call's worst case is reserved under it until
    :func:`spend_release` is called with the same slot. A model that takes no
    per-call cap is admitted only at its whole cap.
    """
    meter = _meter_of(ledger)
    if meter is None:
        return None
    from maljan.llm.generation_rate import model_name_of

    return meter.admit(
        kind="report",
        model=model_name_of(llm),
        prompt_chars=int(prompt_chars),
        cap_tokens=int(cap_tokens),
        slot=slot,
        holdable=_holdable(llm),
        deadline_s=call_deadline_of(llm),
    )


def spend_preview(ledger: Any, llm: Any, prompt_chars: int, cap_tokens: int) -> int | None:
    """What :func:`spend_bound` would answer now, with nothing reserved, logged or latched.

    ``0`` for a call that would not be made.
    """
    meter = _meter_of(ledger)
    if meter is None:
        return None
    from maljan.llm.generation_rate import model_name_of

    try:
        return meter.preview(
            kind="report",
            model=model_name_of(llm),
            prompt_chars=int(prompt_chars),
            cap_tokens=int(cap_tokens),
            holdable=_holdable(llm),
            deadline_s=call_deadline_of(llm),
        )
    except Exception:  # noqa: BLE001 — a preview is a question, never a failure
        return None


def spend_release(ledger: Any, slot: Any) -> None:
    """The call reserved under ``slot`` has returned (or was never sent). Never raises."""
    meter = _meter_of(ledger)
    if meter is not None and slot is not None:
        meter.release(slot)


def spend_left_said(ledger: Any) -> str:
    """The words for what is left: the X USD left under the spend ceiling of Y USD."""
    meter = _meter_of(ledger)
    if meter is None or meter.ceiling_usd is None:
        return ""
    return (
        f"the {meter.remaining() or 0.0:.4f} USD left under the spend ceiling of "
        f"{meter.ceiling_usd:.4f} USD"
    )


@contextlib.contextmanager
def admitted(
    ledger: Any,
    *,
    kind: str,
    llm: Any,
    model: str,
    prompt_chars: int,
    cap_tokens: int,
    holdable: bool | None = None,
) -> Iterator[int | None]:
    """One call admitted by the job's spend meter, its reservation released when the block ends.

    Yields ``None`` (as it is) or the held cap; raises
    :class:`SpendCeilingStop` when the call is not to be made. With no meter
    it yields ``None``. Record the call's usage inside the block, so its cost
    is on the ledger before its reservation goes.
    """
    meter = _meter_of(ledger)
    if meter is None:
        yield None
        return
    slot = object()
    try:
        yield meter.admit(
            kind=kind,
            model=model,
            prompt_chars=int(prompt_chars),
            cap_tokens=int(cap_tokens),
            slot=slot,
            holdable=_holdable(llm) if holdable is None else bool(holdable),
            deadline_s=call_deadline_of(llm),
        )
    finally:
        meter.release(slot)


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        return None
    return float(value)


def _minutes(value: Any) -> int | None:
    found = _HHMM.match(str(value or "").strip())
    if found is None:
        return None
    return int(found.group(1)) * 60 + int(found.group(2))


class PriceWindow:
    """A span of the day, UTC, on some weekdays, when a model is priced otherwise."""

    __slots__ = ("days", "end", "price", "start")

    def __init__(self, start: int, end: int, days: frozenset[int], price: Price) -> None:
        self.start = start
        self.end = end
        self.days = days
        self.price = price

    def _on(self, weekday: int) -> bool:
        return not self.days or weekday in self.days

    def covers(self, when: datetime) -> bool:
        """Whether ``when`` (UTC) falls inside this window; the start is in it, the end is not."""
        minute = when.hour * 60 + when.minute
        weekday = when.weekday()
        if self.start < self.end:
            return self._on(weekday) and self.start <= minute < self.end
        # Across midnight: the days name the day the window opens on.
        if minute >= self.start:
            return self._on(weekday)
        return minute < self.end and self._on((weekday - 1) % 7)

    def edges(self, start: datetime, until: datetime) -> list[datetime]:
        """Every instant in ``(start, until]`` where this window opens or closes."""
        found: list[datetime] = []
        day = datetime(start.year, start.month, start.day, tzinfo=UTC)
        while day <= until:
            for minute in (self.start, self.end):
                edge = day + timedelta(minutes=minute)
                if start < edge <= until:
                    found.append(edge)
            day += timedelta(days=1)
        return found


class Price:
    """One model's prices per million tokens, where they were read, its windows and its tiers."""

    __slots__ = (
        "cache_write",
        "cache_write_1h",
        "cached_input",
        "input",
        "output",
        "source",
        "tiers",
        "windows",
    )

    def __init__(
        self,
        input: float,
        output: float,
        cached_input: float | None = None,
        source: str = "",
        windows: tuple[PriceWindow, ...] = (),
        *,
        cache_write: float | None = None,
        cache_write_1h: float | None = None,
        tiers: tuple[tuple[int, Price], ...] = (),
    ) -> None:
        self.input = float(input)
        self.output = float(output)
        self.cached_input = None if cached_input is None else float(cached_input)
        self.source = str(source or "")
        self.windows = tuple(windows)
        self.cache_write = None if cache_write is None else float(cache_write)
        self.cache_write_1h = None if cache_write_1h is None else float(cache_write_1h)
        # ``(over this many prompt tokens, the prices then)``, smallest first.
        self.tiers = tuple(sorted(tiers, key=lambda tier: tier[0]))

    def for_prompt(self, prompt_tokens: int) -> Price:
        """The prices of a request whose prompt is ``prompt_tokens``: its tier's, else these."""
        found: Price = self
        for over, price in self.tiers:
            if int(prompt_tokens) > over:
                found = price
        return found

    def for_admission(self, prompt_tokens: int, hour_writes: bool = False) -> Price:
        """The prices a call is admitted at: its prompt's tier, every prompt token at its dearest.

        A prompt token is uncached input, or written to the prompt cache where
        a write costs more; which one it will be is not known before the call.
        An hour's write is counted only where the deployment asks for one
        (``hour_writes``): no request writes for an hour otherwise. The tier is
        chosen from the prompt counted with :data:`TIER_COUNT_MARGIN`.
        """
        tier = self.for_prompt(
            math.ceil(int(prompt_tokens) * TIER_COUNT_MARGIN) if self.tiers else prompt_tokens
        )
        dearest = max(tier.input, tier.written, tier.written_1h if hour_writes else 0.0)
        if dearest == tier.input and tier is self:
            return self
        return Price(dearest, tier.output, tier.cached_input, tier.source, tier.windows)

    def at(self, when: datetime) -> Price:
        """The prices in force at ``when`` (UTC): the first window covering it, else these."""
        for window in self.windows:
            if window.covers(when):
                return window.price
        return self

    def highest_over(self, start: datetime, seconds: float) -> Price:
        """The highest prices in force at any instant from ``start`` for ``seconds``."""
        until = start + timedelta(seconds=max(0.0, float(seconds)))
        found: list[Price] = [self.at(start)]
        for window in self.windows:
            for edge in window.edges(start, until):
                found.append(self.at(edge))
        distinct = list({id(price): price for price in found}.values())
        if len(distinct) == 1:
            return distinct[0]
        return Price._dearest_of(distinct)

    @staticmethod
    def _dearest_of(rows: list[Price]) -> Price:
        """One price holding, for each component, the highest of ``rows``' figures.

        A window dearer only on input must not hide behind one dearer on
        output: the worst case of a call is each component at its own worst.
        Tiers are merged the same way at every threshold any row names.
        """
        thresholds = sorted({over for row in rows for over, _ in row.tiers})
        tiers = (
            tuple(
                (over, Price._dearest_of([row.for_prompt(over + 1) for row in rows]))
                for over in thresholds
            )
            if thresholds
            else ()
        )
        base = [row.for_prompt(0) if tiers else row for row in rows]
        return Price(
            max(row.input for row in base),
            max(row.output for row in base),
            max(row.cached for row in base),
            rows[0].source,
            (),
            cache_write=max(row.written for row in base),
            cache_write_1h=max(row.written_1h for row in base),
            tiers=tiers,
        )

    @property
    def cached(self) -> float:
        """The price of a cached input token (an input token's where none is given)."""
        return self.input if self.cached_input is None else self.cached_input

    @property
    def written(self) -> float:
        """The price of an input token written to the prompt cache (an input token's by default)."""
        return self.input if self.cache_write is None else self.cache_write

    @property
    def written_1h(self) -> float:
        """The price of an input token written to the prompt cache for an hour."""
        return self.written if self.cache_write_1h is None else self.cache_write_1h

    def cost(self, usage: Mapping[str, Any]) -> float:
        """What one call's reported usage costs at these prices, at its prompt's tier."""
        total_in = int(usage.get("input_tokens") or 0)
        price = self.for_prompt(total_in)
        cached = min(total_in, int(usage.get("cached_input_tokens") or 0))
        written = min(total_in - cached, int(usage.get("cache_write_input_tokens") or 0))
        written_1h = min(written, int(usage.get("cache_write_1h_input_tokens") or 0))
        out = int(usage.get("output_tokens") or 0)
        if not written:
            return (
                (total_in - cached) * price.input + cached * price.cached + out * price.output
            ) / MILLION
        return (
            (total_in - cached - written) * price.input
            + cached * price.cached
            + (written - written_1h) * price.written
            + written_1h * price.written_1h
            + out * price.output
        ) / MILLION


def _window_from(row: Any, parent_source: str) -> PriceWindow | None:
    read = row.model_dump() if hasattr(row, "model_dump") else row
    if not isinstance(read, Mapping):
        return None
    start, end = _minutes(read.get("utc_from")), _minutes(read.get("utc_to"))
    if start is None or end is None or start == end:
        return None
    days: set[int] = set()
    for day in read.get("days") or []:
        name = str(day).strip().lower()[:3]
        if name not in _DAYS:
            return None
        days.add(_DAYS.index(name))
    price = _price_from(
        {k: v for k, v in read.items() if k != "windows"},
        f"{parent_source} ({read.get('utc_from')}-{read.get('utc_to')} UTC)",
    )
    if price is None:
        return None
    return PriceWindow(start, end, frozenset(days), price)


def _price_from(row: Any, source: str = "") -> Price | None:
    """A ``Price`` from a settings row or a table row, or ``None`` when it is not one."""
    read = row.model_dump() if hasattr(row, "model_dump") else row
    if not isinstance(read, Mapping):
        return None
    given_in = _number(read.get("input_usd_per_mtok"))
    given_out = _number(read.get("output_usd_per_mtok"))
    if given_in is None or given_out is None:
        return None
    said = str(read.get("source") or source)
    windows: list[PriceWindow] = []
    for window in read.get("windows") or []:
        found = _window_from(window, said)
        if found is None:
            logger.debug("a price window that is not one was left out: %r", window)
            continue
        windows.append(found)
    tiers: list[tuple[int, Price]] = []
    for tier in read.get("tiers") or []:
        found_tier = _tier_from(tier, said)
        if found_tier is None:
            logger.debug("a price tier that is not one was left out: %r", tier)
            continue
        tiers.append(found_tier)
    # A window that names no tiers of its own keeps the row's: a long prompt
    # sent inside a window is still priced at the long prompt's tier.
    for window in windows:
        if tiers and not window.price.tiers:
            window.price.tiers = tuple(sorted(tiers, key=lambda tier: tier[0]))
    return Price(
        given_in,
        given_out,
        _number(read.get("cached_input_usd_per_mtok")),
        said,
        tuple(windows),
        cache_write=_number(read.get("cache_write_input_usd_per_mtok")),
        cache_write_1h=_number(read.get("cache_write_1h_input_usd_per_mtok")),
        tiers=tuple(tiers),
    )


def _tier_from(row: Any, parent_source: str) -> tuple[int, Price] | None:
    """``(over this many prompt tokens, the prices then)`` from a tier row, or ``None``."""
    read = row.model_dump() if hasattr(row, "model_dump") else row
    if not isinstance(read, Mapping):
        return None
    over = read.get("over_prompt_tokens")
    if isinstance(over, bool) or not isinstance(over, int) or over <= 0:
        return None
    price = _price_from(
        {k: v for k, v in read.items() if k not in ("windows", "tiers")},
        f"{parent_source} (prompts over {over:,} tokens)",
    )
    if price is None:
        return None
    return over, price


_table: dict[str, Price] | None = None
# Why the last read of the vendored table failed, or ``None``; read by the
# unpriced statement so a model it could not price is not blamed alone.
table_failure: str | None = None
_table_lock = threading.Lock()
# The table file's stat (existence, mtime, size) at the last failed read; an
# unchanged stat is not read again. ``None``: no failure is held.
_failed_stat: tuple[bool, int, int] | None = None


def _stat_of(path: Path) -> tuple[bool, int, int]:
    try:
        info = path.stat()
    except OSError:
        return (False, 0, 0)
    return (True, info.st_mtime_ns, info.st_size)


def table_prices() -> dict[str, Price]:
    """The vendored model table's ``prices`` rows, read once; keyed by lower-cased model name.

    A failed read is not kept as the table: it is read again once the file's
    stat differs from the one recorded at the failure, and warned about only
    when its text changes.
    """
    global _table, table_failure, _failed_stat
    from maljan.core.paths import resolve_data
    from maljan.llm.context_window import TABLE_PATH

    with _table_lock:
        if _table is not None:
            return _table
        rows: dict[str, Price] = {}
        path: Path | None = None
        try:
            path = Path(resolve_data(TABLE_PATH))
            if _failed_stat is not None and _stat_of(path) == _failed_stat:
                return rows
            raw = json.loads(path.read_text(encoding="utf-8"))
            for key, row in (raw.get("prices") or {}).items():
                if str(key).startswith("_"):
                    continue
                price = _price_from(row)
                if price is not None and price.source:
                    rows[str(key).lower()] = price
        except Exception as exc:  # noqa: BLE001 — a fallback table never fails a run
            said = f"{type(exc).__name__}: {exc}"
            _failed_stat = _stat_of(path) if path is not None else None
            if said != table_failure:
                logger.warning(
                    "the vendored price table could not be read (%s); models are priced from "
                    "the operator's llm.model_prices only until it can be",
                    exc,
                )
            table_failure = said
            return {}
        _table = rows
        table_failure = None
        _failed_stat = None
        return _table


def _uncapped_output(name: str) -> tuple[int, str]:
    """``(tokens, where from)``: the most a call sent with no output cap may answer.

    :func:`_uncapped_is_declared` says which of the two it is.

    The model's declared maximum output where its provider or the vendored
    table states one, else the documented fallback reply the derived caps use
    for a hosted API that declares none (``context_window.DEFAULT_REPLY_TOKENS``).
    Only a priced call is asked about, and a priced model is a hosted one.
    """
    from maljan.llm.context_window import DEFAULT_REPLY_TOKENS
    from maljan.llm.model_output_limits import declared_output

    tokens, where = declared_output(name)
    if tokens > 0:
        return tokens, f"the model's declared maximum output, from {where}"
    return DEFAULT_REPLY_TOKENS, (
        f"the documented fallback reply of {DEFAULT_REPLY_TOKENS:,} tokens, the model "
        "declaring no maximum output"
    )


def _uncapped_is_declared(name: str) -> bool:
    """Whether :func:`_uncapped_output` for ``name`` is the model's own declared maximum."""
    from maljan.llm.model_output_limits import declared_output

    return declared_output(name)[0] > 0


def _clean(model: str) -> str:
    """A model name as the tables key it: lower-cased, without its endpoint or vendor path.

    A model list labels a model ``openai/deepseek-flash @ https://api.deepseek.com``;
    the price is the model's, whichever endpoint served it. The tag after a
    colon is kept: ``qwen3:8b`` and ``qwen3:32b`` are two models.
    """
    name = str(model or "").strip().lower().split(" @ ", 1)[0].strip()
    return name.rsplit("/", 1)[-1]


def price_key(model: str) -> str:
    """The name the spend block keys a model by (``prices_from``, ``unpriced_models``)."""
    return _clean(model) or "(unnamed model)"


def _untagged(name: str) -> str:
    return name.split(":", 1)[0]


def _sent_at(usage: Mapping[str, Any] | None, fallback: datetime) -> datetime:
    """When the call was sent, as the answer was stamped (``sent_at``), else ``fallback``."""
    stamp = _number((usage or {}).get("sent_at"))
    if stamp is None:
        return fallback
    try:
        return datetime.fromtimestamp(stamp, UTC)
    except (OverflowError, OSError, ValueError):
        return fallback


def _default_deadline() -> float:
    """How long a request with no deadline of its caller's may run: its client's own timeout."""
    from maljan.llm.generation_rate import UNMEASURED_REQUEST_TIMEOUT_SECONDS

    return float(UNMEASURED_REQUEST_TIMEOUT_SECONDS)


class _Decision:
    """What :meth:`SpendMeter.admit` decides about one call, before anything is recorded."""

    __slots__ = (
        "available",
        "bound",
        "cap",
        "fallback_cap",
        "input_cost",
        "minimum",
        "minimum_said",
        "name",
        "refused",
        "reservation",
        "reserve",
        "room",
    )

    def __init__(self, name: str) -> None:
        self.name = name
        self.bound: int | None = None
        self.refused = ""
        self.reservation = 0.0
        self.available = 0.0
        self.reserve = 0.0
        self.input_cost = 0.0
        self.room = 0
        self.minimum = 0
        self.minimum_said = ""
        self.cap = 0
        # Set when a call sent with no cap of its own is given one only because
        # the most it may answer is the fallback figure, not a model's limit.
        self.fallback_cap = 0


class SpendMeter:
    """One job's spend against the operator's ceiling. Thread-safe; never raises but to refuse."""

    def __init__(
        self,
        ceiling_usd: float | None = None,
        prices: Mapping[str, Any] | None = None,
        *,
        table: Mapping[str, Price] | None = None,
        clock: Callable[[], datetime] | None = None,
        hour_writes: bool | Iterable[str] = False,
    ) -> None:
        self.ceiling_usd = None if ceiling_usd is None else float(ceiling_usd)
        # Which models' requests may write the prompt cache for an hour, which
        # admission prices and a write reported without its lifetime is
        # settled as: ``True`` every model, ``False`` none, or the names of the
        # models whose provider says so (``LLMProvider.writes_hour_caches``).
        if isinstance(hour_writes, bool):
            self._hour_models: frozenset[str] | None = None
            self.hour_writes = hour_writes
        else:
            self._hour_models = frozenset(_clean(name) for name in hour_writes if name)
            self.hour_writes = bool(self._hour_models)
        self._lock = threading.Lock()
        # Woken whenever a reservation goes, for a call waiting on one.
        self._drained = threading.Condition(self._lock)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._operator: dict[str, Price] = {}
        for key, row in (prices or {}).items():
            price = _price_from(row, "llm.model_prices")
            if price is not None:
                if not price.source:
                    price.source = "llm.model_prices"
                self._operator[_clean(key)] = price
        self._table = dict(table) if table is not None else None
        self._settled = 0.0
        # A running loop's turns so far, and the worst case of each call in flight.
        self._in_flight: dict[Any, float] = {}
        self._reserved: dict[Any, float] = {}
        # Every slot an admitted call holds now, priced or not: a model with
        # no price reserves nothing, and its call is still in flight.
        self._active: set[Any] = set()
        self._unpriced: dict[str, int] = {}
        self._priced_from: dict[str, set[str]] = {}
        self._reached_at: float | None = None
        self._said_unpriced = False
        self._unreported = 0
        # Calls whose provider reported no usage and that carried a stated
        # estimate instead (an answer ended while it streamed), and what the
        # estimates cost.
        self._estimated_calls = 0
        self._estimated_usd = 0.0
        self._estimated_source = ""
        # What this job has measured. The largest answer (output tokens,
        # reasoning included) of each model, per group: ``loop`` for tool-loop
        # turns, ``single`` for every other call. The largest prompt (tokens)
        # of each kind of call as the window accounting measured it before it
        # was sent: ``tail:verdict``, ``tail:report``, ``single``, ``loop``.
        # The input and cached input tokens of each model's calls, for its
        # cache-hit share: settled, and each running loop's so far.
        self._largest_output: dict[str, dict[str, int]] = {"loop": {}, "single": {}}
        # The answers of each model, summed and counted, for their mean: per
        # group, ``single`` for every call that is not a tool-loop turn and
        # ``tail:verdict`` / ``tail:report`` for the planned calls themselves.
        self._answers: dict[str, dict[str, list[int]]] = {}
        self._largest_prompt: dict[str, int] = {}
        # The smallest tool-loop turn the ledger recorded: a loop's first turn
        # where no running loop has said which turn was its first.
        self._smallest_loop_prompt = 0
        self._inputs: dict[str, list[int]] = {}
        self._loop_inputs: dict[Any, dict[str, list[int]]] = {}
        # The verdict and report calls still to come:
        # kind -> [model, calls, prompt tokens the window accounting allows].
        self._tail: dict[str, list[Any]] = {}
        # What the ceiling did to calls before they were made, one sentence each.
        self._held: list[str] = []
        # When and why the spend was first exhausted, or ``None``.
        self._exhausted: dict[str, Any] | None = None
        # Every kind of call admitted or refused so far, with the smallest
        # prompt (tokens) it was sent with, its cap, whether it can be held
        # and its deadline: what "would another call still fit" is asked of.
        self._kinds: dict[str, dict[str, Any]] = {}
        # A count of the kinds noted so far, so the kind made last is known:
        # each row carries the count at its latest call (``used``).
        self._uses = 0
        # How many calls the ceiling refused.
        self._refused = 0
        # A refusal made while other calls held reservations: whether anything
        # still fits is asked again once none is outstanding.
        self._pending_check: str | None = None
        # The stage count so far; a kind of call counts as still planned only
        # when it was made in the current stage.
        self._generation = 0
        # First calls and validation retries admitted, per kind of call.
        self._calls_made: dict[str, list[int]] = {}
        # Set when the job is cancelled (:meth:`close`): no call waits any more.
        self._closed = False
        # Each agent's own ceilings, by its ``llm.agents`` key: (USD, tokens of
        # unpriced calls), either ``None``. Only the agents that set one.
        self._agent_ceilings: dict[str, tuple[float | None, int | None]] = {}
        # What each of those agents' calls cost and used so far: [priced USD,
        # tokens of calls with no price, calls counted at a stated estimate],
        # and the sentence of each one stopped.
        self._agent_spent: dict[str, list[float]] = {}
        self._agent_stops: dict[str, str] = {}

    @classmethod
    def from_settings(cls, cfg: Any) -> SpendMeter:
        llm = getattr(cfg, "llm", None)
        meter = cls(
            getattr(llm, "max_spend_usd_per_job", None),
            getattr(llm, "model_prices", None) or {},
            hour_writes=hour_cache_models(cfg),
        )
        for key, entry in (getattr(llm, "agents", None) or {}).items():
            meter.set_agent_ceiling(
                str(key),
                getattr(entry, "max_spend_usd", None),
                getattr(entry, "max_unpriced_tokens", None),
            )
        return meter

    # ── One agent's own ceiling ───────────────────────────────────────────

    def set_agent_ceiling(
        self, agent: str, usd: float | None = None, unpriced_tokens: int | None = None
    ) -> None:
        """Give ``agent`` (its ``llm.agents`` key) a ceiling of its own; both ``None`` is none."""
        key = str(agent).lower()
        with self._lock:
            if usd is None and unpriced_tokens is None:
                self._agent_ceilings.pop(key, None)
                return
            self._agent_ceilings[key] = (
                None if usd is None else float(usd),
                None if unpriced_tokens is None else int(unpriced_tokens),
            )

    def agent_ceiling(self, agent: str) -> tuple[float | None, int | None] | None:
        """``agent``'s own ceilings (USD, unpriced tokens), or ``None`` when it sets none."""
        with self._lock:
            return self._agent_ceilings.get(str(agent).lower())

    def note_agent_call(
        self,
        agent: str,
        usage: Mapping[str, Any] | None,
        model: str,
        *,
        estimated: Mapping[str, Any] | None = None,
    ) -> None:
        """One call of ``agent`` its provider billed, toward its own ceiling. Never raises.

        Priced the way :meth:`settle` prices a call (the provider's reported
        cost, else the model's rates in force when it was sent); a call whose
        model has no price counts its input and output tokens instead.
        ``estimated`` is the stated estimate a call that reported no usage
        carried (an answer ended while it streamed, a failed attempt the
        provider bills): its tokens are counted, the prompt as uncached input,
        and the call is counted as one that reported no usage. With neither,
        nothing is counted, as nothing is toward the job's ceiling.
        """
        key = str(agent).lower()
        if self.agent_ceiling(key) is None:
            return
        try:
            figures: dict[str, Any] | None = dict(usage) if usage is not None else None
            by_estimate = False
            if estimated:
                guessed = {
                    "input_tokens": int(estimated.get("input_tokens") or 0),
                    "output_tokens": int(estimated.get("output_tokens") or 0),
                }
                if figures is None:
                    figures, by_estimate = guessed, True
                elif estimated.get(OUTPUT_ESTIMATED):
                    figures["output_tokens"] = guessed["output_tokens"]
                    by_estimate = True
            if figures is None:
                return
            charged = self._charged(figures, model)
            tokens = int(figures.get("input_tokens") or 0) + int(figures.get("output_tokens") or 0)
            with self._lock:
                spent = self._agent_spent.setdefault(key, [0.0, 0.0, 0.0])
                if charged is None:
                    spent[1] += tokens
                else:
                    spent[0] += charged[0]
                if by_estimate:
                    spent[2] += 1
        except Exception as exc:  # noqa: BLE001 — telemetry never costs a run
            logger.debug("agent spend not noted (%s).", exc)

    def agent_refusal(self, agent: str) -> tuple[str, bool]:
        """Why ``agent`` makes no further model call, and whether this is the first time said.

        ``("", False)`` while it is under its own ceilings. Once its priced
        calls have cost its ``max_spend_usd`` or its unpriced calls used its
        ``max_unpriced_tokens``, every further call of it is refused, the job's
        spend and every other agent untouched. Checked before each call, so the
        call that crosses a ceiling is the agent's last and its answer is kept.
        """
        key = str(agent).lower()
        with self._lock:
            limits = self._agent_ceilings.get(key)
            if limits is None:
                return "", False
            said = self._agent_stops.get(key)
            if said is not None:
                return said, False
            usd, tokens = limits
            spent_usd, spent_tokens, guessed = self._agent_spent.get(key, [0.0, 0.0, 0.0])
            if usd is not None and spent_usd >= usd:
                said = (
                    f"agent {key} reached its spend ceiling of {usd_said(usd)} USD "
                    f"(llm.agents.{key}.max_spend_usd) at {usd_said(spent_usd)} USD spent"
                )
            elif tokens is not None and spent_tokens >= tokens:
                said = (
                    f"agent {key} reached its unpriced-token ceiling of {tokens:,} tokens "
                    f"(llm.agents.{key}.max_unpriced_tokens) at {int(spent_tokens):,} tokens "
                    "used by calls of a model with no price"
                )
            else:
                return "", False
            if guessed:
                said += (
                    f"; {int(guessed)} call(s) reported no usage and are counted at a stated "
                    "estimate"
                )
            self._agent_stops[key] = said
        logger.warning("%s; it makes no further model call.", said)
        return said, True

    def agents_stopped(self) -> frozenset[str]:
        """The ``llm.agents`` keys of the agents stopped at their own ceiling."""
        with self._lock:
            return frozenset(self._agent_stops)

    def agent_reasons(self) -> list[str]:
        """One degradation reason per agent stopped at its own ceiling, in key order."""
        with self._lock:
            stops = dict(self._agent_stops)
        return [
            f"The {stops[key]}: it made no further model call, what it had produced was kept, "
            "and no other agent was affected."
            for key in sorted(stops)
        ]

    def _agent_block_locked(self) -> dict[str, Any]:
        """The ``agent_ceilings`` block: each agent's ceilings, what it used, whether it stopped."""
        out: dict[str, Any] = {}
        for key in sorted(self._agent_ceilings):
            usd, tokens = self._agent_ceilings[key]
            spent_usd, spent_tokens, guessed = self._agent_spent.get(key, [0.0, 0.0, 0.0])
            row: dict[str, Any] = {"spent_usd": round(spent_usd, 6)}
            if usd is not None:
                row["max_spend_usd"] = usd
            if tokens is not None:
                row["max_unpriced_tokens"] = tokens
            row["unpriced_tokens"] = int(spent_tokens)
            if guessed:
                row["estimated_calls"] = int(guessed)
            row["stopped"] = key in self._agent_stops
            if key in self._agent_stops:
                row["stopped_because"] = self._agent_stops[key]
            out[key] = row
        return out

    def writes_hour_caches(self, model: str) -> bool:
        """Whether ``model``'s requests may write the prompt cache for an hour."""
        if self._hour_models is None:
            return self.hour_writes
        name = _clean(model)
        return name in self._hour_models or _untagged(name) in self._hour_models

    # ── Prices ────────────────────────────────────────────────────────────

    def price_of(self, model: str) -> Price | None:
        """The price row of ``model``: the operator's, else the vendored table's, else ``None``."""
        name = _clean(model)
        if not name:
            return None
        table = self._table if self._table is not None else table_prices()
        # The tagged name first, in the operator's prices and then the table's;
        # the base name only where no row names the tag.
        for key in dict.fromkeys((name, _untagged(name))):
            found = self._operator.get(key) or table.get(key)
            if found is not None:
                return found
        return None

    def price_now(self, model: str) -> Price | None:
        """The prices of ``model`` in force now."""
        price = self.price_of(model)
        return None if price is None else price.at(self._clock())

    def _charged(self, usage: Mapping[str, Any], model: str) -> tuple[float, str] | None:
        """What one call cost and where the figure came from, or ``None`` unpriced."""
        reported = _number(usage.get("cost"))
        if reported is not None:
            return reported, PROVIDER_REPORTED
        price = self.price_of(model)
        if price is None:
            return None
        in_force = price.at(_sent_at(usage, self._clock()))
        if (
            self.writes_hour_caches(model)
            and usage.get("cache_write_input_tokens")
            and "cache_write_1h_input_tokens" not in usage
        ):
            # A streamed Anthropic answer reports its cache writes without the
            # split by lifetime (``message_delta``'s usage carries none); where
            # every write is an hour's, it is settled as one.
            usage = {**usage, "cache_write_1h_input_tokens": usage["cache_write_input_tokens"]}
        # The source is the tier's the call was priced at: a long prompt is
        # not said to be priced at the short prompt's figures.
        tier = in_force.for_prompt(int(usage.get("input_tokens") or 0))
        return in_force.cost(usage), tier.source

    def _cost(self, usage: Mapping[str, Any] | None, model: str) -> tuple[float, str] | None:
        if usage is None:
            self._note_unreported()
            return None
        name = price_key(model)
        charged = self._charged(usage, model)
        if charged is None:
            self._note_unpriced(name)
            return None
        cost, source = charged
        with self._lock:
            self._priced_from.setdefault(name, set()).add(source)
        return cost, source

    def _measure_locked(self, usage: Mapping[str, Any], name: str, group: str) -> None:
        out = int(usage.get("output_tokens") or 0)
        largest = self._largest_output[group]
        if out > largest.get(name, 0):
            largest[name] = out

    def _count_answer_locked(self, usage: Mapping[str, Any], name: str, group: str) -> None:
        out = int(usage.get("output_tokens") or 0)
        if out <= 0:
            return
        sums = self._answers.setdefault(group, {}).setdefault(name, [0, 0])
        sums[0] += out
        sums[1] += 1

    def _mean_answer_locked(self, name: str, group: str) -> tuple[int, int]:
        """``(mean output tokens, calls)`` of ``name``'s answers in ``group``, or ``(0, 0)``."""
        total, calls = self._answers.get(group, {}).get(name, [0, 0])
        if calls <= 0:
            return 0, 0
        return -(-total // calls), calls

    def _note_unreported(self) -> None:
        """One call whose provider reported no usage: counted, and said once with a ceiling."""
        with self._lock:
            self._unreported += 1
            first = self._unreported == 1 and self.ceiling_usd is not None
        if first:
            logger.warning(
                "spend ceiling: a call reported no usage, so it cannot be priced; the spend "
                "compared with the ceiling leaves it out. A model that never reports usage "
                "(a local or mock one) cannot trip the ceiling."
            )

    def _note_unpriced(self, name: str) -> None:
        with self._lock:
            self._unpriced[name] = self._unpriced.get(name, 0) + 1
            first = not self._said_unpriced and self.ceiling_usd is not None
            if first:
                self._said_unpriced = True
        if first:
            logger.warning(
                "spend ceiling: model %r has no price (llm.model_prices or the vendored "
                "table%s), so its calls are not counted; the ceiling is compared with what "
                "the priced calls cost, which the job has spent at least.",
                name,
                f"; the table could not be read: {table_failure}" if table_failure else "",
            )

    # ── What was spent ────────────────────────────────────────────────────

    def settle(
        self,
        usage: Mapping[str, Any] | None,
        model: str,
        call: str = "",
        *,
        estimated: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """One recorded call, from the token ledger; ``call`` is what the ledger names it.

        ``estimated`` is the stated estimate a call that reported no usage
        carried (its prompt priced as uncached input and its generated pieces
        as output). It is charged against the ceiling and counted apart as
        estimated; the call's reported figures stay absent.

        An ``estimated`` carrying :data:`OUTPUT_ESTIMATED` beside ``usage`` is
        an estimate of the output alone: the call is priced on the reported
        usage with that output, and the output's share of the cost is counted
        as estimated.

        Returns what the call was charged, as its record keeps it
        (``priced_usd``, ``price_source``, and for a charge by estimate
        ``estimated_usd`` and ``estimated_part``), or ``None`` where nothing
        was charged: no usage and no estimate, a model with no price, or a
        failure here.
        """
        if usage is None and estimated:
            return self._settle_estimate(estimated, model)
        if usage is not None and estimated and estimated.get(OUTPUT_ESTIMATED):
            return self._settle_output_estimate(usage, estimated, model)
        try:
            name = _clean(model)
            if usage and name:
                with self._lock:
                    group = "loop" if call == LOOP_TURN_CALL else "single"
                    self._measure_locked(usage, name, group)
                    if group == "loop":
                        sent = int(usage.get("input_tokens") or 0)
                        least = self._smallest_loop_prompt
                        if sent > 0 and (least == 0 or sent < least):
                            self._smallest_loop_prompt = sent
                    if group == "single":
                        # The planned calls' own answers are counted apart, so
                        # the verdict's answer does not move the plan of the
                        # report calls after it.
                        tail = TAIL_CALLS.get(call)
                        if tail:
                            self._count_answer_locked(usage, name, f"tail:{tail}")
                        else:
                            self._count_answer_locked(usage, name, "single")
            charged = self._cost(usage, model)
            if charged is None:
                return None
            cost, source = charged
            with self._lock:
                self._settled += cost
            return {"priced_usd": cost, "price_source": source}
        except Exception as exc:  # noqa: BLE001 — telemetry never costs a run
            logger.debug("spend not settled (%s).", exc)
            return None

    def _settle_estimate(self, estimated: Mapping[str, Any], model: str) -> dict[str, Any] | None:
        try:
            name = price_key(model)
            figures = {
                "input_tokens": int(estimated.get("input_tokens") or 0),
                "output_tokens": int(estimated.get("output_tokens") or 0),
            }
            said = str(estimated.get("source") or "")
            if estimated.get(AT_CACHED_SHARE):
                # The prompt priced at the share of this model's input the job
                # measured read from the provider's cache, where it measured
                # one; otherwise priced as uncached, and said to overstate.
                with self._lock:
                    share = self._cache_share_locked(name)
                if share:
                    figures["cached_input_tokens"] = round(figures["input_tokens"] * share)
                    said += (
                        f"; its prompt priced with {share:.0%} read from the cache, the share "
                        "this job measured for the model"
                    )
                else:
                    said += (
                        "; its prompt priced as uncached input, which overstates a prompt the "
                        "provider read from its cache"
                    )
            charged = self._charged(figures, model)
            if charged is None:
                self._note_unpriced(name)
                return None
            cost, source = charged
            with self._lock:
                self._priced_from.setdefault(name, set()).add(source)
                self._settled += cost
                self._estimated_calls += 1
                self._estimated_usd += cost
                self._estimated_source = said
            return {
                "priced_usd": cost,
                "price_source": source,
                "estimated_usd": cost,
                "estimated_part": ESTIMATED_WHOLE,
            }
        except Exception as exc:  # noqa: BLE001 — telemetry never costs a run
            logger.debug("estimated spend not settled (%s).", exc)
            return None

    def _settle_output_estimate(
        self, usage: Mapping[str, Any], estimated: Mapping[str, Any], model: str
    ) -> dict[str, Any] | None:
        """A call priced on its reported usage and an estimate of its output alone."""
        try:
            name = price_key(model)
            output = max(0, int(estimated.get("output_tokens") or 0))
            whole = {**usage, "output_tokens": output}
            charged = self._charged(whole, model)
            unanswered = self._charged({**usage, "output_tokens": 0}, model)
            if charged is None or unanswered is None:
                self._note_unpriced(name)
                return None
            cost, source = charged
            by_estimate = max(0.0, cost - unanswered[0])
            with self._lock:
                self._priced_from.setdefault(name, set()).add(source)
                self._settled += cost
                self._estimated_calls += 1
                self._estimated_usd += by_estimate
                self._estimated_source = str(estimated.get("source") or "")
            return {
                "priced_usd": cost,
                "price_source": source,
                "estimated_usd": by_estimate,
                "estimated_part": ESTIMATED_OUTPUT,
            }
        except Exception as exc:  # noqa: BLE001 — telemetry never costs a run
            logger.debug("estimated spend not settled (%s).", exc)
            return None

    def note_loop(self, key: Any, turns: list[Any], model: str = "") -> None:
        """What a running loop's turns so far cost, counted until the ledger has them.

        The loop's turn that was in flight has returned by now, so its
        reservation is released: its cost is among the turns.
        """
        try:
            from maljan.core.token_ledger import turn_usage
            from maljan.llm.fallback import turn_model

            total = 0.0
            inputs: dict[str, list[int]] = {}
            measured: list[tuple[Mapping[str, Any], str]] = []
            answered = 0
            opening = 0
            for turn in turns:
                if getattr(turn, "type", "") != "ai":
                    continue
                answered += 1
                answered_by, _fallback = turn_model(turn, model)
                if not answered_by:
                    metadata = getattr(turn, "response_metadata", None) or {}
                    answered_by = str(metadata.get("model_name") or "")
                usage = turn_usage(turn)
                if usage is None:
                    continue
                name = _clean(answered_by)
                if name:
                    measured.append((usage, name))
                if answered == 1:
                    opening = max(opening, int(usage.get("input_tokens") or 0))
                if name and answered > 1:
                    # The share a conversation reads from the cache is measured
                    # after its first call, which has nothing cached to read.
                    total_in = int(usage.get("input_tokens") or 0)
                    sums = inputs.setdefault(name, [0, 0])
                    sums[0] += total_in
                    sums[1] += min(total_in, int(usage.get("cached_input_tokens") or 0))
                charged = self._charged(usage, answered_by)
                if charged is None:
                    continue
                total += charged[0]
            with self._lock:
                for turn_used, name in measured:
                    self._measure_locked(turn_used, name, "loop")
                if opening > self._largest_prompt.get("opening", 0):
                    self._largest_prompt["opening"] = opening
                self._in_flight[key] = total
                self._loop_inputs[key] = inputs
                self._reserved.pop(key, None)
                self._active.discard(key)
                self._drained.notify_all()
            self._after_drain()
        except Exception as exc:  # noqa: BLE001 — telemetry never costs a run
            logger.debug("in-flight spend not noted (%s).", exc)

    def forget_loop(self, key: Any) -> None:
        """A loop whose turns the ledger now holds (or never will).

        What its turns after the first read from the cache stays measured.
        """
        with self._lock:
            self._in_flight.pop(key, None)
            for name, (total, cached) in (self._loop_inputs.pop(key, None) or {}).items():
                sums = self._inputs.setdefault(name, [0, 0])
                sums[0] += total
                sums[1] += cached
            self._reserved.pop(key, None)
            self._active.discard(key)
            self._drained.notify_all()
        self._after_drain()

    def release(self, slot: Any) -> None:
        """The call reserved under ``slot`` has returned and its cost is on the ledger."""
        with self._lock:
            self._reserved.pop(slot, None)
            self._active.discard(slot)
            self._drained.notify_all()
        self._after_drain()

    def close(self) -> None:
        """The job is cancelled: every call waiting on another's reservation gives up now."""
        with self._lock:
            self._closed = True
            self._drained.notify_all()

    def begin_stage(self, kinds: tuple[str, ...] = ()) -> None:
        """A stage of the job has started: the kinds of call made before it are not planned now.

        ``kinds`` are the kinds of call the stage is known to make
        (:data:`STAGE_CALL_KINDS`). They count as planned from its start, so a
        refused first call of another kind cannot exhaust the spend before they
        were asked about. One this job has made before keeps what it measured
        of it; one it has not is asked about at this job's largest single-shot
        prompt and answer, holdable.
        """
        with self._lock:
            self._generation += 1
            for kind in kinds:
                row = self._kinds.get(kind)
                if row is None:
                    self._kinds[kind] = {"seeded": True, "generation": self._generation}
                else:
                    row["generation"] = self._generation

    def _after_drain(self) -> None:
        """A refusal made while calls were in flight is looked at again once none is."""
        with self._lock:
            said = self._pending_check
            if said is None or self._reserved or self._exhausted is not None:
                return
            self._pending_check = None
            fits = self._another_fits_locked(self._clock())
        if not fits:
            self._exhaust("a refusal", said)

    def spent(self) -> float:
        """What the job has spent: settled calls and the turns of running loops."""
        with self._lock:
            return self._settled + sum(self._in_flight.values())

    def committed(self) -> float:
        """What is spent, and the worst case of every call in flight."""
        with self._lock:
            return self._settled + sum(self._in_flight.values()) + sum(self._reserved.values())

    def remaining(self) -> float | None:
        """US dollars not yet spent or reserved under the ceiling, or ``None`` with no ceiling."""
        if self.ceiling_usd is None:
            return None
        return max(0.0, self.ceiling_usd - self.committed())

    def worst_case(self, model: str, prompt_tokens: int, output_tokens: int) -> float | None:
        """What one call could cost at most now: its whole prompt uncached and its whole cap."""
        price = self.price_now(model)
        if price is None:
            return None
        return price.for_admission(int(prompt_tokens), self.writes_hour_caches(model)).cost(
            {"input_tokens": int(prompt_tokens), "output_tokens": int(output_tokens)}
        )

    # ── The reserve for the verdict and the report ───────────────────────

    def plan_tail(self, calls: Mapping[str, tuple[Any, ...]]) -> None:
        """The verdict and report calls this job will make.

        ``{kind: (model, calls[, prompt tokens[, output cap]])}``: the prompt is
        what the window accounting allows that kind of call (its window less
        its output budget), ``0`` where no window is known; the cap is the
        output cap the call is admitted with, ``0`` for none known, which is
        planned, with nothing measured, at the most a call sent with no cap may
        answer (the model's declared maximum output, else the fallback reply).
        """
        with self._lock:
            for kind, row in calls.items():
                model, count = row[0], int(row[1])
                allowed = int(row[2]) if len(row) > 2 and row[2] else 0
                cap = int(row[3]) if len(row) > 3 and row[3] else 0
                if kind in TAIL_KINDS and count > 0:
                    self._tail[kind] = [str(model or ""), count, max(0, allowed), max(0, cap)]

    def _cache_share_locked(self, name: str) -> float | None:
        total, cached = self._inputs.get(name, [0, 0])
        for inputs in self._loop_inputs.values():
            loop_total, loop_cached = inputs.get(name, [0, 0])
            total += loop_total
            cached += loop_cached
        return cached / total if total > 0 else None

    def _tail_prompt_locked(self, kind: str, allowed: int) -> tuple[int, str]:
        """The prompt a planned call of ``kind`` will be sent with, as this job has measured it."""
        own = self._largest_prompt.get(f"tail:{kind}", 0)
        if own:
            return own, f"the largest {kind} prompt sent"
        found, said = 0, ""
        single = self._largest_prompt.get("single", 0)
        opening = self._largest_prompt.get("opening", 0) or self._smallest_loop_prompt
        if single:
            found = single
            said = "the largest single-shot prompt sent (a revision carries the reports)"
        elif opening:
            found = opening
            said = (
                "the largest opening prompt of a conversation sent (no single-shot prompt sent yet)"
            )
        if found:
            if allowed and allowed < found:
                return allowed, f"what the window accounting allows a {kind} call's prompt"
            return found, said
        if allowed:
            return allowed, (
                f"what the window accounting allows a {kind} call's prompt (no prompt sent yet)"
            )
        return 0, ""

    def _planned_answer_locked(self, kind: str, name: str, cap: int = 0) -> tuple[int, str]:
        """The answer a planned call of ``kind`` is planned at, and where the figure came from.

        The verdict at what its admission demands; a report call at the mean
        answer this job has measured of its kind, else of the model's other
        single-shot calls, else at the model's largest tool-loop turn, else
        the largest answer measured of any model. Bounded by ``cap`` where one
        is known.
        """
        if kind == "verdict":
            return self._minimum_locked(kind, name, cap)
        tokens, said = 0, ""
        for group, what in ((f"tail:{kind}", f"{kind}"), ("single", "single-shot")):
            mean, calls = self._mean_answer_locked(name, group)
            if mean:
                tokens = mean
                said = f"the mean of the {calls} {what} answer(s) measured of {name}"
                break
        if not tokens:
            for group, what in (
                ("loop", "tool-loop turn"),
                ("single", "single-shot or verdict/report answer"),
            ):
                largest = self._largest_output[group]
                if largest.get(name):
                    tokens, said = largest[name], f"the largest {what} measured of {name}"
                    break
                if largest:
                    other, found = max(largest.items(), key=lambda row: row[1])
                    tokens, said = found, f"the largest {what} measured of {other}"
                    break
        if tokens and cap and tokens > cap:
            return cap, f"{said}, bounded by its cap of {cap:,}"
        if not tokens and cap <= 0:
            # Planned with no cap of its own and nothing measured: reserved for
            # the most it may answer, never for nothing.
            most, where = _uncapped_output(name)
            return most, f"the most it may answer, sent with no cap ({where})"
        return tokens, said

    def _planned_retries_locked(self, kind: str, firsts: int) -> tuple[int, str]:
        """How many validation retries the ``firsts`` planned calls of ``kind`` are given.

        One per planned call until a call of the kind was made; then at this
        job's own rate for the kind, counted with that first assumed retry —
        ``(retries + 1) / (first calls + 1)`` — so a call whose own retry has
        not been asked yet is never planned without one.
        """
        made, retried = self._calls_made.get(kind, [0, 0])
        if firsts <= 0:
            return 0, ""
        if made <= 0:
            return firsts, "one per planned call (none of its kind made yet)"
        planned = math.ceil(firsts * (retried + 1) / (made + 1) - 1e-9)
        return planned, (
            f"{retried} retr{'y' if retried == 1 else 'ies'} measured over {made} {kind} "
            "call(s), counted with the one retry assumed before any was made"
        )

    def _reserve_locked(
        self, now: datetime, taking: str = "", retrying: bool = False
    ) -> tuple[float, list[dict[str, Any]]]:
        """The reserve kept for the planned calls still to come, and its derivation.

        ``taking`` is the kind of a planned call being admitted now, and
        ``retrying`` whether it is a validation retry: its own planned share
        is not in the reserve it is admitted against. A first call being
        admitted leaves its own possible retry planned.

        Each planned call is kept at what its admission will demand — its
        prompt as uncached input and its planned answer — so the reserve is
        never below what the tail needs to be made. The row's expected charge
        prices the first call of a kind with its prompt uncached and the ones
        after it, which share its prefix, at the cache-hit share measured over
        calls that were not the first of their conversation (at the cached rate
        of that prefix while none is measured).
        """
        total = 0.0
        rows: list[dict[str, Any]] = []
        for kind in _TAIL_ORDER:
            if kind not in self._tail:
                continue
            model, count, allowed, cap = self._tail[kind]
            retried_for = count
            if kind == taking and not retrying and count > 0:
                count -= 1
            retries, retries_said = self._planned_retries_locked(kind, retried_for)
            if count <= 0 and retries <= 0:
                continue
            row_price = self.price_of(model)
            if row_price is None:
                continue
            name = _clean(model)
            prompt, prompt_said = self._tail_prompt_locked(kind, int(allowed))
            price = row_price.at(now).for_admission(prompt, self.writes_hour_caches(model))
            answer, answer_said = self._planned_answer_locked(kind, name, int(cap))
            if not answer:
                continue
            share = self._cache_share_locked(name)
            later_rate = (
                price.cached
                if share is None
                else (share * price.cached + (1 - share) * price.input)
            )
            demand = (prompt * price.input + answer * price.output) / MILLION
            # A retry is sent with the answer it corrects in its prompt.
            retry_prompt = prompt + answer
            retry_demand = (retry_prompt * price.input + answer * price.output) / MILLION
            usd = demand * count + retry_demand * retries
            first_sent = bool(self._largest_prompt.get(f"tail:{kind}", 0)) or kind == taking
            expected = (
                sum(
                    (
                        prompt * (price.input if index == 0 and not first_sent else later_rate)
                        + answer * price.output
                    )
                    / MILLION
                    for index in range(count)
                )
                + retries * (retry_prompt * later_rate + answer * price.output) / MILLION
            )
            total += usd
            rows.append(
                {
                    "kind": kind,
                    "model": name,
                    "calls": count,
                    "priced_calls": count,
                    "prompt_tokens": prompt,
                    "prompt_from": prompt_said,
                    "answer_tokens": answer,
                    "answer_from": answer_said,
                    "cache_hit_share": None if share is None else round(share, 4),
                    "cache_hit_share_from": (
                        "the cached rate of the shared prefix (no share measured yet)"
                        if share is None
                        else "calls after the first of their conversation"
                    ),
                    "retries": retries,
                    "retries_from": retries_said,
                    "retry_prompt_tokens": retry_prompt,
                    "usd": round(usd, 6),
                    "expected_usd": round(expected, 6),
                }
            )
        return total, rows

    # ── Before a call ─────────────────────────────────────────────────────

    def _minimum_locked(self, kind: str, name: str, cap: int) -> tuple[int, str]:
        if kind == "report":
            # A report call demands the answer the reserve kept for it, so
            # what was kept is what makes it.
            planned, said = self._planned_answer_locked(kind, name, cap)
            if planned:
                return planned, said
        groups = ("loop", "single") if kind in LOOP_KINDS else ("single",)
        for group in groups:
            measured = self._largest_output[group].get(name, 0)
            if measured:
                what = (
                    "tool-loop turn" if group == "loop" else "single-shot or verdict/report answer"
                )
                return (
                    min(measured, cap) if cap else measured,
                    f"the largest {what} this job has measured of {name}",
                )
        if cap <= 0:
            # Sent with no cap of its own: the most it may answer is what it
            # may need, so a planned call of it is reserved for that.
            tokens, said = _uncapped_output(name)
            return tokens, f"the most it may answer, sent with no cap ({said})"
        return cap, "its configured output cap, with no answer of its kind measured yet"

    def _decide_locked(
        self,
        *,
        kind: str,
        name: str,
        price: Price | None,
        prompt_tokens: int,
        cap: int,
        slot: Any,
        holdable: bool,
        now: datetime,
        count_reserved: bool = True,
        retrying: bool = False,
    ) -> _Decision:
        decision = _Decision(name)
        decision.cap = cap
        tail = kind in TAIL_KINDS
        latched = self._exhausted is not None or self._reached_at is not None
        if latched and kind not in AFTER_EXHAUSTION_KINDS:
            decision.refused = f"the spend ceiling of {self.ceiling_usd:.4f} USD is exhausted"
            return decision
        if price is None:
            return decision
        # A call sent with no output cap of its own (cap 0) is not refused for
        # want of one: it is priced at the most it may answer, the model's
        # declared maximum output, else the documented fallback reply.
        uncapped_said = ""
        if cap <= 0:
            if not holdable and not _uncapped_is_declared(name):
                # Nothing bounds its answer: no cap is sent, none can be, and
                # the model declares no maximum, so no reservation could hold.
                decision.refused = (
                    "it is sent with no output cap, its model takes none per call, and the "
                    "model declares no maximum output, so what it may cost cannot be bounded "
                    "under the spend ceiling"
                )
                return decision
            cap, uncapped_said = _uncapped_output(name)
            decision.cap = cap
        others = (
            sum(v for k, v in self._reserved.items() if k is not slot) if count_reserved else 0.0
        )
        committed = self._settled + sum(self._in_flight.values()) + others
        reserve = self._reserve_locked(now, taking=kind if tail else "", retrying=retrying)[0]
        available = float(self.ceiling_usd or 0.0) - committed - reserve
        input_cost = prompt_tokens * price.input / MILLION
        minimum, minimum_said = self._minimum_locked(kind, name, cap)
        if uncapped_said and minimum == cap:
            minimum_said = (
                f"the most it may answer, sent with no cap ({uncapped_said}), with no answer "
                "of its kind measured yet"
            )
        # A loop turn keeps room for the loop's closing answer after it.
        closing = input_cost + minimum * price.output / MILLION if kind in LOOP_KINDS else 0.0
        spendable = available - input_cost - closing
        room = int(spendable * MILLION / price.output) if price.output > 0 else cap
        room = max(0, room) if spendable >= 0 else 0
        decision.available = max(0.0, available)
        decision.reserve = reserve
        decision.input_cost = input_cost
        decision.room = room
        decision.minimum = minimum
        decision.minimum_said = minimum_said
        if spendable >= 0 and (price.output <= 0 or (cap and room >= cap)):
            decision.bound = None
            decision.reservation = input_cost + cap * price.output / MILLION
            if uncapped_said and holdable and price.output > 0 and not _uncapped_is_declared(name):
                # The fallback figure is what was reserved, and only a model's
                # own limit stops an uncapped answer from running past it: it
                # is sent as the call's cap, so the reservation holds.
                decision.bound = cap
                decision.fallback_cap = cap
            return decision
        if holdable and cap and room >= max(minimum, 1):
            decision.bound = room
            decision.reservation = input_cost + room * price.output / MILLION
            return decision
        if not holdable and uncapped_said:
            needed = f"the {cap:,} tokens it may answer with, sent with no cap ({uncapped_said})"
        elif not holdable:
            needed = f"its whole {cap:,}-token cap (its model takes no cap of its own per call)"
        else:
            needed = f"the {minimum:,} tokens of the smallest answer it can give ({minimum_said})"
        decision.refused = (
            f"the {decision.available:.4f} USD it may spend under the spend ceiling of "
            f"{self.ceiling_usd:.4f} USD"
            + (
                f" (after {reserve:.4f} USD kept for the "
                + ("other planned verdict and report calls" if tail else "verdict and the report")
                + ")"
                if reserve
                else ""
            )
            + f" pays for {room:,} output tokens after its prompt ({input_cost:.4f} USD)"
            + (" and the loop's closing answer" if closing else "")
            + f", fewer than {needed}"
        )
        return decision

    def _prompt_key(self, kind: str) -> str:
        if kind in TAIL_KINDS:
            return f"tail:{kind}"
        return "loop" if kind in LOOP_KINDS else "single"

    def _admission_price(
        self, model: str, now: datetime, deadline_s: float | None, prompt_tokens: int = 0
    ) -> Price | None:
        row = self.price_of(model)
        if row is None:
            return None
        return row.highest_over(
            now, _default_deadline() if deadline_s is None else deadline_s
        ).for_admission(prompt_tokens, self.writes_hour_caches(model))

    def preview(
        self,
        *,
        kind: str,
        model: str,
        prompt_chars: int,
        cap_tokens: int,
        holdable: bool = True,
        deadline_s: float | None = None,
    ) -> int | None:
        """What :meth:`admit` would answer now, with nothing reserved, logged or latched.

        ``None`` as it is, a number as its held cap, ``0`` when it would not be made.
        """
        if self.ceiling_usd is None:
            return None
        from maljan.llm.context_window import tokens_for_chars

        now = self._clock()
        prompt_tokens = tokens_for_chars(prompt_chars)
        price = self._admission_price(model, now, deadline_s, prompt_tokens)
        with self._lock:
            decision = self._decide_locked(
                kind=kind,
                name=_clean(model) or "the model",
                price=price,
                prompt_tokens=prompt_tokens,
                cap=max(0, int(cap_tokens or 0)),
                slot=object(),
                holdable=holdable,
                now=now,
            )
        return 0 if decision.refused else decision.bound

    def admit(
        self,
        *,
        kind: str,
        model: str,
        prompt_chars: int,
        cap_tokens: int,
        slot: Any = None,
        holdable: bool = True,
        deadline_s: float | None = None,
        wait_s: float | None = None,
        attempt: bool = False,
    ) -> int | None:
        """Whether a call may be made, before it is: ``None`` as it is, a number as a held cap.

        ``attempt`` is a model list's fallback attempt at a call already
        admitted: the same logical call at another model's price, so it is not
        counted as a call of its kind and takes nothing from the planned tail.
        Given the call's own ``slot`` it replaces that reservation.

        With no ceiling every call is made as it is. With one, a call is made
        with its output cap held to what the spend it may use pays for after
        its prompt (see the module docstring), and refused with
        :class:`SpendCeilingStop` when that is below the smallest answer it can
        give — or, for a call whose cap cannot be held (``holdable=False``: its
        model takes no per-call cap, or its caller cannot send one), below its
        whole cap. It is priced at the highest rate in force between now and
        ``deadline_s`` seconds on (its client's own timeout when ``None``).
        Once the spend is exhausted only the verdict, the report and a loop's
        closing answer (:data:`AFTER_EXHAUSTION_KINDS`) are made, where they
        fit. A call of a model with no price is made as it is until the spend
        is exhausted. With ``slot`` the admitted call's worst case is reserved
        under it until :meth:`release` (or, for a loop's turn,
        :meth:`note_loop`) is called with it. Every held or refused call is
        logged with its numbers and recorded.

        A call that does not fit only because other calls in flight hold their
        worst case waits for them to settle: at most until ``deadline_s``, or
        ``wait_s`` when the caller's own clock (a tool loop's) ends sooner, and
        never past the job's cancellation (:meth:`close`), which wakes it and
        raises ``JobCancelled``, so the caller ends as cancelled. The
        wait blocks the calling thread. The calls that can run beside another —
        analyst nodes, revisions, tool loops — each run on a thread of their
        own; the verdict and report calls, which admit from a coroutine, run
        alone, so nothing in flight holds a reservation that would make them
        wait.
        """
        if self.ceiling_usd is None:
            return None
        from maljan.core import cancellation
        from maljan.llm.context_window import tokens_for_chars

        job = cancellation.current()
        prompt_tokens = tokens_for_chars(prompt_chars)
        cap = max(0, int(cap_tokens or 0))
        name = _clean(model) or "the model"
        retrying = _RETRYING.get()
        # A call that does not fit only because other calls in flight hold
        # their worst case waits for them to settle — most settle far below
        # it — for as long as its own deadline allows.
        bound_s = _default_deadline() if deadline_s is None else float(deadline_s)
        if wait_s is not None:
            bound_s = min(bound_s, max(0.0, float(wait_s)))
        waits_until = time.monotonic() + bound_s
        gave_up = ""
        noted = False
        while True:
            now = self._clock()
            price = self._admission_price(model, now, deadline_s, prompt_tokens)
            # Latched here as well, so a call admitted after the ceiling was
            # reached is read against the latch.
            self.reached()
            with self._lock:
                if not noted and not attempt:
                    self._note_kind_locked(kind, model, prompt_tokens, cap, holdable, deadline_s)
                    noted = True
                decision = self._decide_locked(
                    kind=kind,
                    name=name,
                    price=price,
                    prompt_tokens=prompt_tokens,
                    cap=cap,
                    slot=slot,
                    holdable=holdable,
                    now=now,
                    retrying=retrying,
                )
                others_in_flight = any(k is not slot for k in self._reserved)
                if decision.refused and others_in_flight:
                    unreserved = self._decide_locked(
                        kind=kind,
                        name=name,
                        price=price,
                        prompt_tokens=prompt_tokens,
                        cap=cap,
                        slot=slot,
                        holdable=holdable,
                        now=now,
                        count_reserved=False,
                        retrying=retrying,
                    )
                    left = waits_until - time.monotonic()
                    cancelled = self._closed or bool(job is not None and job.is_cancelled)
                    if not unreserved.refused and cancelled:
                        gave_up = "the job was cancelled while it waited for calls in flight"
                    elif not unreserved.refused and left > 0:
                        self._drained.wait(timeout=min(left, _WAIT_SLICE_SECONDS))
                        continue
                if not decision.refused:
                    key = self._prompt_key(kind)
                    if not attempt and prompt_tokens > self._largest_prompt.get(key, 0):
                        self._largest_prompt[key] = prompt_tokens
                    made = self._calls_made.setdefault(kind, [0, 0])
                    if not attempt:
                        made[1 if retrying else 0] += 1
                    if (
                        not attempt
                        and not retrying
                        and kind in TAIL_KINDS
                        and kind in self._tail
                        and self._tail[kind][1] > 0
                    ):
                        self._tail[kind][1] -= 1
                    if slot is not None:
                        self._active.add(slot)
                        if price is not None:
                            self._reserved[slot] = decision.reservation
            break
        if decision.refused:
            if gave_up:
                # Not the spend's refusal: the job is ending, and its loops
                # record a cancellation, not the spend cap.
                from maljan.core.cancellation import JobCancelled

                where = f"while a {kind} call of {name} waited for calls in flight"
                if job is not None and job.is_cancelled:
                    job.check(where)
                raise JobCancelled(f"the job was cancelled; stopped {where}")
            said = f"a {kind} call of {name} was not made: {decision.refused}"
            with self._lock:
                self._refused += 1
            self._note_held(said)
            self._exhaust_if_nothing_fits(said, now)
            raise SpendCeilingStop(said)
        if decision.fallback_cap:
            logger.debug(
                "spend ceiling: the %s call of %s, sent with no cap of its own, is sent with a "
                "cap of %d tokens: the most it was reserved for, its model declaring no maximum "
                "output.",
                kind,
                name,
                decision.fallback_cap,
            )
        elif decision.bound is not None:
            had = (
                f"its cap was {cap:,}"
                if cap
                else f"it was sent with no cap of its own, so it may answer {decision.cap:,} tokens"
            )
            self._note_held(
                f"the {kind} call of {name} was held to {decision.bound:,} output tokens "
                f"({had}): what the {decision.available:.4f} USD it may spend "
                "under the spend ceiling pays for after its prompt "
                f"({decision.input_cost:.4f} USD)"
                + (
                    f", {decision.reserve:.4f} USD being kept for the "
                    + (
                        "other planned verdict and report calls"
                        if kind in TAIL_KINDS
                        else "verdict and the report"
                    )
                    if decision.reserve
                    else ""
                )
            )
        if slot is not None and not attempt:
            _ADMISSION.set(Admission(self, kind, int(prompt_chars), slot))
        return decision.bound

    def holds(self, slot: Any) -> bool:
        """Whether ``slot`` has a reservation held now."""
        with self._lock:
            return slot in self._active

    @contextlib.contextmanager
    def held(
        self,
        *,
        kind: str,
        model: str,
        prompt_chars: int,
        cap_tokens: int,
        holdable: bool = True,
    ) -> Iterator[int | None]:
        """:meth:`admit` for one call, its reservation released when the block ends."""
        slot = object()
        try:
            yield self.admit(
                kind=kind,
                model=model,
                prompt_chars=prompt_chars,
                cap_tokens=cap_tokens,
                slot=slot,
                holdable=holdable,
            )
        finally:
            self.release(slot)

    def _note_kind_locked(
        self,
        kind: str,
        model: str,
        prompt_tokens: int,
        cap: int,
        holdable: bool,
        deadline_s: float | None,
    ) -> None:
        """Remember a kind of call this job makes, at the smallest prompt it was sent with."""
        self._uses += 1
        row = self._kinds.get(kind)
        if row is None or row.get("seeded"):
            self._kinds[kind] = {
                "model": model,
                "prompt": prompt_tokens,
                "cap": cap,
                "holdable": holdable,
                "deadline": deadline_s,
                "generation": self._generation,
                "used": self._uses,
            }
            return
        if prompt_tokens < row["prompt"]:
            row["prompt"] = prompt_tokens
        row["model"], row["cap"], row["deadline"] = model, cap, deadline_s
        row["holdable"] = bool(row["holdable"] or holdable)
        row["generation"] = self._generation
        row["used"] = self._uses

    def _another_fits_locked(self, now: datetime) -> bool:
        """Whether a call of any kind this job makes would still be admitted.

        Each kind still planned — made in the current stage — is asked at the
        smallest prompt it was sent with, its cap and its own holdability,
        against what is left after the reserve. The verdict, the report and a
        loop's closing answer are left out: they are made after exhaustion too.
        """
        made = [row for row in self._kinds.values() if not row.get("seeded")]
        latest = max(made, key=lambda row: int(row.get("used", 0))) if made else None
        for kind, row in self._kinds.items():
            if kind in AFTER_EXHAUSTION_KINDS or row.get("generation") != self._generation:
                continue
            if row.get("seeded"):
                # Planned for this stage and not made yet: asked about on the
                # model of the kind this job made last, at its largest
                # single-shot prompt and answer; with nothing to ask it on, it
                # is taken to fit rather than latch the job on a guess.
                if latest is None:
                    return True
                model = str(latest["model"])
                name = _clean(model) or "the model"
                prompt = int(
                    self._largest_prompt.get("single", 0)
                    or self._largest_prompt.get("opening", 0)
                    or self._smallest_loop_prompt
                )
                answer = self._largest_output["single"].get(name, 0) or self._largest_output[
                    "loop"
                ].get(name, 0)
                row = {
                    "model": model,
                    "prompt": prompt,
                    "cap": max(1, answer),
                    "holdable": True,
                    "deadline": latest["deadline"],
                }
            price = self._admission_price(
                str(row["model"]), now, row["deadline"], int(row["prompt"])
            )
            decision = self._decide_locked(
                kind=kind,
                name=_clean(str(row["model"])) or "the model",
                price=price,
                prompt_tokens=int(row["prompt"]),
                cap=int(row["cap"]),
                slot=object(),
                holdable=bool(row["holdable"]),
                now=now,
            )
            if not decision.refused:
                return True
        return False

    def _exhaust_if_nothing_fits(self, said: str, now: datetime) -> None:
        """After a refusal: latch the exhaustion only when no further call of any kind fits.

        Never while other calls hold reservations: what they reserved is their
        worst case, and what they settle at is usually far below it. The
        question is asked again once none is outstanding (:meth:`_after_drain`).
        """
        with self._lock:
            if self._exhausted is not None:
                return
            if self._reserved:
                self._pending_check = said
                logger.info(
                    "spend ceiling: that call was refused while other calls were in flight; "
                    "whether anything still fits is asked again once they settle."
                )
                return
            fits = self._another_fits_locked(now)
        if fits:
            logger.info(
                "spend ceiling: that call was refused, and smaller calls of this job still fit "
                "what is left; the job goes on."
            )
            return
        self._exhaust("a refusal", said)

    def exhausted(self) -> bool:
        """Whether the spend is exhausted: the ceiling reached, or no further call fits.

        Every gate reads this — a new tool loop, a chunk, an ask, a negotiation
        round — and so does the degradation reason. Latched.
        """
        if self.reached():
            return True
        with self._lock:
            return self._exhausted is not None

    def _exhaust(self, why: str, said: str) -> None:
        """Latch the exhaustion the first time: when (the spend so far) and why."""
        with self._lock:
            if self._exhausted is not None:
                return
            spent = self._settled + sum(self._in_flight.values())
            self._exhausted = {"at_usd": round(spent, 6), "why": why, "call": said}
        logger.warning(
            "spend ceiling exhausted at %.4f USD of %.4f USD (%s); no further tool loop, chunk, "
            "ask or negotiation round is started.",
            spent,
            self.ceiling_usd or 0.0,
            why,
        )

    def _note_held(self, said: str) -> None:
        with self._lock:
            if said in self._held:
                return
            self._held.append(said)
        logger.warning("spend ceiling: %s.", said)

    def reached(self) -> bool:
        """Whether the ceiling is set and what the job has spent has reached it. Latches."""
        if self.ceiling_usd is None:
            return False
        with self._lock:
            if self._reached_at is not None:
                return True
            spent = self._settled + sum(self._in_flight.values())
            if spent < self.ceiling_usd:
                return False
            self._reached_at = spent
            if self._exhausted is None:
                self._exhausted = {"at_usd": round(spent, 6), "why": "reached", "call": ""}
        logger.warning(
            "spend ceiling reached: %.4f USD of %.4f USD; every running tool loop ends its "
            "tool phase and writes its answer from what it gathered.",
            spent,
            self.ceiling_usd,
        )
        return True

    def reason(self) -> str:
        """The degradation reason an exhausted spend gives, or ``""``."""
        self.exhausted()
        with self._lock:
            latch = dict(self._exhausted) if self._exhausted else None
            unreported = self._unreported
        if latch is None or self.ceiling_usd is None:
            return ""
        spent = f"at least {latch['at_usd']:.4f} USD spent" + (
            f"; {unreported} call(s) reported no usage and are not counted" if unreported else ""
        )
        how = (
            "was reached"
            if latch["why"] == "reached"
            else "was exhausted: what was left no longer paid for the smallest answer of any "
            "call this job makes"
        )
        return (
            f"The spend ceiling of {self.ceiling_usd:.4f} USD {how} ({spent}). The tool phases "
            "still running ended there and their agents wrote their answers from what they had "
            "gathered; no further negotiation round, chunk, ask or tool loop was started, and "
            "only the verdict and the report ran, tool-free, on what was kept for them."
        )

    def snapshot(self) -> dict[str, Any] | None:
        """The run summary's ``spend`` block, or ``None`` with no ceiling set.

        ``agent_ceilings`` is there only when an agent sets a ceiling of its
        own, and is then the whole block where the job sets none.
        """
        if self.ceiling_usd is None:
            with self._lock:
                if not self._agent_ceilings:
                    return None
                return {"agent_ceilings": self._agent_block_locked()}
        now = self._clock()
        with self._lock:
            reserve, rows = self._reserve_locked(now)
            out: dict[str, Any] = {
                "ceiling_usd": self.ceiling_usd,
                "spent_usd": round(self._settled + sum(self._in_flight.values()), 6),
                "reached": self._reached_at is not None,
                "exhausted": self._exhausted is not None,
                "prices_from": {
                    name: "; ".join(sorted(sources))
                    for name, sources in sorted(self._priced_from.items())
                },
            }
            if rows:
                out["reserve_usd"] = round(reserve, 6)
                out["reserve"] = rows
            if self._exhausted is not None:
                out["exhausted_at_usd"] = self._exhausted["at_usd"]
                out["exhausted_by"] = self._exhausted["why"]
            if self._held:
                out["held_calls"] = list(self._held)
            if self._refused:
                out["refused_calls"] = self._refused
            if self._unreported:
                out["unreported_calls"] = self._unreported
                out["spent_is_at_least"] = True
            if self._estimated_calls:
                out["estimated_calls"] = self._estimated_calls
                out["estimated_usd"] = round(self._estimated_usd, 6)
                out["estimated_source"] = self._estimated_source
            if self._unpriced:
                out["unpriced_models"] = dict(sorted(self._unpriced.items()))
                out["note"] = (
                    "no price for "
                    + ", ".join(sorted(self._unpriced))
                    + ": their calls are not counted, so spent_usd is what the priced calls "
                    "cost and the job spent at least that"
                )
                if table_failure:
                    out["note"] += f"; price table could not be read: {table_failure}"
                    out["price_table_error"] = table_failure
            if self._agent_ceilings:
                out["agent_ceilings"] = self._agent_block_locked()
            return out


def hour_cache_models(cfg: Any) -> frozenset[str]:
    """The models these settings call whose provider writes the prompt cache for an hour.

    Each provider answers for itself (``LLMProvider.writes_hour_caches``), and
    only the models that provider serves are priced that way: a job whose
    agents run on another provider is not charged one provider's hour rate
    because of that provider's setting. The models are the global ones and
    every agent entry's, its fallbacks included. Never raises: settings it
    cannot read name no model.
    """
    try:
        from maljan.llm.provider_base import facts_of

        llm = cfg.llm
        pairs: list[tuple[str, str]] = []
        provider = str(llm.provider)
        pairs.extend((provider, str(m)) for m in (llm.expert_model, llm.judge_model))
        for entry in (getattr(llm, "agents", None) or {}).values():
            chain = entry.chain() if hasattr(entry, "chain") else [entry]
            pairs.extend((str(c.provider), str(c.model)) for c in chain)
        writes: dict[str, bool] = {}
        out: set[str] = set()
        for name, model in pairs:
            if name not in writes:
                writes[name] = bool(facts_of(name).writes_hour_caches(cfg))
            if writes[name] and model:
                out.add(model)
        return frozenset(out)
    except Exception as exc:  # noqa: BLE001 — a price knob is never worth a failed job
        logger.debug("spend: the hour-cache providers could not be read (%s).", exc)
        return frozenset()
