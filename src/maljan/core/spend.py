"""What one job has spent on its models, in US dollars, against the operator's ceiling.

``llm.max_spend_usd_per_job`` is the ceiling and has no default: a deployment
that sets none has none. It is a hard bound against the platform's own measure
of a prompt (characters over ``CHARS_PER_TOKEN``): nothing is sent that could
take the job past it by that measure.

**What a call costs.** The cost a provider reports in its answer, where it
reports one. Otherwise the usage it reported — the input tokens it read from
its prompt cache, the other input tokens, and the output tokens — at the
prices of the model that answered *in force when the request was sent*.
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
price, after its prompt priced as uncached input, both at the highest rate in
force between now and the call's deadline (a call sent across a window's edge
is never settled above what it reserved). It is refused only when that does
not pay for the smallest answer the call can give: for a tool-loop turn the
largest turn this job has measured of the model, for any other call the
largest single-shot or verdict/report answer measured of it, and with nothing
measured the call's own configured output cap. A call whose model takes no
cap of its own per call is admitted only at its whole configured cap. Every
admitted call reserves its worst case — its prompt and its held cap — until it
returns and its cost is on the ledger, so calls running at the same time never
spend the same remainder twice.

**The reserve for the verdict and the report.** A job plans its verdict call
and its report calls (:meth:`SpendMeter.plan_tail`), each with the prompt the
window accounting allows it (what its model's window leaves after its output
budget). The reserve is the worst case of the next planned call — its prompt
uncached and the answer planned for it — plus the expected charge of every
other planned call: its prompt at this job's measured cache-hit share for the
model (uncached until one is measured) and the planned answer. A planned call's
prompt is the largest prompt of its own kind once one was sent; the verdict's
is the largest single-shot prompt before that (a revision's prompt carries the
same reports), and a report call's is its window allowance; a tool loop's
conversation is never used. The planned answer is the largest single-shot or
verdict/report answer measured of the model, else the largest tool-loop turn
of it; with no answer measured the reserve is not sized. Calls that are not
the verdict or the report spend only above the whole reserve; a verdict or
report call spends above the reserve of the other planned calls.

A tool loop's turns reach the token ledger when the loop ends, so a running
loop also reports the turns it has taken so far (:meth:`SpendMeter.note_loop`)
and the meter counts them until the ledger has them. A loop's turn keeps room
for the loop's closing answer: it is admitted only when what is left after it
still pays for the smallest answer.

When the spend is exhausted — the first call refused, or the ceiling reached —
every running tool loop ends its tool phase the way it does at its step cap:
its agent writes its answer from what it gathered, and only the verdict and
the report run after it, on the reserve kept for them.
"""

from __future__ import annotations

import contextlib
import json
import re
import threading
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from maljan.core.logger import logger

MILLION = 1_000_000

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

# What the run summary names a price the provider reported with its answer.
PROVIDER_REPORTED = "provider-reported"

_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_HHMM = re.compile(r"\A([01]\d|2[0-3]):([0-5]\d)\Z")


class SpendCeilingStop(Exception):
    """A model call the operator's spend ceiling does not admit, in the words the run records."""


def _meter_of(ledger: Any) -> SpendMeter | None:
    meter = getattr(ledger, "spend", None)
    return meter if isinstance(meter, SpendMeter) else None


def spend_ceiling_set(ledger: Any) -> bool:
    """Whether the job ``ledger`` records has a spend ceiling. Never raises."""
    meter = _meter_of(ledger)
    return meter is not None and meter.ceiling_usd is not None


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
    """One model's prices per million tokens, where they were read, and their time windows."""

    __slots__ = ("cached_input", "input", "output", "source", "windows")

    def __init__(
        self,
        input: float,
        output: float,
        cached_input: float | None = None,
        source: str = "",
        windows: tuple[PriceWindow, ...] = (),
    ) -> None:
        self.input = float(input)
        self.output = float(output)
        self.cached_input = None if cached_input is None else float(cached_input)
        self.source = str(source or "")
        self.windows = tuple(windows)

    def at(self, when: datetime) -> Price:
        """The prices in force at ``when`` (UTC): the first window covering it, else these."""
        for window in self.windows:
            if window.covers(when):
                return window.price
        return self

    def highest_over(self, start: datetime, seconds: float) -> Price:
        """The highest prices in force at any instant from ``start`` for ``seconds``."""
        until = start + timedelta(seconds=max(0.0, float(seconds)))
        best = self.at(start)
        for window in self.windows:
            for edge in window.edges(start, until):
                found = self.at(edge)
                if (found.output, found.input) > (best.output, best.input):
                    best = found
        return best

    @property
    def cached(self) -> float:
        """The price of a cached input token (an input token's where none is given)."""
        return self.input if self.cached_input is None else self.cached_input

    def cost(self, usage: Mapping[str, Any]) -> float:
        """What one call's reported usage costs at these prices."""
        total_in = int(usage.get("input_tokens") or 0)
        cached = min(total_in, int(usage.get("cached_input_tokens") or 0))
        out = int(usage.get("output_tokens") or 0)
        return (
            (total_in - cached) * self.input + cached * self.cached + out * self.output
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
    return Price(
        given_in,
        given_out,
        _number(read.get("cached_input_usd_per_mtok")),
        said,
        tuple(windows),
    )


_table: dict[str, Price] | None = None
_table_lock = threading.Lock()


def table_prices() -> dict[str, Price]:
    """The vendored model table's ``prices`` rows, read once; keyed by lower-cased model name."""
    global _table
    from maljan.core.paths import resolve_data
    from maljan.llm.context_window import TABLE_PATH

    with _table_lock:
        if _table is not None:
            return _table
        rows: dict[str, Price] = {}
        try:
            raw = json.loads(Path(resolve_data(TABLE_PATH)).read_text(encoding="utf-8"))
            for key, row in (raw.get("prices") or {}).items():
                if str(key).startswith("_"):
                    continue
                price = _price_from(row)
                if price is not None and price.source:
                    rows[str(key).lower()] = price
        except Exception as exc:  # noqa: BLE001 — a fallback table never fails a run
            logger.debug("the vendored price table could not be read: %s", exc)
        _table = rows
        return _table


def _clean(model: str) -> str:
    """A model name as the tables key it: lower-cased, without its endpoint or vendor path.

    A model list labels a model ``openai/deepseek-flash @ https://api.deepseek.com``;
    the price is the model's, whichever endpoint served it. The tag after a
    colon is kept: ``qwen3:8b`` and ``qwen3:32b`` are two models.
    """
    name = str(model or "").strip().lower().split(" @ ", 1)[0].strip()
    return name.rsplit("/", 1)[-1]


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


class SpendMeter:
    """One job's spend against the operator's ceiling. Thread-safe; never raises but to refuse."""

    def __init__(
        self,
        ceiling_usd: float | None = None,
        prices: Mapping[str, Any] | None = None,
        *,
        table: Mapping[str, Price] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.ceiling_usd = None if ceiling_usd is None else float(ceiling_usd)
        self._lock = threading.Lock()
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
        self._unpriced: dict[str, int] = {}
        self._priced_from: dict[str, set[str]] = {}
        self._reached_at: float | None = None
        self._said_unpriced = False
        self._unreported = 0
        # What this job has measured. The largest answer (output tokens,
        # reasoning included) of each model, per group: ``loop`` for tool-loop
        # turns, ``single`` for every other call. The largest prompt (tokens)
        # of each kind of call as the window accounting measured it before it
        # was sent: ``tail:verdict``, ``tail:report``, ``single``, ``loop``.
        # The input and cached input tokens of each model's calls, for its
        # cache-hit share: settled, and each running loop's so far.
        self._largest_output: dict[str, dict[str, int]] = {"loop": {}, "single": {}}
        self._largest_prompt: dict[str, int] = {}
        self._inputs: dict[str, list[int]] = {}
        self._loop_inputs: dict[Any, dict[str, list[int]]] = {}
        # The verdict and report calls still to come:
        # kind -> [model, calls, prompt tokens the window accounting allows].
        self._tail: dict[str, list[Any]] = {}
        # What the ceiling did to calls before they were made, one sentence each.
        self._held: list[str] = []
        # When and why the spend was first exhausted, or ``None``.
        self._exhausted: dict[str, Any] | None = None

    @classmethod
    def from_settings(cls, cfg: Any) -> SpendMeter:
        llm = getattr(cfg, "llm", None)
        return cls(
            getattr(llm, "max_spend_usd_per_job", None),
            getattr(llm, "model_prices", None) or {},
        )

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
        return in_force.cost(usage), in_force.source

    def _cost(self, usage: Mapping[str, Any] | None, model: str) -> float | None:
        if usage is None:
            self._note_unreported()
            return None
        name = _clean(model) or "(unnamed model)"
        charged = self._charged(usage, model)
        if charged is None:
            self._note_unpriced(name)
            return None
        cost, source = charged
        with self._lock:
            self._priced_from.setdefault(name, set()).add(source)
        return cost

    def _measure_locked(self, usage: Mapping[str, Any], name: str, group: str) -> None:
        out = int(usage.get("output_tokens") or 0)
        largest = self._largest_output[group]
        if out > largest.get(name, 0):
            largest[name] = out

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
                "table), so its calls are not counted; the ceiling is compared with what "
                "the priced calls cost, which the job has spent at least.",
                name,
            )

    # ── What was spent ────────────────────────────────────────────────────

    def settle(self, usage: Mapping[str, Any] | None, model: str, call: str = "") -> None:
        """One recorded call, from the token ledger; ``call`` is what the ledger names it."""
        try:
            name = _clean(model)
            if usage and name:
                with self._lock:
                    group = "loop" if call == LOOP_TURN_CALL else "single"
                    self._measure_locked(usage, name, group)
            cost = self._cost(usage, model)
            if cost is not None:
                with self._lock:
                    self._settled += cost
        except Exception as exc:  # noqa: BLE001 — telemetry never costs a run
            logger.debug("spend not settled (%s).", exc)

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
                self._in_flight[key] = total
                self._loop_inputs[key] = inputs
                self._reserved.pop(key, None)
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

    def release(self, slot: Any) -> None:
        """The call reserved under ``slot`` has returned and its cost is on the ledger."""
        with self._lock:
            self._reserved.pop(slot, None)

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
        return price.cost({"input_tokens": int(prompt_tokens), "output_tokens": int(output_tokens)})

    # ── The reserve for the verdict and the report ───────────────────────

    def plan_tail(self, calls: Mapping[str, tuple[Any, ...]]) -> None:
        """The verdict and report calls this job will make.

        ``{kind: (model, calls[, prompt tokens[, output cap]])}``: the prompt is
        what the window accounting allows that kind of call (its window less
        its output budget), ``0`` where no window is known; the cap is the
        output cap the call is admitted with, ``0`` unknown.
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
        own = self._largest_prompt.get(f"tail:{kind}", 0)
        if own:
            return own, f"the largest {kind} prompt sent"
        single = self._largest_prompt.get("single", 0)
        if kind == "verdict" and single:
            if allowed and allowed < single:
                return allowed, "what the window accounting allows the verdict's prompt"
            return single, "the largest single-shot prompt sent (a revision carries the reports)"
        if allowed:
            return allowed, f"what the window accounting allows a {kind} call's prompt"
        if single:
            return single, "the largest single-shot prompt sent (no window known)"
        return 0, ""

    def _planned_answer_locked(self, name: str) -> tuple[int, str]:
        for group, said in (
            ("single", "single-shot or verdict/report answer"),
            ("loop", "tool-loop turn"),
        ):
            largest = self._largest_output[group]
            if largest.get(name):
                return largest[name], f"the largest {said} measured of {name}"
        for group, said in (
            ("single", "single-shot or verdict/report answer"),
            ("loop", "tool-loop turn"),
        ):
            largest = self._largest_output[group]
            if largest:
                other, tokens = max(largest.items(), key=lambda row: row[1])
                return tokens, f"the largest {said} measured of {other}"
        return 0, ""

    def _reserve_locked(
        self, now: datetime, taking: str = ""
    ) -> tuple[float, list[dict[str, Any]]]:
        """The reserve kept for the planned calls still to come, and its derivation.

        ``taking`` is the kind of a planned call being admitted now: its own
        planned share is not in the reserve it is admitted against.

        The first call of each kind is priced with its prompt uncached; the
        ones after it — which share the first one's prefix — at the cache-hit
        share measured over calls that were not the first of their conversation,
        and at the cached rate of that prefix while none is measured. The
        verdict is planned at the answer its admission will demand (its
        configured cap until a single-shot answer is measured); a report call at
        the planned answer.
        """
        total = 0.0
        rows: list[dict[str, Any]] = []
        for kind in _TAIL_ORDER:
            if kind not in self._tail:
                continue
            model, count, allowed, cap = self._tail[kind]
            if kind == taking and count > 0:
                count -= 1
            if count <= 0:
                continue
            row_price = self.price_of(model)
            if row_price is None:
                continue
            price = row_price.at(now)
            name = _clean(model)
            prompt, prompt_said = self._tail_prompt_locked(kind, int(allowed))
            answer, answer_said = self._planned_answer_locked(name)
            share = self._cache_share_locked(name)
            later_rate = (
                price.cached
                if share is None
                else (share * price.cached + (1 - share) * price.input)
            )
            calls: list[float] = []
            # The verdict is planned at what its admission will demand, so the
            # reserve kept for it is what it needs to be made.
            size = answer
            if kind == "verdict":
                demanded, _said = self._minimum_locked(kind, name, int(cap))
                size = demanded or answer
            for index in range(count):
                if not size:
                    continue
                rate = price.input if index == 0 else later_rate
                calls.append((prompt * rate + size * price.output) / MILLION)
            if not calls:
                continue
            usd = sum(calls)
            total += usd
            rows.append(
                {
                    "kind": kind,
                    "model": name,
                    "calls": count,
                    "priced_calls": len(calls),
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
                    "usd": round(usd, 6),
                }
            )
        return total, rows

    # ── Before a call ─────────────────────────────────────────────────────

    def _minimum_locked(self, kind: str, name: str, cap: int) -> tuple[int, str]:
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
        others = sum(v for k, v in self._reserved.items() if k is not slot)
        committed = self._settled + sum(self._in_flight.values()) + others
        reserve = self._reserve_locked(now, taking=kind if tail else "")[0]
        available = float(self.ceiling_usd or 0.0) - committed - reserve
        input_cost = prompt_tokens * price.input / MILLION
        minimum, minimum_said = self._minimum_locked(kind, name, cap)
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
            return decision
        if holdable and cap and room >= max(minimum, 1):
            decision.bound = room
            decision.reservation = input_cost + room * price.output / MILLION
            return decision
        needed = (
            f"its whole {cap:,}-token cap (its model takes no cap of its own per call)"
            if not holdable
            else f"the {minimum:,} tokens of the smallest answer it can give ({minimum_said})"
        )
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

    def _admission_price(self, model: str, now: datetime, deadline_s: float | None) -> Price | None:
        row = self.price_of(model)
        if row is None:
            return None
        return row.highest_over(now, _default_deadline() if deadline_s is None else deadline_s)

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
        from maljan.llm.context_window import CHARS_PER_TOKEN

        now = self._clock()
        price = self._admission_price(model, now, deadline_s)
        with self._lock:
            decision = self._decide_locked(
                kind=kind,
                name=_clean(model) or "the model",
                price=price,
                prompt_tokens=-(-max(0, int(prompt_chars)) // CHARS_PER_TOKEN),
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
    ) -> int | None:
        """Whether a call may be made, before it is: ``None`` as it is, a number as a held cap.

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
        """
        if self.ceiling_usd is None:
            return None
        from maljan.llm.context_window import CHARS_PER_TOKEN

        prompt_tokens = -(-max(0, int(prompt_chars)) // CHARS_PER_TOKEN)
        cap = max(0, int(cap_tokens or 0))
        name = _clean(model) or "the model"
        now = self._clock()
        price = self._admission_price(model, now, deadline_s)
        # Latched here as well, so a call admitted after the ceiling was
        # reached is read against the latch.
        self.reached()
        with self._lock:
            decision = self._decide_locked(
                kind=kind,
                name=name,
                price=price,
                prompt_tokens=prompt_tokens,
                cap=cap,
                slot=slot,
                holdable=holdable,
                now=now,
            )
            if not decision.refused:
                key = self._prompt_key(kind)
                if prompt_tokens > self._largest_prompt.get(key, 0):
                    self._largest_prompt[key] = prompt_tokens
                if kind in TAIL_KINDS and kind in self._tail and self._tail[kind][1] > 0:
                    self._tail[kind][1] -= 1
                if slot is not None and price is not None:
                    self._reserved[slot] = decision.reservation
        if decision.refused:
            said = f"a {kind} call of {name} was not made: {decision.refused}"
            self._exhaust("a refusal", said)
            self._note_held(said)
            raise SpendCeilingStop(said)
        if decision.bound is not None:
            self._note_held(
                f"the {kind} call of {name} was held to {decision.bound:,} output tokens "
                f"(its cap was {cap:,}): what the {decision.available:.4f} USD it may spend "
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
        return decision.bound

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

    def exhausted(self) -> bool:
        """Whether the spend is exhausted: the ceiling reached, or a call refused for it.

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
            else "was exhausted: what was left no longer paid for a call's smallest answer"
        )
        return (
            f"The spend ceiling of {self.ceiling_usd:.4f} USD {how} ({spent}). The tool phases "
            "still running ended there and their agents wrote their answers from what they had "
            "gathered; no further negotiation round, chunk, ask or tool loop was started, and "
            "only the verdict and the report ran, tool-free, on what was kept for them."
        )

    def snapshot(self) -> dict[str, Any] | None:
        """The run summary's ``spend`` block, or ``None`` with no ceiling set."""
        if self.ceiling_usd is None:
            return None
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
            if self._unreported:
                out["unreported_calls"] = self._unreported
                out["spent_is_at_least"] = True
            if self._unpriced:
                out["unpriced_models"] = dict(sorted(self._unpriced.items()))
                out["note"] = (
                    "no price for "
                    + ", ".join(sorted(self._unpriced))
                    + ": their calls are not counted, so spent_usd is what the priced calls "
                    "cost and the job spent at least that"
                )
            return out
