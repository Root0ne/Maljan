"""What one job has spent on its models, in US dollars, against the operator's ceiling.

``llm.max_spend_usd_per_job`` is the ceiling and has no default: a deployment
that sets none has none. Spend is computed from the usage each provider
reported — the input tokens it read from its prompt cache, the other input
tokens, and the output tokens — at the prices of the model that answered.
Prices come from the operator's ``llm.model_prices`` first, then from a
``prices`` row of the vendored model table, which carries a vendor's
documented prices as data, with the page they were read from.

Nothing is guessed. A call whose model has no price adds nothing it could be
wrong about: it is named, once in the log and in the run summary, and the
spend the ceiling is compared against is then what the priced calls cost — a
figure the job has spent at least. A call whose provider reported no usage is
the token ledger's ``unreported`` row, and adds nothing here either.

A tool loop's turns reach the token ledger when the loop ends, so a running
loop also reports the turns it has taken so far (:meth:`SpendMeter.note_loop`)
and the meter counts them until the ledger has them.

When the ceiling is reached, every running tool loop ends its tool phase the
way it does at its step cap: its agent writes its answer from what it
gathered. The stages after it still run where they must — the judge's
verdict and the report, tool-free — so the report is never lost; the run
summary's degradation reasons say the ceiling ended the tool phases.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from maljan.core.logger import logger

MILLION = 1_000_000

# The cap name a loop the ceiling ended records, beside ``steps``, ``time``,
# ``repeats`` and ``no_room``.
SPEND_CAP = "spend"

# The calls that are still made when their worst case would pass the ceiling:
# the verdict and a report section (the report is never lost), and the answer
# a tool loop the ceiling ended writes from what it gathered. Each is made with
# its output cap lowered to what the remaining spend pays for.
HELD_KINDS = frozenset({"verdict", "report", "salvage"})

# The least output room a held call is given once the spend is exhausted, or
# its own cap when that is smaller: an answer held to a handful of tokens is
# no answer. What it writes past the ceiling is recorded in ``held_calls``.
MIN_ANSWER_TOKENS = 8192


class SpendCeilingStop(Exception):
    """A model call the operator's spend ceiling does not admit, in the words the run records."""


def spend_bound(ledger: Any, llm: Any, prompt_chars: int, cap_tokens: int) -> int | None:
    """A report section's output cap under the spend ceiling, or ``None`` for its own."""
    meter = getattr(ledger, "spend", None)
    if not isinstance(meter, SpendMeter):
        return None
    try:
        from maljan.llm.generation_rate import model_name_of

        held: int | None = meter.admit(
            kind="report",
            model=model_name_of(llm),
            prompt_chars=int(prompt_chars),
            cap_tokens=int(cap_tokens),
        )
        return held
    except Exception:  # noqa: BLE001 — a report section is never lost over the meter
        return None


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        return None
    return float(value)


class Price:
    """One model's prices per million tokens, and where they were read."""

    __slots__ = ("cached_input", "input", "output", "source")

    def __init__(
        self, input: float, output: float, cached_input: float | None = None, source: str = ""
    ) -> None:
        self.input = float(input)
        self.output = float(output)
        self.cached_input = None if cached_input is None else float(cached_input)
        self.source = str(source or "")

    def cost(self, usage: Mapping[str, Any]) -> float:
        """What one call's reported usage costs at these prices."""
        total_in = int(usage.get("input_tokens") or 0)
        cached = min(total_in, int(usage.get("cached_input_tokens") or 0))
        cached_price = self.input if self.cached_input is None else self.cached_input
        out = int(usage.get("output_tokens") or 0)
        return (
            (total_in - cached) * self.input + cached * cached_price + out * self.output
        ) / MILLION


def _price_from(row: Any, source: str = "") -> Price | None:
    """A ``Price`` from a settings row or a table row, or ``None`` when it is not one."""
    read = row.model_dump() if hasattr(row, "model_dump") else row
    if not isinstance(read, Mapping):
        return None
    given_in = _number(read.get("input_usd_per_mtok"))
    given_out = _number(read.get("output_usd_per_mtok"))
    if given_in is None or given_out is None:
        return None
    return Price(
        given_in,
        given_out,
        _number(read.get("cached_input_usd_per_mtok")),
        str(read.get("source") or source),
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


class SpendMeter:
    """One job's spend against the operator's ceiling. Thread-safe; never raises."""

    def __init__(
        self,
        ceiling_usd: float | None = None,
        prices: Mapping[str, Any] | None = None,
        *,
        table: Mapping[str, Price] | None = None,
    ) -> None:
        self.ceiling_usd = None if ceiling_usd is None else float(ceiling_usd)
        self._lock = threading.Lock()
        self._operator: dict[str, Price] = {}
        for key, row in (prices or {}).items():
            price = _price_from(row, "llm.model_prices")
            if price is not None:
                if not price.source:
                    price.source = "llm.model_prices"
                self._operator[_clean(key)] = price
        self._table = dict(table) if table is not None else None
        self._settled = 0.0
        self._in_flight: dict[Any, float] = {}
        self._unpriced: dict[str, int] = {}
        self._priced_from: dict[str, str] = {}
        self._reached_at: float | None = None
        self._said_unpriced = False
        self._unreported = 0
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

    def price_of(self, model: str) -> Price | None:
        """The price of ``model``: the operator's, else the vendored table's, else ``None``."""
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

    def _cost(self, usage: Mapping[str, Any] | None, model: str) -> float | None:
        if usage is None:
            self._note_unreported()
            return None
        price = self.price_of(model)
        name = _clean(model) or "(unnamed model)"
        if price is None:
            self._note_unpriced(name)
            return None
        with self._lock:
            self._priced_from.setdefault(name, price.source)
        return price.cost(usage)

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

    def settle(self, usage: Mapping[str, Any] | None, model: str) -> None:
        """One recorded call, from the token ledger."""
        try:
            cost = self._cost(usage, model)
            if cost is not None:
                with self._lock:
                    self._settled += cost
        except Exception as exc:  # noqa: BLE001 — telemetry never costs a run
            logger.debug("spend not settled (%s).", exc)

    def note_loop(self, key: Any, turns: list[Any], model: str = "") -> None:
        """What a running loop's turns so far cost, counted until the ledger has them."""
        try:
            from maljan.core.token_ledger import turn_usage
            from maljan.llm.fallback import turn_model

            total = 0.0
            for turn in turns:
                if getattr(turn, "type", "") != "ai":
                    continue
                answered_by, _fallback = turn_model(turn, model)
                if not answered_by:
                    metadata = getattr(turn, "response_metadata", None) or {}
                    answered_by = str(metadata.get("model_name") or "")
                usage = turn_usage(turn)
                if usage is None:
                    continue
                price = self.price_of(answered_by)
                if price is None:
                    continue
                total += price.cost(usage)
            with self._lock:
                self._in_flight[key] = total
        except Exception as exc:  # noqa: BLE001 — telemetry never costs a run
            logger.debug("in-flight spend not noted (%s).", exc)

    def forget_loop(self, key: Any) -> None:
        """A loop whose turns the ledger now holds (or never will)."""
        with self._lock:
            self._in_flight.pop(key, None)

    def remaining(self) -> float | None:
        """US dollars left under the ceiling, or ``None`` with no ceiling."""
        if self.ceiling_usd is None:
            return None
        return max(0.0, self.ceiling_usd - self.spent())

    def worst_case(self, model: str, prompt_tokens: int, output_tokens: int) -> float | None:
        """What one call could cost at most: its whole prompt uncached and its whole output cap."""
        price = self.price_of(model)
        if price is None:
            return None
        return price.cost({"input_tokens": int(prompt_tokens), "output_tokens": int(output_tokens)})

    def output_room(self, model: str, prompt_tokens: int) -> int | None:
        """Output tokens the remaining spend pays for after this prompt, or ``None`` unknown."""
        price = self.price_of(model)
        left = self.remaining()
        if price is None or left is None or price.output <= 0:
            return None
        after_prompt = left - price.cost({"input_tokens": int(prompt_tokens), "output_tokens": 0})
        return max(0, int(after_prompt * MILLION / price.output))

    def admit(self, *, kind: str, model: str, prompt_chars: int, cap_tokens: int) -> int | None:
        """Whether a call may be made, before it is: ``None`` as it is, a number as a lowered cap.

        With no ceiling every call is made as it is. With one, and while the
        spend is not exhausted, a call whose worst case — its whole prompt as
        uncached input and its whole output cap as output, at its model's
        prices — fits what is left is made as it is. Otherwise the spend is
        exhausted (:meth:`exhausted`, latched here the first time) and only a
        :data:`HELD_KINDS` call is made: its output cap lowered to what the
        remaining spend pays for after its prompt, and never below
        :data:`MIN_ANSWER_TOKENS` (or its own cap, when that is smaller), the
        overshoot recorded. Any other call raises :class:`SpendCeilingStop`. A
        call of a model with no price cannot be measured and is made as it is
        until the spend is exhausted. Every lowered or refused call is logged
        and recorded.
        """
        if self.ceiling_usd is None:
            return None
        from maljan.llm.context_window import CHARS_PER_TOKEN

        prompt_tokens = -(-max(0, int(prompt_chars)) // CHARS_PER_TOKEN)
        cap = max(0, int(cap_tokens or 0))
        exhausted = self.exhausted()
        worst = self.worst_case(model, prompt_tokens, cap) if cap else None
        left = self.remaining() or 0.0
        if not exhausted and (worst is None or worst <= left):
            return None
        name = _clean(model) or "the model"
        if kind not in HELD_KINDS:
            said = (
                f"a {kind} call of {name} was not made: the spend ceiling of "
                f"{self.ceiling_usd:.4f} USD "
                + (
                    "is exhausted"
                    if exhausted
                    else f"leaves {left:.4f} USD, under its worst case of {worst or 0:.4f} USD"
                )
            )
            self._exhaust("a worst-case refusal", said)
            self._note_held(said)
            raise SpendCeilingStop(said)
        self._exhaust("a worst-case refusal" if not self.reached() else "reached", "")
        room = self.output_room(model, prompt_tokens) or 0
        floor = min(MIN_ANSWER_TOKENS, cap) if cap else MIN_ANSWER_TOKENS
        held = max(room, floor)
        if cap and held >= cap:
            if room < cap:
                self._note_held(
                    f"the {kind} call of {name} was made at its own {cap:,}-token cap, past what "
                    f"the {left:.4f} USD left under the spend ceiling pays for ({room:,} tokens): "
                    "an answer is never given less room than that cap or "
                    f"{MIN_ANSWER_TOKENS:,} tokens"
                )
            return None
        if held > room:
            said = (
                f"the {kind} call of {name} was held to {held:,} output tokens (its cap was "
                f"{cap:,}), the minimum answer room, past the {room:,} tokens the {left:.4f} USD "
                "left under the spend ceiling pays for"
            )
        else:
            said = (
                f"the {kind} call of {name} was held to {held:,} output tokens (its cap was "
                f"{cap:,}): what the {left:.4f} USD left under the spend ceiling pays for"
            )
        self._note_held(said)
        return held

    def exhausted(self) -> bool:
        """Whether the spend is exhausted: the ceiling reached, or a call refused or held for it.

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

    def spent(self) -> float:
        with self._lock:
            return self._settled + sum(self._in_flight.values())

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
            else "was exhausted: a call's worst case would have passed what was left"
        )
        return (
            f"The spend ceiling of {self.ceiling_usd:.4f} USD {how} ({spent}). The tool phases "
            "still running ended there and their agents wrote their answers from what they had "
            "gathered; no further negotiation round, chunk, ask or tool loop was started, and "
            "only the verdict and the report ran, tool-free."
        )

    def snapshot(self) -> dict[str, Any] | None:
        """The run summary's ``spend`` block, or ``None`` with no ceiling set."""
        if self.ceiling_usd is None:
            return None
        with self._lock:
            out: dict[str, Any] = {
                "ceiling_usd": self.ceiling_usd,
                "spent_usd": round(self._settled + sum(self._in_flight.values()), 6),
                "reached": self._reached_at is not None,
                "exhausted": self._exhausted is not None,
                "prices_from": dict(sorted(self._priced_from.items())),
            }
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
