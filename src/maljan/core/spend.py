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
    """A model name as the tables key it: lower-cased, without its endpoint, vendor path or tag.

    A model list labels a model ``openai/deepseek-flash @ https://api.deepseek.com``;
    the price is the model's, whichever endpoint served it.
    """
    name = str(model or "").strip().lower().split(" @ ", 1)[0].strip()
    name = name.rsplit("/", 1)[-1]
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
        found = self._operator.get(name)
        if found is not None:
            return found
        table = self._table if self._table is not None else table_prices()
        return table.get(name)

    def _cost(self, usage: Mapping[str, Any] | None, model: str) -> float | None:
        if usage is None:
            return None
        price = self.price_of(model)
        name = _clean(model) or "(unnamed model)"
        if price is None:
            self._note_unpriced(name)
            return None
        with self._lock:
            self._priced_from.setdefault(name, price.source)
        return price.cost(usage)

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
        logger.warning(
            "spend ceiling reached: %.4f USD of %.4f USD; every running tool loop ends its "
            "tool phase and writes its answer from what it gathered.",
            spent,
            self.ceiling_usd,
        )
        return True

    def reason(self) -> str:
        """The degradation reason a reached ceiling gives, or ``""``."""
        with self._lock:
            at = self._reached_at
        if at is None or self.ceiling_usd is None:
            return ""
        return (
            f"The spend ceiling of {self.ceiling_usd:.4f} USD was reached ({at:.4f} USD spent); "
            "the tool phases still running ended there and their agents wrote their answers "
            "from what they had gathered."
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
                "prices_from": dict(sorted(self._priced_from.items())),
            }
            if self._unpriced:
                out["unpriced_models"] = dict(sorted(self._unpriced.items()))
                out["note"] = (
                    "no price for "
                    + ", ".join(sorted(self._unpriced))
                    + ": their calls are not counted, so spent_usd is what the priced calls "
                    "cost and the job spent at least that"
                )
            return out
