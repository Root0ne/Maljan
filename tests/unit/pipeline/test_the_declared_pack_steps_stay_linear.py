"""The declared step list and the readings by kind grow linearly with what they read.

Ten times the steps an operator declares, ten times the function starts and
rules an answer lists, ten times the rows a generic line counts and ten times
the rules a rule line read through its declaration shows each take
about ten times as long: a quadratic step would take a hundred.
"""

from __future__ import annotations

import gc
import time
from collections.abc import Callable
from typing import Any

from maljan.core.pack_steps import effective_steps
from maljan.pipeline.triage_pack import PIPELINE, index_inputs, render_pack
from maljan.schemas.evidence import LedgerEntry


def _seconds(work: Callable[[], Any]) -> float:
    gc.collect()
    gc.disable()
    try:
        began = time.perf_counter()
        work()
        return time.perf_counter() - began
    finally:
        gc.enable()


def _ratio(make: Callable[[int], Callable[[], Any]], small: int) -> tuple[float, float]:
    """The seconds at ``small`` and at ten times it, each the least of two runs after a warm-up."""
    _seconds(make(small))
    low = min(_seconds(make(small)) for _ in range(2))
    high = min(_seconds(make(small * 10)) for _ in range(2))
    return low, high


def _declared_steps(n: int) -> list[dict[str, Any]]:
    """``n`` new steps, each after the one before it, a shipped step moved after the last."""
    steps: list[dict[str, Any]] = [
        {"id": f"step_{i}", "server": "s", "tool": "t", **({"after": f"step_{i - 1}"} if i else {})}
        for i in range(n)
    ]
    return [*steps, {"id": "strings", "after": f"step_{n - 1}"}, {"id": "capa", "enabled": False}]


def _declared(n: int) -> Callable[[], Any]:
    steps = _declared_steps(n)
    return lambda: effective_steps(steps)


def _matcher(n: int, kind: str = "capability_rules") -> LedgerEntry:
    data = {
        "functions": [hex(0x1000 + 16 * i) for i in range(n)],
        "hits": [{"name": f"rule {i}", "at": [hex(0x1000 + 16 * i)]} for i in range(n)],
    }
    return LedgerEntry(
        id="ev_0001",
        agent=PIPELINE,
        server="rules",
        tool="match",
        output="",
        structured=data,
        facts={
            "v": 1,
            "kind": kind,
            "rows": "/hits/*",
            "places": {"addresses": "/at"},
            "values": {"rule": "/name"},
            "function_starts": "/functions",
        },
    )


def _joined(n: int) -> Callable[[], Any]:
    entries = [_matcher(n)]
    return lambda: index_inputs(entries)


def _listed(n: int) -> Callable[[], Any]:
    """A generic line counting ``n`` rows, each with its value and place."""
    entry = _matcher(n, "rule_table").model_copy(update={"pack_step": {"v": 1, "id": "match"}})
    return lambda: render_pack([entry], 0)


def _ruled(n: int) -> Callable[[], Any]:
    """A rule matcher's line read through its declaration: ``n`` rules, each where it matched."""
    entry = _matcher(n).model_copy(update={"pack_step": {"v": 1, "id": "match"}})
    return lambda: render_pack([entry], 0)


class TestTenTimesTheInput:
    def test_the_declared_steps(self) -> None:
        low, high = _ratio(_declared, 2_000)
        print("declared steps:", round(low, 4), round(high, 4))
        assert high < low * 20
        ids = [step.id for step in effective_steps(_declared_steps(2_000))]
        assert ids.index("strings") == ids.index("step_1999") + 1

    def test_the_function_starts_and_rules_an_answer_lists(self) -> None:
        low, high = _ratio(_joined, 5_000)
        print("starts and rules:", round(low, 4), round(high, 4))
        assert high < low * 20
        joined = index_inputs([_matcher(5_000)])
        assert len(joined.function_starts[0][2]) == 5_000
        assert len(joined.rule_hits[0][2]) == 5_000

    def test_the_rows_a_generic_line_counts(self) -> None:
        low, high = _ratio(_listed, 5_000)
        print("generic line rows:", round(low, 4), round(high, 4))
        assert high < low * 20
        assert render_pack(
            [_matcher(3, "rule_table").model_copy(update={"pack_step": {"v": 1, "id": "m"}})], 0
        ) == (
            "[ev_0001] match: 3 rows of kind rule_table "
            "(rule 0 @ 0x1000, rule 1 @ 0x1010, rule 2 @ 0x1020)"
        )

    def test_the_rules_a_declared_rule_line_shows(self) -> None:
        low, high = _ratio(_ruled, 5_000)
        print("declared rule line:", round(low, 4), round(high, 4))
        assert high < low * 20
        assert render_pack(
            [_matcher(3).model_copy(update={"pack_step": {"v": 1, "id": "m"}})], 0
        ) == (
            "[ev_0001] match: 3 capabilities (rule 0 @ 0x1000, rule 1 @ 0x1010, rule 2 @ "
            "0x1020); each rule @ the offsets from the image base where it matched"
        )
