"""The readers of model-written text run in time linear in the text, on hostile lines too.

A model answer is untrusted and can be arbitrarily long. Each reader below is
given a line of about 200 KB of words with no comma, semicolon or full stop and
many technique-id tokens, and ten times less of the same; the long one may cost
at most a constant factor more than ten times the short one. Nothing is cut to
make it pass.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from maljan.agents.base_agent import (
    _EVIDENCE_ENDS_INLINE_RE,
    _PARTIAL_ID_AT_END_RE,
    read_technique_line,
)
from maljan.agents.claim_headings import CLAIM_HEAD_RE, claim_heading_counts
from maljan.agents.repeat_watch import ClaimRepeatReader
from maljan.pipeline.claim_drops import claim_substance
from maljan.pipeline.debate_facts import fact_atoms, ledger_count_facts, ledger_stated
from maljan.pipeline.validation import EntryTexts, ledger_absence_contradictions
from maljan.schemas.evidence import build_entry

UNIT = "T1234 Native words T1106 more is not read 0x1400 which that 12 hits Web Protocols "
FACTOR = 30


def _hostile(size: int) -> str:
    return (UNIT * (size // len(UNIT) + 1))[:size]


def _scales_linearly(read: Callable[[str], object]) -> None:
    def cost(text: str) -> float:
        start = time.perf_counter()
        read(text)
        return time.perf_counter() - start

    cost(_hostile(2_000))
    small = cost(_hostile(20_000))
    large = cost(_hostile(200_000))
    assert large <= max(small, 1e-3) * FACTOR, (small, large)


ENTRIES = EntryTexts.from_ledger(
    [
        build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="a",
            server="a",
            tool="decompile_function",
            args={"address": "0x1400"},
            output="undefined8 FUN_00001400(void)\n{ FUN_00001800(); }",
        )
    ]
)
LEDGER = [{"id": "ev_0001", "tool": "t", "structured": {"matches": [], "total": 12}}]


@pytest.mark.parametrize(
    "read",
    [
        pytest.param(read_technique_line, id="technique line"),
        pytest.param(lambda t: read_technique_line("T1106 " + t), id="technique line after an id"),
        pytest.param(lambda t: CLAIM_HEAD_RE.match("CLAIM " + t), id="claim heading"),
        pytest.param(lambda t: CLAIM_HEAD_RE.match("CLAIM" + " " * len(t) + "x"), id="spaces"),
        pytest.param(lambda t: claim_heading_counts("CLAIM R1: " + t), id="heading counts"),
        pytest.param(lambda t: ClaimRepeatReader(None).feed("CLAIM R1: " + t), id="streaming"),
        pytest.param(
            lambda t: ledger_absence_contradictions({"body": t}, ENTRIES), id="absence sentences"
        ),
        pytest.param(
            lambda t: ledger_count_facts(["[analysts: A] ev_0001 " + t], {}, LEDGER, ["a"]),
            id="ledger counts",
        ),
        pytest.param(
            lambda t: ledger_stated(
                ["[analysts: A] ev_0001 " + t],
                {},
                LEDGER,
                ["a"],
                ["entry ev_0001 states total = 12."],
            ),
            id="stated lines",
        ),
        pytest.param(
            lambda t: fact_atoms(['For the line "x": ' + "entry ev_1 (" * (len(t) // 12)]),
            id="stated fact parts",
        ),
        pytest.param(
            lambda t: read_technique_line("T1106" + " " * len(t) + "1"),
            id="technique line with a run of spaces",
        ),
        pytest.param(
            lambda t: read_technique_line("T1106" + " - " * (len(t) // 3) + "x"),
            id="technique line with spaced dashes",
        ),
        pytest.param(
            lambda t: _EVIDENCE_ENDS_INLINE_RE.search(" " * len(t) + "x"),
            id="evidence end after a run of spaces",
        ),
        pytest.param(
            lambda t: _PARTIAL_ID_AT_END_RE.sub("", " " * len(t) + "x"),
            id="partial id after a run of spaces",
        ),
        pytest.param(
            lambda t: claim_substance(
                SimpleNamespace(claims=[SimpleNamespace(claim=t + "a" + "." * len(t))])
            ),
            id="claim substance",
        ),
        pytest.param(
            lambda t: ledger_absence_contradictions(
                {
                    "body": "The names "
                    + "(" * (len(t) // 2)
                    + "A1)" * (len(t) // 4)
                    + " are not read."
                },
                ENTRIES,
            ),
            id="absence sentence with brackets",
        ),
    ],
)
def test_ten_times_the_hostile_line_costs_at_most_ten_times(read: Callable[[str], object]) -> None:
    _scales_linearly(read)
