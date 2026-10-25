"""The readers of model-written text run in time linear in the text, on hostile lines too.

A model answer is untrusted and can be arbitrarily long. Each reader below is
given a line of words with no comma, semicolon or full stop and many
technique-id tokens, sized so that it costs at least 10 ms of CPU time (from
20 KB up), and four times as much of the same; the long one may cost less than
``TIME_RATIO_LIMIT`` times the short one, each the best CPU time of five runs
(``tests.linear_cost.cpu_seconds``), so a loaded machine does not move it.
Nothing is cut to make it pass.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace

import pytest

from maljan.agents.base_agent import (
    _EVIDENCE_ENDS_INLINE_RE,
    _PARTIAL_ID_AT_END_RE,
    read_technique_line,
)
from maljan.agents.claim_headings import CLAIM_HEAD_RE, claim_blocks
from maljan.agents.repeat_watch import ClaimRepeatReader
from maljan.pipeline.claim_drops import claim_substance
from maljan.pipeline.debate_facts import fact_atoms, ledger_count_facts, ledger_stated
from maljan.pipeline.validation import EntryTexts, ledger_absence_contradictions
from maljan.schemas.evidence import build_entry
from tests.linear_cost import TIME_RATIO_LIMIT, cpu_seconds

UNIT = "T1234 Native words T1106 more is not read 0x1400 which that 12 hits Web Protocols "
# The short line's least size and CPU time, and the largest size it grows to.
SMALLEST = 20_000
LEAST_SECONDS = 0.01
LARGEST = 1_280_000


def _hostile(size: int) -> str:
    return (UNIT * (size // len(UNIT) + 1))[:size]


def _scales_linearly(read: Callable[[str], object]) -> None:
    def cost(size: int) -> float:
        text = _hostile(size)
        return cpu_seconds(lambda: read(text), repeats=5)

    size = SMALLEST
    small = cost(size)
    while small < LEAST_SECONDS and size < LARGEST:
        size *= 2
        small = cost(size)
    large = cost(size * 4)
    assert large < max(small, LEAST_SECONDS) * TIME_RATIO_LIMIT, (size, small, large)


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
        pytest.param(lambda t: claim_blocks("CLAIM R1: " + t), id="claim blocks"),
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
        pytest.param(lambda t: read_technique_line("T1106 (" + t + ")"), id="technique note"),
        pytest.param(
            lambda t: read_technique_line("T1106 (a); " * (len(t) // 10) + "T1106 ("),
            id="technique line of notes left open",
        ),
        pytest.param(
            lambda t: read_technique_line("none" + " " * len(t) + "(T1106 not supported"),
            id="none line with a note left open",
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
        pytest.param(
            lambda t: ledger_absence_contradictions(
                {"body": "is not read, which is not in the ledger. " * (len(t) // 41)}, ENTRIES
            ),
            id="one clause of many statements",
        ),
        pytest.param(
            lambda t: ledger_absence_contradictions(
                {"body": "no a " * (len(t) // 5) + "is in the evidence."}, ENTRIES
            ),
            id="many subjects of no",
        ),
        pytest.param(
            lambda t: ledger_absence_contradictions(
                {"body": "The decompile of " + "x " * (len(t) // 2) + "0x1400 was not obtained."},
                ENTRIES,
            ),
            id="a long decompile subject",
        ),
        pytest.param(
            lambda t: ledger_count_facts([" " * len(t) + "x"], {}, LEDGER, ["a"]),
            id="claim numbers after a run of spaces",
        ),
        pytest.param(
            lambda t: ledger_count_facts(["T1106" + " " * len(t) + "1"], {}, LEDGER, ["a"]),
            id="claim numbers between an id and a number",
        ),
    ],
)
def test_four_times_the_hostile_line_stays_under_the_ratio(read: Callable[[str], object]) -> None:
    _scales_linearly(read)
