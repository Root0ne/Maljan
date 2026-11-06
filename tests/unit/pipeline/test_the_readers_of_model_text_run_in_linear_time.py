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
from maljan.pipeline.debate_facts import (
    claim_references_of,
    fact_atoms,
    ledger_count_facts,
    ledger_stated,
    read_claim_references,
    read_marks,
)
from maljan.pipeline.limit_rulings import REASON_LIMIT, clean_quote, read_rulings
from maljan.pipeline.validation import (
    EntryTexts,
    absence_holders_note,
    ledger_absence_contradictions,
)
from maljan.reporting.absence_answers import (
    FailureCounts,
    count_disagrees,
    denied_subject,
    denies_an_observation,
    failure_counts,
    kept_absence,
    negated_clauses,
    quote_stands,
    reading_denied_in,
)
from maljan.reporting.section_agreement import (
    _candidates,
    _reports_a_claim,
    _said_unread,
    _unread_addresses,
    closing_negations,
    unread_listed_sentences,
    whole_code_absences,
)
from maljan.schemas.evidence import build_entry
from tests.linear_cost import TIME_RATIO_LIMIT, cpu_seconds

UNIT = "T1234 Native words T1106 more is not read 0x1400 which that 12 hits Web Protocols "
# The short line's least size and CPU time, and the largest size it grows to.
SMALLEST = 20_000
LEAST_SECONDS = 0.01
LARGEST = 1_280_000


_COUNTS = FailureCounts(failed=2, redone=1, by_name={"decompil": (1, 1)})


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
# A fact about a routine an entry lists, as the agreement round reads it.
LISTED = [SimpleNamespace(addresses=frozenset({0x1400}), id="listed.1")]


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
            lambda t: ledger_absence_contradictions(
                {
                    "body": "The body of 0x1400"
                    + ", which a" * (len(t) // 9)
                    + " is not in my rows."
                },
                ENTRIES,
            ),
            id="a subject of many asides",
        ),
        pytest.param(
            lambda t: ledger_absence_contradictions(
                {"body": "the " + "plain " * (len(t) // 6) + "slots 0x1400 remain unresolved."},
                ENTRIES,
            ),
            id="many words describing a kind noun",
        ),
        pytest.param(
            lambda t: absence_holders_note("Slot 0x1400 is unresolved, and " + t, ENTRIES),
            id="a claim's absence note",
        ),
        pytest.param(
            lambda t: ledger_count_facts([" " * len(t) + "x"], {}, LEDGER, ["a"]),
            id="claim numbers after a run of spaces",
        ),
        pytest.param(
            lambda t: ledger_count_facts(["T1106" + " " * len(t) + "1"], {}, LEDGER, ["a"]),
            id="claim numbers between an id and a number",
        ),
        pytest.param(
            lambda t: read_marks(
                ["[analysts: a]" + " [new]" * (len(t) // 6) + " [not blocking: x"]
            ),
            id="many marks after the field and one left open",
        ),
        pytest.param(
            lambda t: read_marks(["[analysts: a] [not blocking: " + "[x] " * (len(t) // 4)]),
            id="a mark after the field whose reason never closes",
        ),
        pytest.param(
            lambda t: claim_references_of(
                "[analysts: a] " + "its claim 3 own " * (len(t) // 16), ["a", "b"], ["a"]
            ),
            id="its claims on a one-analyst line",
        ),
        pytest.param(
            lambda t: read_claim_references(
                ["[analysts: a] " + "its claim 3 own " * (len(t) // 16) + "[blocking: x]"],
                ["a", "b"],
            ),
            id="the merge's reading of its claims",
        ),
        pytest.param(
            lambda t: read_claim_references(
                ["[analysts: a, b] " + "claim 3 " * (len(t) // 8) + "[blocking: x]"], ["a", "b"]
            ),
            id="claim numbers read for no analyst",
        ),
        pytest.param(
            lambda t: unread_listed_sentences(t, LISTED),  # type: ignore[arg-type]
            id="sentences calling listed code unread",
        ),
        pytest.param(lambda t: _unread_addresses(t, t), id="addresses said unread"),
        pytest.param(lambda t: _said_unread([SimpleNamespace(text=t)]), id="said unread"),  # type: ignore[list-item]
        pytest.param(whole_code_absences, id="whole-code absences"),
        pytest.param(closing_negations, id="closing negations"),
        pytest.param(_reports_a_claim, id="a reported claim"),
        pytest.param(
            lambda t: whole_code_absences(t, unsettled=True), id="unsettled section 5 absences"
        ),
        pytest.param(negated_clauses, id="negated clauses"),
        pytest.param(
            lambda t: denied_subject("and, " * (len(t) // 5) + " not known"),
            id="the items of what a sentence denies",
        ),
        pytest.param(
            lambda t: reading_denied_in("no " * (len(t) // 3) + "0x1400 was not read."),
            id="the clause denying a reading",
        ),
        pytest.param(
            lambda t: denies_an_observation("not " + "that word " * (len(t) // 10)),
            id="a denied observation",
        ),
        pytest.param(
            lambda t: denied_subject("that set " * (len(t) // 9) + "was not known"),
            id="nouns a demonstrative points back with",
        ),
        pytest.param(lambda t: kept_absence(negated_clauses(t), t), id="an absence kept"),
        pytest.param(
            lambda t: kept_absence(
                ["the mutex name is not passed in that call"], "name is not, " * (len(t) // 13)
            ),
            id="an absence kept among many clauses",
        ),
        pytest.param(
            lambda t: kept_absence(
                negated_clauses(
                    "; ".join(f"wordx{i} alphax{i} is not known" for i in range(len(t) // 30))
                ),
                "; ".join(f"betay{i} gammay{i} is not shown" for i in range(len(t) // 30)),
            ),
            id="an absence kept among distinct clauses on both sides",
        ),
        pytest.param(
            lambda t: kept_absence(
                negated_clauses(
                    "; ".join(f"name{i} mutex is not known" for i in range(len(t) // 26))
                ),
                "; ".join(f"name mutex{i} is not shown" for i in range(len(t) // 26)),
            ),
            id="an absence kept among clauses sharing its words",
        ),
        pytest.param(lambda t: quote_stands(t[: len(t) // 2], [t]), id="a kept sentence's quote"),
        pytest.param(
            lambda t: _candidates(
                "The more words of 0x1400 are not read.",
                {
                    "s": SimpleNamespace(
                        id="s",
                        kind="section 5",
                        text=t,
                        cites=frozenset(),
                        addresses=frozenset(),
                        write=print,
                        lists_code=False,
                        label="5",
                    )
                },  # type: ignore[dict-item]
            ),
            id="a refused keep's candidate sources",
        ),
        pytest.param(
            lambda t: failure_counts("4 of 158 calls " * (len(t) // 15) + "failed"),
            id="failure counts",
        ),
        pytest.param(
            lambda t: count_disagrees("3 tool calls failed and " * (len(t) // 24), _COUNTS),
            id="a failure count held to the ledger",
        ),
        pytest.param(lambda t: read_rulings("L1: UPHELD: " + t, 1), id="limit ruling"),
        pytest.param(
            lambda t: read_rulings("L1 " + " " * len(t) + " UPHELD", 1), id="limit ruling spaces"
        ),
        pytest.param(lambda t: read_rulings("- **L1 " + t, 1), id="limit ruling with no word"),
        pytest.param(lambda t: clean_quote(t, REASON_LIMIT), id="limit ruling reason"),
    ],
)
def test_four_times_the_hostile_line_stays_under_the_ratio(read: Callable[[str], object]) -> None:
    _scales_linearly(read)
