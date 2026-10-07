"""The function claim check grows with the claims, not with claims times strings times sources.

The names a sentence may name, the sample strings and the index rows are read
once per answer; each claim then reads only its own values against them. Ten
times the claims, over the same index and the same large strings answer, take
about ten times as long.

Every name, string and address here is made up for the test.
"""

from __future__ import annotations

import gc
import json
import time
from types import SimpleNamespace

from maljan.agents.function_map import function_artefacts
from maljan.pipeline.events import _catalogue_names
from maljan.pipeline.function_claims import (
    _catalogue_lower,
    _clause_starts,
    check_function_claims,
    function_facts,
    listed_functions,
    named_values,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import ClaimEvidence

BASE = 0x140000000
FUNCTIONS = 200


def _setup() -> tuple[list[LedgerEntry], list[LedgerEntry]]:
    rows = [
        {
            "function": hex(BASE + 0x1000 + 0x10 * i),
            "offset": hex(0x1000 + 0x10 * i),
            "direct": 2,
            "imports": [{"name": f"RtlUserRoutine{i:03d}", "sources": ["this entry"]}],
            "decoded_strings": [{"text": f"setting number {i:03d}", "sources": ["ev_0003"]}],
            "callers": [],
            "callees": [hex(BASE + 0x1000 + 0x10 * (i + 1))] if i + 1 < FUNCTIONS else [],
        }
        for i in range(FUNCTIONS)
    ]
    data = {
        "tool": "function_index",
        "image_base": hex(BASE),
        "undecoded_functions": 0,
        "undecoded": [],
        "calls_unnamed": {},
        "other_callees": {},
        "rows": rows,
    }
    index = LedgerEntry(
        id="ev_0002", agent="pipeline", tool="function_index", output="{}", structured=data
    )
    strings = LedgerEntry(
        id="ev_0003",
        agent="pipeline",
        tool="strings",
        output=json.dumps([f"a printable text {k:06d}" for k in range(20_000)]),
    )
    listing = LedgerEntry(
        id="ev_0007",
        tool="decompile_function",
        args={"address": hex(BASE + 0x1000 + 0x10 * (FUNCTIONS - 1))},
        output="void f(void) { }",
    )
    return [index, strings], [listing]


def _timed(claims: int) -> float:
    pack, own = _setup()
    sentence = (
        f"0x{BASE + 0x1000 + 0x10 * (FUNCTIONS - 1):x} calls RtlUserRoutine001 and "
        'CreateMutexW and reads "a printable text 000001", "setting number 007" and '
        '"a printable text 019999".'
    )
    isr = SimpleNamespace(
        claims=[
            ClaimEvidence(claim=f"{sentence} {n}", evidence_ref="[ev_0007]", confidence=0.5)
            for n in range(claims)
        ]
    )
    began = time.perf_counter()
    facts = function_facts(own, function_artefacts(pack), pack_entries=pack, bases=(BASE,))
    found = check_function_claims(isr, listed_functions(own), facts, (BASE,))
    seconds = time.perf_counter() - began
    assert found.asked == claims
    return seconds


class TestTheCheckGrowsWithTheClaims:
    def test_ten_times_the_claims_take_about_ten_times_as_long(self) -> None:
        _timed(100)
        low = min(_timed(300) for _ in range(2))
        high = min(_timed(3_000) for _ in range(2))
        print("function claims, 300 and 3,000:", round(low, 3), round(high, 3))
        assert high < low * 20


def _grown(scale: int) -> float:
    """``scale`` claims over a chain of ``20 * scale`` functions, each holding two strings."""
    functions = 20 * scale
    offsets = [0x100000 + 0x10 * i for i in range(functions)]
    rows = [
        {
            "function": hex(BASE + offset),
            "offset": hex(offset),
            "direct": 2,
            "imports": [],
            "plain_strings": [
                {"text": f"text {i} {j}", "sources": ["this entry"]} for j in range(2)
            ],
            "callers": [hex(BASE + offsets[i - 1])] if i else [],
            "callees": [hex(BASE + offsets[i + 1])] if i + 1 < functions else [],
        }
        for i, offset in enumerate(offsets)
    ]
    data = {
        "tool": "function_index",
        "image_base": hex(BASE),
        "undecoded_functions": 0,
        "undecoded": [],
        "calls_unnamed": {},
        "other_callees": {},
        "rows": rows,
    }
    index = LedgerEntry(
        id="ev_0002", agent="pipeline", tool="function_index", output="{}", structured=data
    )
    listing = LedgerEntry(
        id="ev_0007",
        tool="decompile_function",
        args={"address": hex(BASE + offsets[0])},
        output="void f(void) { }",
    )
    far = functions - 1
    isr = SimpleNamespace(
        claims=[
            ClaimEvidence(
                claim=f'0x{BASE + offsets[0]:x} reads "text {far} 0" and "text {far} 1", {n}.',
                evidence_ref="[ev_0007]",
                confidence=0.5,
            )
            for n in range(scale)
        ]
    )
    began = time.perf_counter()
    facts = function_facts([listing], function_artefacts([index]), pack_entries=[index])
    found = check_function_claims(isr, listed_functions([listing]), facts, (BASE,))
    seconds = time.perf_counter() - began
    assert found.asked == 0 and found.checked == scale
    return seconds


class TestTheCheckGrowsWithClaimsAndGraphTogether:
    def test_ten_times_the_claims_over_ten_times_the_graph_take_about_ten_times_as_long(
        self,
    ) -> None:
        _grown(20)
        low = min(_grown(100) for _ in range(2))
        high = _grown(1_000)
        print("claims over a graph, 100 over 2,000 and 1,000 over 20,000:", low, high)
        assert high < low * 20

    def test_claims_naming_several_functions_cost_the_listings_times_the_graph_alone(
        self,
    ) -> None:
        low, kept_low = _paired(19)
        high, kept_high = _paired(190)
        print("claims naming two of 20 listed functions, 19 and 190:", low, high)
        assert kept_low == kept_high == LISTINGS
        assert high < low * 3


LISTINGS = 20


def _paired(count: int) -> tuple[float, int]:
    """``count`` claims, each naming two of 20 listed functions at the head of a chain of
    20,000 functions: each listed function reaches nearly the whole chain."""
    functions = 20_000
    offsets = [0x100000 + 0x10 * i for i in range(functions)]
    rows = [
        {
            "function": hex(BASE + offset),
            "offset": hex(offset),
            "direct": 2,
            "imports": [{"name": "CreateMutexW", "sources": ["this entry"]}],
            "plain_strings": [
                {"text": f"text {i} {j}", "sources": ["this entry"]} for j in range(2)
            ],
            "callers": [hex(BASE + offsets[i - 1])] if i else [],
            "callees": [hex(BASE + offsets[i + 1])] if i + 1 < functions else [],
        }
        for i, offset in enumerate(offsets)
    ]
    data = {
        "tool": "function_index",
        "image_base": hex(BASE),
        "undecoded_functions": 0,
        "undecoded": [],
        "calls_unnamed": {},
        "other_callees": {},
        "rows": rows,
    }
    index = LedgerEntry(
        id="ev_0002", agent="pipeline", tool="function_index", output="{}", structured=data
    )
    listings = [
        LedgerEntry(
            id=f"ev_{100 + k:04d}",
            agent="reverser",
            tool="decompile_function",
            args={"address": hex(BASE + offsets[k])},
            output="void f(void) { }",
        )
        for k in range(LISTINGS)
    ]
    pairs = [(a, b) for a in range(LISTINGS) for b in range(a + 1, LISTINGS)][:count]
    isr = SimpleNamespace(
        claims=[
            ClaimEvidence(
                claim=(
                    f"0x{BASE + offsets[a]:x} and 0x{BASE + offsets[b]:x} guard with CreateMutexW."
                ),
                evidence_ref=f"[ev_{100 + a:04d}] [ev_{100 + b:04d}]",
                confidence=0.5,
            )
            for a, b in pairs
        ]
    )
    facts = function_facts(
        listings, function_artefacts([index]), pack_entries=[index], bases=(BASE,)
    )
    # The collector's sweeps of the whole test session's heap are not the check's cost.
    gc.collect()
    gc.disable()
    try:
        began = time.perf_counter()
        found = check_function_claims(isr, listed_functions(listings), facts, (BASE,))
        seconds = time.perf_counter() - began
    finally:
        gc.enable()
    assert found.asked == 0 and found.checked == count
    return seconds, len(facts.reaches)


class TestASentenceIsReadInWindows:
    def test_a_text_of_dots_finds_its_sentences_in_well_under_a_second(self) -> None:
        for unit in ("x. ", "e.g. ", "a."):
            text = (unit * (200_000 // len(unit) + 1))[:200_000]
            began = time.perf_counter()
            _clause_starts(text)
            seconds = time.perf_counter() - began
            print("sentences of 200 KB of", repr(unit), round(seconds, 3))
            assert seconds < 1.0

    def test_an_abbreviation_still_ends_no_sentence_and_a_long_word_still_does(self) -> None:
        assert _clause_starts("it reads e.g. the key") == [0]
        assert _clause_starts("it reads xapprox. Then it") == [0, 17]

    def test_four_thousand_distinct_names_in_one_sentence_are_read_in_well_under_a_second(
        self,
    ) -> None:
        names = sorted(n for n in _catalogue_names() if any(ch.isupper() for ch in n[1:]))
        text = " ".join(names[:4_000])
        assert len(text) > 60_000
        known = _catalogue_lower()
        began = time.perf_counter()
        apis, _strings = named_values(text, known)
        seconds = time.perf_counter() - began
        print("4,000 names in one sentence:", round(seconds, 3))
        assert len(apis) > 3_000
        assert seconds < 1.0

    def test_a_statement_of_absence_is_still_read_around_a_name_in_a_long_sentence(
        self,
    ) -> None:
        filler = " ".join(f"step{k}" for k in range(5_000))
        text = f"{filler} and it does not use CreateRemoteThread, {filler} it calls CreateMutexW"
        apis, _strings = named_values(text, _catalogue_lower())
        assert apis == ["CreateMutexW"]
