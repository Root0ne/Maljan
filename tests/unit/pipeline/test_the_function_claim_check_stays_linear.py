"""The function claim check grows with the claims, not with claims times strings times sources.

The names a sentence may name, the sample strings and the index rows are read
once per answer; each claim then reads only its own values against them. Ten
times the claims, over the same index and the same large strings answer, take
about ten times as long.

Every name, string and address here is made up for the test.
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

from maljan.agents.function_map import function_artefacts
from maljan.pipeline.function_claims import check_function_claims, function_facts, listed_functions
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
