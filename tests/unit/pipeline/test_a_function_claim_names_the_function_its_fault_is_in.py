"""A function claim's record names the function a fault is in, and counts each function once.

A claim naming two functions said "the decoder stopped in <the first>" whichever
of them it stopped in, and a function cited twice (by its address and by its
offset) was subtracted twice from the count of what it reaches.
"""

from __future__ import annotations

from maljan.pipeline import function_claims as fc
from maljan.schemas.evidence import LedgerEntry
from tests.unit.pipeline.test_a_function_claim_is_checked_against_its_function_s_facts import (
    BASE,
    MAIN,
    MAIN_VA,
    OTHER,
    ROWS,
    _check,
    _index,
    _listing,
)


def _decompile(entry: str, address: int) -> LedgerEntry:
    return LedgerEntry(
        id=entry,
        agent="reverser",
        tool="decompile_function",
        args={"address": f"{address:x}"},
        output=f"\nundefined8 FUN_{address:x}(void)\n\n{{\n  return 0;\n}}\n",
    )


def test_the_function_the_decoder_stopped_in_is_the_one_named() -> None:
    other_va = f"0x{BASE + OTHER:x}"
    found = _check(
        f"{MAIN_VA} and {other_va} call SleepEx.",
        own=[_listing(), _decompile("ev_0009", BASE + OTHER)],
        evidence="[ev_0007] [ev_0009]",
        index=_index(ROWS, undecoded=[OTHER]),
    )
    assert found.not_checked == [f"claim 1: {fc.UNDECODED.format(address=other_va)}"]


def test_a_function_cited_twice_is_counted_once() -> None:
    found = _check(
        f"{MAIN_VA} and 0x{MAIN:x} sleep with SleepEx.",
        own=[_listing(), _decompile("ev_0009", MAIN)],
        evidence="[ev_0007] [ev_0009]",
    )
    (violation,) = found.violations
    assert "(2 functions reachable)" in violation.message
    assert violation.message.count("row holds") == 1
    assert " for function " in violation.message and " for functions " not in violation.message
