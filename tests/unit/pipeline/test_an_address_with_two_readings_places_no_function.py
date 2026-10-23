"""An answer's function address is placed only when it has one reading.

A function index keys its rows by offset (RVA); an answer may give the
address as an offset or as a virtual address. When both readings name a
function the index knows, which one the answer meant cannot be told, so the
address places no function rather than the wrong one.
"""

from __future__ import annotations

from maljan.pipeline.function_claims import FunctionFacts


def _facts(*known: int, bases: tuple[int, ...] = (0x10000,)) -> FunctionFacts:
    return FunctionFacts(base=bases[0], bases=bases, known=set(known))


def test_an_offset_or_a_virtual_address_with_one_reading_is_placed() -> None:
    facts = _facts(0x1000)
    assert facts.offset(0x1000) == 0x1000
    assert facts.offset(0x11000) == 0x1000


def test_an_address_both_readings_name_a_function_places_none() -> None:
    facts = _facts(0x1000, 0x11000)
    assert facts.offset(0x11000) is None
    assert facts.offset(0x1000) == 0x1000


def test_two_bases_giving_two_functions_place_none() -> None:
    facts = _facts(0x1000, 0x2000, bases=(0x400000, 0x401000))
    assert facts.offset(0x402000) is None


def test_two_bases_giving_the_same_function_place_it() -> None:
    facts = _facts(0x1000, bases=(0x400000, 0x400000))
    assert facts.offset(0x401000) == 0x1000


def test_an_unknown_address_places_none() -> None:
    assert _facts(0x1000).offset(0x5000) is None
    assert _facts(0x1000).offset(None) is None


def test_of_two_readings_the_one_whose_row_shows_the_cited_address_is_placed() -> None:
    facts = _facts(0x1000, 0x11000)
    facts.rows = {0x1000: {"function": "0x1000"}, 0x11000: {"function": "0x11000"}}
    assert facts.offset(0x11000) == 0x11000
    facts.rows = {0x1000: {"function": "0x11000"}, 0x11000: {"function": "0x21000"}}
    assert facts.offset(0x11000) == 0x1000


def test_two_rows_showing_the_cited_address_or_none_place_none() -> None:
    facts = _facts(0x1000, 0x11000)
    facts.rows = {0x1000: {"function": "0x11000"}, 0x11000: {"function": "0x11000"}}
    assert facts.offset(0x11000) is None
    facts.rows = {0x1000: {"function": "0x9000"}, 0x11000: {"function": "0x21000"}}
    assert facts.offset(0x11000) is None
