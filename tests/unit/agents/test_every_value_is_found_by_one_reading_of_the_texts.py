"""``first_holders`` answers what ``whole_value_in`` answers, without the product.

The emulation record split each recovered value from the plain strings by
asking ``whole_value_in`` of every value against every string: 4000 values over
8000 strings took seconds. ``first_holders`` reads each string once, at the
places a value may open, and has to give the same first holder for every value,
boundary and escape rules included.
"""

from __future__ import annotations

import random
import string

import pytest

from maljan.agents._indicator_denylists import first_holders, whole_value_in
from tests.unit.agents.test_a_value_is_found_at_its_own_boundaries import FOUND, NOT_FOUND


def _by_product(literals: list[str], haystacks: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for literal in literals:
        at = next((i for i, text in enumerate(haystacks) if whole_value_in(literal, text)), None)
        if at is not None:
            out[literal.lower()] = at
    return out


@pytest.mark.parametrize(("literal", "haystack"), FOUND + NOT_FOUND)
def test_each_pinned_boundary_is_answered_alike(literal: str, haystack: str) -> None:
    assert first_holders([literal], [haystack]) == _by_product([literal], [haystack])


def test_the_first_holder_is_the_first_text_that_holds_the_value_whole() -> None:
    texts = ["notevil.com", "c:\\tmp\\evil.com.br", "see evil.com.", "evil.com"]
    assert first_holders(["evil.com", "absent.example"], texts) == {"evil.com": 2}


def test_an_escape_opens_and_closes_a_value() -> None:
    texts = ['{"a": "x\\nevil.com\\t"}']
    assert first_holders(["evil.com"], texts) == _by_product(["evil.com"], texts) == {"evil.com": 0}


def test_random_texts_are_answered_alike() -> None:
    rng = random.Random(7)
    alphabet = string.ascii_lowercase[:4] + "./\\:-_ \"'@n"
    texts = ["".join(rng.choices(alphabet, k=rng.randint(0, 24))) for _ in range(300)]
    literals = list(
        dict.fromkeys(
            "".join(rng.choices(alphabet.strip(), k=rng.randint(1, 5))).strip() for _ in range(300)
        )
    )
    literals = [literal for literal in literals if literal]
    assert first_holders(literals, texts) == _by_product(literals, texts)


def test_many_values_over_many_texts_are_read_in_one_pass() -> None:
    """The size the product took seconds on: answered, and alike on a sample of it."""
    rng = random.Random(1)

    def word() -> str:
        return "".join(rng.choices(string.ascii_lowercase, k=16))

    values = [word() for _ in range(4000)]
    texts = [word() for _ in range(8000)] + [f"x {values[17]} y"]
    found = first_holders(values, texts)
    assert found == {values[17]: 8000}
    assert _by_product(values[:40], texts) == {values[17]: 8000}


def test_the_emulation_record_holds_out_what_a_plain_string_holds() -> None:
    from maljan.reporting.renderers.stix_renderer import _hold_out_plain

    values = {"evil.com": "ev_0003", "c2.example": "ev_0003", "hidden.example": "ev_0004"}
    plain = [("", "evil.com"), ("ev_0001", "see evil.com."), ("ev_0002", "c2.example/x")]
    kept, held = _hold_out_plain(values, plain)
    # A value whose first holder names no entry is kept, as it was.
    assert kept == {"evil.com": "ev_0003", "hidden.example": "ev_0004"}
    assert held == {"c2.example": "ev_0002"}


def test_the_reading_costs_the_text_plus_the_occurrences() -> None:
    """Many distinct lengths over a large text: the work is counted, not timed."""
    from maljan.agents._indicator_denylists import _Automaton

    literals = ["a" * k for k in range(1, 401)] + ["q" * k for k in range(1, 401)]
    text = "a b " * 100_000
    automaton = _Automaton(literals)
    found = sum(1 for _ in automaton.occurrences(text))
    assert found == 100_000
    assert automaton.steps <= 3 * len(text) + 2 * found
    assert first_holders(literals, [text]) == {"a": 0}
