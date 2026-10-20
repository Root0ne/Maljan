"""The proposer reads a pattern as a hash by what it accepts: a hex string of a hash length."""

from __future__ import annotations

import pytest

from maljan.core.declaration_proposals import _argument_role, _Shape


def _role(regex: str) -> tuple[str, str, str] | None:
    return _argument_role("value", _Shape(regex=regex))


@pytest.mark.parametrize(
    "regex",
    [
        r"^[0-9a-fA-F]{32}$",
        r"^[a-f\d]{64}$",
        r"^[A-Fa-f0-9]{40}$|^[a-f0-9]{64}$",
        r"^(?:[0-9a-f]{2}){32}$",
        r"^[[:xdigit:]]{64}$",
        r"^(?i:[0-9a-f]){64}$",
        r"^[\x30-\x39a-f]{32}$",
    ],
)
def test_a_pattern_taking_exactly_a_hex_string_of_a_hash_length_is_a_hash(regex: str) -> None:
    assert _role(regex) == ("hash", "high", "pattern")


@pytest.mark.parametrize(
    "regex",
    [
        r"^[a-f]-\d{32}$",  # a hex letter and a count, but the count is not the class's
        r"^[a-z]{32}$",
        r"^[^a-f]{32}$",
        r"^[0-9]{40}$",
        r"^[0-9a-f]{33}$",
        r"^[0-9a-f]{32,64}$",
        r"^.{32}$",
        r"(unclosed[0-9a-f]{32}",
    ],
)
def test_any_other_pattern_is_no_hash(regex: str) -> None:
    assert _role(regex) is None
