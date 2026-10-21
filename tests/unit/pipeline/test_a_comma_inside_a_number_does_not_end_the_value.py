"""A comma that goes on through a number does not end a field's value (T-201)."""

from __future__ import annotations

import pytest

from maljan.pipeline.validation import field_pair_in


@pytest.mark.parametrize(
    ("pair", "text", "expected"),
    [
        ("size: 1", "size: 1,024 bytes", False),
        ("size: 1", "size: 1,024,512 bytes", False),
        ("size: 1", "size: 1, then more", True),
        ("size: 1", "size: 1,0245", True),
        ("size: 1,024", "size: 1,024 bytes", True),
        ("size: 1", "size: 1 bytes", True),
        ("name: a", "name: a,bcd", True),
        ("port=8080", "port=8080,443", True),
        ("size: 1024", "size: 1024,512", True),
        ("pid: 12345", "pid: 12345,678", True),
        ("v: 0x5a17c0d0", "v: 0x5a17c0d0,123", True),
        ("v: 1.5", "v: 1.5,000", True),
        ("id: 7", "id: 7,000x", True),
        # Decided residual: read as one number.
        ("ports: 80", "ports: 80,443", False),
    ],
)
def test_the_digit_group_continues_the_number(pair: str, text: str, expected: bool) -> None:
    assert field_pair_in(pair, text) is expected
