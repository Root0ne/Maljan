"""F11-L1: sample text can never close the quote it sits in. Every value is synthetic."""

from __future__ import annotations

import re

import pytest

from maljan.tools.transforms import _ascii_reading, _utf16_reading
from maljan.utils.written_forms import pack_escaped, pack_reads


def test_a_backslash_before_a_quote_is_written_out() -> None:
    assert pack_escaped('a\\"b') == 'a\\x5c\\"b'
    assert pack_escaped('a\\\\"b') == 'a\\x5c\\x5c\\"b'


def test_every_quote_is_preceded_by_exactly_one_backslash() -> None:
    for value in ['\\"', '\\\\"', 'x\\"\\"y', '"\\', 'C:\\dir\\"q"']:
        shown = pack_escaped(value)
        for m in re.finditer(r'"', shown):
            before = shown[: m.start()]
            assert len(before) - len(before.rstrip("\\")) == 1


def test_a_reader_gets_the_value_back() -> None:
    value = 'say \\"hi\\"'
    assert value in pack_reads(pack_escaped(value))


@pytest.mark.parametrize(
    "path", ["C:\\Windows\\System32\\x.exe", "\\\\host\\share\\f", "C:\\a\\", "plain \\ text"]
)
def test_ordinary_windows_paths_are_unchanged(path: str) -> None:
    expected = path[:-1] + "\\x5c" if path.endswith("\\") else path
    assert pack_escaped(path) == expected


def test_a_value_without_a_backslash_quote_is_as_it_was() -> None:
    assert pack_escaped('say "hi" \\n') == 'say \\"hi\\" \\n'


def test_the_byte_transform_readings_agree_with_the_pack() -> None:
    text = 'x\\"y\\\\"z C:\\p\\"'
    assert _ascii_reading(text.encode("latin-1")) == pack_escaped(text)
    assert _utf16_reading(text.encode("utf-16-le")) == pack_escaped(text)
