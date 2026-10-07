"""With a function index in the pack, the map's coverage line counts against the index's rows.

The index lists every function the run's answers and the platform's decoder
place an artefact in, so it is the better denominator: the line then says how
many of its rows the analyst visited and names the entry. Without an index the
line is the one it always was. Nothing else in the block changes.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.agents.function_map import build_function_map, function_artefacts, function_map_block
from maljan.schemas.evidence import LedgerEntry
from tests.unit.agents.test_the_function_map_is_built_from_the_ledger import (
    BASE,
    _blobs,
    _claim,
    _decompiled,
    _entry,
    _floss,
    _hashes,
)


def _index(offsets: list[int], entry_id: str = "ev_0023") -> LedgerEntry:
    output = {
        "tool": "function_index",
        "image_base": hex(BASE),
        "rows": [
            {"function": hex(BASE + offset), "offset": hex(offset), "direct": 1}
            for offset in offsets
        ],
    }
    return _entry(entry_id, "function_index", {}, json.dumps(output), server="pipeline")


def _own() -> list[Any]:
    return [
        _decompiled("ev_0031", "0x1360bc0904c"),
        _entry("ev_0050", "disassemble_function", {"address": "0x1360bc0b344"}, "mov rax, rbx"),
    ]


class TestTheCoverageLine:
    def test_with_an_index_the_rows_are_the_denominator(self) -> None:
        pack = function_artefacts([_hashes(), _blobs(), _floss(), _index([0x904C, 0x2200, 0x4110])])
        found = build_function_map(_own(), pack, [], (BASE,))
        assert found.coverage() == (
            "2 functions visited (1 decompiled, 1 listed); 3 functions hold artefacts in the "
            "function index (ev_0023), 1 of them visited"
        )

    def test_a_visit_by_offset_and_a_row_by_virtual_address_are_one_function(self) -> None:
        pack = function_artefacts([_index([0x904C])])
        found = build_function_map([_decompiled("ev_0031", "0x904c")], pack, [], (BASE,))
        assert found.coverage().endswith(
            "1 function holds artefacts in the function index (ev_0023), 1 of them visited"
        )

    def test_without_an_index_the_line_is_unchanged(self) -> None:
        pack = function_artefacts([_hashes(), _blobs(), _floss()])
        found = build_function_map(_own(), pack, [_claim("x")], (BASE,))
        assert found.coverage() == (
            "2 functions visited (1 decompiled, 1 listed); 5 functions reach artefacts "
            "the analysis server tied to them, 1 of them visited"
        )

    def test_the_rest_of_the_block_is_the_same_with_and_without_an_index(self) -> None:
        plain = function_artefacts([_hashes(), _blobs(), _floss()])
        indexed = function_artefacts([_hashes(), _blobs(), _floss(), _index([0x904C])])
        without = function_map_block(build_function_map(_own(), plain, [], (BASE,)))
        with_index = function_map_block(build_function_map(_own(), indexed, [], (BASE,)))
        assert without.splitlines()[2:] == with_index.splitlines()[2:]
        assert without.splitlines()[0] == with_index.splitlines()[0]
