"""With a function index in the pack, the map's coverage and not-visited lines read its rows.

The index lists every function the run's answers and the platform's decoder
place an artefact in, so it is the one source both lines read: the coverage
line counts the visited functions among the rows and names the entry, and the
not-visited line lists the other rows in the pack's rank order. Without an
index both lines are the ones they always were. Every address here is a
neutral synthetic value.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.agents.function_map import build_function_map, function_artefacts, function_map_block
from maljan.schemas.evidence import LedgerEntry

BASE = 0x10000000


def _entry(entry_id: str, tool: str, args: dict[str, Any], output: str = "") -> LedgerEntry:
    return LedgerEntry(id=entry_id, tool=tool, args=args, output=output)


def _index(rows: list[tuple[int, int]], entry_id: str = "ev_0009") -> LedgerEntry:
    """An index entry whose rows are ``(offset, direct)``, in the order given (its rank)."""
    output = {
        "tool": "function_index",
        "image_base": hex(BASE),
        "rows": [
            {"function": hex(BASE + offset), "offset": hex(offset), "direct": direct}
            for offset, direct in rows
        ],
    }
    return _entry(entry_id, "function_index", {}, json.dumps(output))


def _hashes() -> LedgerEntry:
    output = {
        "tool": "resolve_api_hashes",
        "image_base": hex(BASE),
        "hits": [
            {
                "readings": [{"set": "exports", "name": "OpenThing"}],
                "occurrences": [{"rva": "0x1104", "function": "0x1100"}],
            },
            {
                "readings": [{"set": "exports", "name": "CloseThing"}],
                "occurrences": [{"rva": "0x2204", "function": "0x2200"}],
            },
        ],
    }
    return _entry("ev_0005", "resolve_api_hashes", {}, json.dumps(output))


def _decompiled(entry_id: str, address: int) -> LedgerEntry:
    return _entry(
        entry_id,
        "decompile_function",
        {"address": hex(address)},
        f"void FUN_{address:x}(void)\n{{\n}}\n",
    )


INDEX_ROWS = [(0x3300, 7), (0x1100, 4), (0x2200, 4), (0x4400, 1)]


class TestWithAnIndex:
    def _map(self) -> Any:
        pack = function_artefacts([_hashes(), _index(INDEX_ROWS)])
        return build_function_map([_decompiled("ev_0011", BASE + 0x1100)], pack, [], (BASE,))

    def test_the_coverage_line_counts_the_visited_rows(self) -> None:
        assert self._map().coverage() == (
            "1 function visited (1 decompiled); 4 functions hold artefacts in the function "
            "index (ev_0009), 1 of them visited"
        )

    def test_the_not_visited_line_lists_the_other_rows_in_the_pack_s_rank_order(self) -> None:
        last = function_map_block(self._map()).splitlines()[-1]
        assert last == (
            "not visited, holding artefacts in the function index (ev_0009): "
            f"{hex(BASE + 0x3300)} (7 artefacts); {hex(BASE + 0x2200)} (4 artefacts); "
            f"{hex(BASE + 0x4400)} (1 artefact)"
        )

    def test_the_index_s_own_image_base_joins_a_visit_by_virtual_address(self) -> None:
        pack = function_artefacts([_index(INDEX_ROWS)])
        found = build_function_map([_decompiled("ev_0011", BASE + 0x3300)], pack, [])
        assert BASE in found.image_bases
        assert found.coverage().endswith("1 of them visited")


class TestWithoutAnIndex:
    def test_both_lines_are_the_ones_they_always_were(self) -> None:
        pack = function_artefacts([_hashes()])
        found = build_function_map([_decompiled("ev_0011", BASE + 0x1100)], pack, [], (BASE,))
        lines = function_map_block(found).splitlines()
        assert lines[1] == (
            "coverage: 1 function visited (1 decompiled); 2 functions reach artefacts the "
            "analysis server tied to them, 1 of them visited"
        )
        assert lines[-1] == (
            f"not visited, reaching artefacts: {hex(BASE + 0x2200)} (1 resolved name; ev_0005)"
        )
