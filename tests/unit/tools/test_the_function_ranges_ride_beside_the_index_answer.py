"""The exception directory's ranges are kept beside the function index's answer, never in it.

The answer is what it was without them, the evidence byte budget charges the
answer alone, and a range holding a function start the index knows other than
its own function's is left out. Each image is synthetic (``synthetic_pe``).
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

from maljan.schemas.evidence import build_entry, stored_bytes
from maljan.tools import artefact_index

from .synthetic_pe import TEXT_RVA, SyntheticPE

FIRST = TEXT_RVA
SECOND = TEXT_RVA + 0x100
LEAF = TEXT_RVA + 0x200


def _load(image: SyntheticPE, tmp_path: Path) -> str:
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())
    return str(target)


def _calls(image: SyntheticPE, at: int, target: int) -> None:
    end = at + 5
    image.put("text", at - TEXT_RVA, b"\xe8" + struct.pack("<i", target - end) + b"\xc3")


class TestTheRangesRideBesideTheAnswer:
    def test_the_answer_holds_no_ranges_and_the_caller_gets_them(self, tmp_path: Path) -> None:
        image = SyntheticPE(functions=[(FIRST, FIRST + 0x40), (SECOND, SECOND + 0x40)])
        _calls(image, FIRST, SECOND)
        path = _load(image, tmp_path)
        ranges: dict[str, list[list[str]]] = {}
        answer = artefact_index.function_index(path, ranges_into=ranges)
        assert answer == artefact_index.function_index(path)
        assert "function_ranges" not in answer
        assert ranges == {
            hex(FIRST): [[hex(FIRST), hex(FIRST + 0x40)]],
            hex(SECOND): [[hex(SECOND), hex(SECOND + 0x40)]],
        }

    def test_a_range_holding_a_call_target_is_left_out(self, tmp_path: Path) -> None:
        # The table says FIRST runs to past LEAF, and FIRST calls LEAF.
        image = SyntheticPE(functions=[(FIRST, LEAF + 0x40)])
        _calls(image, FIRST, LEAF)
        ranges: dict[str, list[list[str]]] = {}
        artefact_index.function_index(_load(image, tmp_path), ranges_into=ranges)
        assert ranges == {}

    def test_the_budget_charges_the_answer_alone(self) -> None:
        entry = build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="pipeline",
            tool=artefact_index.TOOL,
            args={},
            server="pipeline",
            output=json.dumps({"tool": artefact_index.TOOL, "rows": []}),
        )
        before = stored_bytes(entry)
        entry.function_ranges = {hex(0x1000 + k): [["0x1000", "0x1040"]] for k in range(5_000)}
        assert stored_bytes(entry) == before
