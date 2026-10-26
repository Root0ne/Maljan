"""The report build keeps a function's code whole in the table that holds it.

Every value a generic table stored was cut at ``CELL_CHARS`` (400), so a
batch decompile's functions reached report.json cut: 55 of haiku6's 78 code
bodies ended in the cut mark (haiku5 38 of 46, run5 56 of 65), and every
surface drawing them could show only what report.json held.

A value is code when the entry it came from stored a decompile or
disassembly kind with its facts, or when it names the function its row
names (``FUN_00401000`` under ``0x401000``). Code spans lines: a one-line
value is a table's fact and is still cut, as is a text of several lines
that is no code. Never read from a tool's name.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.reporting.ledger_report import CELL_CHARS, build_sections
from maljan.schemas.evidence import LedgerEntry
from maljan.utils.marked_cut import CUT_MARK

BODY = "".join(f"  local_{i:02x} = FUN_00405000(local_{i:02x}, 0x{i:x});\n" for i in range(40))
LONG_CODE = f"\nint FUN_00401000(int cmd)\n\n{{\n{BODY}  return 0;\n}}\n"
OTHER_CODE = LONG_CODE.replace("FUN_00401000(int", "FUN_00402000(int")
# A text of several lines that names no function: a tool's own report.
TEXT_DUMP = "".join(f"line {i}: nothing to see in this section of the dump\n" for i in range(40))
ONE_LINE = "token " * 120


def _entry(answer: Any, facts: dict[str, Any] | None, tool: str = "lookup_things") -> LedgerEntry:
    output = json.dumps(answer)
    return LedgerEntry(
        id="ev_0008",
        agent="reverser",
        tool=tool,
        args={"program": "sample.exe"},
        output=output,
        structured=answer,
        seq=8,
        source="mcp:things",
        facts=facts,
    )


def _cells(entry: LedgerEntry) -> dict[str, list[str]]:
    """Each column's cells, over every table the entry's answer drew."""
    out: dict[str, list[str]] = {}
    for section in build_sections([entry]):
        if "ev_0008" not in section.evidence_ids:
            continue
        for row in section.rows:
            for at, cell in enumerate(row):
                name = section.columns[at] if at < len(section.columns) else str(at)
                out.setdefault(name, []).append(cell)
    return out


def _row_value(entry: LedgerEntry, field: str) -> str:
    for section in build_sections([entry]):
        for row in section.rows:
            if row and row[0] == field:
                return row[1]
    raise AssertionError(f"no row {field!r}")


def test_a_declared_batch_keeps_each_function_whole_and_cuts_a_one_line_fact() -> None:
    assert len(LONG_CODE) > CELL_CHARS
    entry = _entry(
        {"0x401000": LONG_CODE, "0x402000": OTHER_CODE, "note": ONE_LINE},
        {"v": 1, "kind": "decompile_batch"},
    )
    assert _row_value(entry, "0x401000") == LONG_CODE
    assert _row_value(entry, "0x402000") == OTHER_CODE
    note = _row_value(entry, "note")
    assert note.endswith(CUT_MARK) and len(note) <= CELL_CHARS


def test_a_declared_listing_keeps_its_code_whole_in_a_table() -> None:
    entry = _entry(
        [{"address": "0x401000", "listing": LONG_CODE, "comment": ONE_LINE}],
        {"v": 1, "kind": "disassembly"},
    )
    cells = _cells(entry)
    assert cells["listing"] == [LONG_CODE]
    assert cells["comment"][0].endswith(CUT_MARK)


def test_an_undeclared_value_is_code_when_it_names_the_function_its_row_names() -> None:
    kv = _entry({"0x401000": LONG_CODE, "report": TEXT_DUMP}, None)
    assert _row_value(kv, "0x401000") == LONG_CODE
    assert _row_value(kv, "report").endswith(CUT_MARK)
    table = _entry([{"function": "FUN_00401000", "body": LONG_CODE}], None)
    assert _cells(table)["body"] == [LONG_CODE]


def test_code_under_another_function_is_no_code_of_its_row() -> None:
    entry = _entry({"0x403000": LONG_CODE}, {"v": 1, "kind": "memory_read"})
    assert _row_value(entry, "0x403000").endswith(CUT_MARK)


def test_a_tool_name_never_decides() -> None:
    named = _entry({"0x403000": LONG_CODE}, {"v": 1, "kind": "memory_read"}, "batch_decompile")
    assert _row_value(named, "0x403000").endswith(CUT_MARK)
    declared = _entry({"0x403000": LONG_CODE}, {"v": 1, "kind": "decompile_batch"}, "lookup")
    assert _row_value(declared, "0x403000") == LONG_CODE
