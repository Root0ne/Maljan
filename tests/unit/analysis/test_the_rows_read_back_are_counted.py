"""The ledger and pack rows an agent read back through ``read_evidence`` are counted.

Every read is filed as a repeat of the row it reads, so the row is the entry
holding the read's answer, followed down a chain of repeats. A row the triage
pack wrote is a pack row. A read whose id named no row is counted apart, and a
read is never evidence of its own nor a repeated call.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

from maljan.agents.tool_answer_clearing import READ_EVIDENCE_TOOL
from maljan.analysis.efficiency import (
    calls_record,
    efficiency_lines,
    efficiency_record,
    rows_read_record,
    uncited_record,
)
from maljan.schemas.evidence import LedgerEntry


def _entry(seq: int, tool: str = "strings", agent: str = "static", **extra: object) -> LedgerEntry:
    return LedgerEntry(id=f"ev_{seq:04d}", agent=agent, tool=tool, seq=seq, **extra)


def _read(seq: int, of: str, agent: str = "static") -> LedgerEntry:
    return _entry(seq, READ_EVIDENCE_TOOL, agent, args={"evidence_id": of}, repeated_of=of)


LEDGER = [
    _entry(1, "pe_info", agent="", pack_step={"step": "pe"}),
    _entry(2),
    _entry(3, repeated_of="ev_0002"),
    _read(4, "ev_0001"),
    _read(5, "ev_0001", agent="dynamic"),
    _read(6, "ev_0003"),
    _read(7, "ev_0099"),
]


def test_each_row_is_named_with_who_read_it() -> None:
    record = rows_read_record(LEDGER)

    assert record == {
        "reads": 4,
        "rows": [
            {"id": "ev_0001", "tool": "pe_info", "pack": True, "by": {"static": 1, "dynamic": 1}},
            {"id": "ev_0002", "tool": "strings", "pack": False, "by": {"static": 1}},
        ],
        "by_agent": {
            "dynamic": {"reads": 1, "rows": 1, "pack_rows": 1},
            "static": {"reads": 3, "rows": 2, "pack_rows": 1},
        },
        "unfound": 1,
    }


def test_a_read_is_neither_evidence_nor_a_repeated_call() -> None:
    uncited = uncited_record(LEDGER, {})
    calls = calls_record(LEDGER)

    assert uncited is not None and uncited["entries"] == 2
    assert calls is not None and (calls["repeated"], calls["refused"]) == (1, 0)


def test_dict_rows_read_the_same() -> None:
    assert rows_read_record([e.model_dump(mode="json") for e in LEDGER]) == rows_read_record(LEDGER)


def test_the_report_line_says_how_many_rows_and_how_many_pack_rows() -> None:
    record = efficiency_record(SimpleNamespace(), entries=LEDGER)
    assert record is not None
    assert efficiency_lines(record)[-1] == (
        "Rows read back by id (read_evidence): 4 reads — `dynamic` 1 read of 1 row "
        "(1 of them pack rows), `static` 3 reads of 2 rows (1 of them pack rows); "
        "1 read named no row the ledger holds."
    )


def test_a_ledger_with_no_read_says_none() -> None:
    record = efficiency_record(SimpleNamespace(), entries=[_entry(1)])
    assert record is not None
    assert record["rows_read"] == {"reads": 0, "rows": [], "by_agent": {}}
    assert efficiency_lines(record)[-1] == "Rows read back by id (read_evidence): none."
    assert rows_read_record([]) is None


def test_the_count_is_linear_in_the_ledger() -> None:
    def timed(scale: int) -> float:
        rows = [_entry(i) for i in range(1, 300 * scale)]
        reads = [_read(300 * scale + i, f"ev_{i:04d}") for i in range(1, 300 * scale)]
        start = time.perf_counter()
        rows_read_record([*rows, *reads])
        return time.perf_counter() - start

    small = max(timed(1), 1e-4)
    assert timed(10) < small * 40
