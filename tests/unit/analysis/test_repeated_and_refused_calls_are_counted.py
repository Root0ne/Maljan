"""Tool calls that found nothing new are counted from the ledger.

A call the repeat guard answered from an earlier identical call without running
is a repeat; one a guard answered with no tool run is refused; one that ran
again with the tool, server and arguments of an earlier call that ran is run
again, whatever order its arguments were written in. A read of a cleared answer
is a read, not a repeat.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

from maljan.agents.tool_answer_clearing import READ_EVIDENCE_TOOL
from maljan.analysis.efficiency import calls_record, efficiency_lines, efficiency_record
from maljan.schemas.evidence import LedgerEntry


def _entry(seq: int, tool: str = "strings", agent: str = "static", **extra: object) -> LedgerEntry:
    return LedgerEntry(id=f"ev_{seq:04d}", agent=agent, tool=tool, seq=seq, **extra)


LEDGER = [
    _entry(1, args={"min": 4, "path": "a"}, server="analysis"),
    _entry(2, args={"path": "a", "min": 4}, server="analysis", agent="dynamic"),
    _entry(3, args={"path": "a", "min": 4}, server="other"),
    _entry(4, repeated_of="ev_0001"),
    _entry(5, repeated_of="ev_0005", tool="decompile"),
    _entry(6, tool=READ_EVIDENCE_TOOL, args={"evidence_id": "ev_0001"}, repeated_of="ev_0001"),
]


def test_each_kind_is_counted_by_agent_and_tool() -> None:
    record = calls_record(LEDGER)

    assert record == {
        "repeated": 1,
        "refused": 1,
        "run_again": 1,
        "by_agent": {
            "dynamic": {"repeated": 0, "refused": 0, "run_again": 1},
            "static": {"repeated": 1, "refused": 1, "run_again": 0},
        },
        "by_tool": {
            "decompile": {"repeated": 0, "refused": 1, "run_again": 0},
            "strings": {"repeated": 1, "refused": 0, "run_again": 1},
        },
    }


def test_dict_rows_read_the_same() -> None:
    assert calls_record([e.model_dump(mode="json") for e in LEDGER]) == calls_record(LEDGER)


def test_no_ledger_is_no_part_and_a_clean_one_counts_zeros() -> None:
    assert calls_record([]) is None
    record = efficiency_record(SimpleNamespace(), entries=[_entry(1)])
    assert record is not None
    assert efficiency_lines(record)[-1] == (
        "Tool calls that found nothing new: 0 answered from an earlier identical call without "
        "running, 0 refused by a guard with no tool run, and 0 run again with the tool, server "
        "and arguments of an earlier call."
    )


def test_the_line_names_the_agents_and_tools() -> None:
    record = efficiency_record(SimpleNamespace(), entries=LEDGER)
    assert record is not None
    assert efficiency_lines(record)[-1].endswith(
        "(by agent: `static` 2, `dynamic` 1; by tool: `strings` 2, `decompile` 1)."
    )


def test_the_count_is_linear_in_the_ledger() -> None:
    def timed(scale: int) -> float:
        ledger = [_entry(i, args={"n": i % 50}) for i in range(1, 500 * scale)]
        start = time.perf_counter()
        calls_record(ledger)
        return time.perf_counter() - start

    small = max(timed(1), 1e-4)
    assert timed(10) < small * 40
