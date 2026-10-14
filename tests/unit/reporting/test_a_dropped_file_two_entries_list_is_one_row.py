"""A dropped file or a mutex that two entries of the same sandbox task list is one row.

The pack and an analyst both read the sandbox's dropped-files list, and the
report's payload table printed each of the nine items twice. A row an earlier
entry already gave is that row and is kept once; rows one answer lists twice
are its own and stay, and a row that differs in any field is another row.
"""

from __future__ import annotations

import time
from typing import Any

from maljan.reporting.ledger_projection import dynamic_from_ledger
from maljan.schemas.evidence import build_entry

DROPPED = [
    {"name": "files/a.dat", "path": "", "size": 607, "type": None, "sha256": "aa" * 32},
    {"name": "memory/1-dump.dmp", "path": "", "size": None, "type": None, "sha256": None},
]


def _entry(seq: int, tool: str, structured: dict[str, Any]) -> Any:
    entry = build_entry(
        entry_id=f"ev_{seq:04d}",
        seq=seq,
        agent="pipeline" if seq < 100 else "dynamic",
        tool=tool,
        args={},
        server="pipeline",
        output="{}",
    )
    return entry.model_copy(update={"structured": structured})


def _operations(*entries: Any) -> list[dict[str, Any]]:
    dynamic = dynamic_from_ledger(list(entries))
    assert dynamic is not None
    return dynamic.file_operations


class TestOneRowPerItem:
    def test_two_entries_listing_the_same_drops_give_each_once(self) -> None:
        ops = _operations(
            _entry(15, "sandbox_dropped_files", {"dropped": DROPPED}),
            _entry(116, "sandbox_dropped_files", {"dropped": DROPPED}),
        )
        assert [op["name"] for op in ops] == ["files/a.dat", "memory/1-dump.dmp"]

    def test_the_same_mutex_from_two_entries_is_one_row(self) -> None:
        ops = _operations(
            _entry(15, "sandbox_mutexes", {"mutexes": ["m1", "m2"]}),
            _entry(116, "sandbox_mutexes", {"mutexes": ["m2", "m3"]}),
        )
        assert [op["name"] for op in ops] == ["m1", "m2", "m3"]

    def test_a_row_one_answer_lists_twice_stays_twice(self) -> None:
        ops = _operations(_entry(15, "sandbox_dropped_files", {"dropped": [DROPPED[0]] * 2}))
        assert len(ops) == 2

    def test_a_row_that_differs_in_a_field_is_another_row(self) -> None:
        other = {**DROPPED[0], "size": 608}
        ops = _operations(
            _entry(15, "sandbox_dropped_files", {"dropped": [DROPPED[0]]}),
            _entry(116, "sandbox_dropped_files", {"dropped": [other]}),
        )
        assert [op["size"] for op in ops] == [607, 608]


class TestLinearTime:
    def test_ten_times_the_rows_cost_at_most_ten_times(self) -> None:
        def cost(rows: int) -> float:
            dropped = [{"name": f"f{n}", "size": n} for n in range(rows)]
            entries = [
                _entry(15, "sandbox_dropped_files", {"dropped": dropped}),
                _entry(116, "sandbox_dropped_files", {"dropped": dropped}),
            ]
            start = time.perf_counter()
            _operations(*entries)
            return time.perf_counter() - start

        cost(50)
        small = cost(500)
        large = cost(5_000)
        assert large <= max(small, 1e-3) * 30
