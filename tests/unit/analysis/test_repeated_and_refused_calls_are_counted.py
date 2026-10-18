"""Tool calls that found nothing new are counted from the ledger, under who made each.

A call the repeat guard answered from an earlier identical call without running
is a repeat; one a guard answered with no tool run is refused. A call that ran
again with the tool, server and arguments of an earlier call the same maker ran
is run again — or retried after a failure, where that earlier call failed —
whatever order its arguments were written in; one identical to a call another
agent or the pack ran first is counted apart, so no maker is charged with a
call it never saw. A read of a cleared answer is a read, not a repeat.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace

import pytest

from maljan.agents.tool_answer_clearing import READ_EVIDENCE_TOOL
from maljan.analysis.efficiency import calls_record, efficiency_lines, efficiency_record
from maljan.schemas.evidence import LedgerEntry


def _entry(seq: int, tool: str = "strings", agent: str = "static", **extra: object) -> LedgerEntry:
    return LedgerEntry(id=f"ev_{seq:04d}", agent=agent, tool=tool, seq=seq, **extra)


def _zero(**counts: int) -> dict[str, int]:
    row = dict.fromkeys(
        ("repeated", "refused", "run_again", "retried_after_failure", "same_call_elsewhere"), 0
    )
    return {**row, **counts}


ARGS = {"min": 4, "path": "a"}
LEDGER = [
    _entry(1, args={"min": 4, "path": "a"}, server="analysis", agent="", pack_step={"s": 1}),
    _entry(2, args={"path": "a", "min": 4}, server="analysis", agent="dynamic"),
    _entry(3, args={"path": "a", "min": 4}, server="analysis", agent="dynamic"),
    _entry(4, args=ARGS, server="other"),
    _entry(5, repeated_of="ev_0004"),
    _entry(6, repeated_of="ev_0006", tool="decompile"),
    _entry(7, tool=READ_EVIDENCE_TOOL, args={"evidence_id": "ev_0001"}, repeated_of="ev_0001"),
]


def _calls_line(record: dict) -> str:
    (line,) = [line for line in efficiency_lines(record) if line.startswith("Tool calls")]
    return line


def test_each_kind_is_filed_under_its_maker() -> None:
    record = calls_record(LEDGER)

    assert record == {
        **_zero(repeated=1, refused=1, run_again=1, same_call_elsewhere=1),
        "by_agent": {
            "dynamic": _zero(run_again=1, same_call_elsewhere=1),
            "static": _zero(repeated=1, refused=1),
        },
        "by_tool": {
            "decompile": _zero(refused=1),
            "strings": _zero(repeated=1, run_again=1, same_call_elsewhere=1),
        },
    }


def test_another_maker_s_identical_call_is_never_a_run_again() -> None:
    """Two agents calling the same tool in parallel: whichever lands second is not charged."""
    first = calls_record([_entry(1, args=ARGS), _entry(2, args=ARGS, agent="network")])
    second = calls_record([_entry(1, args=ARGS, agent="network"), _entry(2, args=ARGS)])

    assert first is not None and second is not None
    assert (first["run_again"], first["same_call_elsewhere"]) == (0, 1)
    assert (second["run_again"], second["same_call_elsewhere"]) == (0, 1)


def test_a_retry_after_a_failure_is_the_platform_s_and_counted_apart() -> None:
    ledger = [
        _entry(1, args=ARGS, ok=False, error="the server did not answer"),
        _entry(2, args=ARGS),
        _entry(3, args=ARGS),
    ]
    record = calls_record(ledger)

    assert record is not None
    assert record["by_agent"]["static"] == _zero(run_again=1, retried_after_failure=1)


def test_dict_rows_read_the_same() -> None:
    assert calls_record([e.model_dump(mode="json") for e in LEDGER]) == calls_record(LEDGER)


def test_no_ledger_is_no_part_and_a_clean_one_counts_zeros() -> None:
    assert calls_record([]) is None
    record = efficiency_record(SimpleNamespace(), entries=[_entry(1)])
    assert record is not None
    assert _calls_line(record) == (
        "Tool calls that found nothing new: 0 answered from an earlier identical call without "
        "running, 0 refused by a guard with no tool run, 0 run again by the maker of an earlier "
        "identical call and 0 identical to a call another maker ran first; besides them, 0 "
        "retried after the maker's own earlier identical call failed."
    )


def test_the_line_names_who_made_each_call() -> None:
    record = efficiency_record(SimpleNamespace(), entries=LEDGER)
    assert record is not None
    assert _calls_line(record).endswith(
        "By who made them — `dynamic`: 1 run again after its own earlier identical call, 1 "
        "identical to a call another maker ran first; `static`: 1 answered from its earlier "
        "identical call without running, 1 refused by a guard with no tool run (by tool: "
        "`strings` 3, `decompile` 1)."
    )


def _field_reads(monkeypatch: pytest.MonkeyPatch, build: Callable[[], object]) -> int:
    """How many entry fields ``build`` reads: the record's unit of work, not a clock."""
    import maljan.analysis.efficiency as efficiency

    counted = [0]
    real = efficiency._field

    def field(entry: object, name: str) -> object:
        counted[0] += 1
        return real(entry, name)

    monkeypatch.setattr(efficiency, "_field", field)
    try:
        build()
    finally:
        monkeypatch.setattr(efficiency, "_field", real)
    return counted[0]


def test_the_count_is_linear_in_the_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    def work(scale: int) -> int:
        ledger = [_entry(i, args={"n": i % 50}) for i in range(1, 500 * scale + 1)]
        return _field_reads(monkeypatch, lambda: calls_record(ledger))

    # Linear: one more unit of ledger costs as much at ten units as at one.
    assert work(11) - work(10) <= (work(2) - work(1)) * 1.1
