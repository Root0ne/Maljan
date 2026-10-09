"""The RunSummary log line says what the stored summary says.

The line used to be built from the judge node's own counters, before the
report round added its retries, so it read 22 retries beside a stored summary
of 30. It is now read from the
summary's own fields, and the report round's amendment is logged the same way.
The memory's lines name their own count (the claimed techniques memory keeps),
so no two lines call two different counts "claimed techniques".
"""

from __future__ import annotations

import inspect

from maljan.analysis.run_summary import summary_counts_line


def _summary() -> dict[str, object]:
    return {
        "final_decision": "Malware",
        "negotiation": {"rounds_completed": 2},
        "corroboration": {
            "T1027": {"claimed_by": ["static"], "asserted_by": ["capa"]},
            "T1106": {"claimed_by": ["static", "reverser"], "asserted_by": []},
            "T1055": {"claimed_by": [], "asserted_by": ["capa"]},
        },
        "validation": {
            "retries": 7,
            "unresolved": [
                {"agent": "judge", "code": "a", "message": "m"},
                {"agent": "static", "code": "b", "message": "m", "count": "3"},
            ],
        },
    }


def test_each_count_is_the_stored_field() -> None:
    assert summary_counts_line(_summary()) == (
        "verdict=Malware, rounds=2, claimed techniques=2, validation retries=7, unresolved=4"
    )


def test_an_empty_summary_reads_as_nothing_counted() -> None:
    assert summary_counts_line({}) == (
        "verdict=None, rounds=0, claimed techniques=0, validation retries=0, unresolved=0"
    )


def test_both_log_lines_are_read_from_a_summary() -> None:
    from maljan.pipeline import nodes

    source = inspect.getsource(nodes)
    assert source.count("summary_counts_line(") == 2
    assert "claimed techniques=%d" not in source
