"""A tool whose rows declare a ``command_line`` place is joined to the process that ran it.

A rule tool of a declared kind shaped otherwise than the shipped tool of its
kind is read by its declared paths. Those paths knew offsets, addresses,
relative addresses and process ids only, so a command line a row named was
lost with ``no: ... nothing to place``; it now gives the process the sandbox
report ties that command to, or says why it gives none.
"""

from __future__ import annotations

from typing import Any

from maljan.analysis.evidence_roots import (
    MATCH_UNPLACED,
    PROCESS_ROOT,
    SHARED_COMMAND,
    EntryRoots,
    reading_branch,
    run_roots,
)
from maljan.core.declared_reading import facts_record
from maljan.schemas.evidence import LedgerEntry

PS = "powershell -enc x"
ANSWER = {"m": [{"cmd": PS, "t": "T1059.001"}]}


def _processes(*rows: dict[str, Any]) -> LedgerEntry:
    return LedgerEntry(
        id="ev_0001",
        seq=1,
        agent="dynamic",
        tool="sandbox_processes",
        source="sandbox",
        output="{}",
        structured={"processes": list(rows)},
        facts=facts_record("sandbox", "sandbox_processes"),
    )


def _rules(answer: dict[str, Any]) -> LedgerEntry:
    return LedgerEntry(
        id="ev_0002",
        seq=2,
        agent="dynamic",
        tool="operator_rules",
        source="mcp:invented",
        output="{}",
        structured=answer,
        facts={
            "v": 1,
            "kind": "event_rules",
            "rows": "/m/*",
            "places": {"command_line": "/cmd"},
        },
    )


def _roots(*entries: LedgerEntry) -> EntryRoots:
    return run_roots(list(entries)).entries["ev_0002"]


def test_a_differently_shaped_event_rule_tool_is_read_by_its_declared_rows() -> None:
    assert reading_branch(_rules(ANSWER)) == "declared_rows"


def test_its_command_line_is_joined_to_the_one_process_that_ran_it() -> None:
    roots = _roots(_processes({"pid": 7, "command_line": PS}), _rules(ANSWER))
    assert roots.roots == [PROCESS_ROOT.format(pid=7)]


def test_a_command_line_no_process_ran_gives_no_root_and_says_why() -> None:
    roots = _roots(_processes({"pid": 7, "command_line": "calc"}), _rules(ANSWER))
    assert roots.roots == []
    assert roots.reason == MATCH_UNPLACED


def test_a_command_line_two_processes_ran_is_shared_not_guessed() -> None:
    rows = [{"pid": 7, "command_line": PS}, {"pid": 9, "command_line": PS}]
    roots = _roots(_processes(*rows), _rules(ANSWER))
    assert roots.roots == []
    assert roots.reason == SHARED_COMMAND
