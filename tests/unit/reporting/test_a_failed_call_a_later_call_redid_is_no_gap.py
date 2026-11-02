"""A failed call a later call redid for the same address is no gap in the evidence.

haiku8 said "The evidence is partial: 5 of 214 tool calls failed" in its
header and its limitations, while three of the five had been asked again and
answered for the same addresses, and the limitations paragraph then said the
reversing tools failed (T-494 D6; the link is T-396's). The run's bounds still
count every failed call and now name the redone ones with the calls that
answered them; the partial-evidence sentence counts only the failures no later
call redid; the limitations paragraph is told which failed calls were redone.
A run with no redone call reads byte for byte as before. Every address, entry
and tool name here is a neutral synthetic value, read by declared kinds.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from maljan.pipeline.nodes import evidence_summary
from maljan.reporting.composer import _bundle_text
from maljan.reporting.composer_pro import analyst_bundle
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.redone_calls import redone_failures
from maljan.reporting.renderers import MarkdownRenderer
from maljan.reporting.renderers.layout import ANALYST, BUNDLE
from maljan.schemas.evidence import LedgerEntry
from tests.unit.reporting._report_inventory import stored_runs

GATE, OTHER = 0x2475A10, 0x2475B20
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}


def _failed(entry_id: str, address: int | None = None, tool: str = "lift_routine") -> LedgerEntry:
    args = {"address": hex(address)} if address is not None else {"pattern": "abc"}
    facts = _DECOMPILE if address is not None else None
    return LedgerEntry(
        id=entry_id,
        tool=tool,
        args=args,
        ok=False,
        error="not a program this job opened",
        facts=facts,
    )


def _lifted(entry_id: str, address: int) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        args={"address": hex(address)},
        output=f"int FUN_{address:x}(int a)\n{{\n  return a;\n}}\n",
        facts=_DECOMPILE,
    )


def _plain(entry_id: str) -> LedgerEntry:
    return LedgerEntry(id=entry_id, tool="image_facts", output="{}")


def _report(ledger: list[LedgerEntry]) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64), file_type="PE32+ DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        run_summary={"evidence": evidence_summary(ledger)},
    )


def _partial(report: MalwareReport) -> list[str]:
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    return [
        line.split("The evidence is partial:", 1)[1].split(".", 1)[0].strip()
        for line in analyst.splitlines()
        if "The evidence is partial:" in line
    ]


# -- which failed calls were redone ------------------------------------------


def test_a_failed_call_a_later_call_answered_for_its_address_is_redone() -> None:
    ledger = [_failed("ev_0001", GATE), _plain("ev_0002"), _lifted("ev_0003", GATE)]
    assert redone_failures(ledger) == [
        {"entry_id": "ev_0001", "tool": "lift_routine", "answered_by": ["ev_0003"]}
    ]


def test_a_failure_nothing_answered_later_is_not_redone() -> None:
    # An answer before the failure, and one for another address, redo nothing.
    ledger = [_lifted("ev_0001", GATE), _failed("ev_0002", GATE), _lifted("ev_0003", OTHER)]
    assert redone_failures(ledger) == []


def test_a_failure_asked_for_no_address_is_never_redone() -> None:
    # Another call of the same tool with other arguments answers another question.
    ledger = [_failed("ev_0001", tool="scan_text"), _plain("ev_0002")]
    ledger.append(LedgerEntry(id="ev_0003", tool="scan_text", args={"pattern": "xyz"}, output="[]"))
    assert redone_failures(ledger) == []


def test_a_batch_is_redone_only_when_every_address_it_asked_was_answered() -> None:
    batch = LedgerEntry(
        id="ev_0001",
        tool="lift_many",
        args={"functions": f"{GATE:x},{OTHER:x}"},
        ok=False,
        error="not a program this job opened",
        facts={"v": 1, "kind": "decompile_batch", "reader": "listing"},
    )
    assert redone_failures([batch, _lifted("ev_0002", GATE)]) == []
    assert redone_failures([batch, _lifted("ev_0002", GATE), _lifted("ev_0003", OTHER)]) == [
        {"entry_id": "ev_0001", "tool": "lift_many", "answered_by": ["ev_0002", "ev_0003"]}
    ]


def test_a_redone_row_s_tool_name_is_one_capped_line() -> None:
    ledger = [_failed("ev_0001", GATE, tool="lift\nroutine " + "x" * 200), _lifted("ev_0002", GATE)]
    (row,) = redone_failures(ledger)
    assert "\n" not in row["tool"] and len(row["tool"]) <= 80


# -- the run's bounds --------------------------------------------------------


def test_the_bounds_keep_every_failure_counted_and_list_the_redone_apart() -> None:
    ledger = [_failed("ev_0001", GATE), _failed("ev_0002", OTHER), _lifted("ev_0003", GATE)]
    summary = evidence_summary(ledger)
    assert summary["failed"] == 2
    assert [row["entry_id"] for row in summary["redone"]] == ["ev_0001"]


def test_a_ledger_with_no_failure_has_the_bounds_it_had() -> None:
    summary = evidence_summary([_lifted("ev_0001", GATE), _plain("ev_0002")])
    assert set(summary) == {"entries", "ok", "failed", "trimmed", "by_tool", "failures"}


# -- what the report says ----------------------------------------------------


def test_redone_failures_alone_leave_the_evidence_whole_and_the_bundle_names_them() -> None:
    ledger = [
        _failed("ev_0001", GATE),
        _failed("ev_0002", OTHER),
        _lifted("ev_0003", GATE),
        _lifted("ev_0004", OTHER),
    ]
    report = _report(ledger)
    assert _partial(report) == []
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    assert (
        "2 failed (2 of them redone by a later call for the same address: "
        "ev_0001 by ev_0003; ev_0002 by ev_0004)"
    ) in bundle
    head = MarkdownRenderer().render(report)
    assert "4 tool call(s), 2 failed, 2 of them redone by a later call for the same address (" in (
        head
    )


def test_a_failure_no_later_call_redid_is_still_said() -> None:
    ledger = [_failed("ev_0001", GATE), _lifted("ev_0002", OTHER), _plain("ev_0003")]
    report = _report(ledger)
    assert _partial(report) == ["1 of 3 tool calls failed"]
    assert "redone" not in MarkdownRenderer(layout=BUNDLE).render(report)


def test_a_mixed_run_says_only_the_failures_not_redone_as_the_gap() -> None:
    ledger = [
        _failed("ev_0001", GATE),
        _failed("ev_0002", tool="scan_text"),
        _failed("ev_0003", OTHER),
        _lifted("ev_0004", GATE),
        _plain("ev_0005"),
    ]
    report = _report(ledger)
    assert _partial(report) == ["2 of 5 tool calls failed and were not redone"]
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    said = "3 failed (1 of them redone by a later call for the same address: ev_0001 by ev_0004)"
    assert said in bundle


@pytest.mark.parametrize("failed", [False, True])
def test_a_run_with_no_redone_call_renders_as_before(failed: bool) -> None:
    # The summary holds the shape it held before, and no product says "redone".
    first = _failed("ev_0001", GATE) if failed else _lifted("ev_0001", GATE)
    report = _report([first, _plain("ev_0002")])
    assert "redone" not in report.run_summary["evidence"]
    assert _partial(report) == (["1 of 2 tool calls failed"] if failed else [])
    for renderer in (MarkdownRenderer(), *(MarkdownRenderer(layout=x) for x in (ANALYST, BUNDLE))):
        assert "redone" not in renderer.render(report)


# -- what the limitations paragraph is shown ---------------------------------


def test_the_limitations_are_told_which_failed_calls_were_redone() -> None:
    ledger = [_failed("ev_0001", GATE), _failed("ev_0002", OTHER), _lifted("ev_0003", GATE)]
    facts = analyst_bundle("limitations", _report(ledger))["facts"]
    assert facts["failed_calls_redone"] == [
        "ev_0001 (lift_routine) failed and was redone: ev_0003 answered for the same address, "
        "so it left no gap"
    ]
    # The ids are the platform's own: shown readable, as a citation.
    text = _bundle_text("limitations", analyst_bundle("limitations", _report(ledger)))
    assert "ev_0001 (lift_routine) failed and was redone: ev_0003" in text


def test_without_a_redone_call_the_limitations_are_shown_what_they_were() -> None:
    for ledger in ([_lifted("ev_0001", GATE)], [_failed("ev_0001", GATE), _plain("ev_0002")]):
        facts = analyst_bundle("limitations", _report(ledger))["facts"]
        assert set(facts) == {
            "limitations_recorded",
            "open_questions",
            "no_sandbox_observation",
            "degraded_run",
            "verdict_not_assessed",
        }


# -- a stored run ------------------------------------------------------------


def _stored_ledger(run: str) -> list[Any]:
    from maljan.reporting.follow_up import stored_ledger

    root = stored_runs()
    path = root / run / "evidence.json" if root is not None else None
    if path is None or not path.is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    document = json.loads(path.read_text())
    rows = document["items"] if isinstance(document, dict) else document
    return stored_ledger(rows)[0]


def test_haiku8_s_redone_reversing_calls_are_named_and_its_other_failures_kept() -> None:
    ledger = _stored_ledger("haiku8")
    summary = evidence_summary(ledger)
    assert summary["failed"] == 5
    assert [(row["entry_id"], row["answered_by"]) for row in summary["redone"]] == [
        ("ev_0168", ["ev_0171"]),
        ("ev_0169", ["ev_0170"]),
        ("ev_0187", ["ev_0191"]),
    ]
