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
# A tool asked for an address whose answer is no code listing: its redo is the
# same question, a listing of the function answering nothing more.
_NOT_A_LISTING = {"v": 1, "kind": "xrefs"}
# The lines a run with one failure and no redo printed before this change,
# rendered by the base branch's code from the same summary.
HEAD_LINE = "Evidence: 2 tool call(s), 1 failed (see §13)."
BOUNDS_LINE = "**Evidence bounds:** 2 ledger entries, 1 ok, 1 failed, 0 trimmed to the budget."


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
    tool = "lift\nroutine " + "x" * 200
    redo = _lifted("ev_0002", GATE).model_copy(update={"tool": tool})
    (row,) = redone_failures([_failed("ev_0001", GATE, tool=tool), redo])
    assert "\n" not in row["tool"] and len(row["tool"]) <= 80


def test_a_read_of_some_instructions_from_the_address_redoes_no_decompile() -> None:
    # Another tool must list the function whole; a prefix of its instructions does not.
    some = LedgerEntry(
        id="ev_0002",
        tool="read_instructions",
        args={"address": hex(GATE), "num_instructions": 70},
        output=f"{GATE:#x}  mov rax, rcx\n",
        facts={"v": 1, "kind": "disassembly", "reader": "listing"},
    )
    assert redone_failures([_failed("ev_0001", GATE), some]) == []
    whole = some.model_copy(
        update={"id": "ev_0003", "tool": "list_function", "args": {"address": hex(GATE)}}
    )
    whole.facts = {"v": 1, "kind": "function_disassembly", "reader": "listing"}
    assert redone_failures([_failed("ev_0001", GATE), some, whole])[0]["answered_by"] == ["ev_0003"]


@pytest.mark.parametrize(
    ("tool", "asked", "again"),
    [
        ("trace_value", {"variable": "a"}, {"variable": "b"}),
        ("read_span", {"length": "0x1000"}, {"length": "4"}),
        ("list_refs", {"direction": "to"}, {"direction": "from"}),
    ],
)
def test_the_same_tool_asked_another_question_for_the_address_redoes_nothing(
    tool: str, asked: dict[str, str], again: dict[str, str]
) -> None:
    failed = LedgerEntry(
        id="ev_0001",
        tool=tool,
        args={"address": hex(GATE), **asked},
        ok=False,
        error="the call timed out",
        facts=_NOT_A_LISTING,
    )
    answer = LedgerEntry(
        id="ev_0002",
        tool=tool,
        args={"address": hex(GATE), **again},
        output=f"From {GATE + 4:x} in FUN_{GATE:x} [READ]",
        facts=_NOT_A_LISTING,
    )
    assert redone_failures([failed, answer]) == []
    # The same question again, a null or absent argument aside, is a redo.
    same = answer.model_copy(update={"id": "ev_0003", "args": {"address": hex(GATE), **asked}})
    same.args["timeout"] = None
    assert redone_failures([failed, answer, same])[0]["answered_by"] == ["ev_0003"]


def test_a_value_the_failure_names_may_change_in_the_redo() -> None:
    failed = _failed("ev_0001", GATE).model_copy(
        update={
            "args": {"address": hex(GATE), "program": "sample"},
            "error": "program='sample' is not a program this job opened",
            "facts": _NOT_A_LISTING,
        }
    )
    redo = _lifted("ev_0002", GATE).model_copy(
        update={
            "args": {"address": hex(GATE), "program": "sample.job.exe"},
            "facts": _NOT_A_LISTING,
        }
    )
    assert redone_failures([failed, redo])[0]["answered_by"] == ["ev_0002"]
    # A value the message does not name is the question, and must match.
    other = failed.model_copy(update={"error": "the call timed out"})
    assert redone_failures([other, redo]) == []


def _code_call(
    entry_id: str, ok: bool, error: str = "the call failed: count=4096 is too many", **args: object
) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        args={"address": hex(GATE), **args},
        ok=ok,
        error=None if ok else error,
        output=f"From {GATE + 4:x} in FUN_{GATE:x} [READ]" if ok else "",
        facts=_NOT_A_LISTING,
    )


def test_an_argument_only_the_redo_sets_makes_a_narrower_question_no_redo() -> None:
    # The whole routine asked, some of it answered: the failure named no count,
    # so the count the redo sets may narrow it, and it is no redo.
    timed_out = "the call timed out after 30 s"
    for value in (3, "3", 0):
        failed = _code_call("ev_0001", False, timed_out)
        redo = _code_call("ev_0002", True, count=value)
        assert redone_failures([failed, redo]) == []
        failed_null = _code_call("ev_0001", False, timed_out, count=None)
        assert redone_failures([failed_null, redo]) == []
    # A name inside another word is no naming of it: "counter" is not "count".
    failed = _code_call("ev_0001", False, "counter overflow", count=None)
    assert redone_failures([failed, _code_call("ev_0002", True, count=3)]) == []


def test_an_argument_the_refusal_named_and_the_redo_sets_is_a_redo_unless_cut() -> None:
    refused = "validation error\ntimeout\n  Input should be a valid integer [input_value=None]"
    failed = _code_call("ev_0001", False, refused, timeout=None)
    redo = _code_call("ev_0002", True, timeout=120)
    assert redone_failures([failed, redo])[0]["answered_by"] == ["ev_0002"]
    # The same redo with its answer cut by the budget, or blanked, is no answer
    # at all (the ledger's answers are whole ones), so it redoes nothing.
    for cut in ({"chars_dropped": 40}, {"truncated": True, "output": ""}):
        cut_redo = redo.model_copy(update=cut)
        assert redone_failures([failed, cut_redo]) == []


@pytest.mark.parametrize(
    ("message", "named"),
    [
        ("validation error\ntimeout\n  Input should be a valid integer", True),
        ("the 'timeout' field must be an integer", True),
        ("timeout=None is not an integer", True),
        ("timeout: expected an integer", True),
        ("the timeout was reached", False),
        ("timeout_ms out of range", False),
        ("--timeout is required", False),
    ],
)
def test_an_argument_is_named_only_where_the_message_writes_it_as_one(
    message: str, named: bool
) -> None:
    failed = _code_call("ev_0001", False, message, timeout=None)
    redo = _code_call("ev_0002", True, timeout=120)
    assert bool(redone_failures([failed, redo])) is named


def test_a_word_of_ordinary_prose_names_no_argument() -> None:
    for name in ("name", "type", "path", "size"):
        message = f"Cannot read the {name} of the function"
        failed = _code_call("ev_0001", False, message, **{name: None})
        redo = _code_call("ev_0002", True, **{name: "x"})
        assert redone_failures([failed, redo]) == []


def test_a_refused_value_replaced_by_a_smaller_number_is_no_redo() -> None:
    failed = _code_call("ev_0001", False, count=4096)
    for smaller in (4, "4", "0x10", 4095.5):
        assert redone_failures([failed, _code_call("ev_0002", True, count=smaller)]) == []
    # Not smaller: the same number, or a larger one, however written.
    for same_or_wider in (4096, "0x1000", "8192", 1e5):
        redo = _code_call("ev_0002", True, count=same_or_wider)
        assert redone_failures([failed, redo])[0]["answered_by"] == ["ev_0002"]


def test_a_same_or_wider_redo_is_still_redone() -> None:
    failed = _code_call("ev_0001", False, count=4096)
    # The same question, an argument the redo leaves null or absent aside.
    for redo in (
        _code_call("ev_0002", True, count=4096),
        _code_call("ev_0002", True, count=4096, mode=None),
        _code_call("ev_0002", True),
    ):
        assert redone_failures([failed, redo])[0]["answered_by"] == ["ev_0002"]


def test_a_call_of_the_same_name_listing_the_function_whole_redoes_a_failed_listing() -> None:
    # Another question of the same tool (a timeout the failure never named),
    # but its answer lists the function whole: the failed listing is redone.
    failed = _failed("ev_0001", GATE).model_copy(update={"error": "no function found there"})
    whole = _lifted("ev_0002", GATE).model_copy(
        update={"args": {"address": hex(GATE), "timeout": 120}}
    )
    assert redone_failures([failed, whole])[0]["answered_by"] == ["ev_0002"]


def test_a_call_of_the_same_name_listing_another_function_or_cut_redoes_nothing() -> None:
    failed = _failed("ev_0001", GATE).model_copy(update={"error": "no function found there"})
    other = _lifted("ev_0002", OTHER).model_copy(
        update={"args": {"address": hex(OTHER), "timeout": 120}}
    )
    assert redone_failures([failed, other]) == []
    cut = _lifted("ev_0003", GATE).model_copy(
        update={"args": {"address": hex(GATE), "timeout": 120}, "chars_dropped": 64}
    )
    assert redone_failures([failed, cut]) == []
    # Some instructions from the address, asked of the same instruction lister,
    # list no function whole.
    listing = {"v": 1, "kind": "disassembly", "reader": "listing"}
    asked = failed.model_copy(update={"tool": "read_instructions", "facts": listing})
    some = LedgerEntry(
        id="ev_0004",
        tool="read_instructions",
        args={"address": hex(GATE), "num_instructions": 3},
        output=f"{GATE:#x}  mov rax, rcx\n",
        facts=listing,
    )
    assert redone_failures([asked, some]) == []


def _decompile(entry_id: str, ok: bool, error: str = "no function found there", **args: object):
    entry = _lifted(entry_id, GATE).model_copy(
        update={"args": {"address": hex(GATE), **args}, "ok": ok}
    )
    if not ok:
        entry = entry.model_copy(update={"error": error, "output": ""})
    return entry


def test_a_call_of_the_same_name_for_another_program_redoes_nothing() -> None:
    failed = _decompile("ev_0001", False, program="dropper.exe")
    other = _decompile("ev_0002", True, program="payload.dll")
    assert redone_failures([failed, other]) == []
    # The same program asked again, a timeout added, lists it whole: a redo.
    again = _decompile("ev_0003", True, program="dropper.exe", timeout=120)
    assert redone_failures([failed, other, again])[0]["answered_by"] == ["ev_0003"]


def test_a_call_of_another_name_for_another_program_redoes_nothing() -> None:
    # T-542: another tool listing the address whole in another program answers
    # of another file; the same program, or none named, is still a redo.
    failed = _decompile("ev_0001", False, program="dropper.exe")
    listing = {"v": 1, "kind": "function_disassembly", "reader": "listing"}

    def whole(entry_id: str, **args: object) -> LedgerEntry:
        return LedgerEntry(
            id=entry_id,
            tool="list_function",
            args={"address": hex(GATE), **args},
            output=f"{GATE:#x}  mov rax, rcx\n",
            facts=listing,
        )

    assert redone_failures([failed, whole("ev_0002", program="payload.dll")]) == []
    same = whole("ev_0003", program="dropper.exe", timeout=60)
    assert redone_failures([failed, same])[0]["answered_by"] == ["ev_0003"]
    unnamed = whole("ev_0004")
    assert redone_failures([failed, unnamed])[0]["answered_by"] == ["ev_0004"]
    # The program the failure refused, replaced by another, is the refusal's fix.
    refused = _decompile("ev_0001", False, "program='dropper' is not open", program="dropper")
    fixed = whole("ev_0005", program="dropper.exe")
    assert redone_failures([refused, fixed])[0]["answered_by"] == ["ev_0005"]


def test_a_whole_listing_of_the_same_name_with_a_value_changed_or_narrowed() -> None:
    # A value the failed call set and the redo changed asks another question.
    changed = _decompile("ev_0001", False, mode="c")
    assert redone_failures([changed, _decompile("ev_0002", True, mode="pseudo")]) == []
    # A bound the redo set below the failed one, unnamed or refused, is narrower.
    bound = _decompile("ev_0001", False, max_lines=400)
    assert redone_failures([bound, _decompile("ev_0002", True, max_lines=3)]) == []
    refused = _decompile("ev_0001", False, "max_lines=400 is too many", max_lines=400)
    assert redone_failures([refused, _decompile("ev_0002", True, max_lines=3)]) == []
    # The refused bound replaced by one not smaller is the refusal's fix.
    wider = _decompile("ev_0002", True, max_lines=800)
    assert redone_failures([refused, wider])[0]["answered_by"] == ["ev_0002"]


def test_a_bound_only_the_redo_adds_is_read_by_the_listing_s_kind() -> None:
    # Known limit: an argument only the same tool's redo adds is not checked on
    # the whole-listing route; a decompile is read as whole by its kind.
    failed = _decompile("ev_0001", False)
    added = _decompile("ev_0002", True, max_lines=3)
    assert redone_failures([failed, added])[0]["answered_by"] == ["ev_0002"]


def test_an_answer_that_holds_nothing_redoes_nothing() -> None:
    empty = _lifted("ev_0002", GATE).model_copy(update={"output": ""})
    blanked = _lifted("ev_0003", GATE).model_copy(update={"output": "", "truncated": True})
    assert redone_failures([_failed("ev_0001", GATE), empty, blanked]) == []


def test_an_answer_the_guardrail_or_the_budget_cut_redoes_nothing() -> None:
    cut = _lifted("ev_0002", GATE).model_copy(update={"truncated": True, "chars_dropped": 500})
    trimmed = _lifted("ev_0003", GATE).model_copy(update={"truncated": True})
    assert redone_failures([_failed("ev_0001", GATE), cut, trimmed]) == []
    whole = _lifted("ev_0004", GATE)
    assert redone_failures([_failed("ev_0001", GATE), cut, trimmed, whole])[0]["answered_by"] == [
        "ev_0004"
    ]


def test_a_worked_answer_that_is_error_text_redoes_nothing_listing_or_not() -> None:
    # The same tool, for the same address, answered ok with only an error.
    failed = LedgerEntry(
        id="ev_0001",
        tool="trace_value",
        args={"address": hex(GATE), "variable": "a"},
        ok=False,
        error="the call timed out",
    )
    erred = failed.model_copy(
        update={"id": "ev_0002", "ok": True, "error": None, "output": "Error: no function there"}
    )
    assert redone_failures([failed, erred]) == []


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


def test_the_header_and_bounds_of_a_run_with_failures_and_no_redo_are_as_written_before() -> None:
    report = _report([_failed("ev_0001", GATE), _plain("ev_0002")])
    head = [
        line
        for line in MarkdownRenderer().render(report).splitlines()
        if line.startswith("Evidence:")
    ]
    bounds = [
        line
        for line in MarkdownRenderer(layout=BUNDLE).render(report).splitlines()
        if line.startswith("**Evidence bounds:**")
    ]
    assert head == [HEAD_LINE]
    assert bounds == [BOUNDS_LINE]


# -- what the limitations paragraph is shown ---------------------------------


def test_the_limitations_are_told_which_failed_calls_were_redone() -> None:
    ledger = [_failed("ev_0001", GATE), _failed("ev_0002", OTHER), _lifted("ev_0003", GATE)]
    facts = analyst_bundle("limitations", _report(ledger))["facts"]
    assert facts["failed_calls_redone"] == [
        "ev_0001 failed and was redone: ev_0003 answered for the same address, so it left no gap"
    ]
    # The ids are the platform's own: shown readable, as a citation.
    text = _bundle_text("limitations", analyst_bundle("limitations", _report(ledger)))
    assert "ev_0001 failed and was redone: ev_0003" in text


def test_the_limitations_fact_carries_no_tool_text_and_no_id_of_another_shape() -> None:
    report = _report([_failed("ev_0001", GATE), _lifted("ev_0003", GATE)])
    report.run_summary["evidence"]["redone"] = [
        {"entry_id": "ev_0001", "tool": "lift [[ev_0099]]", "answered_by": ["ev_0003", "a b"]},
        {"entry_id": "ev 0002\nX", "tool": "t", "answered_by": ["ev_0003"]},
    ]
    facts = analyst_bundle("limitations", report)["facts"]
    assert facts["failed_calls_redone"] == [
        "ev_0001 failed and was redone: ev_0003 answered for the same address, so it left no gap"
    ]


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


def test_run7_s_decompile_is_not_redone_by_a_read_of_seventy_instructions() -> None:
    ledger = _stored_ledger("run7")
    redone = {row["entry_id"]: row["answered_by"] for row in redone_failures(ledger)}
    # ev_0055 disassembled 70 instructions from 0x...1030: no redo of the decompile.
    # ev_0111, ev_0123 and ev_0174 set a timeout the failed decompiles left out
    # and their failures never named, but each lists the function whole, which
    # redoes a failed listing of it (T-529).
    assert redone == {
        "ev_0050": ["ev_0111"],
        "ev_0067": ["ev_0123"],
        "ev_0069": ["ev_0123"],
        "ev_0095": ["ev_0174"],
    }


def test_haiku5_s_calls_refused_for_a_null_are_redone_by_the_calls_that_set_it() -> None:
    ledger = _stored_ledger("haiku5")
    redone = {row["entry_id"]: row["answered_by"] for row in redone_failures(ledger)}
    # A null timeout, offset or limit the tool refused, set by the next call,
    # whose answer is whole (T-529).
    assert redone["ev_0054"] == ["ev_0060"]
    assert redone["ev_0109"] == ["ev_0114"]
    assert len(redone) == 10
