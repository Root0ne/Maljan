"""A limitations sentence that calls a redone call failed is asked against the ledger (T-526).

haiku8's limitations paragraph said the reversing tools for emulation, batch
decompilation and disassembly failed, "so the control flow of the dispatch
routines was read from the function index", while every decompile and
disassembly that failed had been answered by a later call. The paragraph is
now one of the passages the agreement round asks about, with the facts it
rests on (the failed calls and the later calls that answered them, the tools
not run, the recorded limitations, the open questions), wherever a sentence
of it says a call failed and the ledger says otherwise; a rewrite that still
says so is not put in. Every address, entry and tool name in the synthetic
tests is a neutral value.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage

from maljan.pipeline.validation import EntryTexts
from maljan.reporting.models import (
    EvidenceSection,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.section_agreement import (
    CLAIM_LED,
    FACT,
    FAILURE_REDONE_CODE,
    REWRITTEN_CODE,
    ask_section_agreement,
    held_limitation_sentences,
    passages_of,
    prompt_text,
)
from maljan.schemas.evidence import LedgerEntry
from tests.unit.reporting._report_inventory import stored_runs

ROUTINE = 0x401A30
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}

FALSE = (
    "The listing tool failed, so the control flow was read from the function index, not "
    "from a listing [ev_0001]."
)
TRUE = "The emulation call failed, so the decoded keys rest on the strings alone [ev_0004]."
OTHER = "The sandbox run was not observed [ev_0001]."


def _ledger(*, failures: bool = True) -> list[LedgerEntry]:
    lifted = LedgerEntry(
        id="ev_0003",
        tool="lift_routine",
        args={"address": hex(ROUTINE)},
        output=f"int FUN_{ROUTINE:x}(int a)\n{{\n  return a;\n}}\n",
        facts=_DECOMPILE,
    )
    out = [LedgerEntry(id="ev_0001", tool="index_routines", output="FUN_401a30 at 0x401a30")]
    if failures:
        out.append(
            LedgerEntry(
                id="ev_0002",
                tool="lift_routine",
                args={"address": hex(ROUTINE)},
                ok=False,
                error="the program is not open",
                facts=_DECOMPILE,
            )
        )
    out.append(lifted)
    if failures:
        out.append(
            LedgerEntry(
                id="ev_0004",
                tool="emulate_names",
                args={"candidates": "alpha,beta"},
                ok=False,
                error="No candidates provided",
            )
        )
    return out


def _report(body: str = f"{FALSE} {OTHER}", *, questions: bool = False) -> MalwareReport:
    sections = []
    if questions:
        sections.append(
            EvidenceSection(
                key="open_questions",
                kind="table",
                title="Open questions",
                columns=["Agent", "Question", "Why open", "What would answer it", "Evidence"],
                rows=[
                    [
                        "lane",
                        "Which key does 0x401a30 load?",
                        "tool_failed: the decompile failed.",
                        "a decompile of 0x401a30",
                        "ev_0001",
                    ],
                    ["lane", "Does the beacon run?", "needs_sandbox_run", "a run", "ev_0001"],
                ],
            )
        )
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64), file_type="PE32 DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        degradation_reasons=[
            "server.lookup.check_name_unavailable(KEY is not configured (no value)); set it",
            "triage.rules_failed",
        ],
        sections=sections,
        technical_analysis=TechnicalAnalysis(
            analyst_limitations=TechnicalSubsection(
                title="Limitations", body=body, evidence_refs=["ev_0001"]
            ),
        ),
    )


class _Reporter:
    def __init__(self, *answers: Any) -> None:
        self.answers = [a if isinstance(a, str) else json.dumps(a) for a in answers]
        self.asked: list[list[BaseMessage]] = []
        self.degradations: list[str] = []

    async def ask(self, turns: list[BaseMessage], *, call: str, what: str) -> AIMessage:
        self.asked.append(list(turns))
        return AIMessage(content=self.answers.pop(0) if self.answers else '{"sentences": []}')


def _ask(report: MalwareReport, ledger: list[LedgerEntry], *answers: Any) -> tuple[Any, _Reporter]:
    reporter = _Reporter(*answers)
    done = asyncio.run(
        ask_section_agreement(
            reporter,
            report,
            citable_ids=[str(e.id) for e in ledger],
            evidence_texts=EntryTexts.from_ledger(ledger),
        )
    )
    return done, reporter


def _row(sentence: str, sources: list[str], rewrite: str) -> dict[str, Any]:
    return {
        "passage": "limitations",
        "sentence": sentence,
        "sources": sources,
        "decision": "rewrite",
        "rewrite": rewrite,
    }


def _by_id(report: MalwareReport, ledger: list[LedgerEntry]) -> dict[str, Any]:
    return {p.id: p for p in passages_of(report, entries=ledger)}


def test_a_sentence_calling_a_redone_call_failed_is_asked_with_the_failed_calls() -> None:
    passages = _by_id(_report(), _ledger())
    limitations = passages["limitations"]
    assert limitations.kind == CLAIM_LED and limitations.write is not None
    assert passages["failed.1"].kind == FACT
    assert passages["failed.1"].text == (
        'ev_0002 ("lift_routine") failed: "the program is not open"; the later call ev_0003 '
        "answered for every address it asked (0x401a30), so it did not fail for good"
    )
    assert passages["failed.1"].cites == {"ev_0002", "ev_0003"}
    assert passages["failed.2"].text.endswith(
        "it asked for no address, so no later call is read as its redo"
    )
    # The tool not run is read with its whole reason, brackets inside it kept.
    assert passages["not_run.1"].text == (
        '"check_name" was not run: "KEY is not configured (no value)"'
    )
    assert passages["recorded.1"].text == '"triage.rules_failed"'
    prompt = prompt_text(list(passages.values()))
    assert "[limitations] 11. Limitations, the composed paragraph" in prompt
    assert "[failed.1] tool call that failed" in prompt


def test_only_the_sentence_the_ledger_says_otherwise_of_is_held() -> None:
    passages = _by_id(_report(f"{FALSE} {TRUE} {OTHER}"), _ledger())
    from maljan.reporting.agreement_facts import ledger_facts
    from maljan.reporting.limitation_facts import limitation_facts

    ledger = _ledger()
    found = ledger_facts(ledger)
    read = limitation_facts(_report(), ledger, found.answered, found.image_bases)
    body = passages["limitations"].text
    # The emulation sentence rests on a failure no later call redid: it agrees.
    assert held_limitation_sentences(body, read.failed, [], ()) == [FALSE]


def test_a_correct_paragraph_is_not_asked_and_the_request_is_unchanged() -> None:
    ledger = _ledger()
    without = _report()
    without.technical_analysis.analyst_limitations = None
    expected = prompt_text(passages_of(without, entries=ledger))
    for body in (f"{TRUE} {OTHER}", OTHER, "The listing tool failed and was redone [ev_0003]."):
        assert prompt_text(passages_of(_report(body), entries=ledger)) == expected


def test_a_paragraph_is_byte_identical_where_no_call_failed() -> None:
    ledger = _ledger(failures=False)
    report = _report()
    before = report.model_dump_json()
    without = _report()
    without.technical_analysis.analyst_limitations = None
    # No failed call: no sentence is held, the request is the one without it.
    assert prompt_text(passages_of(report, entries=ledger)) == prompt_text(
        passages_of(without, entries=ledger)
    )
    _ask(report, ledger)
    assert report.model_dump_json() == before


def test_a_rewrite_saying_the_later_call_answered_is_put_in() -> None:
    report = _report()
    rewrite = (
        "The listing tool failed once and a later call listed the routine, so the control "
        "flow was read from that listing [ev_0001][ev_0003]."
    )
    done, _ = _ask(report, _ledger(), {"sentences": [_row(FALSE, ["failed.1"], rewrite)]})
    body = report.technical_analysis.analyst_limitations.body
    assert body == f"{rewrite} {OTHER}"
    assert report.technical_analysis.analyst_limitations.evidence_refs == ["ev_0001", "ev_0003"]
    assert done.summary["rewritten"] == 1
    assert [r["code"] for r in done.tally.unresolved] == [REWRITTEN_CODE]


@pytest.mark.parametrize(
    "rewrite",
    [
        # Cites the failed call a later call redid, and still calls it failed.
        "The listing tool failed, so the control flow was read from the function index "
        "[ev_0001][ev_0002].",
        # Cites the later call, and still calls the tool failed for good.
        "The listing tool failed, so the control flow was read from the function index "
        "[ev_0001][ev_0003].",
    ],
)
def test_a_rewrite_repeating_the_false_claim_is_not_put_in(rewrite: str) -> None:
    report = _report()
    row = _row(FALSE, ["failed.1"], rewrite)
    done, reporter = _ask(report, _ledger(), {"sentences": [row]}, {"sentences": [row]})
    assert report.technical_analysis.analyst_limitations.body == f"{FALSE} {OTHER}"
    assert done.summary["rewritten"] == 0 and done.summary["not_applied"] == 1
    # The model was told why, and asked once more.
    assert len(reporter.asked) == 2
    assert FAILURE_REDONE_CODE in str(reporter.asked[1][-1].content)
    assert FAILURE_REDONE_CODE in [r["code"] for r in done.tally.unresolved]


def test_a_question_filed_on_a_redone_call_is_marked_and_kept() -> None:
    passages = _by_id(_report(questions=True), _ledger())
    assert passages["open.1"].text == (
        '"Which key does 0x401a30 load?", filed as tool_failed; redone: the failed call '
        "ev_0002 for 0x401a30, an address it names, was answered by ev_0003"
    )
    assert passages["open.1"].cites == {"ev_0001", "ev_0002", "ev_0003"}
    assert passages["open.2"].text == "1 more open question, filed as needs_sandbox_run (1)"


# ---------------------------------------------------------------------------
# The stored run the defect was read off
# ---------------------------------------------------------------------------

HAIKU8_SENTENCE = (
    "The reversing tools for emulation, batch decompilation and disassembly failed, so the "
    "control flow of the dispatch routines was read from the function index and the recovered "
    "artefacts, not from a decompiler listing [ev_0025]."
)


def _haiku8() -> tuple[MalwareReport, list[LedgerEntry]]:
    from maljan.reporting.follow_up import stored_ledger

    root = stored_runs()
    if root is None or not (root / "haiku8" / "report.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    run = root / "haiku8"
    report = MalwareReport.model_validate(json.loads((run / "report.json").read_text()))
    document = json.loads((run / "evidence.json").read_text())
    rows = document.get("items") or document.get("entries") if isinstance(document, dict) else []
    ledger, _unread = stored_ledger(rows)
    return report, ledger


def test_the_stored_run_s_reversing_tools_sentence_is_asked() -> None:
    report, ledger = _haiku8()
    passages = {p.id: p for p in passages_of(report, entries=ledger)}
    limitations = passages["limitations"]
    from maljan.reporting.agreement_facts import ledger_facts
    from maljan.reporting.limitation_facts import limitation_facts

    found = ledger_facts(ledger)
    read = limitation_facts(report, ledger, found.answered, found.image_bases)
    listed = [routine.address for routine in found.listed]
    assert held_limitation_sentences(limitations.text, read.failed, listed, found.image_bases) == [
        HAIKU8_SENTENCE
    ]
    redone = {call.entry: call.redone_by for call in read.failed if call.redone}
    assert redone == {
        "ev_0168": ("ev_0171",),
        "ev_0169": ("ev_0170",),
        "ev_0187": ("ev_0191",),
    }
    # The emulation and the capa call stand: no later call redid them.
    assert {call.entry for call in read.failed if not call.redone} == {"ev_0008", "ev_0122"}
    said = [p.text for p in passages.values() if p.id.startswith("failed.")]
    assert any(t.startswith('ev_0168 ("batch_decompile") failed') and "ev_0171" in t for t in said)
    # The stale questions filed as tool_failed are marked, not dropped.
    marked = [p.text for p in passages.values() if p.id.startswith("open.") and "redone:" in p.text]
    assert any("Which RC4 key" in t and "ev_0187" in t and "ev_0191" in t for t in marked)


def test_the_stored_run_s_false_rewrite_is_not_put_in_and_a_true_one_is() -> None:
    report, ledger = _haiku8()
    body = report.technical_analysis.analyst_limitations.body
    facts = {p.id: p for p in passages_of(report, entries=ledger)}
    batch = next(i for i, p in facts.items() if p.text.startswith('ev_0168 ("batch_decompile")'))
    emulation = next(
        i for i, p in facts.items() if p.text.startswith('ev_0122 ("emulate_hash_batch")')
    )
    false = (
        "The reversing tools for batch decompilation and disassembly failed, so the control "
        "flow was read from the function index [ev_0025][ev_0168]."
    )
    row = _row(HAIKU8_SENTENCE, [batch], false)
    done, _ = _ask(report, ledger, {"sentences": [row]}, {"sentences": [row]})
    assert report.technical_analysis.analyst_limitations.body == body
    assert done.summary["not_applied"] == 1
    true = (
        "The emulation call by candidate names failed [ev_0122]; the batch decompile that "
        "failed was redone by a later call, so the dispatch routines' control flow was read "
        "from its listing [ev_0025][ev_0171]."
    )
    row = _row(HAIKU8_SENTENCE, [emulation, batch], true)
    done, _ = _ask(report, ledger, {"sentences": [row]})
    assert done.summary["rewritten"] == 1
    assert report.technical_analysis.analyst_limitations.body == body.replace(HAIKU8_SENTENCE, true)
