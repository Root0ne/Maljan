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
    KeyFinding,
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
    _sentences_of,
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
    "The decompiler failed, so the control flow was read from the function index, not "
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


def _held(body: str, ledger: list[LedgerEntry] | None = None) -> list[str]:
    """The sentences held, read with what production reads: the listed routines and bases."""
    from maljan.reporting.agreement_facts import ledger_facts
    from maljan.reporting.limitation_facts import limitation_facts

    ledger = ledger if ledger is not None else _ledger()
    found = ledger_facts(ledger)
    read = limitation_facts(_report(), ledger, found.answered, found.image_bases)
    listed = [routine.address for routine in found.listed]
    return held_limitation_sentences(body, read.failed, listed, found.image_bases)


def test_only_the_sentence_the_ledger_says_otherwise_of_is_held() -> None:
    passages = _by_id(_report(f"{FALSE} {TRUE} {OTHER}"), _ledger())
    # The emulation sentence rests on a failure no later call redid: it agrees.
    assert _held(passages["limitations"].text) == [FALSE]


@pytest.mark.parametrize(
    ("sentence", "held"),
    [
        # A sample's behaviour names no tool and no kind of call.
        ("The beacon failed to connect to its server in the sandbox.", False),
        ("The beacon failed to connect to its server [ev_0001].", False),
        # A redone call cited without its redo is held, whatever the words say.
        ("The decompiler failed, so the routine was re-read from the index [ev_0002].", True),
        # A negated redo word says no redo.
        ("The decompiler failed and no later call answered it [ev_0001].", True),
        ("The decompiler failed and was not redone [ev_0001].", True),
        ("The decompiler failed and was never redone [ev_0001].", True),
        # A redo said and cited agrees.
        ("The decompiler failed once and was redone [ev_0002][ev_0003].", False),
        # A listing that is no listing of code names no call that lists code.
        ("The process listing failed to enumerate the running services [ev_0001].", False),
        ("The check-in failed, so no listing of the server's commands was kept [ev_0001].", False),
        ("The decompiler failed, so no routine listing was read [ev_0001].", True),
    ],
)
def test_a_sentence_is_held_by_the_call_it_names_or_cites(sentence: str, held: bool) -> None:
    assert _held(sentence) == ([sentence] if held else [])


@pytest.mark.parametrize(
    ("sentence", "held"),
    [
        # A short tool name is read as a whole word, never inside another one.
        ("The thread injection failed in the sandbox [ev_0001].", False),
        ("The spread routine failed [ev_0001].", False),
        ("The read call failed [ev_0001].", True),
    ],
)
def test_a_tool_s_name_is_read_as_a_whole_word(sentence: str, held: bool) -> None:
    ledger = [
        LedgerEntry(id="ev_0001", tool="index_routines", output="FUN_401a30 at 0x401a30"),
        LedgerEntry(
            id="ev_0002", tool="read", args={"address": "0x401a30"}, ok=False, error="not open"
        ),
        LedgerEntry(id="ev_0003", tool="read", args={"address": "0x401a30"}, output="90 90 c3"),
    ]
    assert _held(sentence, ledger) == ([sentence] if held else [])


def test_a_correct_paragraph_is_not_asked_and_the_request_is_unchanged() -> None:
    ledger = _ledger()
    without = _report()
    without.technical_analysis.analyst_limitations = None
    expected = prompt_text(passages_of(without, entries=ledger))
    for body in (f"{TRUE} {OTHER}", OTHER, "The decompiler failed and was redone [ev_0003]."):
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


@pytest.mark.parametrize(
    "rewrite",
    [
        "The decompiler failed once and a later call decompiled the routine, so the control "
        "flow was read from that listing [ev_0001][ev_0003].",
        # Decided by citation, not vocabulary: no redo word, the redo cited.
        "The first decompile call failed, and a second call decompiled the routine, so the control "
        "flow was read from it [ev_0001][ev_0003].",
    ],
)
def test_a_rewrite_citing_the_call_that_redid_it_is_put_in(rewrite: str) -> None:
    report = _report()
    done, _ = _ask(report, _ledger(), {"sentences": [_row(FALSE, ["failed.1"], rewrite)]})
    body = report.technical_analysis.analyst_limitations.body
    assert body == f"{rewrite} {OTHER}"
    assert report.technical_analysis.analyst_limitations.evidence_refs == ["ev_0001", "ev_0003"]
    assert done.summary["rewritten"] == 1
    assert [r["code"] for r in done.tally.unresolved] == [REWRITTEN_CODE]


@pytest.mark.parametrize(
    ("rewrite", "sources"),
    [
        # Cites the failed call a later call redid, and still calls it failed.
        (
            "The decompiler failed, so the control flow was read from the function index "
            "[ev_0001][ev_0002].",
            ["failed.1"],
        ),
        # One failure that stands cited beside it is no cover.
        (
            "The decompiler failed, so the control flow was read from the function index "
            "[ev_0001][ev_0002][ev_0004].",
            ["failed.1", "failed.2"],
        ),
        (
            "The listing and emulation tools failed, so the control flow was read from the "
            "function index [ev_0001][ev_0004].",
            ["failed.1", "failed.2"],
        ),
        # A negated redo word is no redo, and a redo word alone is never enough.
        (
            "The decompiler failed and was never redone, so the control flow was read from "
            "the function index [ev_0001][ev_0002].",
            ["failed.1"],
        ),
        (
            "The decompiler failed and no later call answered it, so the control flow was "
            "read from the function index [ev_0001][ev_0002].",
            ["failed.1"],
        ),
        (
            "The decompiler failed and was redone, so the control flow was read from the "
            "function index [ev_0001][ev_0002].",
            ["failed.1"],
        ),
        # R1: a negated redo is no redo, even citing the call that redid it.
        (
            "The decompiler failed and was never redone, so the control flow was read from "
            "the function index [ev_0001][ev_0002][ev_0003].",
            ["failed.1"],
        ),
        # R2: naming the redone call is enough, with a standing failure the only source;
        # the check reads a bare "listing" as naming every call that lists code.
        (
            "The listing and emulation tools failed, so the control flow was read from the "
            "function index [ev_0001][ev_0004].",
            ["failed.2"],
        ),
        (
            "The decompiler and emulation tools failed, so the control flow was read from the "
            "function index [ev_0001][ev_0004].",
            ["failed.2"],
        ),
        # R3: "for good" denies the redo it cites.
        (
            "The decompiler failed for good; ev_0003 shows only the function index "
            "[ev_0001][ev_0003].",
            ["failed.1"],
        ),
    ],
)
def test_a_rewrite_repeating_the_false_claim_is_not_put_in(
    rewrite: str, sources: list[str]
) -> None:
    report = _report()
    row = _row(FALSE, sources, rewrite)
    done, reporter = _ask(report, _ledger(), {"sentences": [row]}, {"sentences": [row]})
    assert report.technical_analysis.analyst_limitations.body == f"{FALSE} {OTHER}"
    assert done.summary["rewritten"] == 0 and done.summary["not_applied"] == 1
    # The model was told why, and asked once more.
    assert len(reporter.asked) == 2
    assert FAILURE_REDONE_CODE in str(reporter.asked[1][-1].content)
    assert FAILURE_REDONE_CODE in [r["code"] for r in done.tally.unresolved]


def test_a_bare_listing_is_not_held_by_the_gate_but_rejects_a_rewrite() -> None:
    # The gate reads narrowly (a sentence held too often costs the prompt); the
    # check broadly (a rewrite refused only keeps the sentence as written).
    sentence = "The listing tool failed, so the control flow came from the index [ev_0001]."
    assert _held(sentence) == []
    report = _report()
    row = _row(FALSE, ["failed.2"], sentence)
    done, _ = _ask(report, _ledger(), {"sentences": [row]}, {"sentences": [row]})
    assert done.summary["rewritten"] == 0
    assert FAILURE_REDONE_CODE in [r["code"] for r in done.tally.unresolved]


def test_a_quoted_message_carries_no_path_and_no_url() -> None:
    ledger = _ledger()
    ledger[1] = ledger[1].model_copy(
        update={"error": "rules at /opt/tools/data/rules are missing on http://10.0.0.5:8089/api"}
    )
    text = _by_id(_report(), ledger)["failed.1"].text
    assert "/opt/tools" not in text and "10.0.0.5" not in text and "8089" not in text
    assert '"rules at rules are missing on a URL"' in text
    # Only the first clause is quoted, a digest in it named so.
    ledger[1] = ledger[1].model_copy(
        update={"error": f"program='{'ab' * 32}' is not open; the call was not sent"}
    )
    text = _by_id(_report(), ledger)["failed.1"].text
    assert "\"program='a digest' is not open\"" in text and "not sent" not in text


def test_how_an_answer_was_read_is_no_recorded_limitation() -> None:
    report = _report()
    report.degradation_reasons.append(
        "The static analyst's answer (round 1) began 42 claim(s), and 40 were read; 2 could "
        "not be read as a claim and are not in its findings."
    )
    recorded = [p.text for i, p in _by_id(report, _ledger()).items() if i.startswith("recorded.")]
    assert recorded == ['"triage.rules_failed"']


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


def _stored(name: str) -> tuple[MalwareReport, list[LedgerEntry]]:
    from maljan.reporting.follow_up import stored_ledger

    root = stored_runs()
    if root is None or not (root / name / "report.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    run = root / name
    report = MalwareReport.model_validate(json.loads((run / "report.json").read_text()))
    document = json.loads((run / "evidence.json").read_text())
    rows = document.get("items") or document.get("entries") if isinstance(document, dict) else []
    ledger, _unread = stored_ledger(rows)
    return report, ledger


def _haiku8() -> tuple[MalwareReport, list[LedgerEntry]]:
    return _stored("haiku8")


def _stored_names() -> list[str]:
    root = stored_runs()
    if root is None:
        return ["haiku8"]
    return sorted(
        run.name
        for run in root.iterdir()
        if (run / "report.json").is_file() and (run / "evidence.json").is_file()
    )


@pytest.mark.parametrize("name", _stored_names())
def test_no_stored_run_but_haiku8_asks_its_limitations(name: str) -> None:
    report, ledger = _stored(name)
    shown = [p.id for p in passages_of(report, entries=ledger) if p.id == "limitations"]
    assert shown == (["limitations"] if name == "haiku8" else [])


def test_a_call_a_later_call_answered_but_did_not_redo_is_not_redone() -> None:
    # run3's ev_0182 (no function at 0x1360bc08690) is answered for its address
    # by ev_0270, which asked another question: it stands, and its fact says so.
    from maljan.reporting.agreement_facts import ledger_facts
    from maljan.reporting.limitation_facts import failed_calls

    report, ledger = _stored("run3")
    found = ledger_facts(ledger)
    (call,) = [
        c for c in failed_calls(ledger, found.answered, found.image_bases) if c.entry == "ev_0182"
    ]
    assert not call.redone and call.redone_by == ()
    assert [by for _address, by in call.answered] == ["ev_0270"]


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
    # Citing the emulation call that stands does not release the sentence: it
    # still names decompiling and disassembling, which later calls redid.
    cited = HAIKU8_SENTENCE.replace("[ev_0025]", "[ev_0025][ev_0122]")
    assert held_limitation_sentences(cited, read.failed, listed, found.image_bases) == [cited]
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
    # The earlier facts come first: the answered-later fact for ev_0168 is the one
    # found, and a rewrite resting on it is held as one resting on failed.N is.
    assert batch.startswith("answered.")
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
    # The same claim covered by the emulation call that stands is not put in either.
    covered = (
        "The reversing tools for emulation, batch decompilation and disassembly failed, so the "
        "control flow of the dispatch routines was read from the function index "
        "[ev_0025][ev_0122]."
    )
    row = _row(HAIKU8_SENTENCE, [emulation, batch], covered)
    done, _ = _ask(report, ledger, {"sentences": [row]}, {"sentences": [row]})
    assert report.technical_analysis.analyst_limitations.body == body
    assert done.summary["not_applied"] == 1
    # The clause that names the batch decompile cites the call that redid it: it
    # accounts for decompiling, and names no other decompile.
    true = (
        "The emulation call by candidate names failed [ev_0122]; the batch decompile that "
        "failed was redone by a later call, so the dispatch routines' control flow was read "
        "from its listing [ev_0025][ev_0171]."
    )
    row = _row(HAIKU8_SENTENCE, [emulation, batch], true)
    done, _ = _ask(report, ledger, {"sentences": [row]})
    assert done.summary["rewritten"] == 1
    assert report.technical_analysis.analyst_limitations.body == body.replace(HAIKU8_SENTENCE, true)
    # P6b: resting on the emulation fact alone, the rewrite still names decompiling and
    # disassembling, which later calls redid.
    row = _row(HAIKU8_SENTENCE, [emulation], covered)
    report, ledger = _haiku8()
    done, _ = _ask(report, ledger, {"sentences": [row]}, {"sentences": [row]})
    assert report.technical_analysis.analyst_limitations.body == body
    assert done.summary["not_applied"] == 1


@pytest.mark.parametrize(
    "rewrite",
    [
        # A1: "for good" in the emulation's clause denies no redo of a decompile.
        "The emulation call by candidate names failed for good [ev_0122]; the batch decompile "
        "that failed was redone by a later call, so the dispatch routines were read from its "
        "output [ev_0025][ev_0171].",
        # A2: "no later call redid" the emulation, in its own clause.
        "No later call redid the emulation by candidate names [ev_0122]; the batch decompile "
        "that failed was answered by a later call [ev_0025][ev_0171].",
        # A3: the clause naming the batch decompile cites the call that redid it.
        "The emulation call by candidate names failed [ev_0122]; the batch decompile that "
        "failed was answered by a later call [ev_0025][ev_0171].",
        # B1: a decompiler listing of 0x6f48, the call that produced it cited.
        "The emulation call by candidate names failed [ev_0122]; the control flow of 0x6f48 "
        "was read from the decompiler listing a later call produced [ev_0025][ev_0171].",
    ],
)
def test_a_denial_or_a_kind_word_counts_in_its_own_clause(rewrite: str) -> None:
    report, ledger = _haiku8()
    sources = ["failed.2", "failed.3"]
    facts = _by_id(report, ledger)
    assert "ev_0122" in facts["failed.2"].cites and "ev_0168" in facts["failed.3"].cites
    done, _ = _ask(report, ledger, {"sentences": [_row(HAIKU8_SENTENCE, sources, rewrite)]})
    assert done.summary["rewritten"] == 1
    assert rewrite in report.technical_analysis.analyst_limitations.body


def test_a_section_5_sentence_saying_a_comparison_fails_is_put_in() -> None:
    # The check on the other passages counts only what a rewrite adds; a section 5
    # rewrite is the platform's own, on a fact with a clause of its own.
    report, ledger = _haiku8()
    facts = _by_id(report, ledger)
    sentence = (
        "The comparison therefore fails, the write is skipped, and 0x6f48 returns 0 [ev_0082]."
    )
    assert sentence in facts["payloads"].text
    row = {
        "passage": "payloads",
        "sentence": sentence,
        "sources": ["unread.5"],
        "decision": "rewrite",
        "rewrite": "The comparison fails, so the write is skipped and 0x6f48 returns 0 [ev_0082].",
    }
    done, _ = _ask(report, ledger, {"sentences": [row]})
    assert done.summary["rewritten"] == 1
    assert FAILURE_REDONE_CODE not in [r["code"] for r in done.tally.unresolved]


def test_a_claim_led_rewrite_keeping_its_sentence_s_failure_is_put_in() -> None:
    # The delta check flags only a failure or a redone call the rewrite adds.
    report = _report()
    report.key_findings = [
        KeyFinding(text="The decompiler failed on the loader [ev_0001].", evidence_ids=["ev_0001"])
    ]
    check = _by_id(report, _ledger())["key_findings.1"].sourced_check
    assert check is not None
    kept = "The decompiler failed on the loader routine [ev_0001]."
    assert check(kept, [], "The decompiler failed on the loader [ev_0001].") == []
    added = "The loader ran; the decompiler failed on it [ev_0001]."
    assert check(added, [], "The loader ran [ev_0001].")


@pytest.mark.parametrize("source", ["failed", "open"])
def test_a_limitation_fact_grounds_no_false_failure_in_another_section(source: str) -> None:
    # A key finding rewritten on a limitation fact is held to the same check.
    report, ledger = _haiku8()
    facts = {p.id: p for p in passages_of(report, entries=ledger)}
    fact = next(i for i, p in facts.items() if i.startswith(f"{source}.") and "ev_0168" in p.cites)
    finding = facts["key_findings.1"]
    assert finding.sourced_check is not None
    sentence = _sentences_of(finding.text)[0]
    rewrite = sentence.rstrip(".").rstrip() + "; the batch decompile of 0x6f48 failed [ev_0168]."
    row = {
        "passage": "key_findings.1",
        "sentence": sentence,
        "sources": [fact],
        "decision": "rewrite",
        "rewrite": rewrite,
    }
    done, _ = _ask(report, ledger, {"sentences": [row]}, {"sentences": [row]})
    assert done.summary["rewritten"] == 0
    assert FAILURE_REDONE_CODE in [r["code"] for r in done.tally.unresolved]
