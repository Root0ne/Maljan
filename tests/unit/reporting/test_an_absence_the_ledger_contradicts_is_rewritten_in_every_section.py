"""An absence the ledger contradicts is answered in every section; a redone call is no gap (T-562).

haiku11's section 5 said "The body of 0x3728 that performs the registration
is not read" while two entries listed that routine; the agreement round
rewrote only the limitations' twin of the sentence, so the limitations then
said the code was listed and section 5 said it was not. A sentence of any
passage that may be rewritten, section 5 and the body included, that calls code
not read which an entry lists is now held like a closing sentence: the answer
lists it. Where its own clause names the routine, the ledger itself says
otherwise: one the answer leaves standing is qualified by the platform with the
listing fact and recorded, never left out and never left as written.

haiku11 also said "4 of 158 tool calls failed and were not redone" in its
introduction and its limitations, while every one of its five failed calls was
asked again and answered: two emulations refused a comma text and were asked
with the list, two byte reads refused a quoted offset and were asked with the
number. A call asked for no address is now redone by a later call of its tool
that asked the same question; the count is the ledger's.

Every address, entry and tool name in the synthetic tests is a neutral value.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage

from maljan.agents.tool_fence import quoted_value
from maljan.core.config import Settings, get_settings, install_settings
from maljan.pipeline.nodes import evidence_summary
from maljan.pipeline.triage_pack import PIPELINE
from maljan.pipeline.validation import EntryTexts
from maljan.reporting.models import (
    FileHashes,
    KeyFinding,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.redone_calls import redone_failures
from maljan.reporting.renderers import MarkdownRenderer
from maljan.reporting.renderers.layout import ANALYST
from maljan.reporting.section_agreement import (
    CLAIM_LED,
    DEBATE,
    DROPPED_CODE,
    HELD_KEPT_CODE,
    QUALIFIED_CODE,
    REWRITE_UNGROUNDED_CODE,
    REWRITTEN_CODE,
    SECTION_5,
    UNKNOWN_SOURCE_CODE,
    UNREAD_STANDING_CODE,
    Passage,
    _merged_rows,
    _reports_a_claim,
    apply_rows,
    ask_section_agreement,
    passages_of,
    prompt_text,
    unread_listed_sentences,
    whole_code_absences,
)
from maljan.schemas.evidence import LedgerEntry
from tests.unit.reporting._report_inventory import stored_runs

BASE = 0x2470000
CALLER, TASK, LINKED = BASE + 0x1400, BASE + 0x2800, BASE + 0x2C00
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}

BODY_UNREAD = (
    "The body of 0x2800 that performs the registration is not read, so the task is not "
    "confirmed [ev_0002]."
)
LINK_UNREAD = "The link from 0x1400 to 0x2c00 is not read directly [ev_0002]."
LIMIT_UNREAD = "The body of the 0x2800 task routine was not read [ev_0002]."
LIMIT_REWRITE = "The code of the 0x2800 task routine is listed [ev_0002] [ev_0003]."
CITABLE = [f"ev_{n:04d}" for n in range(1, 10)]


def _lifted(entry_id: str, address: int, body: str = "  return a;") -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        args={"address": hex(address)},
        output=f"int FUN_{address:x}(int a)\n{{\n{body}\n}}\n",
        facts=_DECOMPILE,
    )


def _ledger() -> list[LedgerEntry]:
    return [
        LedgerEntry(id="ev_0001", tool="image_facts", output='{"image_base": "0x2470000"}'),
        _lifted("ev_0002", CALLER, f"  FUN_{TASK:x}(a);\n  FUN_{LINKED:x}(a);\n  return 1;"),
        _lifted("ev_0003", TASK),
        _lifted("ev_0004", LINKED),
    ]


def _report(section_5: str = BODY_UNREAD, limitations: str = LIMIT_UNREAD) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64), file_type="PE32+ DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        technical_analysis=TechnicalAnalysis(
            persistence_detail=TechnicalSubsection(
                title="Persistence",
                body=f"Routine 0x1400 calls 0x2800 with the task name [ev_0002]. {section_5}",
                evidence_refs=["ev_0002"],
            ),
            analyst_limitations=TechnicalSubsection(
                title="Limitations", body=limitations, evidence_refs=["ev_0002"]
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


def _ask(report: MalwareReport, *answers: Any) -> tuple[Any, _Reporter]:
    ledger = _ledger()
    reporter = _Reporter(*answers)
    done = asyncio.run(
        ask_section_agreement(
            reporter,
            report,
            citable_ids=CITABLE,
            evidence_texts=EntryTexts.from_ledger(ledger),
        )
    )
    return done, reporter


def _listed_id(passages: list[Any], address: int) -> str:
    (fact,) = [p for p in passages if p.lists_code and address in p.addresses]
    return str(fact.id)


# -- which sentences are held -------------------------------------------------


def test_a_section_5_sentence_calling_listed_code_unread_is_held_under_shipped_settings() -> None:
    previous = get_settings()
    install_settings(Settings())
    try:
        passages = passages_of(_report(), entries=_ledger())
    finally:
        install_settings(previous)
    by_id = {p.id: p for p in passages}
    task = _listed_id(passages, TASK)
    section_5 = by_id["persistence_detail"]
    assert section_5.kind == SECTION_5
    assert section_5.held == (BODY_UNREAD,)
    assert section_5.unread_listed == ((BODY_UNREAD, (task,), (task,)),)
    # The limitations' twin is held as well, on the same fact.
    assert LIMIT_UNREAD in by_id["limitations"].held
    prompt = prompt_text(passages)
    assert "[persistence_detail] list each of these sentences" in prompt


def test_a_routine_only_a_modifier_names_is_held_but_not_its_own() -> None:
    passages = passages_of(_report(section_5=LINK_UNREAD), entries=_ledger())
    (row,) = next(p for p in passages if p.id == "persistence_detail").unread_listed
    sentence, ids, own = row
    # The link is not the routine's code: the model decides, the platform adds nothing.
    assert sentence == LINK_UNREAD and ids and own == ()


def test_the_bare_word_unread_says_nothing_of_a_routine_s_own_code() -> None:
    listed = [p for p in passages_of(_report(), entries=_ledger()) if p.lists_code]
    text = "The task name buffer is unread in 0x2800 [ev_0002]."
    ((_sentence, ids, own),) = unread_listed_sentences(text, listed)
    assert ids and own == ()


def test_a_relative_clause_s_subject_is_the_address_before_it() -> None:
    listed = [p for p in passages_of(_report(), entries=_ledger()) if p.lists_code]
    text = "The name is passed to routine 0x2800, which is not read, and then returned."
    ((_sentence, _ids, own),) = unread_listed_sentences(text, listed)
    assert own


def test_a_sentence_no_listed_routine_is_said_of_is_not_held() -> None:
    listed = [p for p in passages_of(_report(), entries=_ledger()) if p.lists_code]
    assert unread_listed_sentences("The body of 0x9900 was not read [ev_0002].", listed) == ()
    assert unread_listed_sentences("Routine 0x2800 writes the task [ev_0003].", listed) == ()


# -- what the round does with them ------------------------------------------


def test_an_answer_that_leaves_the_body_standing_is_corrected_by_the_platform() -> None:
    report = _report()
    # The model rewrites the limitations' twin only, as haiku11's did, twice.
    passages = passages_of(report, entries=_ledger())
    task = _listed_id(passages, TASK)
    row = {
        "passage": "limitations",
        "sentence": LIMIT_UNREAD,
        "sources": [task],
        "decision": "rewrite",
        "rewrite": LIMIT_REWRITE,
    }
    done, reporter = _ask(report, {"sentences": [row]}, {"sentences": [row]})
    assert len(reporter.asked) == 2
    retry = str(reporter.asked[1][-1].content)
    # The retry names the listing, so the model may state it in its own words.
    assert "persistence_detail" in retry and "calls code not read" in retry
    assert "offset 0x2800" in retry and "ev_0003" in retry
    assert "Answer with every row again" in retry
    ta = report.technical_analysis
    assert ta is not None and ta.persistence_detail is not None
    assert ta.analyst_limitations is not None
    assert LIMIT_REWRITE in ta.analyst_limitations.body
    body = ta.persistence_detail.body
    # The sentence as it stood, then the ledger's fact alone, no inference.
    assert body.endswith(
        "is not read, so the task is not confirmed [ev_0002]; the ledger lists the code of the "
        "routine at offset 0x2800 (decompiled or disassembled) [ev_0003]."
    ), body
    assert "so it was read" not in body
    codes = [r["code"] for r in done.tally.unresolved]
    assert codes.count(QUALIFIED_CODE) == 1 and REWRITTEN_CODE in codes
    assert UNREAD_STANDING_CODE in codes
    assert done.summary["qualified"] == 1 and done.summary["rewritten"] == 1


def test_a_sentence_the_model_rewrote_in_its_own_words_is_not_corrected() -> None:
    report = _report()
    passages = passages_of(report, entries=_ledger())
    task = _listed_id(passages, TASK)
    own_words = (
        "The body of 0x2800 is listed and was read, but the registration it may perform is "
        "not confirmed [ev_0002] [ev_0003]."
    )
    rows = [
        {
            "passage": "persistence_detail",
            "sentence": BODY_UNREAD,
            "sources": [task],
            "decision": "rewrite",
            "rewrite": own_words,
        },
        {
            "passage": "limitations",
            "sentence": LIMIT_UNREAD,
            "sources": [task],
            "decision": "rewrite",
            "rewrite": LIMIT_REWRITE,
        },
    ]
    done, reporter = _ask(report, {"sentences": rows})
    assert len(reporter.asked) == 1
    ta = report.technical_analysis
    assert ta is not None and ta.persistence_detail is not None
    assert ta.persistence_detail.body.endswith(own_words)
    assert "the ledger lists" not in ta.persistence_detail.body
    assert done.summary["qualified"] == 0 and done.summary["rewritten"] == 2


def test_a_rewrite_still_calling_the_routine_unread_is_asked_again_then_corrected() -> None:
    report = _report(limitations="Nothing else is open [ev_0002].")
    passages = passages_of(report, entries=_ledger())
    task = _listed_id(passages, TASK)
    row = {
        "passage": "persistence_detail",
        "sentence": BODY_UNREAD,
        "sources": [task],
        "decision": "rewrite",
        "rewrite": "The body of 0x2800 was not read [ev_0002] [ev_0003].",
    }
    done, reporter = _ask(report, {"sentences": [row]}, {"sentences": [row]})
    assert len(reporter.asked) == 2
    ta = report.technical_analysis
    assert ta is not None and ta.persistence_detail is not None
    assert "; the ledger lists the code of the routine" in ta.persistence_detail.body
    assert done.summary["qualified"] == 1


def test_a_retry_listing_only_the_missing_row_keeps_the_first_answer_s_rewrites() -> None:
    report = _report()
    passages = passages_of(report, entries=_ledger())
    task = _listed_id(passages, TASK)
    first = {
        "passage": "limitations",
        "sentence": LIMIT_UNREAD,
        "sources": [task],
        "decision": "rewrite",
        "rewrite": LIMIT_REWRITE,
    }
    missing = {
        "passage": "persistence_detail",
        "sentence": BODY_UNREAD,
        "sources": [task],
        "decision": "rewrite",
        "rewrite": "The body of 0x2800 is listed [ev_0002] [ev_0003].",
    }
    done, reporter = _ask(report, {"sentences": [first]}, {"sentences": [missing]})
    assert len(reporter.asked) == 2
    ta = report.technical_analysis
    assert ta is not None and ta.analyst_limitations is not None
    assert ta.persistence_detail is not None
    assert ta.analyst_limitations.body == LIMIT_REWRITE
    assert ta.persistence_detail.body.endswith("The body of 0x2800 is listed [ev_0002] [ev_0003].")
    assert done.summary["rewritten"] == 2


def test_a_sentence_whose_routine_is_a_modifier_stays_as_the_model_left_it() -> None:
    report = _report(section_5=LINK_UNREAD, limitations="Nothing else is open [ev_0002].")
    done, _reporter = _ask(report)
    ta = report.technical_analysis
    assert ta is not None and ta.persistence_detail is not None
    assert ta.persistence_detail.body.endswith(LINK_UNREAD)
    assert done.summary["qualified"] == 0


def test_without_a_listed_routine_nothing_is_held_and_the_prompt_is_as_before() -> None:
    report = _report(
        section_5="The task is not confirmed [ev_0002].", limitations="None [ev_0002]."
    )
    passages = passages_of(report, entries=_ledger())
    assert not any(p.lists_code for p in passages)
    # Only the closing sentence is held: every one is answered (T-568).
    assert all(not p.held and not p.unread_listed for p in passages if not p.closing)
    assert [p.held for p in passages if p.closing] == [("None [ev_0002].",)]
    assert "list each of these sentences" not in prompt_text(passages)


# -- the failed calls a later call redid --------------------------------------


def _refused(entry_id: str, tool: str, args: dict[str, Any], error: str) -> LedgerEntry:
    return LedgerEntry(id=entry_id, tool=tool, args=args, ok=False, error=error)


def _answered(entry_id: str, tool: str, args: dict[str, Any]) -> LedgerEntry:
    return LedgerEntry(id=entry_id, tool=tool, args=args, output='{"tested": 2}')


def test_a_comma_text_asked_again_as_a_list_of_every_item_is_redone() -> None:
    asked = {"names": "alpha,beta", "target": "0x1234"}
    ledger = [
        _refused("ev_0001", "match_names", asked, "nothing was given"),
        _answered("ev_0002", "match_names", {**asked, "names": '["alpha", "beta", "gamma"]'}),
    ]
    assert redone_failures(ledger) == [
        {"entry_id": "ev_0001", "tool": "match_names", "answered_by": ["ev_0002"]}
    ]


def test_a_list_holding_fewer_items_or_another_target_redoes_nothing() -> None:
    asked = {"names": "alpha,beta", "target": "0x1234"}
    fewer = {**asked, "names": '["alpha"]'}
    other = {"names": '["alpha", "beta"]', "target": "0x9999"}
    for again in (fewer, other):
        ledger = [
            _refused("ev_0001", "match_names", asked, "nothing was given"),
            _answered("ev_0002", "match_names", again),
        ]
        assert redone_failures(ledger) == []


def test_a_refused_quoted_value_asked_again_in_another_spelling_is_redone() -> None:
    error = "the range's start is '\"0xf000\"'; give an integer"
    ledger = [
        _refused("ev_0001", "read_range", {"start": '"0xf000"', "length": "6"}, error),
        _answered("ev_0002", "read_range", {"start": "61440", "length": "6"}),
    ]
    assert [row["answered_by"] for row in redone_failures(ledger)] == [["ev_0002"]]


def test_a_refused_value_replaced_by_another_asks_another_question() -> None:
    # The value is the question: another part of the report is not the one refused.
    ledger = [
        _refused("ev_0001", "report_part", {"part": "summary"}, "no part 'summary' in the report"),
        _answered("ev_0002", "report_part", {"part": "behaviour"}),
    ]
    assert redone_failures(ledger) == []


def test_a_value_the_redo_leaves_out_unnamed_by_the_refusal_is_another_question() -> None:
    error = "give exactly one source"
    ledger = [
        _refused("ev_0001", "scan_rules", {"text": "abc def", "path": "x"}, error),
        _answered("ev_0002", "scan_rules", {"text": "", "path": "x"}),
    ]
    assert redone_failures(ledger) == []


def test_a_run_whose_every_failure_was_redone_says_no_partial_evidence() -> None:
    error = "the range's start is '\"0xf000\"'; give an integer"
    ledger = [
        _refused("ev_0001", "read_range", {"start": '"0xf000"', "length": "6"}, error),
        _answered("ev_0002", "read_range", {"start": "61440", "length": "6"}),
    ]
    summary = evidence_summary(ledger)
    assert summary["failed"] == 1 and len(summary["redone"]) == 1
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64), file_type="PE32+ DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        run_summary={"evidence": summary},
    )
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    assert "The evidence is partial" not in analyst
    assert "not redone" not in analyst


# -- the stored run the defect was read in ------------------------------------


def _stored(name: str) -> tuple[MalwareReport, list[Any]]:
    from maljan.reporting.follow_up import stored_ledger

    root = stored_runs()
    if root is None or not (root / name / "report.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    run = root / name
    report = MalwareReport.model_validate(json.loads((run / "report.json").read_text()))
    document = json.loads((run / "evidence.json").read_text())
    rows = document["items"] if isinstance(document, dict) else document
    return report, stored_ledger(rows)[0]


def test_haiku11_s_five_failed_calls_were_all_redone() -> None:
    _report_, ledger = _stored("haiku11")
    summary = evidence_summary(ledger)
    assert summary["failed"] == 5
    assert {row["entry_id"]: row["answered_by"] for row in summary["redone"]} == {
        "ev_0062": ["ev_0084"],
        "ev_0090": ["ev_0093"],
        "ev_0091": ["ev_0094"],
        "ev_0130": ["ev_0133"],
        "ev_0131": ["ev_0132"],
    }


def test_haiku11_s_section_5_absence_is_held_and_states_the_listing() -> None:
    report, ledger = _stored("haiku11")
    passages = passages_of(report, entries=ledger)
    (persistence,) = [p for p in passages if p.id == "persistence_detail"]
    ((sentence, _ids, own),) = persistence.unread_listed
    assert sentence.startswith("The body of 0x3728 that performs the registration is not read")
    assert own
    # An answer that lists nothing: the platform qualifies it on the listing.
    counts, found = apply_rows({"sentences": []}, passages)
    assert counts["qualified"] == 1
    assert [v.code for v in found] == [QUALIFIED_CODE]
    ta = report.technical_analysis
    assert ta is not None and ta.persistence_detail is not None
    body = ta.persistence_detail.body
    assert "; the ledger lists the code of the routine at offset 0x3728" in body


# -- round 2: whole-code absences, closing negations, reported claims ----------

WHOLE = "No flag read appears in the analysed code [ev_0002]."
STATED = "Routine 0x2800 reads the flag at the second byte [ev_0003]."
WHOLE_REWRITE = "Routine 0x2800 reads the flag [ev_0003]; no other flag read appears [ev_0002]."


def _whole_report(limitations: str = "Nothing else is open [ev_0002].") -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64), file_type="PE32+ DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        key_findings=[KeyFinding(text="The sample checks for a debugger [ev_0002].")],
        technical_analysis=TechnicalAnalysis(
            evasion_antiforensics=TechnicalSubsection(
                title="Evasion", body=f"Routine 0x1400 starts [ev_0002]. {WHOLE}"
            ),
            string_resolution=TechnicalSubsection(title="Resolution", body=STATED),
            analyst_limitations=TechnicalSubsection(title="Limitations", body=limitations),
        ),
    )


def _whole_row(sources: list[str], rewrite: str = WHOLE_REWRITE) -> dict[str, Any]:
    return {
        "passage": "evasion_antiforensics",
        "sentence": WHOLE,
        "sources": sources,
        "decision": "rewrite",
        "rewrite": rewrite,
    }


def test_a_whole_code_absence_is_held_in_every_passage_by_its_shape() -> None:
    passages = {p.id: p for p in passages_of(_whole_report(), entries=_ledger())}
    assert passages["evasion_antiforensics"].whole_code == (WHOLE,)
    assert WHOLE in passages["evasion_antiforensics"].held
    prompt = prompt_text(list(passages.values()))
    assert "[evasion_antiforensics] each of these calls something absent" in prompt
    # One naming an address is about that address, not the whole code.
    assert whole_code_absences("No flag read of 0x2800 appears in the code [ev_0002].") == ()


def _scope_kept(sentence: str = "Nothing else is open [ev_0002].") -> dict[str, Any]:
    """A closing sentence no source speaks of, kept with the reason (T-568)."""
    return {
        "passage": "limitations",
        "sentence": sentence,
        "sources": [],
        "decision": "keep",
        "reason": "no source speaks of what else is open",
    }


def test_a_section_5_whole_code_absence_is_rewritten_on_section_5_in_the_model_s_words() -> None:
    report = _whole_report()
    rows = [_whole_row(["string_resolution"]), _scope_kept()]
    done, reporter = _ask(report, {"sentences": rows})
    assert len(reporter.asked) == 1
    ta = report.technical_analysis
    assert ta is not None and ta.evasion_antiforensics is not None
    assert ta.evasion_antiforensics.body.endswith(WHOLE_REWRITE)
    assert done.summary["rewritten"] == 1


def test_a_whole_code_rewrite_rests_on_no_claim_and_cites_its_source() -> None:
    for sources, rewrite in (
        (["key_findings.1"], WHOLE_REWRITE),
        (["string_resolution"], "No flag read appears in the code read [ev_0002]."),
    ):
        report = _whole_report()
        row = _whole_row(sources, rewrite)
        done, _reporter = _ask(report, {"sentences": [row]}, {"sentences": [row]})
        ta = report.technical_analysis
        assert ta is not None and ta.evasion_antiforensics is not None
        assert ta.evasion_antiforensics.body.endswith(WHOLE), sources
        codes = {r["code"] for r in done.tally.unresolved}
        assert codes & {UNKNOWN_SOURCE_CODE, REWRITE_UNGROUNDED_CODE}, (sources, codes)


def test_a_closing_negation_kept_on_no_source_section_5_speaks_of_is_left_out() -> None:
    denial = "The flag read was not attributed to a routine [ev_0002]."
    report = _whole_report(limitations=denial)
    passages = {p.id: p for p in passages_of(report, entries=_ledger())}
    assert denial in passages["limitations"].held
    # Kept on a section 5 passage without words of it that state the denial: asked
    # once more (T-568); then kept with the reason no source speaks of it.
    unquoted = {
        "passage": "limitations",
        "sentence": denial,
        "sources": ["string_resolution"],
        "decision": "keep",
        "quote": "reads the flag at the second byte",
    }
    reasoned = {**_scope_kept(denial), "reason": "no source names the routine"}
    done, reporter = _ask(
        report,
        {"sentences": [_whole_row(["string_resolution"]), unquoted]},
        {"sentences": [_whole_row(["string_resolution"]), reasoned]},
    )
    assert len(reporter.asked) == 2
    assert "its quote states no absence" in str(reporter.asked[1][-1].content)
    # Kept on no source while section 5 speaks of the flag read: no source backs it,
    # so it is left out, recorded with the refused keep's reason (T-568).
    assert done.summary["held_kept"] == 0 and done.summary["dropped"] == 1
    (record,) = [r for r in done.tally.unresolved if r["code"] == DROPPED_CODE]
    assert "no source names the routine" in record["message"] and denial in record["message"]


def test_a_closing_negation_kept_on_a_quoted_debate_round_is_counted_not_recorded() -> None:
    denial = "The flag byte was not attributed to a routine [ev_0002]."
    closing = Passage(
        id="limitations",
        label="11. Limitations",
        text=denial,
        kind=CLAIM_LED,
        cites=frozenset({"ev_0002"}),
        write=lambda _text: None,
        closing=True,
        held=(denial,),
    )
    debate = Passage(
        id="debate.1",
        label="debate round 1",
        text="The flag byte was not attributed to any routine this round.",
        kind=DEBATE,
    )
    row = {
        "passage": "limitations",
        "sentence": denial,
        "sources": ["debate.1"],
        "quote": "The flag byte was not attributed to any routine",
    }
    counts, found = apply_rows({"sentences": [{**row, "decision": "keep"}]}, [debate, closing])
    # A quote that passes every check: counted, not recorded (T-568 review ruling).
    assert counts["held_kept"] == 1
    assert found == []
    # Kept on no source: recorded with its reason.
    reasoned = {**row, "sources": [], "quote": "", "reason": "no round names it"}
    counts, found = apply_rows({"sentences": [{**reasoned, "decision": "keep"}]}, [debate, closing])
    assert counts["held_kept"] == 1
    assert [v.code for v in found] == [HELD_KEPT_CODE]
    assert "no round names it" in found[0].message


@pytest.mark.parametrize(
    "sentence",
    [
        "They say the call is unverified and that 0x2800 was not read.",
        "The statement that 0x2800 was not read is also wrong [ev_0003].",
        "Claim 4 holds that the body of 0x2800 was not read.",
    ],
)
def test_a_sentence_reporting_or_refuting_a_claim_is_held_but_never_qualified(
    sentence: str,
) -> None:
    report = _report(section_5=sentence, limitations="Nothing else is open [ev_0002].")
    passages = passages_of(report, entries=_ledger())
    (persistence,) = [p for p in passages if p.id == "persistence_detail"]
    assert sentence in persistence.held
    counts, found = apply_rows({"sentences": []}, passages)
    assert counts["qualified"] == 0 and QUALIFIED_CODE not in [v.code for v in found]


def test_haiku8_s_reported_claims_are_held_not_qualified() -> None:
    report, ledger = _stored("haiku8")
    passages = passages_of(report, entries=ledger)
    (evasion,) = [p for p in passages if p.id == "evasion_antiforensics"]
    reported = [s for s, _ids, _own in evasion.unread_listed if _reports_a_claim(s)]
    assert [s[:40] for s in reported] == [
        "They say the call from 0x3074 to 0x309c ",
        "The statement that the 0x6328 and 0x3074",
    ]
    assert all(s in evasion.held for s in reported)
    counts, _found = apply_rows({"sentences": []}, passages)
    assert counts["qualified"] == 0


def test_haiku11_s_whole_code_absence_and_closing_denials_are_held() -> None:
    report, ledger = _stored("haiku11")
    passages = {p.id: p for p in passages_of(report, entries=ledger)}
    (absence,) = passages["evasion_antiforensics"].whole_code
    assert absence.startswith("No BeingDebugged or NtGlobalFlag read appears in the analysed")
    held = passages["limitations"].held
    assert any(s.startswith("The sandbox's process list was not attributed") for s in held)
    assert any(s.startswith("The C2 replies were not recovered") for s in held)
    # Answered on the section 5 passage that cites the listing, in the model's words.
    rewrite = (
        "A routine reads the flag at PEB+2 [ev_0143]; no NtGlobalFlag read and no anti-debug "
        "API is present [ev_0088, ev_0024]."
    )
    row = {
        "passage": "evasion_antiforensics",
        "sentence": absence,
        "sources": ["string_resolution"],
        "decision": "rewrite",
        "rewrite": rewrite,
    }
    counts, found = apply_rows(
        {"sentences": [row]},
        list(passages.values()),
        citable=[str(e.id) for e in ledger],
        entries=EntryTexts.from_ledger(ledger),
    )
    assert counts["rewritten"] == 1, [v.message for v in found]
    ta = report.technical_analysis
    assert ta is not None and ta.evasion_antiforensics is not None
    assert rewrite in ta.evasion_antiforensics.body


# -- first review (T-562): each probe kept as a test -----------------------------


@pytest.mark.parametrize(
    ("failed", "error", "again"),
    [
        # A name looked up, then nothing looked up: another question.
        ({"name": "InstallService"}, "no symbol 'InstallService' in the program", {"name": None}),
        # A pattern searched, then none.
        ({"pattern": "Mozilla/5.0"}, "pattern: invalid", {}),
        # Case is part of the value.
        ({"pattern": "MZ"}, "timeout", {"pattern": "mz"}),
        # A bare hex text is not a decimal number the failure never named.
        ({"names": "a"}, "bad", {"names": "10"}),
    ],
)
def test_a_redo_of_another_question_is_no_redo(
    failed: dict[str, Any], error: str, again: dict[str, Any]
) -> None:
    ledger = [_refused("ev_0001", "lookup", failed, error), _answered("ev_0002", "lookup", again)]
    assert redone_failures(ledger) == []


def test_a_refused_bare_hex_value_the_failure_names_is_redone_as_a_number() -> None:
    error = "Invalid target: 572d5d8e"
    ledger = [
        _refused("ev_0001", "match_names", {"target": "572d5d8e"}, error),
        _answered("ev_0002", "match_names", {"target": "0x572d5d8e"}),
    ]
    assert [row["answered_by"] for row in redone_failures(ledger)] == [["ev_0002"]]


# The pipeline's own identity answer: the platform's record of the run's sample.
_IDENTITY = LedgerEntry(
    id="ev_0000",
    tool="identify",
    agent=PIPELINE,
    args={"path": "/work/sample.bin"},
    output="{}",
    facts={"v": 1, "kind": "identity", "arguments": {"path": "path"}},
)
_PROGRAM_FACTS = {"v": 1, "kind": "", "arguments": {"program": "program"}}


def _program_refused(program: str, facts: dict[str, Any] = _PROGRAM_FACTS) -> LedgerEntry:
    return LedgerEntry(
        id="ev_0001",
        tool="program_info",
        args={"program": program},
        ok=False,
        error=f"Program not found: {program}",
        facts=facts,
    )


_PROGRAM_AGAIN = LedgerEntry(
    id="ev_0002", tool="program_info", args={"program": None}, output="{}", facts=_PROGRAM_FACTS
)


def test_a_refused_program_left_out_is_a_redo_only_for_the_declared_program_argument() -> None:
    failed = _program_refused("/work/sample.bin")
    ledger = [_IDENTITY, failed, _PROGRAM_AGAIN]
    assert [row["answered_by"] for row in redone_failures(ledger)] == [["ev_0002"]]
    undeclared = failed.model_copy(update={"facts": {"v": 1, "kind": ""}})
    again = _PROGRAM_AGAIN.model_copy(update={"facts": None})
    assert redone_failures([_IDENTITY, undeclared, again]) == []


def test_a_refused_other_program_left_out_asks_about_the_sample_another_question() -> None:
    # A dropped file refused, then the server's own program, the sample, asked.
    ledger = [_IDENTITY, _program_refused("/work/dropped_payload.bin"), _PROGRAM_AGAIN]
    assert redone_failures(ledger) == []
    # Without the platform's record of the sample, no program left out is a redo.
    assert redone_failures([_program_refused("/work/sample.bin"), _PROGRAM_AGAIN]) == []


def test_a_whole_code_absence_never_rests_on_its_own_passage() -> None:
    sentence = "No string decryption routine appears in the analysed code [ev_0002]."
    report = _report(section_5=sentence, limitations="Nothing else is open [ev_0002].")
    row = {
        "passage": "persistence_detail",
        "sentence": sentence,
        "sources": ["persistence_detail"],
        "decision": "rewrite",
        "rewrite": "The sample decrypts strings with a custom routine [ev_0003].",
    }
    done, _reporter = _ask(report, {"sentences": [row]}, {"sentences": [row]})
    ta = report.technical_analysis
    assert ta is not None and ta.persistence_detail is not None
    assert ta.persistence_detail.body.endswith(sentence)
    assert UNKNOWN_SOURCE_CODE in [r["code"] for r in done.tally.unresolved]


@pytest.mark.parametrize(
    "sentence",
    [
        "The registry value 0x2800 sets is not read by any later routine [ev_0002].",
        "The second stage that 0x2800 downloads was not read [ev_0002].",
        "The buffer that 0x2800 fills was not read [ev_0002].",
        "The callee 0x2c00 of routine 0x2800 was not read [ev_0002].",
        "According to the static analyst, 0x2800 was not read [ev_0002].",
        "The static analyst noted that 0x2800 was not read [ev_0002].",
        "0x2800 was not read at runtime because no trace exists [ev_0002].",
        "That call in 0x2800 is not read as a debug check [ev_0002].",
    ],
)
def test_no_ledger_clause_is_added_to_a_sentence_not_about_the_routine_s_code(
    sentence: str,
) -> None:
    report = _report(section_5=sentence, limitations="Nothing else is open [ev_0002].")
    done, _reporter = _ask(report)
    ta = report.technical_analysis
    assert ta is not None and ta.persistence_detail is not None
    assert ta.persistence_detail.body.endswith(sentence)
    assert done.summary["qualified"] == 0


def test_a_section_5_whole_code_absence_is_quoted_once_in_the_prompt() -> None:
    passages = passages_of(_whole_report(), entries=_ledger())
    # Once, in the note: the held line leaves out what the note lists.
    assert prompt_text(passages).count(quoted_value(WHOLE)) == 1


@pytest.mark.parametrize(
    "sentence",
    [
        "The body of the 0x2800 task routine was not read [ev_0002].",
        "The 0x2800 routine was not read [ev_0002].",
        "0x2800's body is not read [ev_0002].",
        "The body of routine 0x2800 is not read [ev_0002].",
        "Function 0x2800 itself was not read [ev_0002].",
        "Routine 0x2800 (the registration routine) was not read [ev_0002].",
        "The body of 0x2800, the registration routine, was not read [ev_0002].",
        "The body of 0x2800 \u2014 the task routine \u2014 was not read [ev_0002].",
        "The code at 0x2800 is not read [ev_0002].",
        "The function at 0x2800 has not been read [ev_0002].",
    ],
)
def test_a_sentence_calling_the_routine_s_own_code_unread_names_its_subject(
    sentence: str,
) -> None:
    listed = [p for p in passages_of(_report(), entries=_ledger()) if p.lists_code]
    ((_sentence, ids, own),) = unread_listed_sentences(sentence, listed)
    assert ids and own == ids, sentence


def test_the_callee_of_a_routine_is_not_the_routine() -> None:
    listed = [p for p in passages_of(_report(), entries=_ledger()) if p.lists_code]
    text = "The callee 0x2c00 of routine 0x2800 was not read [ev_0002]."
    ((_sentence, _ids, own),) = unread_listed_sentences(text, listed)
    assert own == ()


@pytest.mark.parametrize(
    ("sentence", "held"),
    [
        ("No code reference to it was found in the listings read [ev_0002].", True),
        ("No anti-debug call was present in the decompiled code [ev_0002].", True),
        ("No C2 was seen in the run [ev_0002].", False),
        ("No beacon was observed in the code [ev_0002].", False),
        ("No sample was found on the reputation service [ev_0002].", False),
    ],
)
def test_a_past_absence_is_whole_code_only_where_its_clause_names_the_code_read(
    sentence: str, held: bool
) -> None:
    assert bool(whole_code_absences(sentence)) is held


def test_a_retry_s_row_replaces_the_first_one_for_the_same_place_in_the_passage() -> None:
    first = {"sentences": [{"passage": "a", "sentence": "x", "decision": "keep"}]}
    retry = {"sentences": [{"passage": "a", "sentence": "x  copied", "decision": "rewrite"}]}
    merged = _merged_rows(first, retry, where=lambda row: (row["passage"], "same place"))
    assert merged["sentences"] == retry["sentences"]
    # Without a place, two spellings are two sentences.
    assert len(_merged_rows(first, retry)["sentences"]) == 2


@pytest.mark.parametrize(
    "sentence",
    [
        "The payload decrypted by the 0x2800 routine was not read [ev_0002].",
        "The 0x2800 routine's callee body was not read [ev_0002].",
        "The string table 0x2800 was not read [ev_0002].",
        "0x2800's callee's body was not read [ev_0002].",
        "The string 0x2800 that holds the key was not read [ev_0002].",
    ],
)
def test_an_address_another_noun_governs_is_no_subject_and_gets_no_clause(
    sentence: str,
) -> None:
    listed = [p for p in passages_of(_report(), entries=_ledger()) if p.lists_code]
    ((_sentence, _ids, own),) = unread_listed_sentences(sentence, listed)
    assert own == (), sentence
    report = _report(section_5=sentence, limitations="Nothing else is open [ev_0002].")
    done, _reporter = _ask(report)
    ta = report.technical_analysis
    assert ta is not None and ta.persistence_detail is not None
    assert ta.persistence_detail.body.endswith(sentence)
    assert done.summary["qualified"] == 0


@pytest.mark.parametrize(
    "sentence",
    [
        "Routine 0x2800 (the registration routine) was not read [ev_0002].",
        "The body of 0x2800 \u2014 the task routine \u2014 was not read [ev_0002].",
    ],
)
def test_the_ledger_s_fact_reads_after_the_model_s_own_dash_or_bracket(sentence: str) -> None:
    report = _report(section_5=sentence, limitations="Nothing else is open [ev_0002].")
    done, _reporter = _ask(report)
    ta = report.technical_analysis
    assert ta is not None and ta.persistence_detail is not None
    stem = sentence.removesuffix(".")
    assert ta.persistence_detail.body.endswith(
        f"{stem}; the ledger lists the code of the routine at offset 0x2800 (decompiled or "
        "disassembled) [ev_0003]."
    ), ta.persistence_detail.body
    assert done.summary["qualified"] == 1
