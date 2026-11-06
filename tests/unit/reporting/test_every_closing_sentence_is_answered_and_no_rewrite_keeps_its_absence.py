"""Every closing sentence is answered, and no rewrite keeps the absence it corrects (T-568).

haiku10, haiku11 and haiku12 each failed the promotion bar on a limitations
paragraph that said otherwise than the body: each fix held more sentence shapes
and each run wrote new ones. haiku12's said 0x6328 "was not read" (an entry lists
it, beside 0x3074 and 0x8560 in one batch), 0x3868 "was read only in part" (three
entries list it), the gates "were not passed", the C2 request body "not
established", and "several functions failed, so some bodies were read from the
function index" (all six failed calls redone); and its rewrites kept the absence
they corrected ("the mutex name is not passed in that call; the code passes it as
argument 3").

Every sentence of the conclusion and the limitations is now answered: kept on a
source's quoted words that state the same, kept with the reason no source speaks
of it, rewritten, or left out with the reason. Each routine a closing passage
names is shown with its listing. A rewrite resting on a fact that states the
absence again is refused; a section 5 denial a decoded value contradicts is
answered in the model's words. A number given failed calls is held to the
ledger's count. Every address, entry and value here is a neutral one.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage

from maljan.core.config import Settings, get_settings, install_settings
from maljan.pipeline.validation import EntryTexts
from maljan.reporting.absence_answers import (
    FailureCounts,
    count_disagrees,
    failure_counts,
    kept_absence,
    quote_stands,
)
from maljan.reporting.models import (
    BoundValue,
    FileHashes,
    FlowStep,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.section_agreement import (
    ABSENCE_KEPT_CODE,
    DROPPED_CODE,
    FAILURE_COUNT_CODE,
    FAILURE_REDONE_CODE,
    HELD_KEPT_CODE,
    KEEP_UNQUOTED_CODE,
    QUALIFIED_CODE,
    REWRITTEN_CODE,
    UNKNOWN_PASSAGE_CODE,
    UNREAD_STANDING_CODE,
    _sentences_of,
    agreement_violations,
    ask_section_agreement,
    passages_of,
    prompt_text,
)
from maljan.schemas.evidence import LedgerEntry
from tests.unit.reporting._report_inventory import stored_runs

BASE = 0x2470000
CALLER, GATE_A, GATE_B, HELPER = BASE + 0x1400, BASE + 0x2800, BASE + 0x2C00, BASE + 0x3000
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}
CITABLE = [f"ev_{n:04d}" for n in range(1, 12)]

GATES = (
    "The gate routines at 0x2800, 0x2c00 and 0x7000 were not read, and whether they pass in a "
    "guest is not known [ev_0002]."
)
IN_PART = "The body of the routine at 0x1400 was read only in part [ev_0002]."
FAILED = (
    "The decompiler calls for several functions failed, so some bodies were read from the "
    "function index alone [ev_0002]."
)
SCOPE = "This analysis does not establish the operator."
CONCLUDED = "The file is a loader [ev_0002]."
MUTEX = (
    "The CreateMutexW call in 0x1400 is listed with two zero arguments, so the mutex name is "
    "not passed in that call [ev_0002]."
)
HASHED = "What the hashing routine hashes is not established."
WHOLE_READ = "The routine at 0x1400 was read whole [ev_0002]."
# A closing sentence a section 5 passage states too, kept on its words.
STILL_OPEN = "What the hashing routine hashes is still not established."
GATES_READ = (
    "The gate routines at 0x2800 and 0x2c00 were read [ev_0003][ev_0004], 0x7000 was not, "
    "and whether they pass in a guest is not known [ev_0002]."
)


def _listed_ids(report: MalwareReport, *addresses: int) -> list[str]:
    """The ids of the listing facts about the addresses, as the round shows them."""
    return sorted(
        p.id
        for p in passages_of(report, entries=_ledger())
        if p.lists_code and not p.addresses.isdisjoint(addresses)
    )


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
        _lifted("ev_0002", CALLER, f"  FUN_{GATE_A:x}(a);\n  FUN_{GATE_B:x}(a);\n  return 1;"),
        _lifted("ev_0003", GATE_A),
        _lifted("ev_0004", GATE_B),
        LedgerEntry(
            id="ev_0005",
            tool="lift_routine",
            args={"address": hex(HELPER)},
            ok=False,
            error="no function there",
            facts=_DECOMPILE,
        ),
        _lifted("ev_0006", HELPER),
    ]


def _report(limitations: str = f"{GATES} {IN_PART} {FAILED} {SCOPE}") -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64), file_type="PE32+ DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        bound_values=[
            BoundValue(
                value="alphaname",
                kind="mutex",
                role="mutex_name",
                role_words="the name of the mutex the call creates or opens",
                api="CreateMutexW",
                argument=3,
                parameter="lpName",
                entry="ev_0002",
                tool="decoder",
                function="0x1400",
                named_by="ev_0003",
            )
        ],
        technical_analysis=TechnicalAnalysis(
            execution_flow=[FlowStep(order=1, action="It resolves its imports [ev_0002].")],
            persistence_detail=TechnicalSubsection(
                title="Persistence",
                body=f"Routine 0x1400 calls 0x2800 and 0x2c00 [ev_0002]. {HASHED}",
                evidence_refs=["ev_0002"],
            ),
            string_resolution=TechnicalSubsection(
                title="Resolution", body=MUTEX, evidence_refs=["ev_0002"]
            ),
            analyst_conclusion=TechnicalSubsection(title="Conclusion", body=CONCLUDED),
            analyst_limitations=TechnicalSubsection(title="Limitations", body=limitations),
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
            reporter, report, citable_ids=CITABLE, evidence_texts=EntryTexts.from_ledger(ledger)
        )
    )
    return done, reporter


def _row(passage: str, sentence: str, decision: str, sources: list[str], **kw: Any) -> dict:
    return {
        "passage": passage,
        "sentence": sentence,
        "decision": decision,
        "sources": sources,
        **kw,
    }


def _settled(report: MalwareReport, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The rows, and one for every other held sentence: the failure a later call redid
    rewritten on its fact, other closing ones kept with the reason, section 5 ones listed
    with keep on the fact."""
    answered = {(row["passage"], row["sentence"]) for row in rows}
    out = list(rows)
    for passage in passages_of(report, entries=_ledger()):
        for sentence in passage.held:
            if (passage.id, sentence) in answered:
                continue
            if sentence == FAILED:
                redone = "One decompiler call failed, and a later call redid it [ev_0002][ev_0006]."
                out.append(_row(passage.id, sentence, "rewrite", ["failed.1"], rewrite=redone))
            elif sentence == GATES:
                read = _listed_ids(report, GATE_A, GATE_B)
                out.append(_row(passage.id, sentence, "rewrite", read, rewrite=GATES_READ))
            elif sentence == IN_PART:
                listing = _listed_ids(report, CALLER)
                out.append(_row(passage.id, sentence, "rewrite", listing, rewrite=WHOLE_READ))
            elif passage.closing:
                out.append(_row(passage.id, sentence, "keep", [], reason="no source speaks of it"))
            else:
                out.append(_row(passage.id, sentence, "keep", ["bound.1"]))
    return out


def _limitations(report: MalwareReport) -> str:
    ta = report.technical_analysis
    assert ta is not None and ta.analyst_limitations is not None
    return ta.analyst_limitations.body


def _facts(report: MalwareReport) -> dict[str, Any]:
    return {p.id: p for p in passages_of(report, entries=_ledger())}


# -- what is held and shown -----------------------------------------------------


def test_every_closing_sentence_is_held_under_the_shipped_settings() -> None:
    previous = get_settings()
    install_settings(Settings())
    try:
        passages = _facts(_report())
    finally:
        install_settings(previous)
    assert passages["limitations"].held == (GATES, IN_PART, FAILED, SCOPE)
    assert passages["conclusion"].held == (CONCLUDED,)
    prompt = prompt_text(list(passages.values()))
    assert "[limitations] answer every sentence of this passage, one row each (4 sentences)" in (
        prompt
    )
    assert "Besides, answer EVERY sentence of [conclusion], [limitations]" in prompt
    # The passage is quoted once: no list of its sentences beside it.
    assert prompt.count(SCOPE) == 1


def test_each_routine_a_closing_passage_names_is_shown_with_its_listing() -> None:
    passages = _facts(_report())
    listed = {p.text.split(" ")[0]: p.id for p in passages.values() if p.lists_code}
    # 0x2800 in "at 0x2800, 0x2c00 and 0x7000 were not read" stands before the comma
    # the unread reading stops at; 0x1400 is "read only in part", no unread shape.
    assert {hex(GATE_A), hex(GATE_B), hex(CALLER)} <= set(listed)


def test_a_report_with_no_closing_section_asks_as_before() -> None:
    report = _report()
    ta = report.technical_analysis
    assert ta is not None
    ta.analyst_conclusion = None
    ta.analyst_limitations = None
    ta.persistence_detail = None
    ta.string_resolution = None
    passages = passages_of(report, entries=_ledger())
    assert not any(p.held for p in passages)
    prompt = prompt_text(passages)
    assert prompt.endswith(
        "List each sentence that says otherwise than its sources, as the system prompt "
        "asks. Return ONLY the JSON object shown there."
    )
    assert "calls.1" not in prompt


# -- what an answer may do with a closing sentence ------------------------------


def test_a_closing_rewrite_calling_a_listed_routine_unread_is_refused() -> None:
    report = _report()
    # haiku12's rewrite: 0x2800 stays "not read".
    still = (
        "The gate routine at 0x2800 was not read, and whether the gates pass in a guest is not "
        "known [ev_0002]; the gate routine at 0x2c00 was read [ev_0004]."
    )
    passages = passages_of(report, entries=_ledger())
    rows = _settled(report, [_row("limitations", GATES, "rewrite", ["listed.3"], rewrite=still)])
    codes = [v.code for v in agreement_violations({"sentences": rows}, passages)]
    assert UNREAD_STANDING_CODE in codes


def test_a_closing_rewrite_stating_the_listing_is_put_in() -> None:
    report = _report()
    done, reporter = _ask(report, {"sentences": _settled(report, [])})
    assert len(reporter.asked) == 1
    # The gates', the routine "read in part"'s and the redone failure's rewrites.
    assert _limitations(report).startswith(f"{GATES_READ} {WHOLE_READ} One decompiler call failed")
    assert done.summary["rewritten"] == 3


def test_a_kept_closing_sentence_quotes_a_source_stating_the_same() -> None:
    report = _report(limitations=f"{STILL_OPEN} {SCOPE}")
    unquoted = _row("limitations", STILL_OPEN, "keep", ["persistence_detail"])
    passages = passages_of(report, entries=_ledger())
    for row, said in (
        (unquoted, "does not stand in a source it names"),
        # haiku12's gamed keep: words that stand, but quote no particular absence.
        ({**unquoted, "quote": "is not established"}, "shares too few"),
        ({**unquoted, "quote": "Routine 0x1400 calls 0x2800 and"}, "shares too few"),
    ):
        found = agreement_violations({"sentences": _settled(report, [row])}, passages)
        (violation,) = [v for v in found if v.code == KEEP_UNQUOTED_CODE]
        assert said in violation.message
    quoted = {**unquoted, "quote": "What the hashing routine hashes is not established"}
    found = agreement_violations({"sentences": _settled(report, [quoted])}, passages)
    assert KEEP_UNQUOTED_CODE not in [v.code for v in found]


def test_a_keep_on_a_quote_that_passes_is_counted_one_on_no_source_recorded() -> None:
    quoted = _row(
        "limitations",
        STILL_OPEN,
        "keep",
        ["persistence_detail"],
        quote="What the hashing routine hashes is not established",
    )
    scope = _row("limitations", SCOPE, "keep", [], reason="no passage speaks of an operator")
    report = _report(limitations=f"{STILL_OPEN} {SCOPE}")
    done, reporter = _ask(report, {"sentences": _settled(report, [quoted, scope])})
    assert len(reporter.asked) == 1
    assert done.summary["held_kept"] == 3  # the two, and the conclusion's sentence
    records = [r["message"] for r in done.tally.unresolved if r["code"] == HELD_KEPT_CODE]
    assert not any(STILL_OPEN[:30] in m for m in records)
    assert any(SCOPE[:30] in m and "no passage speaks of an operator" in m for m in records)


def test_a_sentence_no_source_speaks_of_is_kept_with_the_reason_and_recorded() -> None:
    report = _report()
    kept = _row("limitations", SCOPE, "keep", [], reason="no passage speaks of an operator")
    done, _ = _ask(report, {"sentences": _settled(report, [kept])})
    assert _limitations(report).endswith(SCOPE)
    records = [r for r in done.tally.unresolved if r["code"] == HELD_KEPT_CODE]
    assert any("no passage speaks of an operator" in r["message"] for r in records)


def test_no_source_speaks_of_a_routine_a_shown_fact_is_about() -> None:
    # haiku12's "0x3868 was read only in part": its listing is shown, so a keep on
    # no source names that listing and quotes it, or the sentence is rewritten.
    report = _report()
    kept = _row("limitations", IN_PART, "keep", [], reason="no source speaks of it")
    found = agreement_violations(
        {"sentences": _settled(report, [kept])}, passages_of(report, entries=_ledger())
    )
    (violation,) = [v for v in found if v.code == KEEP_UNQUOTED_CODE]
    assert "speaks of what it names" in violation.message
    assert _listed_ids(report, CALLER)[0] in violation.message


def test_a_closing_sentence_is_left_out_on_the_model_s_reason_and_recorded() -> None:
    report = _report()
    drop = _row("limitations", SCOPE, "drop", [], reason="no source speaks of an operator")
    done, _ = _ask(report, {"sentences": _settled(report, [drop])})
    assert SCOPE not in _limitations(report)
    (record,) = [r for r in done.tally.unresolved if r["code"] == DROPPED_CODE]
    assert "no source speaks of an operator" in record["message"] and SCOPE in record["message"]
    assert record["subject"] == "limitations"


def test_only_a_closing_sentence_is_left_out() -> None:
    report = _report()
    drop = _row("persistence_detail", HASHED, "drop", [], reason="x")
    found = agreement_violations({"sentences": [drop]}, passages_of(report, entries=_ledger()))
    assert UNKNOWN_PASSAGE_CODE in [v.code for v in found]


def test_a_kept_failure_a_later_call_redid_is_left_out() -> None:
    report = _report()
    kept = _row("limitations", FAILED, "keep", ["failed.1"], quote="no function there")
    done, reporter = _ask(
        report, {"sentences": _settled(report, [kept])}, {"sentences": _settled(report, [kept])}
    )
    assert len(reporter.asked) == 2
    assert FAILURE_REDONE_CODE in str(reporter.asked[1][-1].content)
    assert FAILED not in _limitations(report)
    (record,) = [r for r in done.tally.unresolved if r["code"] == DROPPED_CODE]
    assert "the ledger says otherwise" in record["message"]


# -- the ledger's count of failed calls ------------------------------------------


def test_a_number_given_failed_calls_is_held_to_the_ledger_s_count() -> None:
    report = _report(limitations=SCOPE)
    ta = report.technical_analysis
    assert ta is not None
    miscount = "Three tool calls failed and were not redone [ev_0005]."
    ta.execution_flow[0].action = f"It resolves its imports [ev_0002]. {miscount}"
    passages = {p.id: p for p in passages_of(report, entries=_ledger())}
    assert passages["calls.1"].text == (
        "1 tool call failed; 1 of them redone by a later call asking the same question; "
        "0 not redone"
    )
    assert miscount in passages["execution_flow.1"].held
    wrong = _row(
        "execution_flow.1",
        miscount,
        "rewrite",
        ["calls.1"],
        rewrite="Two tool calls failed [ev_0005].",
    )
    right = {
        **wrong,
        "rewrite": "One tool call failed and a later call redid it [ev_0005][ev_0006].",
    }
    codes = [
        v.code
        for v in agreement_violations(
            {"sentences": _settled(report, [wrong])}, list(passages.values())
        )
    ]
    assert FAILURE_COUNT_CODE in codes
    done, _ = _ask(report, {"sentences": _settled(report, [right])})
    assert ta.execution_flow[0].action.endswith(right["rewrite"])
    assert done.summary["rewritten"] == 1


@pytest.mark.parametrize(
    "sentence",
    [
        # Numbers that count no call (review r1): never read as a failure count.
        "Emulation of 20 candidate API names failed to match the hash for 17 of them [ev_0040].",
        "The decompiler output for 3 of the 150 functions failed to recover types.",
        "Hash resolution over 164 values failed for 12 of them, so 12 API slots stay unnamed.",
        "Two of the 11 DNS lookups the sample's calls made failed in the sandbox.",
        "4 of 158 functions failed to decompile, so their bodies are not read.",
        "In 2 of the 3 emulations the hash failed to match.",
    ],
)
def test_a_number_counting_no_call_is_no_failure_count(sentence: str) -> None:
    counts = FailureCounts(failed=6, redone=6, by_name={"decompil": (4, 4)})
    assert failure_counts(sentence) == []
    assert not count_disagrees(sentence, counts)


def test_a_kept_miscount_is_recorded_never_left_out() -> None:
    # A wrong number, the redo stated: only the count disagrees with the ledger.
    miscount = "Three tool calls failed, and later calls redid them [ev_0005][ev_0006]."
    report = _report(limitations=f"{SCOPE} {miscount}")
    keep = _row("limitations", miscount, "keep", [], reason="as the run said")
    answer = {"sentences": _settled(report, [keep])}
    done, _ = _ask(report, answer, answer)
    assert miscount in _limitations(report)
    assert done.summary["dropped"] == 0
    assert FAILURE_COUNT_CODE in {r["code"] for r in done.tally.unresolved}


def test_the_count_reader() -> None:
    counts = FailureCounts(failed=6, redone=6, by_name={"decompil": (4, 4)})
    assert failure_counts("4 of 158 tool calls failed and were not redone.") == [4]
    assert failure_counts("Six calls failed.") == [6]
    assert failure_counts("Two decompile calls failed and were not redone.") == [2]
    assert failure_counts("The beacon failed twice.") == []
    assert count_disagrees("4 of 158 tool calls failed and were not redone.", counts)
    assert not count_disagrees("Six tool calls failed; all six were redone.", counts)
    assert not count_disagrees("Four decompile calls failed.", counts)
    assert not count_disagrees("Several calls failed.", counts)


# -- a section 5 denial a decoded value contradicts -------------------------------


def test_a_section_5_denial_a_bound_value_contradicts_is_rewritten_in_the_model_s_words() -> None:
    report = _report()
    passages = _facts(report)
    assert MUTEX in passages["string_resolution"].on_fact
    assert "[string_resolution] each of these denies something" in prompt_text(
        list(passages.values())
    )
    words = (
        "The CreateMutexW call in 0x1400 is listed with two zero arguments [ev_0002], but the "
        "code passes 'alphaname' to it as the mutex name [ev_0003]."
    )
    row = _row("string_resolution", MUTEX, "rewrite", ["bound.1"], rewrite=words)
    done, reporter = _ask(report, {"sentences": _settled(report, [row])})
    assert len(reporter.asked) == 1
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    assert ta.string_resolution.body == words
    assert done.summary["qualified"] == 0


def test_a_rewrite_stating_the_denial_again_is_refused_then_the_fact_is_added() -> None:
    report = _report()
    again = MUTEX[:-1] + "; the code passes 'alphaname' to CreateMutexW [ev_0003]."
    row = _row("string_resolution", MUTEX, "rewrite", ["bound.1"], rewrite=again)
    answer = {"sentences": _settled(report, [row])}
    done, reporter = _ask(report, answer, answer)
    assert ABSENCE_KEPT_CODE in str(reporter.asked[1][-1].content)
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    # As before the model's words were asked for: the fact's clause, recorded.
    assert ta.string_resolution.body.startswith(MUTEX[:-1] + "; the code passes")
    assert done.summary["qualified"] == 1
    assert QUALIFIED_CODE in [r["code"] for r in done.tally.unresolved]


def test_a_section_5_sentence_calling_something_unsettled_is_held() -> None:
    passages = _facts(_report())
    assert HASHED in passages["persistence_detail"].whole_code
    assert HASHED in passages["persistence_detail"].held


@pytest.mark.parametrize(
    ("absence", "rewrite", "kept"),
    [
        ("so the mutex name is not passed in that call", "the mutex name is not passed", True),
        ("The mutex name is not established", "The mutex is unnamed [ev_0001].", True),
        ("The mutex name is not established", "The code passes it as the name.", False),
        # A clause splitting the absence names other addresses: another statement.
        ("0x2800 and 0x2c00 were not read", "0x2800 was not read [ev_0002].", False),
        # One word in common is no absence.
        ("whether they pass in a guest is not known", "the name is not known", False),
        # Another absence of the same subject is no absence kept (review r1, haiku12's
        # own mutex and request-body rewrites among them).
        (
            "the mutex name is not passed in that call",
            "The code passes the mutex name as argument 3 [ev_0010]; what the mutex name "
            "guards is not known.",
            False,
        ),
        (
            "the mutex name is not passed in that call",
            "The call passes it as the mutex name [ev_0010], although the mutex name is not "
            "checked afterwards.",
            False,
        ),
        (
            "The C2 request body is not established",
            "The C2 request body is built from the template [ev_0079]; no POST carrying the "
            "request body was observed.",
            False,
        ),
        (
            "the mutex name was not recovered",
            'The code passes "alphaname" to CreateMutexW as argument 3 (lpName) [ev_0021], '
            "and what the mutex name guards against is not established.",
            False,
        ),
        (
            "The registry key name is not known",
            "The registry key name is Software\\X [ev_1]; whether the key is written on every "
            "run is not known.",
            False,
        ),
    ],
)
def test_the_absence_a_rewrite_keeps(absence: str, rewrite: str, kept: bool) -> None:
    assert (kept_absence([absence], rewrite) == absence) is kept


def test_a_quote_stands_whole_and_long_enough() -> None:
    source = "Routine 0x1400 is  not\nread by any listing [ev_0002]."
    assert quote_stands("“is not read by any listing”", [source])
    assert quote_stands("...is not read by any listing…", [source])
    assert not quote_stands("not read", [source])
    assert not quote_stands("is not read by any decompile", [source])


# -- the stored run the defects were read in -----------------------------------


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


def test_haiku12_s_limitations_are_answered_against_every_listing_they_name() -> None:
    report, ledger = _stored("haiku12")
    passages = {p.id: p for p in passages_of(report, entries=ledger)}
    limitations = passages["limitations"]
    assert limitations.held == tuple(dict.fromkeys(_sentences_of(limitations.text)))
    listed = {p.text.split(" (offset ")[1].split(")")[0] for p in passages.values() if p.lists_code}
    # C1 and C2: ev_0086 lists 0x6328 beside 0x3074 and 0x8560; three entries list 0x3868.
    assert {"0x6328", "0x3868", "0x3074", "0x8560"} <= listed
    # C6: all six failed calls were redone, counted as the bundle header counts them.
    assert passages["calls.1"].text.startswith("6 tool calls failed; 6 of them redone")
    (gates,) = [s for s in limitations.held if "0x6328 was not read" in s]
    found = agreement_violations(
        {"sentences": [_row("limitations", gates, "keep", [], reason="x")]}, list(passages.values())
    )
    assert UNREAD_STANDING_CODE in [v.code for v in found]
    # D3: whole-code absences section 5 calls unsettled are held.
    held = {s for p in passages.values() for s in p.held}
    assert any(s.startswith("What the FNV routine hashes is not established") for s in held)
    assert any("information-class values" in s for s in held)


def _haiku12_limitations() -> tuple[list[Any], dict[str, Any], dict[str, str]]:
    report, ledger = _stored("haiku12")
    passages = passages_of(report, entries=ledger)
    by_id = {p.id: p for p in passages}
    held = by_id["limitations"].held

    def opening(words: str) -> str:
        return next(s for s in held if s.startswith(words))

    said = {
        "C1": opening("The gate routine at 0x6328"),
        "C2": opening("The body of the routine at 0x3868"),
        "C3": opening("Whether the beacon"),
        "C4": opening("The C2 request body"),
        "C5": opening("The C2 protocol beyond"),
        "C6": opening("The decompiler and disassembler"),
        "SCOPE": opening("Traffic beyond the captured window"),
        "WRITE": opening("The body of the file-write routine at 0x7acc"),
        "TASK": opening("The registration routine for the scheduled task (0xc42c)"),
    }
    return passages, by_id, said


def _fact_about(by_id: dict[str, Any], offset: str) -> str:
    """The id of the routine fact whose text writes ``offset`` as its own address first."""
    own = f"(offset {offset})"
    return next(
        pid
        for pid, p in by_id.items()
        if pid.startswith(("unread.", "listed.")) and own in p.text.split(" is called")[0][:40]
    )


@pytest.mark.parametrize(
    ("which", "named"),
    [("WRITE", "unread"), ("TASK", "unread"), ("SCOPE", "command_and_control")],
)
def test_haiku12_s_retry_names_the_sources_a_true_limitation_may_be_kept_on(
    which: str, named: str
) -> None:
    passages, by_id, said = _haiku12_limitations()
    row = _row("limitations", said[which], "keep", [], reason="no source speaks of it")
    found = agreement_violations({"sentences": [row]}, passages)
    (violation,) = [v for v in found if v.code == KEEP_UNQUOTED_CODE]
    assert "The shown sources that speak of it: [" in violation.message
    assert f"[{named}" in violation.message
    assert "Keep it on one of these, quoting its words, or rewrite or drop it." in (
        violation.message
    )
    # Bounded: at most three sources, each excerpt one capped quoted value.
    assert violation.message.count('] "') + violation.message.count("] '") <= 3
    if which == "TASK":
        assert f"[{_fact_about(by_id, '0xc42c')}]" in violation.message


def test_haiku12_s_true_limitation_kept_on_the_named_source_stands() -> None:
    from maljan.reporting.section_agreement import apply_rows

    report, ledger = _stored("haiku12")
    passages = passages_of(report, entries=ledger)
    by_id = {p.id: p for p in passages}
    _p, _b, said = _haiku12_limitations()
    fact = _fact_about(by_id, "0xc42c")
    text = by_id[fact].text
    quote = text[text.index("(offset 0xc42c)") :]
    row = _row("limitations", said["TASK"], "keep", [fact], quote=quote)
    found = agreement_violations({"sentences": [row]}, passages)
    assert KEEP_UNQUOTED_CODE not in [v.code for v in found if v.path.startswith("sentences")]
    counts, records = apply_rows({"sentences": [row]}, passages)
    assert said["TASK"] in _limitations(report)
    assert counts["held_kept"] == 1 and counts["dropped"] == 0
    assert not [v for v in records if v.code in (DROPPED_CODE, HELD_KEPT_CODE)]


def test_haiku12_s_c1_to_c6_kept_unsourced_again_are_left_out_and_recorded() -> None:
    from maljan.reporting.section_agreement import apply_rows

    report, ledger = _stored("haiku12")
    passages = passages_of(report, entries=ledger)
    _p, _b, said = _haiku12_limitations()
    names = ("C1", "C2", "C3", "C4", "C5", "C6")
    rows = [
        _row("limitations", said[n], "keep", [], reason="no source speaks of it") for n in names
    ]
    counts, records = apply_rows({"sentences": rows}, passages)
    body = _limitations(report)
    assert all(said[n] not in body for n in names)
    dropped = [v.message for v in records if v.code == DROPPED_CODE]
    assert counts["dropped"] == len(dropped) == 6
    assert all(any(said[n][:40] in m for m in dropped) for n in names)


@pytest.mark.parametrize("which", ["C2", "C3", "C4", "C5"])
def test_haiku12_s_c2_to_c5_are_kept_on_no_generic_quote_and_no_empty_source(which: str) -> None:
    passages, by_id, said = _haiku12_limitations()
    general = next(
        p.id for p in passages if "is not established" in p.text and p.kind == "section 5"
    )
    sentence = said[which]
    for row in (
        _row("limitations", sentence, "keep", [general], quote="is not established"),
        _row("limitations", sentence, "keep", [], reason="no source speaks of it"),
    ):
        found = agreement_violations({"sentences": [row]}, passages)
        assert KEEP_UNQUOTED_CODE in [v.code for v in found], (which, row["sources"])


def test_haiku12_s_c2_to_c5_kept_unsourced_on_both_answers_are_left_out_and_recorded() -> None:
    from maljan.reporting.section_agreement import apply_rows

    report, ledger = _stored("haiku12")
    passages = passages_of(report, entries=ledger)
    _p, _by_id, said = _haiku12_limitations()
    rows = [
        _row("limitations", said[which], "keep", [], reason="no source speaks of it")
        for which in ("C2", "C3", "C4", "C5")
    ]
    # The retry's answer, as the first: apply_rows reads the last answer.
    counts, records = apply_rows({"sentences": rows}, passages)
    body = _limitations(report)
    assert counts["dropped"] == 4
    for which in ("C2", "C3", "C4", "C5"):
        assert said[which] not in body, which
    dropped = [v.message for v in records if v.code == DROPPED_CODE]
    assert len(dropped) == 4
    assert all("no source, because 'no source speaks of it'" in m for m in dropped)
    assert all(KEEP_UNQUOTED_CODE in m for m in dropped)
    # Nothing left out silently: every sentence gone is one recorded.
    gone = [s for s in _sentences_of(_by_id["limitations"].text) if s not in body]
    assert all(
        any(s[:40] in m for m in dropped) for s in gone if s in [r["sentence"] for r in rows]
    )


def test_a_closing_keep_on_a_refused_quote_is_left_out_with_its_quote() -> None:
    report = _report(limitations=f"{STILL_OPEN} {SCOPE}")
    gamed = _row(
        "limitations", STILL_OPEN, "keep", ["persistence_detail"], quote="is not established"
    )
    scope = _row("limitations", SCOPE, "keep", [], reason="no passage speaks of an operator")
    answer = {"sentences": _settled(report, [gamed, scope])}
    done, reporter = _ask(report, answer, answer)
    assert len(reporter.asked) == 2
    assert _limitations(report) == SCOPE
    (record,) = [r for r in done.tally.unresolved if r["code"] == DROPPED_CODE]
    assert "persistence_detail, quoting 'is not established'" in record["message"]
    assert STILL_OPEN in record["message"]


def test_a_section_5_keep_a_check_refuses_stands() -> None:
    report = _report()
    # A section 5 sentence listed on another passage's words: refused, and it stands.
    keep = _row("persistence_detail", HASHED, "keep", ["conclusion"])
    answer = {"sentences": _settled(report, [keep])}
    done, _ = _ask(report, answer, answer)
    ta = report.technical_analysis
    assert ta is not None and ta.persistence_detail is not None
    assert ta.persistence_detail.body.endswith(HASHED)
    assert done.summary["dropped"] == 0


def test_haiku12_s_genuinely_sourced_keep_passes() -> None:
    passages, by_id, said = _haiku12_limitations()
    sentence = said["SCOPE"]
    # The section 5 words that state the same: the capture shows no contact past its
    # window (command_and_control).
    source = by_id["command_and_control"].text
    quote = next(s for s in _sentences_of(source) if "window" in s and ("no " in s or "not " in s))
    row = _row("limitations", sentence, "keep", ["command_and_control"], quote=quote)
    found = agreement_violations({"sentences": [row]}, passages)
    assert KEEP_UNQUOTED_CODE not in [v.code for v in found if v.path.startswith("sentences")]


@pytest.mark.parametrize("name", ["haiku10", "haiku11", "haiku12"])
def test_the_stored_runs_answer_every_closing_sentence(name: str) -> None:
    report, ledger = _stored(name)
    for passage in passages_of(report, entries=ledger):
        if passage.closing:
            assert passage.held == tuple(dict.fromkeys(_sentences_of(passage.text))), passage.id


def test_a_closing_rewrite_is_recorded_with_what_stood() -> None:
    report = _report()
    done, _ = _ask(report, {"sentences": _settled(report, [])})
    records = [r["message"] for r in done.tally.unresolved if r["code"] == REWRITTEN_CODE]
    assert any(GATES[:40] in m and GATES_READ[:40] in m for m in records)


# -- review round 2 ----------------------------------------------------------


@pytest.mark.parametrize(
    ("which", "source", "quote"),
    [
        # Another routine's sentence: the overlap was {body, read}.
        ("C2", "payloads", "The body of 0x7acc was not read to its end"),
        # Another subject's sentence: the overlap was {decoded, strings}.
        ("C4", "persistence_detail", "No Run or RunOnce string appears in the decoded strings"),
        ("C5", "persistence_detail", "No Run or RunOnce string appears in the decoded strings"),
        # The overlap was only what is denied: {established, passed}.
        (
            "C3",
            "evasion_antiforensics",
            "Confidence is moderate: the information-class values passed to "
            "SetFileInformationByHandle were not established.",
        ),
    ],
)
def test_haiku12_s_brute_forced_keeps_are_refused(which: str, source: str, quote: str) -> None:
    passages, by_id, said = _haiku12_limitations()
    assert quote.rstrip(".") in by_id[source].text
    row = _row("limitations", said[which], "keep", [source], quote=quote)
    found = agreement_violations({"sentences": [row]}, passages)
    assert KEEP_UNQUOTED_CODE in [v.code for v in found], which


def test_a_keep_resting_on_fewer_than_two_subject_words_is_recorded() -> None:
    from maljan.reporting.section_agreement import Passage, apply_rows

    sentence = "Packing is not established [ev_0002]."
    closing = Passage(
        id="limitations",
        label="11. Limitations",
        text=sentence,
        kind="claim-led",
        cites=frozenset({"ev_0002"}),
        write=lambda _text: None,
        closing=True,
        held=(sentence,),
    )
    source = Passage(
        id="packing_obfuscation",
        label="5. Technical analysis, 'Packing'",
        text="Packing is not established by any section entropy reading.",
        kind="section 5",
    )
    row = {
        "passage": "limitations",
        "sentence": sentence,
        "sources": ["packing_obfuscation"],
        "decision": "keep",
        "quote": "Packing is not established by any section entropy reading",
    }
    counts, found = apply_rows({"sentences": [row]}, [source, closing])
    # One subject word: the keep passes, and is recorded, not only counted.
    assert counts["held_kept"] == 1 and counts["dropped"] == 0
    assert [v.code for v in found] == [HELD_KEPT_CODE]


def test_a_restated_absence_is_found_among_many_unrelated_denials() -> None:
    absence = ["the mutex name is not passed in that call"]
    assert kept_absence(absence, "The code passes it [ev_1]; the mutex name is not passed.")
    for decoys in (10, 63, 64, 70, 500):
        rewrite = (
            "The code passes runnung [ev_1]; "
            + "; ".join(f"item{i} thing{i} is not shown" for i in range(decoys))
            + "; the mutex name is not passed in that call."
        )
        assert kept_absence(absence, rewrite) == absence[0], decoys


@pytest.mark.parametrize(
    ("sentence", "counts"),
    [
        ("Of 158 tool calls, 12 hit cached answers and 4 failed.", [4]),
        ("Of the 158 tool calls, 6 failed.", [6]),
        ("4 of 158 tool calls failed and were not redone.", [4]),
        ("Of 158 functions, 4 failed to decompile.", []),
    ],
)
def test_calls_counted_before_the_number(sentence: str, counts: list[int]) -> None:
    assert failure_counts(sentence) == counts
