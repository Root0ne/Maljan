"""The conclusion and the limitations state nothing section 5 or a fact says otherwise of (T-554).

haiku10's limitations paragraph called the mutex "not named", the PEB gate
"not determined", the RC4 and FNV data "not recovered", slot 0x10b38
"unresolved" and the reverser's task, gate and staging claims "not visible",
and its conclusion called the mutex text unexplained, while section 5 and the
platform's own facts state each one. Neither section was shown to the
agreement round: the conclusion never, the limitations only where a sentence
said a call failed. Both are now passages written without the code like every
other; a sentence of either listed against a source is rewritten, and one
whose rewrite passes no check is left out, never kept, with what stood
recorded. Every address and value in the synthetic tests is a neutral one.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage

from maljan.core.config import Settings, get_settings, install_settings
from maljan.reporting.models import (
    BoundValue,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.section_agreement import (
    CLAIM_LED,
    DROPPED_CODE,
    HELD_KEPT_CODE,
    HELD_UNLISTED_CODE,
    REWRITE_CITES_ELSEWHERE_CODE,
    REWRITTEN_CODE,
    SECTION_5,
    UNKNOWN_SOURCE_CODE,
    _sentences_of,
    ask_section_agreement,
    closing_negations,
    held_closing_sentences,
    passages_of,
    prompt_text,
)
from tests.unit.reporting._report_inventory import stored_runs

OPEN_MUTEX = "The mutex the gate routine creates was not named [ev_0004]."
OPEN_GATE = "Whether the environment read gates execution was not determined."
KEPT = "No sandbox contact with the hosts was observed [ev_0005]."
CONCLUDED = "The gate's text remains unexplained [ev_0004]."
CITABLE = [f"ev_{n:04d}" for n in range(1, 10)]


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="b" * 64), file_type="PE32+ DLL"),
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
                site="0x1100",
                function="0x1000",
                decoder_call="0x1104",
                call_at="0x1120",
                slot="0x2000",
                named_by="ev_0003",
            )
        ],
        technical_analysis=TechnicalAnalysis(
            evasion_antiforensics=TechnicalSubsection(
                title="Evasion",
                body="Routine 0x1200 reads the environment and returns -1, which stops the "
                "start-up [ev_0006].",
                evidence_refs=["ev_0006"],
            ),
            analyst_conclusion=TechnicalSubsection(
                title="Conclusion",
                body=f"The file is a loader [ev_0001]. {CONCLUDED}\n\nIt beacons [ev_0001].",
                evidence_refs=["ev_0001"],
            ),
            analyst_limitations=TechnicalSubsection(
                title="Limitations",
                body=f"{OPEN_MUTEX} {OPEN_GATE} {KEPT}",
                evidence_refs=["ev_0004", "ev_0005"],
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


def _row(passage: str, sentence: str, sources: list[str], rewrite: str) -> dict[str, Any]:
    return {
        "passage": passage,
        "sentence": sentence,
        "sources": sources,
        "decision": "rewrite",
        "rewrite": rewrite,
    }


def _ask(report: MalwareReport, *answers: Any) -> tuple[Any, _Reporter]:
    reporter = _Reporter(*answers)
    done = asyncio.run(ask_section_agreement(reporter, report, citable_ids=CITABLE))
    return done, reporter


def _every_other_kept(report: MalwareReport, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The rows, and one keeping with the reason each closing sentence they leave out:
    every closing sentence is answered (T-568)."""
    ta = report.technical_analysis
    assert ta is not None
    answered = {(row["passage"], row["sentence"]) for row in rows}
    kept: list[dict[str, Any]] = []
    for pid, sub in (
        ("conclusion", ta.analyst_conclusion),
        ("limitations", ta.analyst_limitations),
    ):
        for sentence in _sentences_of(sub.body if sub is not None else ""):
            if (pid, sentence) not in answered:
                kept.append(
                    {
                        "passage": pid,
                        "sentence": sentence,
                        "sources": [],
                        "decision": "keep",
                        "reason": "no source speaks of it",
                    }
                )
    return [*rows, *kept]


def test_both_closing_sections_are_asked_as_passages_written_without_the_code() -> None:
    # Under the shipped settings, as the worker reads which section reads code.
    previous = get_settings()
    install_settings(Settings())
    try:
        passages = {p.id: p for p in passages_of(_report())}
    finally:
        install_settings(previous)
    assert passages["evasion_antiforensics"].kind == SECTION_5
    for pid, label in (("conclusion", "7. Conclusion"), ("limitations", "11. Limitations")):
        passage = passages[pid]
        assert passage.kind == CLAIM_LED and passage.closing and passage.write is not None
        assert passage.label == label
    prompt = prompt_text(list(passages.values()))
    passages_block = prompt.split("PASSAGES WRITTEN WITHOUT THE CODE", 1)[1]
    assert "[conclusion] 7. Conclusion (cites ev_0001, ev_0004):" in passages_block
    assert "[limitations] 11. Limitations (cites ev_0004, ev_0005):" in passages_block
    # The conclusion comes before the limitations, as the report prints them.
    assert passages_block.index("[conclusion]") < passages_block.index("[limitations]")


def test_a_report_without_them_asks_as_before() -> None:
    report = _report()
    report.technical_analysis.analyst_conclusion = None  # type: ignore[union-attr]
    report.technical_analysis.analyst_limitations = None  # type: ignore[union-attr]
    assert {p.id for p in passages_of(report)} == {"bound.1", "evasion_antiforensics"}


def test_a_closing_sentence_a_source_contradicts_is_rewritten() -> None:
    report = _report()
    rewrite = "The mutex the gate routine creates is named 'alphaname' [ev_0002][ev_0004]."
    # Every other closing sentence is kept, with the reason (T-568).
    rows = _every_other_kept(report, [_row("limitations", OPEN_MUTEX, ["bound.1"], rewrite)])
    done, reporter = _ask(report, {"sentences": rows})
    assert len(reporter.asked) == 1
    body = report.technical_analysis.analyst_limitations.body  # type: ignore[union-attr]
    assert body == f"{rewrite} {OPEN_GATE} {KEPT}"
    assert done.summary["rewritten"] == 1 and done.summary["dropped"] == 0
    # Every kept closing sentence is counted and recorded with its reason (T-568).
    codes = [r["code"] for r in done.tally.unresolved]
    assert codes.count(REWRITTEN_CODE) == 1 and codes.count(HELD_KEPT_CODE) == len(rows) - 1
    assert done.summary["held_kept"] == len(rows) - 1


def test_a_closing_sentence_whose_rewrite_fails_is_left_out_and_recorded() -> None:
    report = _report()
    # Cites an entry neither the source nor the passage cites, twice.
    wrong = "The environment read returns -1 and stops the start-up [ev_0009]."
    row = _row("limitations", OPEN_GATE, ["evasion_antiforensics"], wrong)
    done, reporter = _ask(report, {"sentences": [row]}, {"sentences": [row]})
    assert len(reporter.asked) == 2
    body = report.technical_analysis.analyst_limitations.body  # type: ignore[union-attr]
    assert body == f"{OPEN_MUTEX} {KEPT}"
    assert done.summary["dropped"] == 1 and done.summary["not_applied"] == 0
    codes = [r["code"] for r in done.tally.unresolved]
    assert REWRITE_CITES_ELSEWHERE_CODE in codes and DROPPED_CODE in codes
    (dropped,) = [r for r in done.tally.unresolved if r["code"] == DROPPED_CODE]
    assert OPEN_GATE in dropped["message"] and "evasion_antiforensics" in dropped["message"]


def test_the_last_sentence_of_a_paragraph_is_left_out_with_the_space_before_it() -> None:
    report = _report()
    report.technical_analysis.analyst_conclusion.body = (  # type: ignore[union-attr]
        f"The file is a loader [ev_0001]. {CONCLUDED}\n\nIt beacons [ev_0001]."
    )
    row = _row("conclusion", CONCLUDED, ["bound.1"], "It is 'alphaname' [ev_0009].")
    done, _ = _ask(report, {"sentences": [row]}, {"sentences": [row]})
    body = report.technical_analysis.analyst_conclusion.body  # type: ignore[union-attr]
    assert body == "The file is a loader [ev_0001].\n\nIt beacons [ev_0001]."
    assert done.summary["dropped"] == 1


def test_a_row_resting_on_no_source_leaves_the_sentence_as_written() -> None:
    report = _report()
    before = report.technical_analysis.analyst_limitations.body  # type: ignore[union-attr]
    # Only another passage written without the code: it grounds nothing, drops nothing.
    row = _row("limitations", OPEN_GATE, ["conclusion"], "It gates execution [ev_0009].")
    done, _ = _ask(report, {"sentences": [row]}, {"sentences": [row]})
    assert report.technical_analysis.analyst_limitations.body == before  # type: ignore[union-attr]
    assert done.summary["dropped"] == 0 and done.summary["not_applied"] == 1


def test_another_passage_s_failed_rewrite_is_still_kept_as_written() -> None:
    report = _report()
    report.intro_background = f"Background [ev_0001]. {OPEN_GATE}"
    row = _row("introduction", OPEN_GATE, ["evasion_antiforensics"], "It gates [ev_0009].")
    done, _ = _ask(report, {"sentences": [row]}, {"sentences": [row]})
    assert report.intro_background == f"Background [ev_0001]. {OPEN_GATE}"
    assert done.summary["dropped"] == 0 and done.summary["not_applied"] == 1


# What haiku10's two closing sections said that section 5 and the facts state
# (score.md section 4, items 5 to 10).
HAIKU10_SAID = {
    "conclusion": ("the 'runnung' string, remain unexplained",),
    "limitations": (
        "the mutex created by CreateMutexW in function 0x3868 was not named",
        "were not visible in this review",
        "Whether the PEB read at 0x8690 gates execution was not determined",
        "the data they decrypt or hash was not recovered",
        "The indirect call through pointer slot 0x10b38 was not resolved to an API",
    ),
}


# The held sentences of two stored runs, by their opening words (T-554): haiku10's
# are the five D2 statements, haiku8's the one naming an address section 5 states.
STORED_HELD = {
    "haiku10": {
        "conclusion": ("Two routines, the wait loop at 0x1030 and the 'runnung' string",),
        "limitations": (
            "The indirect call through pointer slot 0x10b38 was not resolved",
            "The RC4 PRGA routine at 0xcaac and the FNV routine at 0xc99c",
            "The reverser-stage claims about task registration",
            "Whether the PEB read at 0x8690 gates execution was not determined",
        ),
    },
    "haiku8": {
        "conclusion": (),
        "limitations": ("Whether the 0xad34 routine allocates executable memory",),
    },
}


@pytest.mark.parametrize("name", sorted(STORED_HELD))
def test_the_stored_runs_hold_exactly_these_closing_sentences(name: str) -> None:
    root = stored_runs()
    if root is None or not (root / name / "report.json").is_file():
        pytest.skip(f"the stored benchmark run {name} is not on this machine")
    from maljan.reporting.follow_up import stored_ledger

    run = root / name
    report = MalwareReport.model_validate(json.loads((run / "report.json").read_text()))
    document = json.loads((run / "evidence.json").read_text())
    rows = document.get("items") or document.get("entries") if isinstance(document, dict) else []
    ledger, _unread = stored_ledger(rows)
    passages = {p.id: p for p in passages_of(report, entries=ledger)}
    for pid, openings in STORED_HELD[name].items():
        passage = passages[pid]
        held = held_closing_sentences(passage.text, [*passages.values()])
        assert len(held) == len(openings), (pid, held)
        assert all(h.startswith(o) for h, o in zip(held, openings, strict=True)), (pid, held)
        # Beside them, every negation the body may state otherwise of is held (T-562),
        # and every other sentence: each closing sentence is answered (T-568).
        assert {*held, *closing_negations(passage.text)} <= set(passage.held), pid
        assert passage.held == tuple(dict.fromkeys(_sentences_of(passage.text))), pid


def test_a_sentence_naming_no_address_is_held_only_where_it_names_the_run_s_reading() -> None:
    report = _held_report(
        "APIs outside that set are not established as absent. "
        "The analysts' claims about the gate were not visible in this review, so that "
        "behaviour is not established."
    )
    passage = {p.id: p for p in passages_of(report)}["limitations"]
    reading = "The analysts' claims about the gate were not visible in this review, so that "
    reading += "behaviour is not established."
    sources = list(passages_of(report))
    assert held_closing_sentences(passage.text, sources) == (reading,)
    # The other one is held too: every closing sentence is answered (T-568).
    assert set(passage.held) == {reading, "APIs outside that set are not established as absent."}


def test_haiku10_s_closing_sentences_are_shown_beside_what_states_otherwise() -> None:
    root = stored_runs()
    if root is None or not (root / "haiku10" / "report.json").is_file():
        pytest.skip("the stored benchmark run haiku10 is not on this machine")
    from maljan.reporting.follow_up import stored_ledger

    run = root / "haiku10"
    report = MalwareReport.model_validate(json.loads((run / "report.json").read_text()))
    document = json.loads((run / "evidence.json").read_text())
    rows = document.get("items") or document.get("entries") if isinstance(document, dict) else []
    ledger, _unread = stored_ledger(rows)
    passages = {p.id: p for p in passages_of(report, entries=ledger)}
    for pid, said in HAIKU10_SAID.items():
        assert passages[pid].kind == CLAIM_LED and passages[pid].closing
        assert all(words in passages[pid].text for words in said), pid
    # The mutex's name is a fact the round is shown, and the gate a section 5 passage.
    assert any(p.id.startswith("bound.") and "runnung" in p.text for p in passages.values())
    for pid, words in (
        ("evasion_antiforensics", "0x3074"),
        ("persistence_detail", "0x10b38"),
        ("command_and_control", "Littlehw"),
    ):
        assert passages[pid].kind == SECTION_5 and words in passages[pid].text, pid


# ---------------------------------------------------------------------------
# Held sentences: each one is listed, as the model decides
# ---------------------------------------------------------------------------

HELD = "The mutex 'alphaname' was not named [ev_0004]."


def _held_report(body: str = f"{HELD} {KEPT}") -> MalwareReport:
    report = _report()
    report.technical_analysis.analyst_limitations.body = body  # type: ignore[union-attr]
    return report


def _limitations(report: MalwareReport) -> str:
    return report.technical_analysis.analyst_limitations.body  # type: ignore[union-attr]


def _keep(sentence: str, sources: list[str]) -> dict[str, Any]:
    return {"passage": "limitations", "sentence": sentence, "sources": sources, "decision": "keep"}


def test_a_closing_sentence_calling_a_stated_value_open_is_held_and_shown_so() -> None:
    passages = {p.id: p for p in passages_of(_held_report())}
    sources = list(passages.values())
    assert held_closing_sentences(passages["limitations"].text, sources) == (HELD,)
    assert held_closing_sentences(passages["conclusion"].text, sources) == ()
    # Every closing sentence is answered (T-568): the passage is not quoted twice.
    assert passages["limitations"].held == (HELD, KEPT)
    prompt = prompt_text(list(passages.values()))
    assert "[limitations] answer every sentence of this passage, one row each (2 sentences)" in (
        prompt
    )
    assert "Besides, answer EVERY sentence of [conclusion], [limitations]" in prompt
    assert "list each of these sentences" not in prompt


def test_a_held_sentence_left_unlisted_is_asked_once_more_and_then_kept() -> None:
    report = _held_report()
    kept = {**_keep(HELD, []), "reason": "the decoded name is not tied to this mutex here"}
    done, reporter = _ask(
        report, {"sentences": []}, {"sentences": _every_other_kept(report, [kept])}
    )
    assert len(reporter.asked) == 2
    assert HELD_UNLISTED_CODE in str(reporter.asked[1][-1].content)
    # Kept on the model's reading: never left out on the platform's read alone.
    assert _limitations(report) == f"{HELD} {KEPT}"
    # Every closing sentence was kept on the retry: five, the held one among them.
    assert done.summary["kept"] == 5 and done.summary["dropped"] == 0
    assert HELD_UNLISTED_CODE not in [r["code"] for r in done.tally.unresolved]


def test_a_held_sentence_never_listed_stays_and_the_finding_is_recorded() -> None:
    report = _held_report()
    done, _ = _ask(report, {"sentences": []}, {"sentences": []})
    assert _limitations(report) == f"{HELD} {KEPT}"
    assert HELD_UNLISTED_CODE in [r["code"] for r in done.tally.unresolved]
    assert done.summary["dropped"] == 0


def test_mixed_valid_and_unknown_sources_on_a_failing_rewrite_keep_the_sentence() -> None:
    report = _held_report()
    row = _row("limitations", HELD, ["bound.1", "conclusion"], "It is 'alphaname' [ev_0002].")
    done, _ = _ask(report, {"sentences": [row]}, {"sentences": [row]})
    # Left out only where every source the row names is one it may rest on.
    assert _limitations(report) == f"{HELD} {KEPT}"
    assert done.summary["dropped"] == 0 and done.summary["not_applied"] == 1
    assert UNKNOWN_SOURCE_CODE in [r["code"] for r in done.tally.unresolved]


def test_a_closing_section_whose_every_sentence_is_left_out_is_empty() -> None:
    report = _held_report(HELD)
    row = _row("limitations", HELD, ["bound.1"], "It is 'alphaname' [ev_0009].")
    done, _ = _ask(report, {"sentences": [row]}, {"sentences": [row]})
    assert _limitations(report) == ""
    (dropped,) = [r for r in done.tally.unresolved if r["code"] == DROPPED_CODE]
    assert dropped["subject"] == "limitations"


def test_an_address_only_a_closing_section_names_is_read_off_the_ledger() -> None:
    from maljan.schemas.evidence import LedgerEntry

    ledger = [
        LedgerEntry(
            id="ev_0003",
            tool="lift_routine",
            args={"address": "0x401a30"},
            output="int FUN_401a30(int a)\n{\n  return a;\n}\n",
            facts={"v": 1, "kind": "decompile", "reader": "listing"},
        )
    ]
    report = _held_report("The code of routine 0x401a30 was not read [ev_0003].")
    facts = [p for p in passages_of(report, entries=ledger) if p.id.startswith("listed.")]
    assert facts and any("0x401a30" in p.text for p in facts)
