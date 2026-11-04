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
    REWRITE_CITES_ELSEWHERE_CODE,
    REWRITTEN_CODE,
    SECTION_5,
    ask_section_agreement,
    passages_of,
    prompt_text,
)
from tests.unit.reporting._report_inventory import stored_runs

OPEN_MUTEX = "The mutex the gate routine creates was not named [ev_0004]."
OPEN_GATE = "Whether the environment read gates execution was not determined."
KEPT = "No sandbox contact with the hosts was observed [ev_0005]."
CONCLUDED = "The text 'alphaname' remains unexplained [ev_0004]."
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
    done, _ = _ask(report, {"sentences": [_row("limitations", OPEN_MUTEX, ["bound.1"], rewrite)]})
    body = report.technical_analysis.analyst_limitations.body  # type: ignore[union-attr]
    assert body == f"{rewrite} {OPEN_GATE} {KEPT}"
    assert done.summary["rewritten"] == 1 and done.summary["dropped"] == 0
    assert [r["code"] for r in done.tally.unresolved] == [REWRITTEN_CODE]


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
