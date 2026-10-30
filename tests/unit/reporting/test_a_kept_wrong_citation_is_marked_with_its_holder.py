"""A wrong citation the model keeps after its question is marked where it stands.

A benchmark report printed a keyword under an entry that does not hold it,
and a digest under two entries that hold neither: the composer asked once,
the model kept the ids, and the body printed them unmarked, because a wrong
citation was kept with a finding but never marked in place. It is now marked
where it stands — after its sentence, or beside the evidence of the table row
that states it — with the ids it cites and the entry that holds the value.
Only one holder is named: a value several entries hold is marked with how many
hold it, attributed to none. The model's ids are printed as written; nothing
is removed or replaced. A rewrite that keeps the same wrong citation was asked
about all the same.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from maljan.pipeline.validation import (
    CITATION_WRONG_ENTRY_CODE,
    MARKED_IN_PLACE,
    EntryTexts,
    cited_row_text,
    record_flagged_statements,
    wrong_entry_citations,
)
from maljan.reporting.composer import ReportComposer, _ProseOut
from maljan.reporting.models import (
    ConfigItem,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import LedgerEntry

# Invented values: a reply keyword one entry holds, and a mutex two entries hold.
KEYWORD = "QUILLSTOP"
MUTEX = "Local\\ferncastle-0x41"


def _entry(entry_id: str, tool: str, output: str) -> LedgerEntry:
    return LedgerEntry(id=entry_id, agent="pipeline", server="pipeline", tool=tool, output=output)


def _texts() -> EntryTexts:
    return EntryTexts.from_ledger(
        [
            _entry("ev_0102", "pe_info", json.dumps({"imports": ["WININET.dll"]})),
            _entry("ev_0105", "decode_blobs", json.dumps({"blobs": ["c3RvcA=="]})),
            _entry("ev_0107", "floss", json.dumps({"strings": [KEYWORD, MUTEX]})),
            _entry("ev_0109", "decompile", json.dumps({"code": f'CreateMutexA("{MUTEX}")'})),
        ]
    )


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64)), verdict="Malware", **over
    )


class TestTheFinding:
    def test_a_prose_wrong_citation_carries_its_sentence_and_its_one_holder(self) -> None:
        sentence = f"The reply parser stops on `{KEYWORD}` [ev_0105]."

        (found,) = wrong_entry_citations({"body": sentence}, _texts(), prose=("body",))

        assert found.quoted == (sentence,)
        assert found.labels == (f'"{KEYWORD}" is not in ev_0105; ev_0107 (floss) holds it',)

    def test_a_value_several_entries_hold_is_attributed_to_none(self) -> None:
        sentence = f"It opens the mutex `{MUTEX}` [ev_0102]."

        (found,) = wrong_entry_citations({"body": sentence}, _texts(), prose=("body",))

        (label,) = found.labels
        assert label.endswith("; 2 other entries hold it")
        assert "ev_0107" not in label and "ev_0109" not in label

    def test_a_row_is_named_by_its_text_under_the_ids_it_cites(self) -> None:
        row = {"key": "Stop word", "value": KEYWORD, "evidence_refs": ["EV_0105"]}

        (found,) = wrong_entry_citations({"items": [row]}, _texts())

        assert found.quoted == (f"{KEYWORD} [ev_0105]",)
        assert found.quoted == (cited_row_text(KEYWORD, row),)

    def test_the_finding_is_marked_in_place(self) -> None:
        assert CITATION_WRONG_ENTRY_CODE in MARKED_IN_PLACE


class TestTheReport:
    def test_a_kept_sentence_is_printed_as_written_with_the_mark_after_it(self) -> None:
        sentence = f"The reply parser stops on `{KEYWORD}` [ev_0105]."
        report = _report(
            technical_analysis=TechnicalAnalysis(
                command_and_control=TechnicalSubsection(title="Command and control", body=sentence)
            )
        )
        record_flagged_statements(
            report, wrong_entry_citations({"body": sentence}, _texts(), prose=("body",))
        )

        text = MarkdownRenderer().render(report)

        line = next(line for line in text.splitlines() if "reply parser" in line)
        assert "[ev_0105]" in line
        assert "cited to an entry that does not hold it" in line
        assert "ev_0107 (floss) holds it" in line

    def test_a_row_is_marked_beside_its_evidence_and_no_other_place(self) -> None:
        wrong = {"key": "Stop word", "value": KEYWORD, "evidence_refs": ["ev_0105"]}
        right = {"key": "Halt word", "value": KEYWORD, "evidence_refs": ["ev_0107"]}
        prose = f"The parser also reads {KEYWORD} lines [ev_0107]."
        report = _report(
            technical_analysis=TechnicalAnalysis(
                configuration=[
                    ConfigItem(how_obtained="static-string", **wrong),
                    ConfigItem(how_obtained="static-string", **right),
                ],
                command_and_control=TechnicalSubsection(title="Command and control", body=prose),
            )
        )
        record_flagged_statements(
            report, wrong_entry_citations({"items": [wrong, right]}, _texts())
        )

        text = MarkdownRenderer().render(report)

        stop = next(line for line in text.splitlines() if line.startswith("| Stop word"))
        assert "ev_0105 **[cited to an entry that does not hold it:" in stop
        halt = next(line for line in text.splitlines() if line.startswith("| Halt word"))
        assert "cited to an entry" not in halt
        reads = next(line for line in text.splitlines() if "also reads" in line)
        assert "cited to an entry" not in reads

    def test_a_key_finding_citing_by_its_ids_is_marked_after_them(self) -> None:
        from maljan.reporting.models import KeyFinding

        finding = {"text": f"Replies end with `{KEYWORD}`.", "evidence_ids": ["ev_0105"]}
        report = _report(key_findings=[KeyFinding(**finding)])
        record_flagged_statements(
            report,
            wrong_entry_citations(
                {"key_findings": [finding]}, _texts(), prose=("executive_summary", "key_findings")
            ),
        )

        text = MarkdownRenderer().render(report)

        line = next(line for line in text.splitlines() if "Replies end with" in line)
        assert line.index("ev_0105") < line.index("cited to an entry that does not hold it")
        assert "ev_0107 (floss) holds it" in line


class _RawLLM:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.sent: list[Any] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, messages: Any) -> Any:
        self.sent.append(list(messages))
        return SimpleNamespace(content=self._answers.pop(0))


def _invoke(*answers: str) -> tuple[_RawLLM, MalwareReport]:
    from langchain_core.messages import HumanMessage

    llm = _RawLLM(*answers)
    report = _report()
    comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
    comp._report = report
    comp._entries = _texts()
    comp._citable = ["ev_0102", "ev_0105", "ev_0107", "ev_0109"]
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=False):
        asyncio.run(comp._invoke([HumanMessage(content="write it")], _ProseOut, section="x"))
    return llm, report


class TestTheComposer:
    def test_a_citation_kept_after_the_question_is_marked_as_asked(self) -> None:
        first = json.dumps({"body": f"It stops on `{KEYWORD}` [ev_0105].", "evidence_refs": []})
        kept = f"Its parser halts on `{KEYWORD}` [ev_0105]."

        llm, report = _invoke(first, json.dumps({"body": kept, "evidence_refs": []}))

        assert len(llm.sent) == 2
        (row,) = report.flagged_statements
        assert row.sentence == kept and row.code == CITATION_WRONG_ENTRY_CODE
        assert row.asked is True
        assert "ev_0107 (floss) holds it" in row.label

    def test_a_citation_fixed_after_the_question_is_not_marked(self) -> None:
        first = json.dumps({"body": f"It stops on `{KEYWORD}` [ev_0105].", "evidence_refs": []})
        fixed = json.dumps({"body": f"It stops on `{KEYWORD}` [ev_0107].", "evidence_refs": []})

        _llm, report = _invoke(first, fixed)

        assert report.flagged_statements == []

    def test_a_wrong_citation_first_raised_by_the_retry_is_marked_not_asked(self) -> None:
        first = json.dumps({"body": f"It stops on `{KEYWORD}` [ev_0105].", "evidence_refs": []})
        second = f"It opens `{MUTEX}` [ev_0102]."
        retry = json.dumps(
            {"body": f"It stops on `{KEYWORD}` [ev_0107]. {second}", "evidence_refs": []}
        )

        _llm, report = _invoke(first, retry)

        (row,) = report.flagged_statements
        assert row.sentence == second and row.asked is False


class TestTheLabel:
    def test_a_value_is_written_as_stated_with_its_backslashes_single(self) -> None:
        sentence = f"It opens the mutex `{MUTEX}` [ev_0105]."

        (found,) = wrong_entry_citations({"body": sentence}, _texts(), prose=("body",))

        (label,) = found.labels
        assert "Local\\ferncastle-0x41" in label and "\\\\" not in label

    def test_several_wrong_citations_of_one_sentence_are_one_mark(self) -> None:
        sentence = f"It stops on `{KEYWORD}` and opens `{MUTEX}` [ev_0105]."
        report = _report(
            technical_analysis=TechnicalAnalysis(
                command_and_control=TechnicalSubsection(title="Command and control", body=sentence)
            )
        )
        found = wrong_entry_citations({"body": sentence}, _texts(), prose=("body",))
        assert len(found) == 2
        record_flagged_statements(report, found)

        text = MarkdownRenderer().render(report)

        line = next(line for line in text.splitlines() if "It stops on" in line)
        assert line.count("cited to an entry that does not hold it") == 1
        assert "ev_0107 (floss) holds it" in line and "2 other entries hold it" in line


def _narrative(*answers: str) -> MalwareReport:
    from unittest.mock import AsyncMock, MagicMock

    from maljan.reporting.narrative_agent import NarrativeAgent

    llm = MagicMock()
    structured = MagicMock()
    structured.ainvoke = AsyncMock(side_effect=Exception("no schema"))
    llm.with_structured_output.return_value = structured
    llm.ainvoke = AsyncMock(side_effect=[MagicMock(content=answer) for answer in answers])
    report = _report()
    asyncio.run(
        NarrativeAgent(llm=llm).generate(
            report, citable_ids=["ev_0102", "ev_0105", "ev_0107", "ev_0109"], evidence=_texts()
        )
    )
    return report


def _summary(text: str) -> str:
    recommendation = {
        "category": "edr_hunting",
        "action": "Hunt for the loader's process tree.",
        "rationale": "It starts from a script host.",
        "priority": "P1",
        "detection": "Process creation of the loader.",
    }
    return json.dumps(
        {
            "executive_summary": f"{text} The loader should be contained on every host it "
            "reached, and its process tree hunted for across the estate.",
            "key_findings": [
                {"text": "It resolves its imports at run time.", "evidence_ids": []},
                {"text": "It starts from a script host.", "evidence_ids": []},
            ],
            "defensive_recommendations": [recommendation] * 3,
        }
    )


class TestTheNarrative:
    def test_a_kept_citation_is_asked_and_one_first_raised_by_the_retry_is_not(self) -> None:
        kept = f"Its parser halts on `{KEYWORD}` [ev_0105]."
        new = f"It opens `{MUTEX}` [ev_0102]."

        report = _narrative(
            _summary(f"It stops on `{KEYWORD}` [ev_0105]."), _summary(f"{kept} {new}")
        )

        asked = {row.sentence: row.asked for row in report.flagged_statements}
        assert asked == {kept: True, new: False}
