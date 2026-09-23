"""A value a report quotes is cited to the entry that holds it.

The benchmark's report cited the reputation lookup for strings that only the
decoded-strings entry holds, section after section, and every citation passed:
the check asked whether the id exists, not whether the entry holds what the
sentence says. Where the question can be decided — a value the sentence states
verbatim — it is asked, and the entry that holds the value is offered. Where it
cannot, nothing is said. The id is never rewritten.

The same record answers a second defect: a section shown an analyst's claim
without the entry behind it called the claim unsupported while another entry
held the claimed string word for word. The platform now tells a section which
entries hold what a claim quotes, and which techniques the report publishes.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from maljan.pipeline.validation import (
    CITATION_WRONG_ENTRY_CODE,
    KEPT_WITH_A_FINDING,
    EntryTexts,
    quoted_values,
    wrong_entry_citations,
)
from maljan.reporting.composer import ReportComposer, _bundle_text, _ProseOut
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TTPMapping,
)
from maljan.schemas.evidence import LedgerEntry

# Invented values of the shapes the benchmark report quoted: a marker string,
# a command line with a quoted argument, and a Windows path.
MARKER = "examplemark-7"
COMMAND = '/c query "Example Operators" /all'
FOLDER = "Software\\ExampleVendor\\Settings"


def _entry(entry_id: str, tool: str, output: str) -> LedgerEntry:
    return LedgerEntry(id=entry_id, agent="pipeline", server="pipeline", tool=tool, output=output)


def _ledger() -> list[LedgerEntry]:
    decoded = json.dumps({"strings": [{"string": MARKER}, {"string": COMMAND}, {"string": FOLDER}]})
    reputation = json.dumps({"engines": 70, "malicious": 40, "labels": ["trojan.example"]})
    return [
        _entry("ev_0004", "pe_info", json.dumps({"imports": ["KERNEL32.dll"]})),
        _entry("ev_0011", "get_file_report", reputation),
        _entry("ev_0012", "floss", decoded),
    ]


def _texts() -> EntryTexts:
    return EntryTexts.from_ledger(_ledger())


def _codes(found: list[Any]) -> list[str]:
    return [v.code for v in found]


class TestTheCheck:
    def test_a_quoted_value_cited_to_the_wrong_entry_is_asked_with_the_right_one(self) -> None:
        body = f"The sample carries the marker `{MARKER}` [ev_0011]."

        (found,) = wrong_entry_citations({"body": body}, _texts(), prose=("body",))

        assert found.code == CITATION_WRONG_ENTRY_CODE
        assert "ev_0011 (get_file_report)" in found.message
        assert "ev_0012 (floss)" in found.message

    def test_a_value_the_cited_entry_holds_is_not_asked_about(self) -> None:
        body = f"The sample carries the marker `{MARKER}` [ev_0012]."

        assert wrong_entry_citations({"body": body}, _texts(), prose=("body",)) == []

    def test_one_of_several_cited_entries_holding_it_is_enough(self) -> None:
        body = f"The sample carries the marker `{MARKER}` [ev_0011, ev_0012]."

        assert wrong_entry_citations({"body": body}, _texts(), prose=("body",)) == []

    def test_a_paraphrase_is_not_judged(self) -> None:
        body = "The sample queries an operators group across the domain [ev_0011]."

        assert wrong_entry_citations({"body": body}, _texts(), prose=("body",)) == []

    def test_a_value_no_entry_holds_is_not_judged(self) -> None:
        body = "The sample writes `%TEMP%\\example\\composed.bin` [ev_0011]."

        assert wrong_entry_citations({"body": body}, _texts(), prose=("body",)) == []

    def test_a_value_escaped_in_the_entry_is_still_found(self) -> None:
        body = f'It runs "{COMMAND.replace(chr(34), chr(39))}" and `{FOLDER}` [ev_0011].'

        (found,) = wrong_entry_citations({"body": body}, _texts(), prose=("body",))

        assert "Settings" in found.message
        assert "ev_0012 (floss)" in found.message

    def test_each_sentence_is_read_under_its_own_citation(self) -> None:
        body = f"It carries `{MARKER}` [ev_0012]. Its reputation is poor [ev_0011]."

        assert wrong_entry_citations({"body": body}, _texts(), prose=("body",)) == []

    def test_values_under_one_wrong_citation_are_asked_about_together(self) -> None:
        body = f"It carries `{MARKER}` and `{FOLDER}` [ev_0011]."

        (found,) = wrong_entry_citations({"body": body}, _texts(), prose=("body",))

        assert MARKER in found.message and "Settings" in found.message
        assert " are not in " in found.message

    def test_a_record_value_is_read_under_the_records_citations(self) -> None:
        payload = {"items": [{"key": "Marker", "value": MARKER, "evidence_refs": ["ev_0011"]}]}

        (found,) = wrong_entry_citations(payload, _texts())

        assert "ev_0012 (floss)" in found.message

    def test_a_quote_in_a_record_description_is_read_too(self) -> None:
        payload = {
            "commands": [
                {
                    "id": "q",
                    "name": "query",
                    "description": f'Runs "{MARKER}" first',
                    "evidence_refs": ["ev_0011"],
                }
            ]
        }

        assert _codes(wrong_entry_citations(payload, _texts())) == [CITATION_WRONG_ENTRY_CODE]

    def test_a_key_finding_is_read_under_its_evidence_ids(self) -> None:
        payload = {
            "executive_summary": "A loader of an example family.",
            "key_findings": [{"text": f"It carries `{MARKER}`.", "evidence_ids": ["ev_0011"]}],
        }

        found = wrong_entry_citations(
            payload, _texts(), prose=("executive_summary", "key_findings")
        )

        assert _codes(found) == [CITATION_WRONG_ENTRY_CODE]

    def test_a_string_with_no_citation_is_not_judged(self) -> None:
        payload = {"items": [{"key": "Marker", "value": MARKER, "evidence_refs": []}]}

        assert wrong_entry_citations(payload, _texts()) == []

    def test_nothing_is_judged_without_the_entries(self) -> None:
        body = f"It carries `{MARKER}` [ev_0011]."

        assert wrong_entry_citations({"body": body}, None, prose=("body",)) == []
        assert wrong_entry_citations({"body": body}, EntryTexts(), prose=("body",)) == []

    def test_the_answer_is_kept_with_a_finding(self) -> None:
        assert CITATION_WRONG_ENTRY_CODE in KEPT_WITH_A_FINDING


class TestTheEntryTexts:
    def test_the_corpus_copy_comes_first(self) -> None:
        class _Corpus:
            def text_for(self, entry_id: str) -> str:
                return "what the model received" if entry_id == "ev_0011" else ""

        texts = EntryTexts.from_ledger(_ledger(), _Corpus())

        assert texts.texts["ev_0011"] == "what the model received"
        assert MARKER in texts.texts["ev_0012"]

    def test_an_entry_with_no_text_is_left_out(self) -> None:
        texts = EntryTexts.from_ledger([_entry("ev_0001", "hashes", "")])

        assert texts.texts == {}

    def test_quoted_values_skip_an_apostrophe_and_a_short_value(self) -> None:
        assert quoted_values("the sample's `%s` and 'ab' and `example.dat`") == ["example.dat"]


class _RawLLM:
    """Structured output unavailable; the raw path answers from a queue."""

    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.sent: list[Any] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, messages: Any) -> Any:
        self.sent.append(list(messages))
        return SimpleNamespace(content=self._answers.pop(0))


def _invoke(*answers: str) -> tuple[Any, _RawLLM, ReportComposer]:
    from langchain_core.messages import HumanMessage

    llm = _RawLLM(*answers)
    comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
    comp._entries = _texts()
    comp._citable = ["ev_0004", "ev_0011", "ev_0012"]
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=False):
        result = asyncio.run(
            comp._invoke([HumanMessage(content="write it")], _ProseOut, section="discovery")
        )
    return result, llm, comp


class TestTheComposerAsks:
    def test_the_model_is_asked_once_and_its_fix_is_taken(self) -> None:
        wrong = json.dumps({"body": f"It carries `{MARKER}` [ev_0011].", "evidence_refs": []})
        right = json.dumps({"body": f"It carries `{MARKER}` [ev_0012].", "evidence_refs": []})

        result, llm, _comp = _invoke(wrong, right)

        assert len(llm.sent) == 2
        assert "ev_0012 (floss)" in str(llm.sent[1][-1].content)
        assert result is not None and "[ev_0012]" in result.body

    def test_a_citation_the_model_keeps_is_printed_as_written_and_recorded(self) -> None:
        wrong = json.dumps({"body": f"It carries `{MARKER}` [ev_0011].", "evidence_refs": []})

        result, _llm, comp = _invoke(wrong, wrong)

        assert result is not None and result.body == f"It carries `{MARKER}` [ev_0011]."
        unresolved = json.dumps(comp.validation_tally.to_dict(), default=str)
        assert CITATION_WRONG_ENTRY_CODE in unresolved


class TestWhatASectionIsShown:
    def test_a_claim_is_shown_with_the_entries_that_hold_what_it_quotes(self) -> None:
        bundle = {
            "claims": [
                {
                    "claim": f"It renames its thread to `{MARKER}`.",
                    "evidence_ref": "text-extracted from static report",
                }
            ]
        }

        text = _bundle_text("packing_obfuscation", bundle, _texts())

        assert f"`{MARKER}` is in ev_0012 (floss)" in text

    def test_a_claim_is_shown_as_written_when_no_entry_holds_its_quote(self) -> None:
        bundle = {"claims": [{"claim": "It uses `nothing-here`.", "evidence_ref": "x"}]}

        text = _bundle_text("packing_obfuscation", bundle, _texts())

        assert "- It uses `nothing-here`. — x\n" in text + "\n"
        assert "the run's evidence" not in text

    def test_every_section_is_shown_the_published_techniques(self) -> None:
        from langchain_core.messages import HumanMessage  # noqa: F401 — the prompt is a message

        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            ttp_mappings=[
                TTPMapping(
                    technique_id="T1204.002",
                    technique_name="Malicious File",
                    tactic="TA0002",
                    tactic_name="Execution",
                )
            ],
        )
        llm = _RawLLM(json.dumps({"text": "An example."}))
        comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
        with patch(
            "maljan.reporting.composer.structured_output_supported_for_llm", return_value=False
        ):
            asyncio.run(comp.compose(report, facts_block="[ev_0001] pe: example"))

        prompt = str(llm.sent[0][-1].content)
        assert "TECHNIQUES THIS REPORT PUBLISHES" in prompt
        assert "- T1204.002 Malicious File" in prompt
