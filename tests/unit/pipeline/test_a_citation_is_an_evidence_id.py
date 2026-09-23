"""A bracketed citation in the report's prose is an evidence id, or it is asked about.

The composer cited "[BINARY FACTS]" and "[DETERMINISTIC FACTS]" — the headings
of its own prompt's blocks — and the report printed them as citations beside
real ones. Nothing checked a citation. Now a bracketed item that is not an
evidence id this section was shown is a validation question whose sentence
names the ids it may cite; the model answers it, and what it leaves is kept
exactly as it wrote it and recorded unresolved. Nothing rewrites a citation.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import patch

from maljan.pipeline.validation import (
    CITATION_NOT_EVIDENCE_CODE,
    FEEDBACK_PREAMBLE,
    citable_ids_in,
    citation_violations,
)
from maljan.reporting.composer import ReportComposer
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.narrative_agent import NarrativeAgent

CITABLE = ["ev_0001", "ev_0004", "ev_0011"]


class TestWhatIsACitation:
    def test_a_prompt_heading_in_brackets_is_asked_about(self) -> None:
        (found,) = citation_violations(
            {"text": "It lacks a signature [ev_0004, BINARY FACTS]."}, CITABLE
        )
        assert found.code == CITATION_NOT_EVIDENCE_CODE
        assert "BINARY FACTS" in found.message
        assert "ev_0001, ev_0004, ev_0011" in found.message
        assert "?" not in found.message

    def test_each_item_that_is_not_an_id_is_one_question(self) -> None:
        found = citation_violations(
            {"text": "Malware (0.92) [DETERMINISTIC FACTS]. Signed [BINARY FACTS]."}, CITABLE
        )
        assert len(found) == 2
        assert {"DETERMINISTIC FACTS" in v.message for v in found} == {True, False}

    def test_the_same_item_twice_is_asked_once(self) -> None:
        found = citation_violations({"a": "x [BINARY FACTS]", "b": ["y [BINARY FACTS]"]}, CITABLE)
        assert len(found) == 1

    def test_an_evidence_id_this_section_was_shown_is_a_citation(self) -> None:
        assert (
            citation_violations({"text": "Packed [ev_0001] and [EV_0004; ev_0011]."}, CITABLE) == []
        )

    def test_an_evidence_id_it_was_not_shown_is_asked_about(self) -> None:
        (found,) = citation_violations({"text": "Seen in [ev_0099]."}, CITABLE)
        assert "ev_0099" in found.message
        assert "not an entry" in found.message

    def test_technique_and_behaviour_ids_are_identifiers_not_citations(self) -> None:
        text = "Obfuscation [T1027], stack strings [T1027.005], RC4 [C0027.009], [B0001.019]."
        assert citation_violations({"text": text}, CITABLE) == []

    def test_a_link_and_an_index_are_not_citations(self) -> None:
        text = "See [VirusTotal](https://www.virustotal.com/) and key[i % 5] in the loop."
        assert citation_violations({"text": text}, CITABLE) == []

    def test_with_nothing_citable_the_sentence_says_to_drop_the_brackets(self) -> None:
        (found,) = citation_violations({"text": "Signed [BINARY FACTS]."}, [])
        assert "no evidence ids" in found.message
        assert "without a bracketed citation" in found.message

    def test_the_ids_a_prompt_offers_are_read_from_it_in_order(self) -> None:
        prompt = "[ev_0004] pe: dll\n[ev_0001] identity\nclaim — ev_0004 and ev_0011"
        assert citable_ids_in(prompt) == ["ev_0004", "ev_0001", "ev_0011"]


def _report() -> MalwareReport:
    return MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)))


class _Answers:
    """A model that answers each turn from a list and keeps what it was sent."""

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.sent: list[list[Any]] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, turns: Any) -> Any:
        self.sent.append(list(turns))
        text = self.answers.pop(0) if self.answers else self.answers_last

        class _Message:
            content = text

        return _Message()

    answers_last = "{}"


def _intro(text: str) -> str:
    return json.dumps({"text": text})


class TestTheComposer:
    def _compose(self, llm: _Answers) -> tuple[MalwareReport, ReportComposer]:
        report = _report()
        composer = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
        facts = "Facts established before analysis\n[ev_0001] identity: pe\n[ev_0004] pe: dll"
        with patch(
            "maljan.reporting.composer.structured_output_supported_for_llm", return_value=False
        ):
            asyncio.run(composer.compose(report, facts_block=facts))
        return report, composer

    def test_a_heading_cited_is_asked_about_and_the_answer_s_fix_is_kept(self) -> None:
        llm = _Answers(
            _intro("A Windows DLL that lacks a signature [ev_0004, BINARY FACTS]."),
            _intro("A Windows DLL that lacks a signature [ev_0004]."),
        )
        report, composer = self._compose(llm)

        retry = str(llm.sent[1][-1].content)
        assert FEEDBACK_PREAMBLE in retry
        assert "BINARY FACTS" in retry and "ev_0001, ev_0004" in retry
        assert report.intro_background == "A Windows DLL that lacks a signature [ev_0004]."
        assert composer.validation_tally.by_code.get(CITATION_NOT_EVIDENCE_CODE) == 1
        assert composer.validation_tally.unresolved == []

    def test_a_citation_still_wrong_is_printed_as_written_and_recorded(self) -> None:
        text = "A Windows DLL, malicious (0.92) [DETERMINISTIC FACTS]."
        llm = _Answers(_intro(text), _intro(text))
        report, composer = self._compose(llm)

        assert report.intro_background == text
        (row,) = [
            r
            for r in composer.validation_tally.unresolved
            if r["code"] == CITATION_NOT_EVIDENCE_CODE
        ]
        assert row["agent"] == "composer:introduction"
        # Kept, so not a section the report lost.
        assert not [d for d in composer.degradations if "'introduction'" in d]


class TestTheNarrative:
    def test_the_narrative_is_asked_about_a_citation_that_is_not_an_id(self) -> None:
        summary = "A loader, malicious by 52 of 75 engines [ev_0011], signed [BINARY FACTS]. " * 3
        answer = {
            "executive_summary": summary,
            "capabilities_narrative": ["one capability", "two capability", "three capability"],
            "defensive_recommendations": [
                {
                    "category": "edr_hunting",
                    "action": "Hunt for the loader's scheduled task.",
                    "rationale": "Persistence artefact.",
                    "priority": "P1",
                }
            ]
            * 3,
        }
        llm = _Answers(json.dumps(answer), json.dumps(answer))
        agent = NarrativeAgent(llm=llm)  # type: ignore[arg-type]
        facts = "Facts established before analysis\n[ev_0011] reputation: VirusTotal 52/75"
        with patch(
            "maljan.reporting.narrative_agent.structured_output_supported_for_llm",
            return_value=False,
        ):
            out = asyncio.run(agent.generate(_report(), facts_block=facts))

        assert out is not None
        assert out.executive_summary == summary
        assert agent.validation_tally.by_code.get(CITATION_NOT_EVIDENCE_CODE) == 2
        assert [r["code"] for r in agent.validation_tally.unresolved] == [
            CITATION_NOT_EVIDENCE_CODE
        ]
