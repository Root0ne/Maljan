"""A technique id is written with the name the ATT&CK catalogue gives it.

Reports printed "T1027 (Indicator Removal from Host)", "T1027 (Impair
Defenses)" and "T1027 (Binary Padding)": an id a reader acts on beside a name
that belongs to another technique, or to none. The report models are asked
once, from the vendored table, with the catalogue's name and the id the written
name belongs to; a name they keep is printed as written with the finding
recorded. And a finding whose technique field said ``NONE`` no longer becomes
an ATT&CK row: the word is an answer — no technique — not an id.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.pipeline.validation import (
    KEPT_WITH_A_FINDING,
    TECHNIQUE_NAME_CODE,
    technique_name_violations,
)
from maljan.reporting.composer import ReportComposer, _ProseOut
from maljan.reporting.ledger_report import _technique_cell


def _messages(text: str) -> list[str]:
    return [v.message for v in technique_name_violations({"body": text})]


class TestTheCheck:
    def test_a_sub_technique_s_name_on_its_parent_is_asked_about(self) -> None:
        (message,) = _messages("It pads the file, T1027 (Binary Padding).")

        assert "'Obfuscated Files or Information'" in message
        assert "T1027.001" in message

    def test_a_name_the_catalogue_gives_no_technique_is_asked_about(self) -> None:
        (message,) = _messages("Defense Evasion T1027 (Indicator Removal from Host).")

        assert "not 'Indicator Removal from Host'" in message

    def test_the_parent_s_name_on_a_sub_technique_is_asked_about(self) -> None:
        (message,) = _messages("Stack strings, T1027.005 (Obfuscated Files or Information).")

        assert "T1027.005 is 'Indicator Removal from Tools'" in message

    def test_the_catalogue_s_name_stands(self) -> None:
        assert (
            _messages("T1027 (Obfuscated Files or Information) and T1204.002 (Malicious File)")
            == []
        )

    def test_a_sub_technique_after_its_parent_s_name_stands(self) -> None:
        text = "T1027.005 (Obfuscated Files or Information: Indicator Removal from Tools)"

        assert _messages(text) == []

    def test_a_bracket_that_is_not_a_name_is_not_read(self) -> None:
        assert _messages("seen by T1059.003 (3 calls) and T1059.003 (e.g. cmd)") == []

    def test_an_id_the_table_does_not_have_is_left_to_the_catalogue_check(self) -> None:
        assert _messages("T9999 (Imaginary Technique)") == []

    def test_one_question_per_id_and_name(self) -> None:
        assert len(_messages("T1027 (Binary Padding). Again, T1027 (binary padding).")) == 1

    def test_a_kept_name_keeps_its_section(self) -> None:
        assert TECHNIQUE_NAME_CODE in KEPT_WITH_A_FINDING


class _RawLLM:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.sent: list[Any] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, messages: Any) -> Any:
        self.sent.append(list(messages))
        return SimpleNamespace(content=self._answers.pop(0))


class TestTheComposerAsks:
    def test_once_and_the_fix_is_taken(self) -> None:
        from langchain_core.messages import HumanMessage

        wrong = json.dumps(
            {"body": "It pads the file (T1027 (Binary Padding)).", "evidence_refs": []}
        )
        right = json.dumps(
            {"body": "It pads the file (T1027.001 (Binary Padding)).", "evidence_refs": []}
        )
        llm = _RawLLM(wrong, right)
        comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
        with patch(
            "maljan.reporting.composer.structured_output_supported_for_llm", return_value=False
        ):
            result = asyncio.run(
                comp._invoke([HumanMessage(content="write it")], _ProseOut, section="payloads")
            )

        assert len(llm.sent) == 2
        assert "T1027.001" in str(llm.sent[1][-1].content)
        assert result is not None and "T1027.001" in result.body


class TestNoTechniqueIsNotARow:
    def test_a_finding_that_says_none_makes_no_row(self) -> None:
        isr = SimpleNamespace(
            domain="static",
            claims=[],
            findings=[
                SimpleNamespace(title="Legitimate tool", confidence=1.0, technique_ids=["NONE"])
            ],
        )

        cells, mappings = build_capability_matrix(stix_output=None, isr_reports={"static": isr})

        assert cells == [] and mappings == []

    def test_a_claim_that_says_not_applicable_makes_no_row(self) -> None:
        claim = SimpleNamespace(
            claim="Signed by its vendor",
            evidence_ref="signing_info [ev_0003]",
            confidence=0.9,
            technique_id="N/A",
            technique_id_valid=True,
        )
        isr = SimpleNamespace(domain="static", claims=[claim], findings=[])

        cells, _mappings = build_capability_matrix(stix_output=None, isr_reports={"static": isr})

        assert cells == []

    def test_the_findings_table_prints_the_word_and_claims_nothing(self) -> None:
        assert _technique_cell(["NONE"], frozenset()) == "NONE"
        assert _technique_cell(["T1027"], frozenset()) == "T1027 (claimed, not published)"
