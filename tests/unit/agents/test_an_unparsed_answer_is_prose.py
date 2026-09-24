"""An answer that does not parse into claims is the analyst's prose, and nothing more.

The large model's ELF run answered with Markdown headings, a findings block and
paragraphs, and no CLAIM block. The text fallback cut that answer into ten
"claims" — "**Binary Identification**:", "- It is linked against libc.so.6" —
each at a flat 0.50 nobody stated, with no evidence id, and the run summary
did not call it a degradation. Now the answer is asked once for the claim
format in the analyst's own validation turn; if it still does not parse, the
analyst has no claims, its prose is its report, and the run says so.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import (
    NO_STRUCTURED_REPORT_STATUS,
    UNPARSED_ANSWER_REASON,
    BaseAnalyst,
    parse_structured_claims,
    parse_structured_claims_counted,
)
from maljan.agents.static_analyst import StaticAnalyst, _parse_claim_blocks
from maljan.pipeline.validation import (
    CLAIM_WITHOUT_CONFIDENCE_CODE,
    UNPARSED_ANSWER_CODE,
    parse_violations,
)
from maljan.schemas.isr_models import AgentISR

# The shape of the large model's ELF answer: headings, bullets, paragraphs.
ELF_ANSWER = (
    "## Static Analysis Report\n\n"
    "**Binary Identification**:\n"
    "   - The binary is a 64-bit ELF executable, 9,800 bytes in size.\n"
    "   - It is linked against `libc.so.6` and uses the dynamic linker "
    "`/lib64/ld-linux-x86-64.so.2`.\n\n"
    "**Behaviour**:\n"
    "The sample downloads a payload into memory with memfd_create and runs it with "
    "fexecve, masquerading as a kernel worker thread.\n"
)

GOOD_ANSWER = (
    "CLAIM: The sample runs a downloaded payload from memory with fexecve.\n"
    "EVIDENCE: memfd_create and fexecve imports [ev_0004]\n"
    "CONFIDENCE: 0.8\n"
    "TECHNIQUE: T1620\n"
    "---\n"
)


def _analyst() -> StaticAnalyst:
    analyst = StaticAnalyst.__new__(StaticAnalyst)
    analyst.name = "static"
    analyst.logger = logging.getLogger("test")
    return analyst


class TestNoClaimIsCutOutOfProse:
    def test_the_elf_answer_yields_no_claim_and_keeps_its_prose(self) -> None:
        isr = _analyst()._text_to_isr(ELF_ANSWER, revision_round=0)

        assert isr.claims == []
        assert isr.unparsed_answer == ELF_ANSWER.strip()
        assert isr.status == NO_STRUCTURED_REPORT_STATUS
        assert isr.status_reason == UNPARSED_ANSWER_REASON

    def test_no_heading_and_no_flat_confidence_reaches_a_claim(self) -> None:
        isr = _analyst()._text_to_isr(ELF_ANSWER, revision_round=0)

        assert not any(claim.confidence == 0.5 for claim in isr.claims)
        assert isr.mean_confidence == 0.0

    def test_a_parsed_answer_carries_no_prose_and_no_status(self) -> None:
        isr = _analyst()._text_to_isr(GOOD_ANSWER, revision_round=0)

        assert [claim.confidence for claim in isr.claims] == [0.8]
        assert isr.unparsed_answer == ""
        assert isr.status is None


class TestABlockWithNoConfidenceIsNotAClaim:
    def test_the_lenient_parser_counts_it_instead_of_writing_one(self) -> None:
        text = (
            "CLAIM: The sample reads the registry run key.\n"
            "EVIDENCE: RegOpenKeyExW [ev_0002]\n"
            "TECHNIQUE: T1547.001\n"
            "---\n" + GOOD_ANSWER
        )

        claims, without = parse_structured_claims_counted(text)

        assert [claim.confidence for claim in claims] == [0.8]
        assert without == 1
        assert parse_structured_claims(text) == claims

    def test_a_confidence_that_is_not_a_number_states_none(self) -> None:
        text = GOOD_ANSWER.replace("CONFIDENCE: 0.8", "CONFIDENCE: 0.8.1")

        assert parse_structured_claims_counted(text) == ([], 1)
        assert _parse_claim_blocks(text) == []

    def test_every_block_without_one_leaves_the_answer_prose(self) -> None:
        text = "CLAIM: The sample is packed.\nEVIDENCE: high entropy [ev_0003]\n---\n"

        isr = _analyst()._text_to_isr(text, revision_round=0)

        assert isr.claims == []
        assert isr.unparsed_answer == text.strip()
        assert isr.blocks_without_confidence == 1


class TestTheQuestionsAsked:
    def test_an_unparsed_answer_and_a_block_without_confidence_are_each_asked(self) -> None:
        prose = _analyst()._text_to_isr(ELF_ANSWER, revision_round=0)
        partly = _analyst()._text_to_isr(
            GOOD_ANSWER + "CLAIM: unrated\nEVIDENCE: x [ev_0001]\n---\n", revision_round=0
        )

        assert [v.code for v in parse_violations(prose)] == [UNPARSED_ANSWER_CODE]
        assert [v.code for v in parse_violations(partly)] == [CLAIM_WITHOUT_CONFIDENCE_CODE]
        assert "1 CLAIM block(s)" in parse_violations(partly)[0].message

    def test_an_isr_built_without_a_parse_is_asked_nothing(self) -> None:
        assert parse_violations(AgentISR(agent_id="static", domain="static")) == []


class _Answers:
    """A model that answers each call from a queue and records what it was sent."""

    def __init__(self, answers: list[str]) -> None:
        self.answers = list(answers)
        self.sent: list[list[Any]] = []

    def invoke(self, messages: list[Any], *args: Any, **kwargs: Any) -> AIMessage:
        self.sent.append(list(messages))
        return AIMessage(content=self.answers.pop(0))

    async def ainvoke(self, messages: list[Any], *args: Any, **kwargs: Any) -> AIMessage:
        return self.invoke(messages)


class _Validated(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def _validated(answers: list[str]) -> tuple[_Validated, _Answers]:
    llm = _Answers(answers)
    analyst = _Validated(llm=llm, name="static")  # type: ignore[arg-type]
    return analyst, llm


class TestTheValidationTurn:
    def test_an_unparsed_answer_asked_once_and_answered_is_the_analyst_s_claims(self) -> None:
        analyst, llm = _validated([GOOD_ANSWER])
        first = analyst._text_to_isr(ELF_ANSWER, revision_round=0)

        with patch("maljan.agents.base_agent.validity_check_available", return_value=True):
            isr = analyst._validate_isr(first, "evidence text")

        assert [claim.confidence for claim in isr.claims] == [0.8]
        assert analyst.validation_fed_back.get(UNPARSED_ANSWER_CODE) == 1
        # The question was asked over the prose the analyst wrote.
        assert any(ELF_ANSWER.strip() in str(m.content) for m in llm.sent[0])

    def test_an_answer_still_prose_keeps_the_loop_s_prose_and_is_recorded(self) -> None:
        analyst, _llm = _validated(["Still just a paragraph about the sample."])
        first = analyst._text_to_isr(ELF_ANSWER, revision_round=0)

        with patch("maljan.agents.base_agent.validity_check_available", return_value=True):
            isr = analyst._validate_isr(first, "evidence text")

        assert isr.claims == []
        assert isr.unparsed_answer == ELF_ANSWER.strip()
        assert isr.status_reason == UNPARSED_ANSWER_REASON
        assert UNPARSED_ANSWER_CODE in {v.code for v in analyst.validation_findings}

    def test_an_answer_the_nudge_already_asked_about_is_recorded_not_asked(self) -> None:
        analyst, llm = _validated([])
        analyst._answer_unstructured = True
        first = analyst._text_to_isr(ELF_ANSWER, revision_round=0)

        with patch("maljan.agents.base_agent.validity_check_available", return_value=True):
            isr = analyst._validate_isr(first, "evidence text")

        assert llm.sent == []
        assert isr.claims == []
        assert isr.unparsed_answer == ELF_ANSWER.strip()
        assert [v.code for v in analyst.validation_findings] == [UNPARSED_ANSWER_CODE]


def test_the_run_names_the_analysts_whose_answer_stayed_prose() -> None:
    from maljan.agents.base_agent import unparsed_answers_reason

    reason = unparsed_answers_reason(["static", "reverser"])

    assert reason.endswith(": static, reverser")
    assert "prose" in reason
