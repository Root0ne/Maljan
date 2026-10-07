"""The judge's technique question shows each asked technique's card, as reference.

A card says what the evidence for a technique has to show and the sibling
techniques it is confused with. It is shown under a technique the judge is
already asked about; it adds no question, decides nothing and is not printed
in the report. The judge reads it and its answer stands.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

from maljan.agents.judge_agent import (
    TECHNIQUE_CARDS_INTRO,
    TECHNIQUE_QUESTION_SYSTEM,
    JudgeAgent,
    technique_question_text,
)
from maljan.extractors.capability_matrix import TechniqueQuestion, judge_questions
from maljan.memory.technique_cards import technique_card_lines
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.stix_models import Bundle
from maljan.tools import knowledge

CARRIED = "T1112"  # Modify Registry: carried by the bundle, no card
CLAIMED = "T1003"  # OS Credential Dumping: claimed, not carried, has a card
UNDESCRIBED = "T1564"  # Hide Artifacts: carried, its claim shares no term with it


def _bundle() -> Bundle:
    return Bundle.model_validate(
        {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": f"attack-pattern--0f1e2d3c-4b5a-4968-8776-65544333221{n}",
                    "name": name,
                    "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
                }
                for n, (tid, name) in enumerate(
                    [(CARRIED, "Modify Registry"), (UNDESCRIBED, "Hide Artifacts")]
                )
            ]
        }
    )


def _claim(text: str, tid: str) -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref="[ev_0001]", confidence=0.9, technique_id=tid)


def _isrs() -> dict[str, AgentISR]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                _claim("The sample writes a registry value", CARRIED),
                _claim("The sample opens a handle on lsass.exe and reads its memory", CLAIMED),
                _claim("The sample opens a window", UNDESCRIBED),
            ],
        )
    }


class _Llm:
    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> Any:
        self.calls.append(list(messages))
        return MagicMock(content=self.answer)


class TestTheQuestionShowsTheCard:
    def test_each_asked_technique_with_a_card_shows_its_lines_under_its_claims(self) -> None:
        text = technique_question_text(
            [
                TechniqueQuestion(CLAIMED, "claimed", [("static", "reads lsass", ["ev_0001"])]),
                TechniqueQuestion(CARRIED, "finding", [("static", "writes a value", [])]),
            ]
        )

        lines = technique_card_lines(CLAIMED)
        assert lines
        block = "\n".join(f"   {line}" for line in lines)
        assert block in text
        # Under its own technique, after its claims, before the next one.
        assert text.index("reads lsass") < text.index(block) < text.index(f"2. {CARRIED}")

    def test_a_question_with_no_card_is_the_question_as_before(self) -> None:
        question = [TechniqueQuestion(CARRIED, "finding", [("static", "writes a value", [])])]

        text = technique_question_text(question)

        assert text == technique_question_text(question, cards=False)
        assert "card" not in text
        assert "card" not in TECHNIQUE_QUESTION_SYSTEM

    def test_what_a_card_is_is_said_once_above_the_techniques(self) -> None:
        text = technique_question_text(
            [
                TechniqueQuestion(CLAIMED, "claimed", [("static", "reads lsass", [])]),
                TechniqueQuestion(UNDESCRIBED, "undescribed", [("static", "opens", [])]),
            ]
        )

        assert text.splitlines()[1] == TECHNIQUE_CARDS_INTRO
        assert text.count(TECHNIQUE_CARDS_INTRO) == 1


class TestNothingNewIsAsked:
    def test_the_techniques_asked_are_the_checks_own(self) -> None:
        questions, _ = judge_questions(_bundle().model_dump(), _isrs(), attck=knowledge)

        assert {(q.technique_id, q.kind) for q in questions} == {
            (CLAIMED, "claimed"),
            (UNDESCRIBED, "undescribed"),
        }

    def test_the_judge_is_asked_once_with_the_cards_and_its_answer_stands(self) -> None:
        llm = _Llm(f'[{{"id": "{CLAIMED}", "decision": "drop", "reason": "not shown"}}]')
        judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]

        review = asyncio.run(
            judge.decide_techniques(
                _bundle(),
                _isrs(),
                reports={"static": "r"},
                evidence_texts={"ev_0001": "entry text"},
            )
        )

        assert len(llm.calls) == 1
        sent = "\n".join(str(getattr(m, "content", m)) for m in llm.calls[0])
        for tid in (CLAIMED, UNDESCRIBED):
            for line in technique_card_lines(tid):
                assert line in sent
        assert review is not None
        decision = review.decision_for(CLAIMED)
        assert decision is not None and decision.decision == "drop"


class TestTheCardsNeverShortenTheEvidence:
    def _sent(self, room: int | None, entry: str) -> tuple[str, Any]:
        llm = _Llm(f'[{{"id": "{CLAIMED}", "decision": "keep", "reason": "shown"}}]')
        judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
        judge._question_room = lambda fixed, cap: room  # type: ignore[method-assign]
        review = asyncio.run(
            judge.decide_techniques(
                _bundle(), _isrs(), reports={"static": "r"}, evidence_texts={"ev_0001": entry}
            )
        )
        return "\n".join(str(getattr(m, "content", m)) for m in llm.calls[0]), review

    def test_with_room_left_after_the_evidence_the_cards_are_shown(self) -> None:
        sent, review = self._sent(100_000, "entry text")

        assert technique_card_lines(CLAIMED)[0] in sent
        assert review.shortened is None

    def test_without_room_left_the_cards_are_left_out_and_the_evidence_is_cut_no_more(
        self,
    ) -> None:
        entry = "x" * 400
        # Room for the reports and the whole entry, and less than the cards need.
        lines = technique_card_lines(CLAIMED) + technique_card_lines(UNDESCRIBED)
        room = 2 * len(entry) + 100
        assert room - len(entry) < sum(len(line) for line in lines)

        sent, review = self._sent(room, entry)

        assert "card:" not in sent
        assert entry in sent
        assert review.shortened is None

    def test_with_no_window_to_measure_the_cards_are_shown(self) -> None:
        sent, _review = self._sent(None, "entry text")

        assert technique_card_lines(CLAIMED)[0] in sent
