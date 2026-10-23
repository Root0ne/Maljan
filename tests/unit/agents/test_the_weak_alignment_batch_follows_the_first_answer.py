"""The weak-alignment batch belongs to the answer a turn began with (T-207).

The first answer kept over a retry is checked again; it must read the challenge
it was asked, not "not asked".
"""

from __future__ import annotations

from unittest.mock import patch

from maljan.agents.base_agent import BaseAnalyst
from maljan.core.config import get_settings
from maljan.pipeline.validation import Violation

FIRST = (
    "CLAIM: The sample injects into another process.\n"
    "EVIDENCE: [ev_0001]\n"
    "CONFIDENCE: 0.8\n"
    "TECHNIQUE: T1055\n"
)


class _Llm:
    def __init__(self, answer: str = "I have nothing to add.") -> None:
        self.answer = answer
        self.sent: list[list[object]] = []

    def invoke(self, messages: list[object], *args: object, **kwargs: object) -> object:
        from langchain_core.messages import AIMessage

        self.sent.append(list(messages))
        return AIMessage(content=self.answer)

    async def ainvoke(self, messages: list[object], *args: object, **kwargs: object) -> object:
        return self.invoke(messages)


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: object, **kwargs: object) -> str:  # pragma: no cover - unused
        return ""


def test_the_first_answer_kept_over_a_retry_is_checked_with_its_challenge() -> None:
    analyst = _Analyst(llm=_Llm(), name="reverser")  # type: ignore[arg-type]
    first = analyst._text_to_isr(FIRST, revision_round=1)
    calls: list[tuple[bool, bool]] = []

    def _checks(candidate: object, inputs: object, **kwargs: object) -> list[Violation]:
        calls.append((candidate is first, bool(kwargs["weak_alignment_challenges"])))
        return [Violation(code="weak_alignment", message="Another technique ranks higher.")]

    settings = get_settings()
    with (
        patch.object(settings.validation, "weak_alignment", True),
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch("maljan.agents.base_agent.analyst_answer_checks", _checks),
    ):
        kept = analyst._validate_isr(first, "evidence text")

    assert kept is first
    # Every check of the first answer, the kept one's re-check included, reads
    # the challenge; a retry's answer is never challenged (one batch per turn).
    assert calls and any(not is_first for is_first, _ in calls)
    assert all(challenged == is_first for is_first, challenged in calls)
    assert calls[-1] == (True, True)


CHALLENGE = "Another technique ranks higher than T1055."


def test_the_challenge_reaches_the_model_once_when_the_setting_is_on() -> None:
    llm = _Llm(FIRST)
    analyst = _Analyst(llm=llm, name="reverser")  # type: ignore[arg-type]
    first = analyst._text_to_isr(FIRST, revision_round=1)

    def _checks(candidate: object, inputs: object, **kwargs: object) -> list[Violation]:
        if kwargs["weak_alignment_challenges"]:
            return [Violation(code="weak_alignment", message=CHALLENGE)]
        return []

    settings = get_settings()
    with (
        patch.object(settings.validation, "weak_alignment", True),
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch("maljan.agents.base_agent.analyst_answer_checks", _checks),
    ):
        analyst._validate_isr(first, "evidence text")

    assert len(llm.sent) == 1
    assert CHALLENGE in str(llm.sent[0][-1].content)  # type: ignore[attr-defined]
