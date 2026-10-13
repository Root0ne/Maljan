"""A retry answer with no text is not sent back when the analyst is asked for its whole answer.

The question for the whole answer, asked after a retry that could not be
merged, followed the retry's own answer with an assistant turn. An answer of
whitespace alone went back as that turn, which the Anthropic API refuses, and
which the request hook then had to leave out, putting two user turns side by
side. The question is now asked at the end of the turn before it, as the
validation retry asks one (``validation._with_feedback``).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage, HumanMessage

from maljan.agents.base_agent import BaseAnalyst
from maljan.llm.answer_text import answer_text
from maljan.pipeline.validation import whole_answer_after_retry_question


def _block(n: int, technique: str = "NONE") -> str:
    return (
        f"CLAIM: The file carries configuration string number {n}.\n"
        "EVIDENCE: [ev_0001] strings\n"
        "CONFIDENCE: 0.8\n"
        f"TECHNIQUE: {technique}\n"
        "---\n"
    )


FIRST = _block(1, "T1055 or T1106") + "".join(_block(n) for n in range(2, 5))


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[str]) -> None:
        super().__init__(llm=MagicMock(), name="static")
        self.pack_ledger_ids = ["ev_0001"]
        self._replies = list(replies)
        self.sent: list[list[Any]] = []

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.sent.append(list(messages))
        text = self._replies.pop(0) if self._replies else FIRST
        self._record_usage(AIMessage(content=text))
        return text


def _check(analyst: _Analyst) -> None:
    isr = analyst._text_to_isr(FIRST, 0)
    with (
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
    ):
        analyst._validate_isr(isr, "evidence")


def test_the_whole_answer_question_follows_no_empty_assistant_turn() -> None:
    analyst = _Analyst(["  \n\n  ", FIRST])

    _check(analyst)

    asked = [
        turns
        for turns in analyst.sent
        if any(
            whole_answer_after_retry_question("x")[:40] in str(getattr(t, "content", ""))
            for t in turns
        )
    ]
    assert asked, "the whole-answer question was asked"
    for turns in asked:
        for turn in turns:
            if isinstance(turn, AIMessage):
                assert answer_text(turn.content).strip(), turns
        assert isinstance(turns[-1], HumanMessage)
