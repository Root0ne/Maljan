"""An analyst reads an Anthropic answer that opens with a thinking block by its text blocks.

``ChatAnthropic`` keeps an answer as the list of blocks the API returned when
it is more than one text block, and a model that thinks answers with a
``thinking`` block before its ``text``. Read with ``str()``, that list is its
own repr, signature and all: the validation retry parsed the repr, and a cap
cut while the model was still thinking read as a cut answer with text. Both
now read the text blocks (``llm.answer_text``); a string answer is read as it
always was.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BaseAnalyst, answer_cut_at_cap
from maljan.pipeline.validation import UNGROUNDED_TECHNIQUE_CODE
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

_THINKING = {"type": "thinking", "thinking": "", "signature": "c2lnbmF0dXJl"}


def _thinking_first(text: str) -> list[dict[str, Any]]:
    return [dict(_THINKING), {"type": "text", "text": text}]


def _cut(content: Any) -> AIMessage:
    return AIMessage(
        content=content,
        response_metadata={"stop_reason": "max_tokens", "finish_reason": "length"},
        usage_metadata={"input_tokens": 3, "output_tokens": 64, "total_tokens": 67},
    )


class TestTheCutReadsTheText:
    def test_a_cut_while_still_thinking_is_a_cut_with_no_text(self) -> None:
        assert answer_cut_at_cap(_cut([dict(_THINKING)]), 64) == (64, "")

    def test_its_question_says_the_answer_was_cut_while_reasoning(self) -> None:
        from maljan.pipeline.validation import analyst_cut_violation

        message = analyst_cut_violation(64, "").message
        assert "while you were still reasoning" in message
        assert "last claim was cut off" not in message

    def test_an_answer_that_ended_on_its_own_is_no_cut(self) -> None:
        ended = AIMessage(
            content=[dict(_THINKING)],
            response_metadata={"stop_reason": "end_turn", "finish_reason": "stop"},
            usage_metadata={"input_tokens": 3, "output_tokens": 5, "total_tokens": 8},
        )
        assert answer_cut_at_cap(ended, 64) is None

    def test_a_cut_after_some_text_is_that_text_alone(self) -> None:
        assert answer_cut_at_cap(_cut(_thinking_first("CLAIM: it rea")), 64) == (
            64,
            "CLAIM: it rea",
        )

    def test_a_string_answer_is_read_as_it_always_was(self) -> None:
        assert answer_cut_at_cap(_cut("CLAIM: it rea"), 64) == (64, "CLAIM: it rea")


class _Analyst(BaseAnalyst):
    def analyze(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        raise NotImplementedError

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        raise NotImplementedError


def _isr(evidence: str) -> AgentISR:
    claim = ClaimEvidence(
        claim="it injects code", evidence_ref=evidence, confidence=0.4, technique_id="T1055"
    )
    return AgentISR(agent_id="static", domain="static", claims=[claim])


def _agent(reply: Any) -> tuple[Any, list[str]]:
    read: list[str] = []
    agent = _Analyst.__new__(_Analyst)
    agent.name = "static"
    agent.logger = MagicMock()
    agent.validation_findings = []
    agent.validation_retries = 0
    agent.validation_fed_back = {}
    agent._findings_buffer = []
    agent._artifacts_buffer = []
    agent._evidence_entries = [LedgerEntry(id="ev_0002", agent="static", tool="pe_info")]
    agent._system_prompt = lambda _evidence, tools=None: "you are an analyst"  # type: ignore[method-assign]
    agent._truncate_input = lambda text, *a, **k: text  # type: ignore[method-assign]
    agent._capture_findings = lambda text: text  # type: ignore[method-assign]
    agent._invoke_llm_with_timeout = lambda turns, timeout, **_: reply  # type: ignore[method-assign]

    def _parse(text: str, revision_round: int = 0) -> AgentISR:
        read.append(text)
        evidence = text.split("EVIDENCE:", 1)[1].split("\n", 1)[0].strip()
        return _isr(evidence)

    agent._text_to_isr = _parse  # type: ignore[method-assign]
    return agent, read


def _validate(agent: Any) -> AgentISR:
    with patch("maljan.agents.base_agent.get_settings") as settings:
        settings.return_value.react_agent_timeout = 60
        settings.return_value.react_agent_timeout_overrides = {}
        return agent._validate_isr(_isr("speculative"), "the evidence the analyst read")


_ANSWER = "CLAIM: it injects code\nEVIDENCE: ev_0002\nCONFIDENCE: 0.4\nTECHNIQUE: T1055\n"


class TestTheValidationRetryReadsTheText:
    def test_a_thinking_first_answer_is_parsed_from_its_text_block(self) -> None:
        agent, read = _agent(AIMessage(content=_thinking_first(_ANSWER)))

        revised = _validate(agent)

        assert read == [_ANSWER]
        assert agent.validation_fed_back.get(UNGROUNDED_TECHNIQUE_CODE) == 1
        assert revised.claims[0].evidence_ref == "ev_0002"
        assert agent.validation_findings == []

    def test_a_string_answer_is_parsed_as_it_always_was(self) -> None:
        agent, read = _agent(AIMessage(content=_ANSWER))

        _validate(agent)

        assert read == [_ANSWER]
