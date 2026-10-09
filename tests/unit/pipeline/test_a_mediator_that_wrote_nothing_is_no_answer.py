"""A mediator that wrote no answer is recorded as no answer, never as disagreement.

An empty answer, or one the output cap cut before any text (a thinking model
that spent its whole cap thinking), used to reach the text fallback, which
read "no agreement score" as agreement 0.0: no consensus, so the router opened
a revision round of every analyst's tool loop, all to mediate again. On the
Haiku 5.5 baseline that was three empty mediations and two needless revision
rounds.

Now the round records the fact — the mediator wrote no answer, and why (empty,
or cut at N tokens) — consensus is neither reached nor refused, the router
sends the analysts' answers in force on to the judge, and the run summary and
report say the mediator wrote no answer.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.agents.judge_agent import JudgeAgent
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.core.config import Settings
from maljan.pipeline.mediation_models import (
    MEDIATOR_NO_ANSWER,
    MediatorVerdict,
    mediator_no_answer_note,
)
from maljan.pipeline.nodes import make_negotiation_node
from maljan.pipeline.routing import NOT_MEDIATED, ConsensusRouter, debate_route
from maljan.pipeline.state import AgentArgument
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

_THINKING = {"type": "thinking", "thinking": "", "signature": "c2lnbmF0dXJl"}


def _isr(name: str, claims: int) -> AgentISR:
    return AgentISR(
        agent_id=name,
        domain=name,
        claims=[
            ClaimEvidence(
                claim=f"claim {i}", evidence_ref=f"[ev_000{i + 1}] imports", confidence=0.7
            )
            for i in range(claims)
        ],
    )


CLAIMING_STATE: dict[str, Any] = {
    "iteration_count": 0,
    "reports": {"static": "found things", "dynamic": "saw things"},
    "isr_reports": {"static": _isr("static", 2), "dynamic": _isr("dynamic", 1)},
}


def _empty() -> AIMessage:
    return AIMessage(content="")


def _cut(tokens: int) -> AIMessage:
    """A thinking model's answer that spent its whole output cap thinking."""
    return AIMessage(
        content=[_THINKING],
        response_metadata={"stop_reason": "max_tokens"},
        usage_metadata={"input_tokens": 10, "output_tokens": tokens, "total_tokens": tokens + 10},
    )


class _Says:
    """A mediator model that answers in turn from ``replies``, the last one from then on."""

    def __init__(self, *replies: AIMessage) -> None:
        self.replies = list(replies)
        self.calls = 0

    async def ainvoke(self, _messages: Any, **_kw: Any) -> AIMessage:
        self.calls += 1
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


def _mediate(*replies: AIMessage) -> tuple[tuple[AgentArgument, bool | None], _Says, AsyncMock]:
    model = _Says(*replies)
    judge = JudgeAgent(llm=model)  # type: ignore[arg-type]
    extract = AsyncMock(
        return_value=MediatorVerdict(contradictions=[], resolution_summary="x", confidence=0.9)
    )
    with patch.object(judge, "_extract_mediator_verdict", extract):
        result = asyncio.run(
            judge.mediate(CLAIMING_STATE["reports"], [], isr_reports=CLAIMING_STATE["isr_reports"])
        )
    return result, model, extract


class TestTheMediatorRecordsNoAnswer:
    def test_an_empty_answer_is_no_answer(self) -> None:
        (argument, consensus), model, extract = _mediate(_empty())

        assert consensus is None
        assert argument.status == MEDIATOR_NO_ANSWER
        assert argument.confidence_score is None
        assert argument.contradictions == []
        assert argument.finding == ""
        assert argument.note == mediator_no_answer_note(
            "the answer was empty, also when asked once more"
        )
        # Asked once more, then nothing is asked to extract a verdict from nothing.
        extract.assert_not_called()
        assert model.calls == 2

    def test_an_answer_cut_before_any_text_says_where_it_was_cut(self) -> None:
        (argument, consensus), _model, extract = _mediate(_cut(4096))

        assert consensus is None
        assert argument.status == MEDIATOR_NO_ANSWER
        assert argument.note == mediator_no_answer_note(
            "the answer was cut at 4096 tokens with no text, also when asked once more"
        )
        extract.assert_not_called()

    def test_an_empty_answer_then_an_answer_is_mediated(self) -> None:
        (argument, consensus), model, extract = _mediate(
            _empty(), AIMessage(content="CONTRADICTIONS: NONE\nagreement_confidence: 0.9")
        )

        assert model.calls == 2
        assert argument.status == "complete"
        assert consensus is True
        extract.assert_called_once()

    def test_a_tool_loop_that_wrote_nothing_is_no_answer(self) -> None:
        judge = JudgeAgent(llm=MagicMock())
        with (
            patch.object(judge, "_has_explicit_dissent", return_value=True),
            patch.object(judge, "_initialize_mcp_client", AsyncMock()),
            patch.object(judge, "execute_tool_loop", AsyncMock(return_value="")),
        ):
            argument, consensus = asyncio.run(
                judge.mediate(
                    CLAIMING_STATE["reports"], [], isr_reports=CLAIMING_STATE["isr_reports"]
                )
            )

        assert consensus is None
        assert argument.status == MEDIATOR_NO_ANSWER
        # The loop has its own nudge and salvage; it is not run a second time.
        assert argument.note == mediator_no_answer_note("the answer was empty")

    def test_an_answer_with_text_is_mediated_as_before(self) -> None:
        (argument, consensus), _model, extract = _mediate(
            AIMessage(content=[_THINKING, {"type": "text", "text": "x"}])
        )

        assert argument.status == "complete"
        assert consensus is not None
        extract.assert_called_once()


def _container(mediated: tuple[AgentArgument, bool | None]) -> Any:
    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = ["static", "dynamic"]
    container.analyst_keys.return_value = ["static", "dynamic"]
    judge = MagicMock()
    judge.mediate = AsyncMock(return_value=mediated)
    container.get_judge_agent.return_value = judge
    return container


def _no_answer() -> AgentArgument:
    return AgentArgument(
        agent_name="Mediator",
        finding="",
        confidence_score=None,
        status=MEDIATOR_NO_ANSWER,
        note=mediator_no_answer_note("the answer was empty"),
    )


class TestTheRoundIsNotMediated:
    def _round(self) -> dict[str, Any]:
        container = _container((_no_answer(), None))
        with patch("maljan.pipeline.nodes.detect_sycophancy", return_value=False):
            return asyncio.run(make_negotiation_node(container)(CLAIMING_STATE))

    def test_the_node_records_no_agreement_and_keeps_consensus_applicable(self) -> None:
        result = self._round()

        assert result["is_consensus"] is None
        assert result["consensus_applicable"] is True
        assert result["confidence_history"] == []
        assert result["discussion_history"][0].status == MEDIATOR_NO_ANSWER

    def test_no_revision_round_is_scheduled_and_the_judge_runs(self) -> None:
        state = {**CLAIMING_STATE, **self._round()}

        assert ConsensusRouter(Settings()).should_continue(state) == "judge"
        assert debate_route(state, max_rounds=5) == ("judge", NOT_MEDIATED)

    def test_a_later_round_with_no_answer_also_ends_the_debate(self) -> None:
        state = {
            **CLAIMING_STATE,
            "iteration_count": 2,
            "is_consensus": None,
            "consensus_applicable": True,
            "confidence_history": [0.4],
            "discussion_history": [
                AgentArgument(agent_name="Mediator", finding="disputed", confidence_score=0.4),
                _no_answer(),
            ],
        }

        assert debate_route(state, max_rounds=5) == ("judge", NOT_MEDIATED)

    def test_the_run_summary_and_the_report_say_the_mediator_wrote_no_answer(self) -> None:
        from maljan.reporting.models import MalwareReport
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_negotiation({**CLAIMING_STATE, **self._round()}, max_iterations=3)
            .build()
        )
        negotiation = summary.to_dict()["negotiation"]
        note = mediator_no_answer_note("the answer was empty")

        assert negotiation["termination_reason"] == NOT_MEDIATED
        assert negotiation["mediation_notes"] == [note]
        assert note in summary.to_markdown()
        report = MalwareReport.model_validate(
            {"identity": {"hashes": {"sha256": "0" * 64}}, "run_summary": summary.to_dict()}
        )
        assert note in MarkdownRenderer().render(report)

    def test_the_note_is_published_to_the_room(self) -> None:
        events: list[tuple[str, dict]] = []
        container = _container((_no_answer(), None))
        container.event_sink = lambda kind, data: events.append((kind, data))
        with patch("maljan.pipeline.nodes.detect_sycophancy", return_value=False):
            asyncio.run(make_negotiation_node(container)(CLAIMING_STATE))

        said = [str(data.get("text", "")) for _kind, data in events]
        assert any(mediator_no_answer_note("the answer was empty") in text for text in said)


class TestADisagreementStillRevises:
    def test_a_mediated_round_with_contradictions_goes_to_revision(self) -> None:
        state = {
            **CLAIMING_STATE,
            "iteration_count": 1,
            "is_consensus": False,
            "consensus_applicable": True,
            "confidence_history": [0.4],
            "discussion_history": [
                AgentArgument(
                    agent_name="Mediator",
                    finding="disputed",
                    confidence_score=0.4,
                    contradictions=["a — b"],
                )
            ],
        }

        assert ConsensusRouter(Settings()).should_continue(state) == "revision"
