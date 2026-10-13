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
            "the answer was empty; asked once more, the answer was empty again"
        )
        # Asked once more, then nothing is asked to extract a verdict from nothing.
        extract.assert_not_called()
        assert model.calls == 2

    def test_an_answer_cut_before_any_text_says_where_it_was_cut(self) -> None:
        (argument, consensus), model, extract = _mediate(_cut(4096))

        assert consensus is None
        assert argument.status == MEDIATOR_NO_ANSWER
        assert argument.note == mediator_no_answer_note(
            "the answer was cut at 4096 tokens with no text; not asked again, as the same call "
            "would be cut again"
        )
        # The same call at the same budget would be cut again: it is not repeated.
        assert model.calls == 1
        extract.assert_not_called()

    def test_a_cut_is_measured_against_the_bound_the_call_was_sent_with(self) -> None:
        # A local server cut at a spend-held bound says ``stop`` with a count
        # equal to that bound, far below the model's built cap.
        silent_cut = AIMessage(
            content="",
            response_metadata={"finish_reason": "stop"},
            usage_metadata={"input_tokens": 10, "output_tokens": 512, "total_tokens": 522},
        )
        model = _Says(silent_cut)
        judge = JudgeAgent(llm=model)  # type: ignore[arg-type]
        with (
            patch.object(judge, "_spend_admits", return_value=512),
            patch(
                "maljan.llm.context_window.output_bound_kwargs",
                return_value={"max_tokens": 512},
            ),
            patch.object(judge, "_built_cap_tokens", return_value=128000),
        ):
            argument, _consensus = asyncio.run(
                judge.mediate(
                    CLAIMING_STATE["reports"], [], isr_reports=CLAIMING_STATE["isr_reports"]
                )
            )

        assert argument.note == mediator_no_answer_note(
            "the answer was cut at 512 tokens with no text; not asked again, as the same call "
            "would be cut again"
        )
        assert model.calls == 1

    def test_a_second_ask_the_spend_ceiling_refuses_is_stated_as_refused(self) -> None:
        from maljan.core.spend import SpendCeilingStop

        model = _Says(_empty())
        judge = JudgeAgent(llm=model)  # type: ignore[arg-type]
        admitted = iter([None])

        def _admit(*_args: Any, **_kw: Any) -> None:
            if next(admitted, "refused") == "refused":
                raise SpendCeilingStop("the ceiling is reached")

        with patch.object(judge, "_spend_admits", side_effect=_admit):
            argument, _consensus = asyncio.run(
                judge.mediate(
                    CLAIMING_STATE["reports"], [], isr_reports=CLAIMING_STATE["isr_reports"]
                )
            )

        assert model.calls == 1
        assert argument.note == mediator_no_answer_note(
            "the answer was empty; asking once more was refused by the job's spend ceiling"
        )

    def test_a_second_ask_that_fails_is_stated_as_failed(self) -> None:
        class _ThenFails(_Says):
            async def ainvoke(self, _messages: Any, **_kw: Any) -> AIMessage:
                self.calls += 1
                if self.calls > 1:
                    raise RuntimeError("the server went away")
                return _empty()

        model = _ThenFails(_empty())
        judge = JudgeAgent(llm=model)  # type: ignore[arg-type]
        argument, _consensus = asyncio.run(
            judge.mediate(CLAIMING_STATE["reports"], [], isr_reports=CLAIMING_STATE["isr_reports"])
        )

        assert model.calls == 2
        assert argument.note == mediator_no_answer_note(
            "the answer was empty; asking once more failed (RuntimeError)"
        )

    def test_a_first_call_the_spend_ceiling_refuses_is_stated_as_not_admitted(self) -> None:
        from maljan.core.spend import SpendCeilingStop

        model = _Says(_empty())
        judge = JudgeAgent(llm=model)  # type: ignore[arg-type]
        with patch.object(judge, "_spend_admits", side_effect=SpendCeilingStop("reached")):
            argument, consensus = asyncio.run(
                judge.mediate(
                    CLAIMING_STATE["reports"], [], isr_reports=CLAIMING_STATE["isr_reports"]
                )
            )

        assert model.calls == 0
        assert consensus is None
        assert argument.note == mediator_no_answer_note(
            "the call was not admitted under the job's spend ceiling"
        )

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
        assert argument.note == mediator_no_answer_note(
            "the answer was empty; the tool loop was not run again"
        )

    def test_a_tool_loop_that_ended_without_an_answer_says_how_it_ended(self) -> None:
        judge = JudgeAgent(llm=MagicMock())

        async def _stopped(_prompt: Any) -> str:
            judge._last_loop_ending = "the tool loop stopped at its step limit with no text"
            return ""

        with (
            patch.object(judge, "_has_explicit_dissent", return_value=True),
            patch.object(judge, "_initialize_mcp_client", AsyncMock()),
            patch.object(judge, "execute_tool_loop", side_effect=_stopped),
        ):
            argument, consensus = asyncio.run(
                judge.mediate(
                    CLAIMING_STATE["reports"], [], isr_reports=CLAIMING_STATE["isr_reports"]
                )
            )

        assert consensus is None
        assert argument.note == mediator_no_answer_note(
            "the tool loop stopped at its step limit with no text; the tool loop was not run again"
        )

    def test_a_failed_salvage_call_is_recorded_as_failed(self) -> None:
        from langchain_core.messages import HumanMessage, SystemMessage

        import maljan.agents.judge_agent as judge_agent

        class _Fails:
            async def ainvoke(self, _messages: Any, **_kw: Any) -> AIMessage:
                raise RuntimeError("the server went away")

            def bind_tools(self, *_args: Any, **_kw: Any) -> _Fails:
                return self

        judge = JudgeAgent(llm=_Fails())  # type: ignore[arg-type]
        gathered = [SystemMessage(content="You mediate."), HumanMessage(content="Reports: x")]
        with (
            patch.object(judge_agent, "_trim_for_synthesis", lambda msgs, _budget: msgs),
            patch.object(judge_agent, "synthesis_budget_chars", return_value=1),
        ):
            said = asyncio.run(
                judge._reasoning_from_what_was_gathered(
                    gathered, 10.0, None, ended_why="3 repeated tool call(s)"
                )
            )

        assert said == ""
        assert judge._last_loop_ending == (
            "the tool loop ended (3 repeated tool call(s)) and the call to write its "
            "reasoning failed (RuntimeError)"
        )

    def test_a_salvage_with_no_time_left_says_so(self) -> None:
        judge = JudgeAgent(llm=MagicMock())

        said = asyncio.run(
            judge._reasoning_from_what_was_gathered([], 0.2, None, ended_why="its clock ran out")
        )

        assert said == ""
        assert judge._last_loop_ending == (
            "the tool loop ended (its clock ran out) with no time left to write its reasoning"
        )

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

    def test_no_answer_at_the_round_limit_is_still_not_mediated(self) -> None:
        state = {
            **CLAIMING_STATE,
            **self._round(),
            "iteration_count": 3,
        }

        assert debate_route(state, max_rounds=3) == ("judge", NOT_MEDIATED)
        summary = RunSummaryBuilder(start_time=0.0).set_negotiation(state, max_iterations=3).build()
        assert summary.to_dict()["negotiation"]["termination_reason"] == NOT_MEDIATED

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

    def test_the_outer_cap_covers_every_call_a_mediation_can_make(self) -> None:
        from maljan.agents.judge_agent import MEDIATION_CALL_SPANS

        caps: list[float | None] = []

        async def _on_agent_loop(coro: Any, hard_timeout: float | None = None, **_kw: Any) -> Any:
            caps.append(hard_timeout)
            return await coro

        container = _container((_no_answer(), None))
        with (
            patch("maljan.pipeline.nodes.detect_sycophancy", return_value=False),
            patch("maljan.agents.base_agent.loop_limits", return_value=(100, 8)),
            patch("maljan.agents.base_agent.run_on_agent_loop", _on_agent_loop),
        ):
            asyncio.run(make_negotiation_node(container)(CLAIMING_STATE))

        # The fast call, its second ask, the block question and the extraction.
        assert MEDIATION_CALL_SPANS == 4
        assert caps == [100 * MEDIATION_CALL_SPANS + 30]

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
