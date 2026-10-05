"""The debate ends when nothing is left to settle, and runs while something is.

Rounds that settled nothing were the largest cost of a hosted run. The rules,
in the order the router applies them:

- the hard round limit still ends every debate;
- a mediation that failed, or a debate where consensus does not apply, goes
  to the judge;
- a revision round whose revisions changed no claim, no technique and no
  finding means the debate converged: it ends;
- the sycophancy check asks for another revision only when the agreement
  arose without new evidence: the revision round before it added no ledger
  entry;
- consensus ends it, as does a stable agreement with no contradiction standing;
- anything else is another revision round.

The run summary's termination reason is read from the same rules, so it says
what ended the debate; ``converged_early`` is true only for a debate that
ended before its limit for a reason other than the limit.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import patch

from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda

from maljan.agents.judge_agent import JudgeAgent
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.core.config import Settings
from maljan.pipeline.debate_settlement import Settlement
from maljan.pipeline.mediation_models import MediatorVerdict
from maljan.pipeline.routing import ConsensusRouter, debate_route
from maljan.pipeline.state import AgentArgument
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _mediator(contradictions: list[str] | None = None, confidence: float = 0.9) -> AgentArgument:
    return AgentArgument(
        agent_name="Mediator",
        finding="x",
        confidence_score=confidence,
        contradictions=contradictions or [],
    )


def _state(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "iteration_count": 2,
        "is_consensus": False,
        "sycophancy_detected": False,
        "confidence_history": [0.6, 0.9],
        "discussion_history": [_mediator(["a: x — ev_0001"])],
        "isr_reports": {},
        "revision_rounds": [{"round": 1, "made": 3, "changed": True, "new_evidence": 2}],
    }
    base.update(over)
    return base


def _router(max_rounds: int = 5) -> ConsensusRouter:
    settings = Settings()
    settings.negotiation.max_iterations = max_rounds
    return ConsensusRouter(settings)


class TestARoundThatChangedNothing:
    def test_ends_the_debate_as_converged(self) -> None:
        state = _state(
            revision_rounds=[{"round": 1, "made": 3, "changed": False, "new_evidence": 0}]
        )

        assert debate_route(state, max_rounds=5) == ("judge", "converged")
        assert _router().should_continue(state) == "judge"

    def test_ends_it_even_with_a_contradiction_still_listed(self) -> None:
        state = _state(
            discussion_history=[_mediator(["a: x — b: y"])],
            revision_rounds=[{"round": 1, "made": 2, "changed": False, "new_evidence": 0}],
        )

        assert debate_route(state, max_rounds=5)[1] == "converged"

    def test_a_round_whose_every_revision_failed_is_not_convergence(self) -> None:
        state = _state(
            revision_rounds=[{"round": 1, "made": 0, "changed": False, "new_evidence": 0}]
        )

        assert debate_route(state, max_rounds=5)[0] == "revision"

    def test_a_round_that_changed_something_goes_on_while_a_contradiction_stands(self) -> None:
        assert debate_route(_state(), max_rounds=5)[0] == "revision"

    def test_only_the_last_round_counts(self) -> None:
        state = _state(
            revision_rounds=[
                {"round": 1, "made": 3, "changed": False, "new_evidence": 0},
                {"round": 2, "made": 3, "changed": True, "new_evidence": 0},
            ]
        )

        assert debate_route(state, max_rounds=5)[0] == "revision"


class TestTheSycophancyCheck:
    def _agreed(self, new_evidence: int, changed: bool = True) -> dict[str, Any]:
        return _state(
            is_consensus=True,
            sycophancy_detected=True,
            discussion_history=[_mediator([])],
            revision_rounds=[
                {"round": 1, "made": 3, "changed": changed, "new_evidence": new_evidence}
            ],
        )

    def test_agreement_without_new_evidence_is_sent_back_once_more(self) -> None:
        assert debate_route(self._agreed(new_evidence=0), max_rounds=5) == (
            "revision",
            "sycophancy",
        )

    def test_agreement_that_new_evidence_brought_ends_the_debate(self) -> None:
        assert debate_route(self._agreed(new_evidence=4), max_rounds=5) == ("judge", "consensus")

    def test_a_forced_revision_that_changed_nothing_is_not_forced_again(self) -> None:
        state = self._agreed(new_evidence=0, changed=False)

        assert debate_route(state, max_rounds=5) == ("judge", "converged")

    def test_switched_off_it_asks_nothing(self) -> None:
        assert debate_route(self._agreed(new_evidence=0), max_rounds=5, sycophancy_check=False) == (
            "judge",
            "consensus",
        )

    def test_a_state_with_no_round_record_keeps_the_check_as_it_was(self) -> None:
        state = self._agreed(new_evidence=0)
        state.pop("revision_rounds")

        assert debate_route(state, max_rounds=5)[0] == "revision"


class TestTheHardLimit:
    def test_still_ends_a_debate_that_would_go_on(self) -> None:
        state = _state(iteration_count=5)

        assert debate_route(state, max_rounds=5) == ("judge", "hard_limit")
        assert _router().should_continue(state) == "judge"

    def test_a_debate_that_agreed_on_its_last_round_ended_by_consensus(self) -> None:
        state = _state(iteration_count=5, is_consensus=True, discussion_history=[_mediator([])])

        assert debate_route(state, max_rounds=5) == ("judge", "consensus")

    def test_a_forced_revision_the_limit_stopped_is_the_limit(self) -> None:
        state = _state(
            iteration_count=5,
            is_consensus=True,
            sycophancy_detected=True,
            discussion_history=[_mediator([])],
            revision_rounds=[{"round": 4, "made": 3, "changed": True, "new_evidence": 0}],
        )

        assert debate_route(state, max_rounds=5) == ("judge", "hard_limit")


class TestTheRunSummarySaysWhatEndedIt:
    def _negotiation(self, state: dict[str, Any], max_rounds: int = 5) -> Any:
        return (
            RunSummaryBuilder(start_time=0.0)
            .set_negotiation(state, max_iterations=max_rounds)
            .build()
            .negotiation
        )

    def test_a_converged_debate_says_converged_and_early(self) -> None:
        negotiation = self._negotiation(
            _state(revision_rounds=[{"round": 1, "made": 3, "changed": False, "new_evidence": 0}])
        )

        assert negotiation.termination_reason == "converged"
        assert negotiation.converged_early is True

    def test_consensus_on_the_last_allowed_round_is_not_early(self) -> None:
        negotiation = self._negotiation(
            _state(iteration_count=5, is_consensus=True, discussion_history=[_mediator([])])
        )

        assert negotiation.termination_reason == "consensus"
        assert negotiation.converged_early is False

    def test_a_debate_the_limit_ended_says_so(self) -> None:
        negotiation = self._negotiation(
            _state(
                iteration_count=5,
                is_consensus=True,
                sycophancy_detected=True,
                discussion_history=[_mediator([])],
                revision_rounds=[{"round": 4, "made": 3, "changed": True, "new_evidence": 0}],
            )
        )

        assert negotiation.termination_reason == "hard_limit"
        assert negotiation.converged_early is False

    def test_the_sycophancy_switch_is_read_the_way_the_router_read_it(self) -> None:
        state = _state(
            iteration_count=5,
            is_consensus=True,
            sycophancy_detected=True,
            discussion_history=[_mediator([])],
            revision_rounds=[{"round": 4, "made": 3, "changed": True, "new_evidence": 0}],
        )
        negotiation = (
            RunSummaryBuilder(start_time=0.0)
            .set_negotiation(state, max_iterations=5, sycophancy_check=False)
            .build()
            .negotiation
        )

        assert negotiation.termination_reason == "consensus"

    def test_closed_and_settled_lines_and_dropped_claims_are_recorded(self) -> None:
        argument = _mediator([])
        argument.closed.append("Closed: gamma claim(s) 9 are not in its answer in force.")
        argument.settled.append("Settled from the ledger: entry ev_0007 states total = 41.")
        negotiation = self._negotiation(
            _state(
                is_consensus=True,
                discussion_history=[argument],
                dropped_claims=[
                    {"agent": "beta", "round": 2, "sentence": "The beta analyst dropped X."}
                ],
            )
        )

        assert negotiation.settled_contradictions == [
            "Closed: gamma claim(s) 9 are not in its answer in force.",
            "Settled from the ledger: entry ev_0007 states total = 41.",
        ]
        assert negotiation.dropped_claims == ["The beta analyst dropped X."]
        as_dict = (
            RunSummaryBuilder(start_time=0.0)
            .set_negotiation(
                _state(
                    is_consensus=True,
                    discussion_history=[argument],
                    dropped_claims=[{"sentence": "The beta analyst dropped X."}],
                ),
                max_iterations=5,
            )
            .build()
            .to_dict()["negotiation"]
        )
        assert as_dict["dropped_claims"] == ["The beta analyst dropped X."]
        assert len(as_dict["settled_contradictions"]) == 2


# ---------------------------------------------------------------------------
# The mediation hands its lines to the platform before deciding consensus
# ---------------------------------------------------------------------------

LISTED = (
    "The analysts agree on the core record.\n\n"
    "CONTRADICTIONS:\n"
    "- GAMMA Claim 30 (an old reading) — contradicted by BETA Claim 2.\n"
    "agreement_confidence: 0.9"
)


class _Model:
    async def ainvoke(self, _messages: Any, **_kw: Any) -> AIMessage:
        return AIMessage(content=LISTED)

    def with_structured_output(self, _schema: Any) -> Any:
        return RunnableLambda(
            lambda _in: MediatorVerdict(
                contradictions=["GAMMA Claim 30 (an old reading) — contradicted by BETA Claim 2."],
                resolution_summary="one line stands",
                confidence=0.9,
            )
        )


def _isrs() -> dict[str, AgentISR]:
    return {
        name: AgentISR(
            agent_id=name,
            domain="static",
            claims=[ClaimEvidence(claim="c", evidence_ref="[ev_0001]", confidence=0.9)] * 3,
        )
        for name in ("gamma", "beta")
    }


def _mediate(settle: Any) -> tuple[AgentArgument, bool | None]:
    judge = JudgeAgent(llm=_Model())  # type: ignore[arg-type]
    with patch.object(judge, "_supports_structured_output", return_value=False):
        return asyncio.run(
            judge.mediate(
                {"gamma": "r", "beta": "r"},
                [],
                isr_reports=_isrs(),
                consensus_threshold=0.85,
                settle_contradictions=settle,
            )
        )


class TestTheMediationAsksThePlatform:
    def test_a_line_the_platform_closes_leaves_consensus(self) -> None:
        def settle(lines: list[str]) -> Settlement:
            return Settlement(standing=[], closed=[f"Closed: {lines[0]}"], settled=[])

        argument, is_consensus = _mediate(settle)

        assert is_consensus is True
        assert argument.contradictions == []
        assert argument.closed == [
            "Closed: GAMMA Claim 30 (an old reading) — contradicted by BETA Claim 2."
        ]
        assert "Contradictions: None" in argument.finding

    def test_a_line_that_stands_keeps_the_round_open(self) -> None:
        def settle(lines: list[str]) -> Settlement:
            return Settlement(standing=list(lines))

        argument, is_consensus = _mediate(settle)

        assert is_consensus is False
        assert len(argument.contradictions) == 1
        assert argument.closed == [] and argument.settled == []

    def test_a_mediation_with_no_settler_reads_the_block_as_before(self) -> None:
        argument, is_consensus = _mediate(None)

        assert is_consensus is False
        assert len(argument.contradictions) == 1

    def test_a_settler_that_raises_leaves_the_lines_standing(self) -> None:
        def settle(_lines: list[str]) -> Settlement:
            raise RuntimeError("boom")

        argument, is_consensus = _mediate(settle)

        assert is_consensus is False
        assert len(argument.contradictions) == 1
