"""Each debate stage counts its own rounds and reads its own confidence series.

``iteration_count`` and ``confidence_history`` are the run's, across every
debate stage. Read by the router as they were, a profile's second debate met
the first one's round count and stable confidence: it ended at ``hard_limit``
or ``convergence`` on its first mediation, before any revision round. Each
debate now records where it began (``debate_starts``), and the router counts
the rounds, reads the confidence series and pairs the mediations of that
debate alone.
"""

from __future__ import annotations

import asyncio
from typing import Any

from maljan.core.config import MEDIATOR_AGENT_NAME
from maljan.pipeline.routing import (
    CONVERGENCE,
    HARD_LIMIT,
    debate_rounds,
    debate_route,
    rounds_held_before,
    route_within_limit,
    with_debate_start,
)
from maljan.pipeline.state import AgentArgument


def _mediation() -> AgentArgument:
    """A mediation that reached no consensus and lists no contradiction still standing."""
    return AgentArgument(
        agent_name=MEDIATOR_AGENT_NAME, finding="No consensus yet.", confidence_score=0.9
    )


def _first_debate_ended() -> dict[str, Any]:
    """Debate one held three mediations, its confidence stable at 0.9."""
    return {
        "iteration_count": 3,
        "confidence_history": [0.9, 0.9, 0.9],
        "discussion_history": [_mediation(), _mediation(), _mediation()],
        "revision_rounds": [{"round": 1, "stage": "debate", "made": 1}],
        "is_consensus": False,
        "consensus_applicable": True,
        "debate_starts": {"debate": {"mediations": 0, "confidences": 0, "arguments": 0}},
    }


def _second_debate_first_mediation() -> dict[str, Any]:
    """Debate two's first mediation, at a confidence that did not move yet."""
    state = _first_debate_ended()
    state["debate_starts"] = {
        **state["debate_starts"],
        "debate2": {"mediations": 3, "confidences": 3, "arguments": 3},
    }
    state["iteration_count"] = 4
    state["confidence_history"] = [*state["confidence_history"], 0.9]
    state["discussion_history"] = [*state["discussion_history"], _mediation()]
    return state


class TestTheRoundLimitIsTheDebatesOwn:
    def test_the_second_debate_is_not_at_the_first_one_s_limit(self) -> None:
        state = _second_debate_first_mediation()

        assert debate_rounds(state, "debate2") == 1
        route, reason = debate_route(state, max_rounds=3, stage="debate2")

        assert (route, reason) == ("revision", "no_consensus")

    def test_it_meets_its_own_limit(self) -> None:
        state = _second_debate_first_mediation()
        state["iteration_count"] = 6
        state["debate_starts"]["debate2"]["confidences"] = 4

        route, reason = debate_route(state, max_rounds=3, stage="debate2")

        assert route == "judge"
        assert reason == HARD_LIMIT

    def test_the_first_debate_still_ends_at_its_limit(self) -> None:
        route, _reason = debate_route(_first_debate_ended(), max_rounds=3, stage="debate")

        assert route == "judge"


class TestTheConfidenceSeriesIsTheDebatesOwn:
    def test_the_first_debate_s_stable_numbers_do_not_end_the_second(self) -> None:
        state = _second_debate_first_mediation()

        _route, reason = route_within_limit(state, stage="debate2", log=False)

        assert reason != CONVERGENCE

    def test_without_a_stage_the_summary_reads_the_last_debate(self) -> None:
        state = _second_debate_first_mediation()

        assert route_within_limit(state, log=False) == route_within_limit(
            state, stage="debate2", log=False
        )

    def test_a_state_with_no_recorded_start_reads_as_it_always_did(self) -> None:
        state = _first_debate_ended()
        del state["debate_starts"]

        _route, reason = route_within_limit(state, log=False)

        assert reason == CONVERGENCE
        assert debate_rounds(state) == 3


class TestWhereADebateBeganIsRecordedOnce:
    def test_the_first_mediation_of_a_stage_records_it(self) -> None:
        state = _first_debate_ended()

        update = with_debate_start(state, "debate2", {"iteration_count": 4})

        assert update["debate_starts"] == {
            "debate2": {"mediations": 3, "confidences": 3, "arguments": 3}
        }

    def test_a_later_mediation_records_nothing(self) -> None:
        state = _first_debate_ended()

        update = with_debate_start(state, "debate", {"iteration_count": 4})

        assert "debate_starts" not in update

    def test_a_node_output_that_held_no_mediation_records_nothing(self) -> None:
        assert "debate_starts" not in with_debate_start({}, "debate", {"is_consensus": None})

    def test_the_negotiation_node_writes_it(self) -> None:
        from maljan.core.config import Settings
        from maljan.pipeline.nodes import make_negotiation_node
        from maljan.schemas.evidence import EvidenceCounter
        from tests.unit.pipeline.test_evidence_ledger_channel import (
            _JudgeContainer,
            _mediates_with_a_tool_call,
        )

        settings = Settings(_env_file=None)
        stage = settings.agents.profiles["default"].stage("debate")
        container = _JudgeContainer(EvidenceCounter())
        container.active_profile = lambda: settings.agents.profiles["default"]  # type: ignore[attr-defined]
        _mediates_with_a_tool_call(container.get_judge_agent(role="expert"))
        state = {"iteration_count": 2, "reports": {"static": "f"}, "isr_reports": {}}

        update = asyncio.run(make_negotiation_node(container, stage=stage)(state))

        assert update["iteration_count"] == 3
        assert update["debate_starts"][stage.key]["mediations"] == 2


class TestTheSecondDebatesFirstMediationIsItsFirst:
    def test_it_has_held_no_round(self) -> None:
        state = _first_debate_ended()

        assert rounds_held_before(state, "debate2") == 0
        assert rounds_held_before(state, "debate") == 3

    def test_a_state_with_no_recorded_start_reads_the_run_s_count(self) -> None:
        state = _first_debate_ended()
        del state["debate_starts"]

        assert rounds_held_before(state, "debate2") == 3

    def test_it_is_never_checked_for_sycophancy(self) -> None:
        from unittest.mock import patch

        from maljan.core.config import Settings
        from maljan.pipeline import nodes
        from maljan.schemas.evidence import EvidenceCounter
        from maljan.schemas.isr_models import AgentISR
        from tests.unit.pipeline.test_evidence_ledger_channel import (
            _JudgeContainer,
            _mediates_with_a_tool_call,
        )

        settings = Settings(_env_file=None)
        stage = settings.agents.profiles["default"].stage("debate")
        container = _JudgeContainer(EvidenceCounter())
        container.active_profile = lambda: settings.agents.profiles["default"]  # type: ignore[attr-defined]
        _mediates_with_a_tool_call(container.get_judge_agent(role="expert"))
        state = {
            **_first_debate_ended(),
            "debate_starts": {"earlier": {"mediations": 0, "confidences": 0, "arguments": 0}},
            "reports": {"static": "f"},
            "isr_reports": {"static": AgentISR(agent_id="static", domain="static")},
        }
        seen: list[int] = []

        def _detect(_isrs: Any, **kwargs: Any) -> bool:
            seen.append(kwargs["iteration"])
            return False

        with patch.object(nodes, "detect_sycophancy", side_effect=_detect):
            asyncio.run(nodes.make_negotiation_node(container, stage=stage)(state))

        assert seen == [0]
