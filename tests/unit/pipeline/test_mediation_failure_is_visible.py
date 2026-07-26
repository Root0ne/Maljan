"""A mediation that never ran must not be recorded as a calm disagreement.

Both outcomes leave ``is_consensus=False`` with a 0.0 confidence, and until
``AgentArgument.status`` existed the *only* thing separating them anywhere in
the system was the literal prefix ``"[ERROR] Mediation "`` inside a free-text
field. Two independent consumers sniffed that string — the router, where it
decides whether to burn a 10-15 minute revision round, and the frontend — so
the wording of an error message was load-bearing routing logic with no test
behind it.

It mattered: every stored run in this deployment's database was an errored
mediation, and every surface drew it as a negotiation that had simply not
converged.
"""

from __future__ import annotations

from maljan.core.config import Settings
from maljan.pipeline.routing import ConsensusRouter
from maljan.pipeline.state import AgentArgument


def _state(**over: object) -> dict:
    base: dict = {
        "iteration_count": 1,
        "is_consensus": False,
        "sycophancy_detected": False,
        "confidence_history": [0.0],
        "discussion_history": [],
        "isr_reports": {},
    }
    base.update(over)
    return base


class TestTheStatusFieldCarriesIt:
    def test_a_contribution_is_complete_by_default(self) -> None:
        """Every existing construction site keeps working untouched."""
        arg = AgentArgument(agent_name="Mediator", finding="agreed", confidence_score=0.9)
        assert arg.status == "complete"

    def test_failure_and_timeout_are_distinguishable(self) -> None:
        failed = AgentArgument(agent_name="Mediator", finding="x", status="failed")
        timed_out = AgentArgument(agent_name="Mediator", finding="x", status="timeout")
        assert failed.status != timed_out.status


class TestTheRouterNoLongerParsesProse:
    def test_an_errored_round_still_short_circuits_to_the_judge(self) -> None:
        """The BUG-05 behaviour, now driven by the field rather than the text."""
        router = ConsensusRouter(Settings())
        state = _state(
            discussion_history=[
                AgentArgument(
                    agent_name="Mediator",
                    finding="mediation could not reach the model",  # no magic prefix
                    confidence_score=0.0,
                    status="failed",
                )
            ]
        )
        assert router.should_continue(state) == "judge"

    def test_a_timed_out_round_routes_the_same_way(self) -> None:
        router = ConsensusRouter(Settings())
        state = _state(
            discussion_history=[
                AgentArgument(agent_name="Mediator", finding="slow", status="timeout")
            ]
        )
        assert router.should_continue(state) == "judge"

    def test_old_state_without_the_field_still_routes_correctly(self) -> None:
        """Reports written before the field existed must not regress."""
        router = ConsensusRouter(Settings())
        state = _state(
            discussion_history=[
                AgentArgument(
                    agent_name="Mediator",
                    finding="[ERROR] Mediation failed: Connection error.",
                    confidence_score=0.0,
                )
            ]
        )
        assert router.should_continue(state) == "judge"

    def test_a_genuine_disagreement_still_goes_to_revision(self) -> None:
        """The distinction is only worth having if the other branch survives."""
        router = ConsensusRouter(Settings())
        state = _state(
            discussion_history=[
                AgentArgument(
                    agent_name="Mediator",
                    finding="static and dynamic contradict each other on injection",
                    confidence_score=0.4,
                    status="complete",
                )
            ]
        )
        assert router.should_continue(state) == "revision"


class TestTheNodeStampsIt:
    def test_a_failed_mediation_is_stamped_and_still_degrades_gracefully(self) -> None:
        import asyncio
        from unittest.mock import AsyncMock, MagicMock

        from maljan.pipeline.nodes import make_negotiation_node

        events: list[tuple[str, dict]] = []
        container = MagicMock()
        container.is_mock = False
        container.event_sink = lambda t, d: events.append((t, d))
        container.agent_registry.list_agents.return_value = ["static"]
        judge = MagicMock()
        judge.mediate = AsyncMock(side_effect=ConnectionError("llama-server went away"))
        container.get_judge_agent.return_value = judge

        node = make_negotiation_node(container)
        result = asyncio.run(node({"iteration_count": 0, "reports": {"static": "r"}}))

        argument = result["discussion_history"][0]
        assert argument.status == "failed"
        assert result["is_consensus"] is False
        # And the live transcript says so too, with the real cause in it.
        message = next(d for t, d in events if t == "agent_message")
        assert message["status"] == "failed"
        assert "llama-server went away" in message["text"]
