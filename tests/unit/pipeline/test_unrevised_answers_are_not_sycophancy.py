"""Answers not revised in a round are not evidence of sycophancy in that round.

A revision round in which an analyst's revision was not made (it failed, wrote
nothing, or carried no structured report) or was not asked (no data to revise)
leaves that analyst's answer in force standing. Two such answers that were
already alike before the round are not two analysts converging in it: the
similarity check judges a pair only where at least one of the two answers was
revised in the round being judged. A round in which no analyst was revised
made no change, and the debate does not go on because of it: the router sends
the answers in force to the judge, by consensus where the mediator stated one
and as ``not_revised`` otherwise. Where answers were revised the check and the
router behave as they did. Every value is synthetic.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.pipeline.nodes import make_negotiation_node, make_revision_node
from maljan.pipeline.routing import NOT_REVISED, debate_route
from maljan.pipeline.state import AgentArgument
from maljan.pipeline.sycophancy_detector import detect_sycophancy
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.stages import paper_profile

NAMES = ["dynamic", "network"]

# One long, shared finding: two answers carrying it are alike far past the
# similarity threshold, with enough words for the check to read them.
SHARED = (
    "The sample resolves the command server host, opens an outbound TLS session on port "
    "443, sends the machine name and user name, and waits for a tasking reply before it "
    "writes a scheduled task for persistence."
)


def _isr(name: str, text: str = SHARED) -> AgentISR:
    return AgentISR(
        agent_id=name,
        domain=name,
        claims=[ClaimEvidence(claim=text, evidence_ref="[ev_0001]", confidence=0.8)],
    )


IN_FORCE = {name: _isr(name) for name in NAMES}


# ---------------------------------------------------------------------------
# The check itself
# ---------------------------------------------------------------------------


class TestTheCheck:
    def test_alike_answers_none_revised_are_not_judged(self) -> None:
        isrs = list(IN_FORCE.values())
        assert detect_sycophancy(isrs, iteration=1, revised=set()) is False

    def test_alike_answers_one_revised_are_judged_as_before(self) -> None:
        isrs = list(IN_FORCE.values())
        assert detect_sycophancy(isrs, iteration=1, revised={"dynamic"}) is True

    def test_alike_revised_answers_are_judged_as_before(self) -> None:
        isrs = list(IN_FORCE.values())
        assert detect_sycophancy(isrs, iteration=1, revised=set(NAMES)) is True
        assert detect_sycophancy(isrs, iteration=1) is True

    def test_a_pair_of_unrevised_answers_beside_a_revised_one_is_left_out(self) -> None:
        other = _isr("static", "A different finding about an unrelated registry key " * 6)
        isrs = [*IN_FORCE.values(), other]
        assert detect_sycophancy(isrs, iteration=1, revised={"static"}) is False

    def test_the_answers_left_out_are_named_in_the_log(self, caplog: Any) -> None:
        import logging

        with caplog.at_level(logging.INFO, logger="maljan"):
            detect_sycophancy(list(IN_FORCE.values()), iteration=1, revised=set())
        said = " ".join(r.getMessage() for r in caplog.records)
        assert "not revised in round 1" in said
        assert "dynamic" in said and "network" in said


# ---------------------------------------------------------------------------
# The revision round records who was revised
# ---------------------------------------------------------------------------


def _revision_container(outcomes: dict[str, Any]) -> Any:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda *_a: None
    container.analyst_keys.return_value = NAMES
    container.agent_role.side_effect = lambda n: n
    container.active_profile.return_value = paper_profile(NAMES)
    container.config.llm.parallel_analysts = False
    agents: dict[str, Any] = {}
    for name in NAMES:
        agent = MagicMock()
        agent.safe_revise_isr.return_value = outcomes[name]
        agent.drain_evidence_entries.return_value = []
        agent.validation_findings = []
        agent.validation_retries = 0
        agent.validation_fed_back = {}
        agent.validation_not_run = []
        agents[name] = agent
    container.get_agent.side_effect = lambda n: agents[n]
    return container


def _revise(outcomes: dict[str, Any], absent: tuple[str, ...] = ()) -> dict[str, Any]:
    state = {
        "iteration_count": 1,
        "reports": {name: f"{name} first answer" for name in NAMES},
        "revised_reports": {},
        "isr_reports": dict(IN_FORCE),
        "discussion_history": [AgentArgument(agent_name="Mediator", finding="revise")],
    }
    container = _revision_container(outcomes)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "maljan.pipeline.nodes._revision_input_is_absent",
            lambda _state, _container, name: name in absent,
        )
        mp.setattr("maljan.pipeline.nodes._build_revision_context", lambda *a: "data")
        return asyncio.run(make_revision_node(container)(state))


class TestTheRoundRecord:
    def test_a_round_of_empty_revisions_is_recorded_as_making_no_change(self) -> None:
        update = _revise({name: ("", _isr(name)) for name in NAMES})

        [record] = update["revision_rounds"]
        assert record["made"] == 0
        assert record["revised"] == []
        assert record["not_revised"] == {
            "dynamic": "no answer was written",
            "network": "no answer was written",
        }
        # The answers in force stand.
        assert update["isr_reports"] == IN_FORCE

    def test_an_analyst_not_asked_is_not_counted_as_revised(self) -> None:
        update = _revise(
            {
                "dynamic": ("dynamic revised answer", _isr("dynamic", "revised")),
                "network": ("unused", _isr("network")),
            },
            absent=("network",),
        )

        [record] = update["revision_rounds"]
        assert record["made"] == 1
        assert record["revised"] == ["dynamic"]
        assert record["not_revised"] == {"network": "not asked: no data to revise"}
        assert update["isr_reports"]["network"] is IN_FORCE["network"]


# ---------------------------------------------------------------------------
# The mediation after it
# ---------------------------------------------------------------------------


def _mediation_after(record: dict[str, Any], *, consensus: bool) -> dict[str, Any]:
    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = NAMES
    container.analyst_keys.return_value = NAMES
    judge = MagicMock()
    argument = AgentArgument(agent_name="Mediator", finding="read", confidence_score=0.9)
    judge.mediate = AsyncMock(return_value=(argument, consensus))
    container.get_judge_agent.return_value = judge
    state: dict[str, Any] = {
        "iteration_count": 1,
        "reports": {name: SHARED for name in NAMES},
        "isr_reports": dict(IN_FORCE),
        "revision_rounds": [record],
        "discussion_history": [AgentArgument(agent_name="Mediator", finding="revise")],
        "confidence_history": [0.5],
    }
    update = asyncio.run(make_negotiation_node(container)(state))
    return {
        **state,
        **update,
        "discussion_history": [*state["discussion_history"], *update["discussion_history"]],
        "confidence_history": [*state["confidence_history"], *update["confidence_history"]],
    }


EMPTY_ROUND = {
    "round": 1,
    "stage": "debate",
    "made": 0,
    "identical": False,
    "revised": [],
    "not_revised": {name: "no answer was written" for name in NAMES},
}
REVISED_ROUND = {
    "round": 1,
    "stage": "debate",
    "made": 2,
    "identical": False,
    "revised": list(NAMES),
    "not_revised": {},
}


class TestAllEmptyRevisions:
    def test_no_devils_advocate_and_the_debate_ends(self) -> None:
        after = _mediation_after(EMPTY_ROUND, consensus=False)

        assert after["sycophancy_detected"] is False
        assert debate_route(after, max_rounds=5) == ("judge", NOT_REVISED)

    def test_a_consensus_the_mediator_stated_is_not_overridden(self) -> None:
        after = _mediation_after(EMPTY_ROUND, consensus=True)

        assert after["sycophancy_detected"] is False
        assert debate_route(after, max_rounds=5) == ("judge", "consensus")

    def test_a_flag_left_on_the_state_does_not_reopen_an_unchanged_round(self) -> None:
        after = _mediation_after(EMPTY_ROUND, consensus=True)
        assert debate_route({**after, "sycophancy_detected": True}, max_rounds=5) == (
            "judge",
            "consensus",
        )


class TestConvergingRevisedAnswers:
    def test_are_flagged_and_sent_back_as_before(self) -> None:
        after = _mediation_after(REVISED_ROUND, consensus=True)

        assert after["sycophancy_detected"] is True
        assert debate_route(after, max_rounds=5) == ("revision", "sycophancy")

    def test_a_record_with_no_names_is_read_as_before(self) -> None:
        legacy = {"round": 1, "stage": "debate", "made": 2, "identical": False}
        after = _mediation_after(legacy, consensus=True)

        assert after["sycophancy_detected"] is True
        assert debate_route(after, max_rounds=5) == ("revision", "sycophancy")
