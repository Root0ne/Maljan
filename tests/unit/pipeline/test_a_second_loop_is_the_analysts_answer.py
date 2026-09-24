"""A second loop over the same material: its answer counts, and it is given only the time left.

On the small model three PE runs ended their first loop with no claim. The
node then ran the whole analyst again from scratch — through the text path,
whose answer was stored as prose and never parsed — with a fresh copy of the
1,500 s budget, whatever the first loop and its salvage had spent: 38–50
minutes of analysis and zero claims. Now the second loop is the ISR path, its
answer is carried like a first loop's, and it runs only when what is left of
the analyst's stage holds one turn and a final answer at the pace the first
loop measured; otherwise the stage record says why it did not.
"""

from __future__ import annotations

from typing import Any

from maljan.agents.base_agent import UNPARSED_ANSWER_REASON
from maljan.pipeline.nodes import make_stage_agent_node
from maljan.schemas.evidence import EvidenceCounter
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.stages import ANALYSIS_STAGE
from tests.unit.pipeline.test_evidence_ledger_channel import (
    _analysis_state,
    _Analyst,
    _Chunk,
    _container,
)


class _EmptyFirst(_Analyst):
    """An analyst whose first loop ends with nothing, and whose second answers."""

    def __init__(self, second: AgentISR, needs: float) -> None:
        super().__init__("static", EvidenceCounter())
        self.second = second
        self.needs = needs
        self.second_loops: list[float] = []

    def safe_analyze_isr(self, data: str) -> AgentISR:
        self._run_one_loop()
        return AgentISR(agent_id="static", domain="static")

    def seconds_a_loop_needs(self) -> float:
        return self.needs

    def safe_analyze_isr_within(self, data: str, seconds: float) -> AgentISR:
        self.second_loops.append(seconds)
        self._run_one_loop()
        return self.second


def _claims() -> AgentISR:
    return AgentISR(
        agent_id="static",
        domain="static",
        claims=[ClaimEvidence(claim="runs from memory", evidence_ref="[ev_0002]", confidence=0.8)],
    )


def _run(agent: _Analyst) -> dict[str, Any]:
    container = _container({"static": agent}, {"static": [_Chunk("ELF 64-bit executable.")]})
    return make_stage_agent_node(ANALYSIS_STAGE, "static", container)(_analysis_state())


def _reasons(update: dict[str, Any]) -> dict[str, str]:
    (result,) = update["stage_results"].values()
    return dict(result.get("agent_reasons") or {})


class TestTheSecondLoopsAnswerIsTheAnalysts:
    def test_its_claims_are_carried_like_a_first_loop_s(self) -> None:
        agent = _EmptyFirst(_claims(), needs=1.0)

        update = _run(agent)

        isr = update["isr_reports"]["static"]
        assert [claim.claim for claim in isr.claims] == ["runs from memory"]
        assert update["reports"]["static"] == isr.to_text_summary()
        assert _reasons(update) == {}

    def test_its_prose_is_the_report_when_it_parsed_into_nothing(self) -> None:
        prose = AgentISR(
            agent_id="static",
            domain="static",
            status="no_claims",
            status_reason=UNPARSED_ANSWER_REASON,
        )
        prose.note_parse(unparsed_answer="It downloads a payload and runs it from memory.")
        agent = _EmptyFirst(prose, needs=1.0)

        update = _run(agent)

        assert update["reports"]["static"] == "It downloads a payload and runs it from memory."
        assert update["isr_reports"]["static"].status_reason == UNPARSED_ANSWER_REASON

    def test_it_is_given_what_is_left_not_a_fresh_budget(self) -> None:
        agent = _EmptyFirst(_claims(), needs=1.0)
        timeout, _steps = agent._loop_limits()

        _run(agent)

        (given,) = agent.second_loops
        assert 0 < given <= timeout

    def test_one_that_also_ends_empty_says_so(self) -> None:
        agent = _EmptyFirst(AgentISR(agent_id="static", domain="static"), needs=1.0)

        update = _run(agent)

        assert update["reports"]["static"] == ""
        assert _reasons(update) == {
            "static": "a second loop over the same material ended empty too"
        }


class TestAStageThatCannotHoldIt:
    def test_the_loop_is_not_run_and_the_record_says_why(self) -> None:
        agent = _EmptyFirst(_claims(), needs=10_000_000.0)

        update = _run(agent)

        assert agent.second_loops == []
        assert update["isr_reports"]["static"].claims == []
        (reason,) = _reasons(update).values()
        assert reason.startswith("not run a second time: ")
        assert "a loop needs 10000000s at the pace its first loop measured" in reason


class TestAnAnalystThatAnswered:
    def test_prose_from_the_first_loop_is_not_asked_for_again(self) -> None:
        class _Prose(_EmptyFirst):
            def safe_analyze_isr(self, data: str) -> AgentISR:
                isr = AgentISR(
                    agent_id="static",
                    domain="static",
                    status="no_claims",
                    status_reason=UNPARSED_ANSWER_REASON,
                )
                isr.note_parse(unparsed_answer="A paragraph about the sample.")
                return isr

        agent = _Prose(_claims(), needs=1.0)

        update = _run(agent)

        assert agent.second_loops == []
        assert update["reports"]["static"] == "A paragraph about the sample."
