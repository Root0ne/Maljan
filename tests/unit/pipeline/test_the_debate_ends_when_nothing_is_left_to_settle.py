"""The debate ends when nothing is left to settle, and runs while something is.

The rules, in the order the router applies them:

- the hard round limit still ends every debate;
- a mediation that failed, or a debate where consensus does not apply, goes
  to the judge;
- a revision round whose every revision is the answer in force again,
  whitespace aside, means the debate converged: it ends;
- a revision round in which no analyst was revised made no change: it ends,
  by consensus where the mediator stated one and as ``not_revised`` otherwise;
- the sycophancy check sends an agreement it flags back to revise, as it did;
- consensus ends it: the confidence meets the threshold and no listed line is
  one the mediator marked blocking or left unmarked;
- a stable agreement with no line standing ends it;
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
from maljan.pipeline.debate_facts import LEDGER_FACTS_HEAD
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


def _round(identical: bool, made: int = 3, round_: int = 1) -> dict[str, Any]:
    return {"round": round_, "stage": "debate", "made": made, "identical": identical}


def _state(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "iteration_count": 2,
        "is_consensus": False,
        "sycophancy_detected": False,
        "confidence_history": [0.6, 0.9],
        "discussion_history": [_mediator(["a: x — ev_0001"])],
        "isr_reports": {},
        "revision_rounds": [_round(identical=False)],
    }
    base.update(over)
    return base


def _router(max_rounds: int = 5) -> ConsensusRouter:
    settings = Settings()
    settings.negotiation.max_iterations = max_rounds
    return ConsensusRouter(settings)


class TestARoundOfIdenticalAnswers:
    def test_ends_the_debate_as_converged(self) -> None:
        state = _state(revision_rounds=[_round(identical=True)])

        assert debate_route(state, max_rounds=5) == ("judge", "converged")
        assert _router().should_continue(state) == "judge"

    def test_ends_it_even_with_a_contradiction_still_listed(self) -> None:
        state = _state(
            discussion_history=[_mediator(["a: x — b: y"])],
            revision_rounds=[_round(identical=True, made=2)],
        )

        assert debate_route(state, max_rounds=5)[1] == "converged"

    def test_a_round_whose_every_revision_failed_is_not_convergence_and_ends_unrevised(
        self,
    ) -> None:
        # No revision stood, so the round made no change: the answers in force
        # go to the judge, and no agreement is claimed for them.
        state = _state(revision_rounds=[_round(identical=False, made=0)])

        assert debate_route(state, max_rounds=5) == ("judge", "not_revised")

    def test_a_round_with_a_changed_answer_goes_on_while_a_line_stands(self) -> None:
        assert debate_route(_state(), max_rounds=5)[0] == "revision"

    def test_a_record_of_an_earlier_round_is_not_this_round_s(self) -> None:
        # The last record belongs to a debate stage that ended before this one.
        state = _state(iteration_count=4, revision_rounds=[_round(identical=True, round_=2)])

        assert debate_route(state, max_rounds=9)[0] == "revision"


class TestTheSycophancyCheckIsAsItWas:
    def _agreed(self, **over: Any) -> dict[str, Any]:
        return _state(
            is_consensus=True,
            sycophancy_detected=True,
            discussion_history=[_mediator([])],
            **over,
        )

    def test_flagged_agreement_is_sent_back(self) -> None:
        assert debate_route(self._agreed(), max_rounds=5) == ("revision", "sycophancy")

    def test_whatever_the_round_before_added_to_the_ledger(self) -> None:
        state = self._agreed(revision_rounds=[{**_round(identical=False), "new_evidence": 40}])

        assert debate_route(state, max_rounds=5) == ("revision", "sycophancy")

    def test_a_forced_revision_that_returned_the_same_answers_is_not_forced_again(self) -> None:
        state = self._agreed(revision_rounds=[_round(identical=True)])

        assert debate_route(state, max_rounds=5) == ("judge", "converged")

    def test_switched_off_it_asks_nothing(self) -> None:
        assert debate_route(self._agreed(), max_rounds=5, sycophancy_check=False) == (
            "judge",
            "consensus",
        )


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
        )

        assert debate_route(state, max_rounds=5) == ("judge", "hard_limit")

    def test_at_the_limit_only_the_limit_is_logged(self, caplog: Any) -> None:
        import logging

        state = _state(
            iteration_count=5,
            is_consensus=True,
            sycophancy_detected=True,
            discussion_history=[_mediator([])],
        )
        with caplog.at_level(logging.INFO, logger="maljan"):
            debate_route(state, max_rounds=5)

        said = " ".join(r.getMessage() for r in caplog.records)
        assert "Hard iteration limit" in said
        assert "Sycophancy override" not in said


class TestTheRunSummarySaysWhatEndedIt:
    def _negotiation(self, state: dict[str, Any], max_rounds: int = 5) -> Any:
        return (
            RunSummaryBuilder(start_time=0.0)
            .set_negotiation(state, max_iterations=max_rounds)
            .build()
            .negotiation
        )

    def test_a_converged_debate_says_converged_and_early(self) -> None:
        negotiation = self._negotiation(_state(revision_rounds=[_round(identical=True)]))

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
        )
        negotiation = (
            RunSummaryBuilder(start_time=0.0)
            .set_negotiation(state, max_iterations=5, sycophancy_check=False)
            .build()
            .negotiation
        )

        assert negotiation.termination_reason == "consensus"

    def test_marks_facts_and_dropped_values_are_recorded(self) -> None:
        argument = _mediator([])
        argument.not_blocking.append("a vs b on a count [not blocking: a tally]")
        argument.ledger_facts.append('For the line "a vs b": entry ev_0007 states total = 41.')
        state = _state(
            is_consensus=True,
            discussion_history=[argument],
            dropped_claims=[{"agent": "beta", "round": 2, "sentence": "beta states nowhere 0x10."}],
        )

        negotiation = self._negotiation(state)

        assert negotiation.not_blocking == ["a vs b on a count [not blocking: a tally]"]
        assert len(negotiation.ledger_facts) == 1
        assert negotiation.dropped_claims == ["beta states nowhere 0x10."]
        as_dict = (
            RunSummaryBuilder(start_time=0.0)
            .set_negotiation(state, max_iterations=5)
            .build()
            .to_dict()["negotiation"]
        )
        assert as_dict["dropped_claims"] == ["beta states nowhere 0x10."]
        assert as_dict["not_blocking"] and as_dict["ledger_facts"]

    def test_dropped_values_are_counted_per_analyst_and_round(self) -> None:
        rows = [
            {"agent": "beta", "round": 2, "missing": ["0x10", "0x20"], "sentence": "s1"},
            {"agent": "beta", "round": 2, "missing": ["0x30"], "sentence": "s2"},
            {"agent": "gamma", "round": 3, "missing": ["T1059"], "sentence": "s3"},
        ]
        as_dict = (
            RunSummaryBuilder(start_time=0.0)
            .set_negotiation(_state(dropped_claims=rows), max_iterations=5)
            .build()
            .to_dict()["negotiation"]
        )

        assert as_dict["dropped_value_counts"] == [
            {"agent": "beta", "round": 2, "values": 3, "claims": 2},
            {"agent": "gamma", "round": 3, "values": 1, "claims": 1},
        ]

    def test_unread_marks_and_the_last_round_s_not_blocking_count_are_recorded(self) -> None:
        earlier = _mediator([])
        earlier.not_blocking.extend(["x [not blocking: r]", "y [not blocking: r]"])
        last = _mediator([])
        last.not_blocking.append("z [not blocking: r]")
        last.unread_marks.append("w [not blocking]")
        as_dict = (
            RunSummaryBuilder(start_time=0.0)
            .set_negotiation(
                _state(is_consensus=True, discussion_history=[earlier, last]), max_iterations=5
            )
            .build()
            .to_dict()["negotiation"]
        )

        assert as_dict["unread_marks"] == ["w [not blocking]"]
        assert as_dict["not_blocking_at_end"] == 1


# ---------------------------------------------------------------------------
# The mediation reads the mediator's marks, and puts the ledger's counts to it
# ---------------------------------------------------------------------------


def _block(*lines: str) -> str:
    return (
        "The analysts agree on the core record.\n\nCONTRADICTIONS:\n"
        + "".join(f"- {line}\n" for line in lines)
        + "agreement_confidence: 0.9"
    )


class _Model:
    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.sent: list[Any] = []

    async def ainvoke(self, messages: Any, **_kw: Any) -> AIMessage:
        self.sent.append(messages)
        return AIMessage(content=self.answers.pop(0))

    def with_structured_output(self, _schema: Any) -> Any:
        return RunnableLambda(
            lambda _in: MediatorVerdict(contradictions=[], resolution_summary="", confidence=0.9)
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


def _mediate(
    model: _Model, history: list[AgentArgument] | None = None
) -> tuple[AgentArgument, bool | None]:
    judge = JudgeAgent(llm=model)  # type: ignore[arg-type]
    with patch.object(judge, "_supports_structured_output", return_value=False):
        return asyncio.run(
            judge.mediate(
                {"gamma": "r", "beta": "r"},
                history or [],
                isr_reports=_isrs(),
                consensus_threshold=0.85,
            )
        )


COUNT_LINE = "GAMMA Claim 2 counts 41 [ev_0007]; BETA Claim 1 counts 40"
TECHNIQUE_LINE = "GAMMA Claim 1 says T1055; BETA Claim 2 says it does not"


class TestTheMediatorDecides:
    def test_an_unmarked_line_blocks_as_before(self) -> None:
        argument, is_consensus = _mediate(_Model(_block(COUNT_LINE)))

        assert is_consensus is False
        assert argument.contradictions == [COUNT_LINE]
        assert argument.not_blocking == []

    def test_a_line_marked_not_blocking_leaves_consensus(self) -> None:
        line = f"{COUNT_LINE} [not blocking: a tally, no reported fact]"
        argument, is_consensus = _mediate(_Model(_block(line)))

        assert is_consensus is True
        assert argument.contradictions == []
        assert argument.not_blocking == [line]
        assert line in argument.finding

    def test_a_technique_line_the_mediator_marks_not_blocking_is_not_overridden(self) -> None:
        line = f"{TECHNIQUE_LINE} [not blocking: both now call it a lead]"
        _argument, is_consensus = _mediate(_Model(_block(line)))

        assert is_consensus is True

    def test_one_blocking_line_beside_a_non_blocking_one_keeps_the_round_open(self) -> None:
        lines = [
            f"{COUNT_LINE} [not blocking: a tally]",
            f"{TECHNIQUE_LINE} [blocking: the technique is published]",
        ]
        argument, is_consensus = _mediate(_Model(_block(*lines)))

        assert is_consensus is False
        assert argument.contradictions == [lines[1]]

    def test_a_mark_that_was_not_read_blocks_and_is_kept_on_the_argument(self) -> None:
        line = f"{COUNT_LINE} [blocking: r] [not blocking: r2]"
        argument, is_consensus = _mediate(_Model(_block(line)))

        assert is_consensus is False
        assert argument.contradictions == [line]
        assert argument.unread_marks == [line]

    def test_a_reason_citing_ledger_ids_in_brackets_is_honoured(self) -> None:
        line = f"{COUNT_LINE} [not blocking: the entries state both, see [ev_0007] and [ev_0008]]"
        argument, is_consensus = _mediate(_Model(_block(line)))

        assert is_consensus is True
        assert argument.unread_marks == []


class TestTheLedgerCountsCostNoCall:
    def test_a_mediation_makes_its_one_call_and_asks_nothing_more(self) -> None:
        model = _Model(_block(COUNT_LINE))

        _argument, is_consensus = _mediate(model)

        assert len(model.sent) == 1
        assert is_consensus is False

    def test_the_next_mediation_s_prompt_carries_the_last_round_s_counts(self) -> None:
        earlier = AgentArgument(
            agent_name="Mediator",
            finding="x",
            confidence_score=0.9,
            contradictions=[COUNT_LINE],
            ledger_facts=['For the line "x": entry ev_0007 (t) states total = 41.'],
        )
        model = _Model(_block())

        _mediate(model, history=[earlier])

        prompt = " ".join(str(m.content) for m in model.sent[0])
        assert "entry ev_0007 (t) states total = 41" in prompt
        assert LEDGER_FACTS_HEAD in prompt
