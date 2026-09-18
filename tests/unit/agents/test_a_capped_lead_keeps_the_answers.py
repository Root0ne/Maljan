"""A lead that never wrote its report does not take its specialists' with it.

A lead's report is the only channel its chunk has out of a stage. One audited
chunk spent 1,830 s, got six specialist asks answered, wrote 52 evidence
entries — and merged zero claims, because the loop hit its wall-clock cap
before the lead wrote anything, and the answers lived only in the conversation
that died with it.

Two fallbacks, in order. The lead is given one bounded turn to write its report
from the answers it already has. If that turn fails too, the specialists' own
ISRs are promoted into the stage's merge, labelled with the agent that produced
them, so no completed ask is lost.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage

from maljan.agents.delegation import tool_name
from maljan.pipeline.nodes import promoted_asks
from tests.unit.agents.test_delegation import _call, _Container, _Scripted, _settings

HELPER_REPORT = (
    "CLAIM: the sample opens a raw socket\nEVIDENCE: ev_0001\nCONFIDENCE: 0.7\nTECHNIQUE: T1095\n"
)
LEAD_REPORT = (
    "CLAIM: the helper saw a raw socket\nEVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: T1095\n"
)

ASKS = 3


def _team(*, lead_answers: list[Any]) -> _Container:
    """A lead that asks three times, then answers with whatever it was given."""
    boss_script: list[Any] = [
        _call(tool_name("helper"), {"task": f"question {n}", "context": ""}, f"ask_{n}")
        for n in range(ASKS)
    ]
    boss_script.extend(lead_answers)
    return _Container(
        _settings(),
        models={
            "boss": _Scripted(script=boss_script),
            "helper": _Scripted(script=[AIMessage(content=HELPER_REPORT)] * ASKS),
        },
        tools={},
    )


def _lead(container: _Container) -> Any:
    boss = container.get_agent("boss")
    boss.pipeline_stage = "lead"
    boss.facts_block = "Facts established before analysis (ledger ids in brackets)\n[ev_0001] x"
    boss.run_state_block = "sample: s"
    boss._analysis_file_path = "/samples/s.bin"
    return boss


def _capped() -> Any:
    """A lead whose own turn dies after the asks are answered."""
    container = _team(lead_answers=[TimeoutError("the loop exceeded its hard cap")])
    return _lead(container)


class TestTheLeadWritesItsReportFromTheAnswers:
    def test_the_salvage_turn_produces_the_missing_report(self) -> None:
        container = _team(
            lead_answers=[
                TimeoutError("the loop exceeded its hard cap"),
                AIMessage(content=LEAD_REPORT),
            ]
        )
        boss = _lead(container)

        isr = boss.safe_analyze_isr("Lead this analysis.")

        assert [claim.technique_id for claim in isr.claims] == ["T1095"]
        assert isr.agent_id == "boss"

    def test_the_salvage_turn_is_shown_every_answer_it_has(self) -> None:
        container = _team(
            lead_answers=[
                TimeoutError("the loop exceeded its hard cap"),
                AIMessage(content=LEAD_REPORT),
            ]
        )
        boss = _lead(container)

        boss.safe_analyze_isr("Lead this analysis.")

        last = "\n".join(str(getattr(turn, "content", turn)) for turn in boss.llm.seen[-1])
        assert last.count("ANSWER FROM helper") == ASKS
        assert "raw socket" in last


class TestWhenTheLeadCannotAnswerAtAll:
    """The salvage turn is given nothing to say either, which is a real run's
    other half: the model that could not finish its loop cannot always write a
    report from the answers once the budget is spent."""

    def test_the_lead_reports_no_claims(self) -> None:
        boss = _capped()

        isr = boss.safe_analyze_isr("Lead this analysis.")

        assert isr.claims == []

    def test_every_answered_ask_is_still_on_the_lead(self) -> None:
        boss = _capped()
        boss.safe_analyze_isr("Lead this analysis.")

        answers = boss.answered_asks()
        assert len(answers) == ASKS
        assert {isr.agent_id for isr in answers} == {"helper"}
        assert [claim.confidence for claim in answers[0].claims] == [0.7]

    def test_the_stage_promotes_them_under_their_own_agent(self) -> None:
        boss = _capped()
        own = boss.safe_analyze_isr("Lead this analysis.")

        promoted = promoted_asks(boss, own)

        assert list(promoted) == ["helper"]
        assert [claim.technique_id for claim in promoted["helper"].claims] == ["T1095"]
        # The specialist's own numbers and its own id, unedited.
        assert [claim.confidence for claim in promoted["helper"].claims] == [0.7]
        assert promoted["helper"].agent_id == "helper"


class TestNothingIsPromotedBesideAReportThatExists:
    def test_a_lead_that_answered_promotes_nothing(self) -> None:
        container = _team(lead_answers=[AIMessage(content=LEAD_REPORT)])
        boss = _lead(container)

        isr = boss.safe_analyze_isr("Lead this analysis.")

        assert isr.claims
        assert promoted_asks(boss, isr) == {}

    def test_an_agent_that_delegated_nothing_promotes_nothing(self) -> None:
        container = _team(lead_answers=[AIMessage(content=LEAD_REPORT)])
        helper = container.get_agent("helper")

        assert promoted_asks(helper) == {}
