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

import pytest
from langchain_core.messages import AIMessage

from maljan.agents.delegation import tool_name
from maljan.pipeline.nodes import promoted_asks
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.unit.agents.test_delegation import _call, _Container, _Scripted, _settings

HELPER_REPORT = (
    "CLAIM: the sample opens a raw socket\nEVIDENCE: ev_0001\nCONFIDENCE: 0.7\nTECHNIQUE: T1095\n"
)
LEAD_REPORT = (
    "CLAIM: the helper saw a raw socket\nEVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: T1095\n"
)

ASKS = 3

# What the audited chunk did: six asks across a small roster, several of them
# to the same specialist — the imports, then the strings, then the packer.
AUDITED = ("helper", "helper", "third", "helper", "third", "helper")


def _report_for(specialist: str, n: int) -> str:
    """One specialist's answer to its nth ask, distinguishable from the others."""
    return (
        f"CLAIM: {specialist} answered ask {n}\n"
        "EVIDENCE: ev_0001\n"
        f"CONFIDENCE: 0.{n + 1}\n"
        f"TECHNIQUE: T109{n}\n"
    )


def _team(*, lead_answers: list[Any], asks: tuple[str, ...] | None = None) -> _Container:
    """A lead that asks, then answers with whatever it was given."""
    roster = asks if asks is not None else ("helper",) * ASKS
    boss_script: list[Any] = [
        _call(tool_name(specialist), {"task": f"question {n}", "context": ""}, f"ask_{n}")
        for n, specialist in enumerate(roster)
    ]
    boss_script.extend(lead_answers)
    counts: dict[str, int] = {}
    scripts: dict[str, list[Any]] = {}
    for specialist in roster:
        counts[specialist] = counts.get(specialist, 0) + 1
        scripts.setdefault(specialist, []).append(
            AIMessage(content=_report_for(specialist, counts[specialist] - 1))
        )
    models: dict[str, Any] = {"boss": _Scripted(script=boss_script)}
    for specialist, script in scripts.items():
        models[specialist] = _Scripted(script=script)
    # The lead is bound to every specialist it asks, which is what a team that
    # gives one agent the others as tools looks like.
    settings = _settings(
        definitions={
            "boss": {
                "role": "lead",
                "prompt": "You lead.",
                "tools": [{"kind": "agent", "agent": key} for key in dict.fromkeys(roster)],
            }
        }
    )
    return _Container(settings, models=models, tools={})


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
        assert "helper answered ask 0" in last


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
        assert [claim.confidence for claim in answers[0].claims] == [0.1]

    def test_the_stage_promotes_every_one_of_them(self) -> None:
        boss = _capped()
        own = boss.safe_analyze_isr("Lead this analysis.")

        promoted = promoted_asks(boss, own)

        assert list(promoted) == ["helper#1", "helper#2", "helper#3"]
        assert [isr.agent_id for isr in promoted.values()] == ["helper"] * ASKS

    def test_each_answer_keeps_its_own_claims(self) -> None:
        boss = _capped()
        own = boss.safe_analyze_isr("Lead this analysis.")

        promoted = promoted_asks(boss, own)

        assert [claim.technique_id for isr in promoted.values() for claim in isr.claims] == [
            "T1090",
            "T1091",
            "T1092",
        ]
        # The specialist's own numbers, unedited.
        assert [claim.confidence for isr in promoted.values() for claim in isr.claims] == [
            0.1,
            0.2,
            0.3,
        ]


class TestTheShapeTheAuditSaw:
    """Six answered asks across two specialists, and a lead with no report.

    The class above drives the real delegation: three asks to one specialist,
    a lead whose own turn dies, and the answers still on it afterwards. What
    this adds is the shape the audited chunk had — six answers, two
    specialists, interleaved — and what the stage makes of it, so the answers
    are handed to the lead the way the delegation hands them over.
    """

    @staticmethod
    def _answered() -> Any:
        container = _team(lead_answers=[], asks=AUDITED)
        boss = _lead(container)
        counts: dict[str, int] = {}
        for specialist in AUDITED:
            counts[specialist] = counts.get(specialist, 0) + 1
            boss.remember_answered_ask(
                AgentISR(
                    agent_id=specialist,
                    domain=specialist,
                    claims=[
                        ClaimEvidence(
                            claim=f"{specialist} answered ask {counts[specialist] - 1}",
                            evidence_ref="[ev_0001] the entry it read",
                            confidence=0.1 * counts[specialist],
                            technique_id="T1095",
                        )
                    ],
                )
            )
        return boss

    def test_no_completed_ask_is_lost(self) -> None:
        promoted = promoted_asks(self._answered())

        assert len(promoted) == len(AUDITED)
        assert list(promoted) == [
            "helper#1",
            "helper#2",
            "third#1",
            "helper#3",
            "third#2",
            "helper#4",
        ]

    def test_the_order_is_the_order_the_lead_asked_in(self) -> None:
        promoted = promoted_asks(self._answered())

        assert [isr.agent_id for isr in promoted.values()] == list(AUDITED)

    def test_each_answer_keeps_the_claims_its_specialist_made(self) -> None:
        promoted = promoted_asks(self._answered())

        assert [claim.claim for isr in promoted.values() for claim in isr.claims] == [
            "helper answered ask 0",
            "helper answered ask 1",
            "third answered ask 0",
            "helper answered ask 2",
            "third answered ask 1",
            "helper answered ask 3",
        ]

    def test_the_salvage_turn_would_be_shown_all_of_them(self) -> None:
        shown = self._answered().answered_asks()

        assert [isr.agent_id for isr in shown] == list(AUDITED)


class TestTheSalvageCannotChangeHowAFailureIsReported:
    """It runs inside the handler that is reporting the original failure."""

    def test_a_truncate_that_raises_is_not_asked_a_second_time(self) -> None:
        from maljan.core.exceptions import AnalystError

        container = _team(lead_answers=[], asks=("helper",))
        boss = _lead(container)
        boss.remember_answered_ask(
            AgentISR(
                agent_id="helper",
                domain="helper",
                claims=[
                    ClaimEvidence(
                        claim="helper answered ask 0",
                        evidence_ref="[ev_0001] the entry it read",
                        confidence=0.7,
                        technique_id="T1095",
                    )
                ],
            )
        )
        calls: list[str] = []

        def _explode(data: str) -> str:
            calls.append(data)
            raise RuntimeError("the input could not be trimmed")

        boss._truncate_input = _explode  # type: ignore[method-assign]

        with pytest.raises(AnalystError):
            boss.safe_analyze_isr("Lead this analysis.")

        assert len(calls) == 1, "the handler does not run it again"

    def test_a_salvage_that_cannot_be_checked_leaves_the_failure(self) -> None:
        from maljan.core.exceptions import AnalystError

        container = _team(lead_answers=[], asks=("helper",))
        boss = _lead(container)
        boss._synthesise_from_answered_asks = lambda: (_ for _ in ()).throw(  # type: ignore[method-assign]
            RuntimeError("the salvage turn broke")
        )
        boss.analyze_isr = lambda data: (_ for _ in ()).throw(  # type: ignore[method-assign]
            AnalystError("the loop failed")
        )

        with pytest.raises(AnalystError, match="the loop failed"):
            boss.safe_analyze_isr("Lead this analysis.")


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
