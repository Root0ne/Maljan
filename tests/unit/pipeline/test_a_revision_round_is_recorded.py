"""What a revision round records: whether it changed anything, what it added, what it dropped.

The router ends a debate whose last revision round changed nothing, and lets
the sycophancy check ask again only when that round added no ledger entry, so
each round writes one record of both. A revision is made against the
analyst's answer in force, and the peers' answers in force, rather than the
first answers of the debate: that is what the mediator read. A claim the
revision dropped is recorded per analyst and round. The round's own time is
added to the debate stage's, so the run summary's duration is the time the
debate took, mediations and revisions both. Every value is synthetic.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.pipeline.nodes import make_negotiation_node, make_revision_node
from maljan.pipeline.state import AgentArgument, _merge_stage_results
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.stages import paper_profile

NAMES = ["static", "dynamic"]


def _isr(name: str, *claims: str, dissent: list[str] | None = None, answer: str = "") -> AgentISR:
    isr = AgentISR(
        agent_id=name,
        domain="static",
        claims=[ClaimEvidence(claim=c, evidence_ref="[ev_0001]", confidence=0.8) for c in claims],
        dissent_items=dissent or [],
    )
    if answer:
        isr.note_answer_text(answer)
    return isr


def _container(outcomes: dict[str, tuple[str, AgentISR]], ledger: dict[str, int]) -> Any:
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
        entries = []
        for i in range(ledger.get(name, 0)):
            entry = MagicMock()
            entry.model_dump.return_value = {"id": f"ev_01{i:02d}", "tool": "t"}
            entries.append(entry)
        agent.drain_evidence_entries.return_value = entries
        agent.validation_findings = []
        agent.validation_retries = 0
        agent.validation_fed_back = {}
        agent.validation_not_run = []
        agents[name] = agent
    container.get_agent.side_effect = lambda n: agents[n]
    return container, agents


IN_FORCE = {
    "static": _isr("static", "Opens a key at 0x40.", "Prose claim."),
    "dynamic": _isr("dynamic", "Writes a file."),
}


def _state() -> dict[str, Any]:
    return {
        "iteration_count": 2,
        "reports": {"static": "static first", "dynamic": "dynamic first"},
        "revised_reports": {"static": "static in force", "dynamic": "dynamic in force"},
        "isr_reports": dict(IN_FORCE),
        "discussion_history": [AgentArgument(agent_name="Mediator", finding="revise")],
    }


def _run(outcomes: dict[str, tuple[str, AgentISR]], ledger: dict[str, int] | None = None) -> Any:
    container, agents = _container(outcomes, ledger or {})
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("maljan.pipeline.nodes._revision_input_is_absent", lambda *a: False)
        mp.setattr("maljan.pipeline.nodes._build_revision_context", lambda *a: "data")
        update = asyncio.run(make_revision_node(container)(_state()))
    return update, agents


class TestTheRoundRecord:
    def test_a_round_that_wrote_the_same_answers_changed_nothing(self) -> None:
        update, _ = _run(
            {
                "static": ("t", _isr("static", "Opens a key at 0x40 (reworded).", "Prose claim.")),
                "dynamic": ("t", _isr("dynamic", "Writes a file.")),
            }
        )

        assert update["revision_rounds"] == [
            {"round": 2, "made": 2, "changed": False, "new_evidence": 0}
        ]

    def test_a_new_claim_and_new_entries_are_recorded(self) -> None:
        update, _ = _run(
            {
                "static": (
                    "t",
                    _isr("static", "Opens a key at 0x40.", "Prose claim.", "New 0x99."),
                ),
                "dynamic": ("t", _isr("dynamic", "Writes a file.")),
            },
            ledger={"static": 3},
        )

        assert update["revision_rounds"] == [
            {"round": 2, "made": 2, "changed": True, "new_evidence": 3}
        ]


class TestTheAnswerInForceIsRevised:
    def test_the_analyst_is_shown_its_answer_and_its_peers_in_force(self) -> None:
        _update, agents = _run(
            {
                "static": ("t", IN_FORCE["static"]),
                "dynamic": ("t", IN_FORCE["dynamic"]),
            }
        )

        args, kwargs = agents["static"].safe_revise_isr.call_args
        assert args[1] == "static in force"
        assert args[2] == {"dynamic": "dynamic in force"}
        assert kwargs["in_force"] is IN_FORCE["static"]


class TestDroppedClaims:
    def test_a_dropped_claim_is_recorded_with_its_sentence(self) -> None:
        update, _ = _run(
            {
                "static": ("t", _isr("static", "Prose claim.")),
                "dynamic": ("t", IN_FORCE["dynamic"]),
            }
        )

        rows = update["dropped_claims"]
        assert [(r["agent"], r["round"], r["claim"]) for r in rows] == [
            ("static", 2, "Opens a key at 0x40.")
        ]
        assert "not withdrawn" in rows[0]["sentence"]

    def test_a_withdrawal_line_is_no_dispute(self) -> None:
        answer = "CLAIM: Prose claim.\nDISPUTES:\n- WITHDRAWN: 0x40 — it was a stack offset.\n"
        revision = _isr(
            "static",
            "Prose claim.",
            dissent=["WITHDRAWN: 0x40 — it was a stack offset.", "dynamic overstates it"],
            answer=answer,
        )
        update, _ = _run({"static": ("t", revision), "dynamic": ("t", IN_FORCE["dynamic"])})

        assert update["isr_reports"]["static"].dissent_items == ["dynamic overstates it"]
        assert update["dropped_claims"][0]["reason"] == "it was a stack offset."


class TestTheDebateDuration:
    def test_a_revision_round_adds_its_own_time_to_the_debate_stage(self) -> None:
        profile = paper_profile(NAMES)
        debate = next(s for s in profile.stages if s.kind == "debate")
        container, _agents = _container(
            {"static": ("t", IN_FORCE["static"]), "dynamic": ("t", IN_FORCE["dynamic"])}, {}
        )
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("maljan.pipeline.nodes._revision_input_is_absent", lambda *a: False)
            mp.setattr("maljan.pipeline.nodes._build_revision_context", lambda *a: "data")
            mp.setattr("maljan.pipeline.nodes._debate_participants", lambda *a: NAMES)
            update = asyncio.run(make_revision_node(container, stage=debate)(_state()))

        record = update["stage_results"][debate.key]
        assert record["ran"] is True
        assert record["mode"] == "sequential"
        mediation = {debate.key: {**record, "duration_ms": 1000}}
        revision = {debate.key: {**record, "duration_ms": 3000}}
        merged = _merge_stage_results(mediation, revision)
        assert merged[debate.key]["duration_ms"] == 4000


class TestTheMediationIsHandedTheSettler:
    def test_the_negotiation_node_passes_a_settler_over_the_answers_in_force(self) -> None:
        notices: list[dict[str, Any]] = []
        container = MagicMock()
        container.is_mock = False
        container.event_sink = lambda kind, data: notices.append(data)
        container.analyst_keys.return_value = NAMES
        judge = MagicMock()
        argument = AgentArgument(
            agent_name="Mediator",
            finding="ok",
            confidence_score=0.9,
            closed=["Closed: dynamic claim(s) 9 are not in its answer in force."],
        )
        judge.mediate = AsyncMock(return_value=(argument, True))
        container.get_judge_agent.return_value = judge
        state = {
            "iteration_count": 1,
            "reports": {"static": "r", "dynamic": "r"},
            "isr_reports": dict(IN_FORCE),
            "evidence_ledger": [{"id": "ev_0007", "tool": "t", "structured": {"total": 41}}],
        }

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("maljan.pipeline.nodes.pack_text", lambda *a: "")
            mp.setattr("maljan.pipeline.nodes.render_run_state", lambda *a: "")
            asyncio.run(make_negotiation_node(container)(state))

        settle = judge.mediate.call_args.kwargs["settle_contradictions"]
        result = settle(["DYNAMIC Claim 9 — contradicted by STATIC Claim 1."])
        assert result.standing == [] and len(result.closed) == 1
        assert any("Closed: dynamic claim(s) 9" in str(n.get("text")) for n in notices)


class TestTheSummaryReadsTheDebatesOwnOptions:
    def test_the_limit_and_the_switch_come_from_the_debate_stage(self) -> None:
        from maljan.pipeline.nodes import debate_options

        profile = paper_profile(NAMES)
        debate = next(s for s in profile.stages if s.kind == "debate")
        debate.debate.max_rounds = 3
        debate.debate.sycophancy_check = False
        container = MagicMock()
        container.config.negotiation.max_iterations = 7
        container.active_profile.return_value = profile

        assert debate_options(container) == (3, False)

    def test_a_profile_without_a_debate_reads_the_global_limit(self) -> None:
        from maljan.pipeline.nodes import debate_options

        container = MagicMock()
        container.config.negotiation.max_iterations = 7
        container.active_profile.side_effect = RuntimeError("no profile")

        assert debate_options(container) == (7, True)
