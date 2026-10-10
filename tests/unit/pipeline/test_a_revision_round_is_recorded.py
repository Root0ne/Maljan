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
    def test_answers_identical_after_whitespace_are_recorded_as_identical(self) -> None:
        update, _ = _run(
            {
                "static": ("static  in\nforce", IN_FORCE["static"]),
                "dynamic": ("dynamic in force", IN_FORCE["dynamic"]),
            }
        )

        assert update["revision_rounds"] == [
            {
                "round": 2,
                "stage": "debate",
                "made": 2,
                "identical": True,
                "revised": NAMES,
                "not_revised": {},
            }
        ]

    def test_one_reworded_answer_is_not_identical(self) -> None:
        update, _ = _run(
            {
                "static": ("static in force, reworded", IN_FORCE["static"]),
                "dynamic": ("dynamic in force", IN_FORCE["dynamic"]),
            },
            ledger={"static": 3},
        )

        assert update["revision_rounds"] == [
            {
                "round": 2,
                "stage": "debate",
                "made": 2,
                "identical": False,
                "revised": NAMES,
                "not_revised": {},
            }
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
        assert kwargs == {}


class TestDroppedValues:
    def test_a_value_stated_nowhere_is_recorded_with_its_sentence(self) -> None:
        update, _ = _run(
            {
                "static": ("Prose claim.", _isr("static", "Prose claim.")),
                "dynamic": ("Writes a file.", IN_FORCE["dynamic"]),
            }
        )

        rows = update["dropped_claims"]
        assert [(r["agent"], r["round"], r["claim"], r["missing"]) for r in rows] == [
            ("static", 2, "Opens a key at 0x40.", ["0x40"])
        ]
        assert "states nowhere 0x40" in rows[0]["sentence"]

    def test_the_log_counts_the_dropped_values_and_keeps_each_sentence_at_debug(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        with caplog.at_level(logging.DEBUG, logger="maljan"):
            _run(
                {
                    "static": ("Other.", _isr("static", "Other.")),
                    "dynamic": ("Writes a file.", IN_FORCE["dynamic"]),
                }
            )

        info = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
        debug = [r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG]
        counted = [m for m in info if "states nowhere" in m]
        assert counted == [
            "The static analyst's round-2 revision states nowhere 1 value(s) from 1 claim(s) "
            "of its answer in force; each is in the run summary."
        ]
        assert not any("Opens a key" in m for m in info)
        assert any("states nowhere 0x40" in m and "Opens a key" in m for m in debug)

    def test_a_value_the_revision_s_text_still_states_is_not_recorded(self) -> None:
        update, _ = _run(
            {
                "static": ("The key at 64 is opened.", _isr("static", "Prose claim.")),
                "dynamic": ("Writes a file.", IN_FORCE["dynamic"]),
            }
        )

        assert "dropped_claims" not in update

    def test_disputes_are_left_as_the_analyst_wrote_them(self) -> None:
        revision = _isr("static", "Opens a key at 0x40.", dissent=["WITHDRAWN: x — y"])
        update, _ = _run({"static": ("t", revision), "dynamic": ("t", IN_FORCE["dynamic"])})

        assert update["isr_reports"]["static"].dissent_items == ["WITHDRAWN: x — y"]


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
        assert record["mode"] == str(debate.mode)
        assert record["rounds_add_up"] is True
        # A debate whose revisions run in parallel still adds its rounds up.
        mediation = {debate.key: {**record, "mode": "parallel", "duration_ms": 1000}}
        revision = {debate.key: {**record, "mode": "parallel", "duration_ms": 3000}}
        merged = _merge_stage_results(mediation, revision)
        assert merged[debate.key]["duration_ms"] == 4000


class TestTheLedgerCountsRideOnCallsAlreadyMade:
    def _negotiate(self, lines: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]], Any]:
        notices: list[dict[str, Any]] = []
        container = MagicMock()
        container.is_mock = False
        container.event_sink = lambda kind, data: notices.append(data)
        container.analyst_keys.return_value = NAMES
        judge = MagicMock()
        argument = AgentArgument(
            agent_name="Mediator", finding="ok", confidence_score=0.9, contradictions=lines
        )
        judge.mediate = AsyncMock(return_value=(argument, False))
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
            update = asyncio.run(make_negotiation_node(container)(state))
        return update, notices, judge

    def test_the_mediation_states_the_counts_after_its_one_call(self) -> None:
        line = "DYNAMIC Claim 1 counts 41 [ev_0007]; STATIC Claim 1 counts 40."
        update, notices, judge = self._negotiate([line])

        assert judge.mediate.await_count == 1
        assert "ledger_counts" not in judge.mediate.call_args.kwargs
        argument = update["discussion_history"][0]
        assert len(argument.ledger_facts) == 1 and "total = 41" in argument.ledger_facts[0]
        assert any("entry ev_0007 (t) states total = 41" in str(n.get("text")) for n in notices)

    def test_a_line_marked_not_blocking_is_stated_too(self) -> None:
        notices: list[dict[str, Any]] = []
        container = MagicMock()
        container.is_mock = False
        container.event_sink = lambda kind, data: notices.append(data)
        container.analyst_keys.return_value = NAMES
        judge = MagicMock()
        line = "DYNAMIC Claim 1 counts 41 [ev_0007]; STATIC Claim 1 counts 40 [not blocking: tally]"
        argument = AgentArgument(
            agent_name="Mediator", finding="ok", confidence_score=0.9, not_blocking=[line]
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
            update = asyncio.run(make_negotiation_node(container)(state))

        assert update["discussion_history"][0].ledger_facts

    def test_no_line_no_count(self) -> None:
        update, _notices, _judge = self._negotiate([])

        assert update["discussion_history"][0].ledger_facts == []

    def test_a_revision_is_told_only_the_counts_of_the_lines_naming_it(self) -> None:
        argument = AgentArgument(
            agent_name="Mediator",
            finding="revise",
            ledger_facts=[
                'For the line "STATIC Claim 1 counts 41 [ev_0007]": entry ev_0007 (t) states '
                "total = 41."
            ],
        )
        container, agents = _container(
            {"static": ("t", IN_FORCE["static"]), "dynamic": ("t", IN_FORCE["dynamic"])}, {}
        )
        state = {**_state(), "discussion_history": [argument]}
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("maljan.pipeline.nodes._revision_input_is_absent", lambda *a: False)
            mp.setattr("maljan.pipeline.nodes._build_revision_context", lambda *a: "data")
            asyncio.run(make_revision_node(container)(state))

        told_static = agents["static"].safe_revise_isr.call_args.args[3]
        told_dynamic = agents["dynamic"].safe_revise_isr.call_args.args[3]
        assert told_static.startswith("revise")
        assert "entry ev_0007 (t) states total = 41" in told_static
        assert told_dynamic == "revise"


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
