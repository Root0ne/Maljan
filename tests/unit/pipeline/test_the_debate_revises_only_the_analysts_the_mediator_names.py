"""A revision round asks only the analysts the mediator names in a contested point.

The mediator opens each line of its final ``CONTRADICTIONS:`` block with an
``[analysts: <name>, ...]`` field naming the analysts who must revise over it.
The platform reads that field and nothing else of the line's prose:

- a revision round asks the analysts its blocking lines name; an analyst no
  blocking line names keeps its answer in force, recorded as not named;
- a block that lists no blocking line schedules no revision round;
- a blocking line without a readable field (or naming no analyst of the
  debate), a block that was not read, or a sycophancy override asks every
  analyst, as before, and the round's record says why;
- a named analyst's revision carries the contested points that name it and,
  of its peers, only the ones those points name (in the field, or by the
  name their report is headed with): the claims they cite by number, or the
  peer's whole answer in force where a point names the peer without citing
  its claims.

Every value is synthetic.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.core.config import Settings
from maljan.pipeline.debate_facts import (
    ANALYSTS_FIELD_MISSING_NOTE,
    BLOCK_NOT_READ_NOTE,
    analysts_field_unknown_note,
    analysts_to_revise,
    contested_input,
    read_analysts_field,
)
from maljan.pipeline.mediation_models import CONTRADICTIONS_BLOCK_MISSING_NOTE
from maljan.pipeline.nodes import (
    NOT_NAMED_BY_MEDIATOR,
    make_negotiation_node,
    make_revision_node,
    sycophancy_asks_every_analyst,
)
from maljan.pipeline.routing import (
    CONSENSUS,
    CONVERGENCE,
    NO_CONSENSUS,
    NO_CONTESTED_POINT,
    SYCOPHANCY,
    ConsensusRouter,
    debate_route,
)
from maljan.pipeline.state import AgentArgument
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

NAMES = ["static", "all_tools_static_r2", "dynamic", "network"]

LINE_STATIC_R2 = (
    "[analysts: ALL_TOOLS_STATIC_R2] ALL_TOOLS_STATIC_R2 Claim 2 says no check at 0x40 — "
    "contradicted by STATIC Claim 1 and [ev_0007]. [blocking: they refute each other]"
)
LINE_STATIC = (
    "[analysts: STATIC ANALYST, dynamic] STATIC says no mutex — contradicted by DYNAMIC and "
    "[ev_0009]. [blocking: the ledger refutes it]"
)
LINE_NOT_BLOCKING = (
    "[analysts: network] NETWORK calls the host live — wording only. "
    "[not blocking: no fact turns on it]"
)


def _isr(name: str, *claims: str) -> AgentISR:
    return AgentISR(
        agent_id=name,
        domain=name,
        claims=[
            ClaimEvidence(claim=c, evidence_ref=f"[ev_00{i + 10}]", confidence=0.8)
            for i, c in enumerate(claims)
        ],
    )


IN_FORCE = {
    "static": _isr("static", "Reads the flag at 0x40.", "Opens a key."),
    "all_tools_static_r2": _isr("all_tools_static_r2", "Lists exports.", "No check at 0x40."),
    "dynamic": _isr("dynamic", "Creates a mutex."),
    "network": _isr("network", "The host is live."),
}
FINDING = (
    "The reports agree on the loader.\n\n"
    f"Contradictions: {LINE_STATIC_R2}; {LINE_STATIC}; {LINE_NOT_BLOCKING}\n"
    "Confidence: 0.60"
)


def _mediator(
    *, revise: list[str] | None, note: str = "", lines: list[str] | None = None
) -> AgentArgument:
    blocking = [LINE_STATIC_R2, LINE_STATIC] if lines is None else lines
    return AgentArgument(
        agent_name="Mediator",
        finding=FINDING,
        confidence_score=0.6,
        contradictions=blocking,
        not_blocking=[LINE_NOT_BLOCKING],
        revise=revise,
        revise_note=note,
    )


# ---------------------------------------------------------------------------
# The field and who it names
# ---------------------------------------------------------------------------


class TestTheField:
    def test_the_names_are_read_as_written(self) -> None:
        assert read_analysts_field(LINE_STATIC) == ["STATIC ANALYST", "dynamic"]

    def test_a_line_without_the_field_reads_none(self) -> None:
        assert read_analysts_field("STATIC says no mutex. [blocking: refuted]") is None

    def test_an_empty_field_reads_none(self) -> None:
        assert read_analysts_field("[analysts: ] STATIC says x. [blocking: y]") is None

    def test_the_blocking_lines_name_the_analysts_in_roster_order(self) -> None:
        named, note = analysts_to_revise([LINE_STATIC_R2, LINE_STATIC], NAMES)

        assert named == ["static", "all_tools_static_r2", "dynamic"]
        assert note == ""

    def test_no_blocking_line_names_nobody(self) -> None:
        assert analysts_to_revise([], NAMES) == ([], "")

    def test_a_blocking_line_without_the_field_reads_none_with_its_note(self) -> None:
        named, note = analysts_to_revise([LINE_STATIC, "STATIC says x. [blocking: y]"], NAMES)

        assert named is None
        assert note == ANALYSTS_FIELD_MISSING_NOTE

    def test_a_name_that_is_no_analyst_of_the_debate_reads_none_with_its_note(self) -> None:
        line = "[analysts: ghidra] GHIDRA says x. [blocking: y]"

        named, note = analysts_to_revise([line], NAMES)

        assert named is None
        assert note == analysts_field_unknown_note("ghidra")

    def test_spacing_case_and_hyphens_in_a_name_are_read_alike(self) -> None:
        line = "[analysts: All-Tools Static R2] says x. [blocking: y]"

        assert analysts_to_revise([line], NAMES) == (["all_tools_static_r2"], "")


# ---------------------------------------------------------------------------
# The mediation records who it names
# ---------------------------------------------------------------------------


def _negotiation_container(argument: AgentArgument, consensus: bool | None) -> Any:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda *_a: None
    container.analyst_keys.return_value = NAMES
    judge = MagicMock()
    judge.mediate = AsyncMock(return_value=(argument, consensus))
    container.get_judge_agent.return_value = judge
    return container


def _negotiate(argument: AgentArgument, consensus: bool | None = False) -> dict[str, Any]:
    state = {
        "iteration_count": 0,
        "reports": {name: f"{name} report" for name in NAMES},
        "isr_reports": dict(IN_FORCE),
    }
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("maljan.pipeline.nodes.pack_text", lambda *a: "")
        mp.setattr("maljan.pipeline.nodes.render_run_state", lambda *a: "")
        mp.setattr("maljan.pipeline.nodes.detect_sycophancy", lambda *a, **k: False)
        update = asyncio.run(
            make_negotiation_node(_negotiation_container(argument, consensus))(state)
        )
    return {**state, **update}


class TestTheMediationRecordsWhoItNames:
    def test_the_named_analysts_are_recorded_on_the_argument(self) -> None:
        argument = AgentArgument(
            agent_name="Mediator",
            finding=FINDING,
            confidence_score=0.6,
            contradictions=[LINE_STATIC_R2],
            not_blocking=[LINE_NOT_BLOCKING],
        )

        state = _negotiate(argument)

        recorded = state["discussion_history"][0]
        assert recorded.revise == ["all_tools_static_r2"]
        assert recorded.revise_note == ""

    def test_a_block_that_was_not_read_names_nobody_and_says_why(self) -> None:
        argument = AgentArgument(
            agent_name="Mediator",
            finding="x",
            confidence_score=0.6,
            contradictions=[],
            note=CONTRADICTIONS_BLOCK_MISSING_NOTE,
        )

        recorded = _negotiate(argument)["discussion_history"][0]

        assert recorded.revise is None
        assert recorded.revise_note == BLOCK_NOT_READ_NOTE

    def test_a_block_with_no_blocking_line_names_an_empty_list(self) -> None:
        argument = AgentArgument(
            agent_name="Mediator",
            finding="x",
            confidence_score=0.6,
            contradictions=[],
            not_blocking=[LINE_NOT_BLOCKING],
        )

        assert _negotiate(argument)["discussion_history"][0].revise == []


# ---------------------------------------------------------------------------
# The router
# ---------------------------------------------------------------------------


def _routed_state(argument: AgentArgument, *, consensus: bool, syco: bool = False) -> Any:
    return {
        "iteration_count": 1,
        "is_consensus": consensus,
        "consensus_applicable": True,
        "sycophancy_detected": syco,
        "confidence_history": [0.6],
        "discussion_history": [argument],
    }


class TestTheRouter:
    def test_a_block_naming_no_contested_point_schedules_no_round(self) -> None:
        state = _routed_state(_mediator(revise=[], lines=[]), consensus=False)

        assert debate_route(state, max_rounds=5) == ("judge", NO_CONTESTED_POINT)
        assert ConsensusRouter(Settings()).should_continue(state) == "judge"

    def test_consensus_with_no_contested_point_goes_to_the_judge_already(self) -> None:
        state = _routed_state(_mediator(revise=[], lines=[]), consensus=True)

        assert debate_route(state, max_rounds=5) == ("judge", CONSENSUS)

    def test_stable_confidence_ends_as_convergence_before_no_contested_point(self) -> None:
        state = {
            **_routed_state(_mediator(revise=[], lines=[]), consensus=False),
            "iteration_count": 3,
            "confidence_history": [0.8, 0.8, 0.8],
        }

        assert debate_route(state, max_rounds=5) == ("judge", CONVERGENCE)

    def test_named_analysts_open_a_round(self) -> None:
        state = _routed_state(_mediator(revise=["static"]), consensus=False)

        assert debate_route(state, max_rounds=5) == ("revision", NO_CONSENSUS)

    def test_an_unread_block_opens_a_round_as_before(self) -> None:
        state = _routed_state(
            _mediator(revise=None, note=BLOCK_NOT_READ_NOTE, lines=[]), consensus=False
        )

        assert debate_route(state, max_rounds=5) == ("revision", NO_CONSENSUS)

    def test_a_sycophancy_override_still_opens_a_round(self) -> None:
        state = _routed_state(_mediator(revise=[], lines=[]), consensus=True, syco=True)

        assert debate_route(state, max_rounds=5) == ("revision", SYCOPHANCY)

    def test_sycophancy_below_agreement_still_opens_the_devil_s_advocate_round(self) -> None:
        state = _routed_state(_mediator(revise=[], lines=[]), consensus=False, syco=True)

        assert debate_route(state, max_rounds=5) == ("revision", NO_CONSENSUS)
        assert debate_route(state, max_rounds=5, sycophancy_check=False) == (
            "revision",
            NO_CONSENSUS,
        )

    def test_the_devil_s_advocate_round_asks_every_analyst_with_its_directive(self) -> None:
        from maljan.pipeline.sycophancy_detector import DEVIL_ADVOCATE_DIRECTIVE

        _update, agents = _revise(_mediator(revise=[], lines=[]), syco=True)

        assert all(agents[name].safe_revise_isr.call_count == 1 for name in NAMES)
        args, _kw = agents["network"].safe_revise_isr.call_args
        assert args[3].startswith(DEVIL_ADVOCATE_DIRECTIVE)
        assert set(args[2]) == {"static", "all_tools_static_r2", "dynamic"}


# ---------------------------------------------------------------------------
# The revision round
# ---------------------------------------------------------------------------


def _revision_container() -> tuple[Any, dict[str, Any]]:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda *_a: None
    container.analyst_keys.return_value = NAMES
    container.agent_role.side_effect = lambda n: n
    container.config.llm.parallel_analysts = False
    agents: dict[str, Any] = {}
    for name in NAMES:
        agent = MagicMock()
        agent.safe_revise_isr.return_value = (f"{name} revised", IN_FORCE[name])
        agent.drain_evidence_entries.return_value = []
        agent.validation_findings = []
        agent.validation_retries = 0
        agent.validation_fed_back = {}
        agent.validation_not_run = []
        agents[name] = agent
    container.get_agent.side_effect = lambda n: agents[n]
    return container, agents


def _revise(
    argument: AgentArgument, *, syco: bool = False, consensus: bool = False
) -> tuple[dict[str, Any], Any]:
    container, agents = _revision_container()
    state = {
        "iteration_count": 1,
        "is_consensus": consensus,
        "consensus_applicable": True,
        "reports": {name: f"{name} first" for name in NAMES},
        "revised_reports": {},
        "isr_reports": dict(IN_FORCE),
        "sycophancy_detected": syco,
        "discussion_history": [argument],
    }
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("maljan.pipeline.nodes._revision_input_is_absent", lambda *a: False)
        mp.setattr("maljan.pipeline.nodes._build_revision_context", lambda *a: "data")
        update = asyncio.run(make_revision_node(container)(state))
    return update, agents


class TestOnlyTheNamedRevise:
    def test_only_the_named_analysts_are_asked(self) -> None:
        update, agents = _revise(_mediator(revise=["all_tools_static_r2"]))

        assert agents["all_tools_static_r2"].safe_revise_isr.call_count == 1
        for name in ("static", "dynamic", "network"):
            assert agents[name].safe_revise_isr.call_count == 0
        record = update["revision_rounds"][0]
        assert record["made"] == 1
        assert record["revised"] == ["all_tools_static_r2"]
        assert record["not_revised"] == {
            "static": NOT_NAMED_BY_MEDIATOR,
            "dynamic": NOT_NAMED_BY_MEDIATOR,
            "network": NOT_NAMED_BY_MEDIATOR,
        }
        assert "asked_all" not in record

    def test_an_analyst_not_named_keeps_its_answer_in_force(self) -> None:
        update, _agents = _revise(_mediator(revise=["all_tools_static_r2"]))

        assert update["isr_reports"]["network"] is IN_FORCE["network"]
        assert update["revised_reports"]["network"] == "network first"
        assert update["revised_reports"]["all_tools_static_r2"] == "all_tools_static_r2 revised"
        assert "dropped_claims" not in update

    def test_an_unread_answer_asks_every_analyst_and_records_why(self) -> None:
        update, agents = _revise(_mediator(revise=None, note=ANALYSTS_FIELD_MISSING_NOTE))

        assert all(agents[name].safe_revise_isr.call_count == 1 for name in NAMES)
        record = update["revision_rounds"][0]
        assert record["revised"] == NAMES
        assert record["asked_all"] == ANALYSTS_FIELD_MISSING_NOTE

    def test_a_sycophancy_round_asks_every_analyst_with_the_whole_feedback(self) -> None:
        update, agents = _revise(_mediator(revise=["static"]), syco=True)

        assert all(agents[name].safe_revise_isr.call_count == 1 for name in NAMES)
        assert update["revision_rounds"][0]["asked_all"] == sycophancy_asks_every_analyst(
            NO_CONSENSUS
        )
        args, _kw = agents["static"].safe_revise_isr.call_args
        assert set(args[2]) == {"all_tools_static_r2", "dynamic", "network"}
        assert LINE_NOT_BLOCKING in args[3]

    def test_the_record_names_the_override_where_the_override_opened_the_round(self) -> None:
        update, _agents = _revise(_mediator(revise=[], lines=[]), syco=True, consensus=True)

        said = update["revision_rounds"][0]["asked_all"]
        assert said == sycophancy_asks_every_analyst(SYCOPHANCY)
        assert "sycophancy override" in said

    def test_the_record_names_no_override_where_no_consensus_opened_the_round(self) -> None:
        update, _agents = _revise(_mediator(revise=["static"]), syco=True, consensus=False)

        said = update["revision_rounds"][0]["asked_all"]
        assert "no_consensus" in said and "override" not in said

    def test_a_record_without_a_reading_asks_every_analyst_as_before(self) -> None:
        update, agents = _revise(
            AgentArgument(agent_name="Mediator", finding="revise", contradictions=["x"])
        )

        assert all(agents[name].safe_revise_isr.call_count == 1 for name in NAMES)
        assert "asked_all" not in update["revision_rounds"][0]


class TestTheNarrowedPrompt:
    def test_a_named_analyst_is_shown_its_points_and_the_peers_they_name(self) -> None:
        _update, agents = _revise(_mediator(revise=["static", "all_tools_static_r2", "dynamic"]))

        args, _kw = agents["static"].safe_revise_isr.call_args
        own, peers, feedback = args[1], args[2], args[3]
        assert own == "static first"
        assert set(peers) == {"dynamic"}
        assert peers["dynamic"] == "dynamic first"
        assert LINE_STATIC in feedback
        assert LINE_STATIC_R2 not in feedback
        assert LINE_NOT_BLOCKING not in feedback
        assert feedback.startswith("The reports agree on the loader.")
        assert feedback.endswith("Confidence: 0.60")

    def test_a_peer_cited_by_claim_number_is_shown_those_claims(self) -> None:
        _update, agents = _revise(_mediator(revise=["static", "all_tools_static_r2", "dynamic"]))

        args, _kw = agents["all_tools_static_r2"].safe_revise_isr.call_args
        peers, feedback = args[2], args[3]
        # Its one point names only itself, and cites STATIC Claim 1: the
        # field names whom the line asks, and the claim it cites is shown.
        assert set(peers) == {"static"}
        assert peers["static"] == (
            "Claim 1: Reads the flag at 0x40. | Evidence: [ev_0010] | Confidence: 0.80"
        )
        assert "Claim 2" in feedback and "[ev_0007]" in feedback

    def test_every_claim_number_and_entry_id_the_points_cite_is_kept(self) -> None:
        feedback, peers = contested_input(
            "all_tools_static_r2",
            FINDING,
            [LINE_STATIC_R2, LINE_STATIC],
            NAMES,
            {name: f"{name} first" for name in NAMES},
            IN_FORCE,
        )

        shown = feedback + "\n".join(peers.values())
        for cited in ("Claim 2", "Claim 1", "[ev_0007]", "0x40"):
            assert cited in shown

    def test_a_claim_number_past_the_peer_s_claims_shows_its_whole_answer(self) -> None:
        line = "[analysts: dynamic] DYNAMIC differs from STATIC Claim 9. [blocking: x]"

        _feedback, peers = contested_input(
            "dynamic",
            FINDING,
            [line],
            NAMES,
            {name: f"{name} first" for name in NAMES},
            IN_FORCE,
        )

        assert peers == {"static": "static first"}

    def test_a_finding_in_another_shape_is_passed_whole(self) -> None:
        feedback, _peers = contested_input(
            "dynamic",
            "free text",
            [LINE_STATIC],
            NAMES,
            {name: f"{name} first" for name in NAMES},
            IN_FORCE,
        )

        assert feedback == "free text"


class TestTheMediatorIsAskedForTheField:
    def test_the_block_rule_and_its_question_ask_for_the_field(self) -> None:
        from maljan.agents.judge_agent import (
            ANALYSTS_FIELD_RULE,
            CONTRADICTIONS_BLOCK_QUESTION,
            CONTRADICTIONS_BLOCK_RULE,
            MEDIATION_EXTRACTION_SYSTEM,
        )

        assert ANALYSTS_FIELD_RULE in CONTRADICTIONS_BLOCK_RULE
        assert "[analysts: <name>, <name>]" in CONTRADICTIONS_BLOCK_QUESTION
        assert "[analysts: …]" in MEDIATION_EXTRACTION_SYSTEM

    def test_a_field_opened_line_is_read_whole_and_its_mark_still_blocks(self) -> None:
        from maljan.agents.judge_agent import read_contradictions_block
        from maljan.pipeline.debate_facts import read_marks

        answer = f"Reasoning.\n\nCONTRADICTIONS:\n- {LINE_STATIC}\nagreement_confidence: 0.6"

        items = read_contradictions_block(answer).items
        assert items == [LINE_STATIC]
        (mark,) = read_marks(items)
        assert mark.blocking and mark.marked and not mark.unread
        assert analysts_to_revise(items, NAMES) == (["static", "dynamic"], "")


class TestACitedClaimIsShownAsTheMediatorReadIt:
    def test_its_technique_marker_heading_note_and_confidence_are_kept(self) -> None:
        claim = ClaimEvidence(
            claim="Writes a startup entry.",
            evidence_ref="[ev_0031]",
            confidence=0.7,
            technique_id="T1547.001",
            heading_note="(revised)",
        )
        claim.technique_id_valid = False
        isrs = {**IN_FORCE, "static": AgentISR(agent_id="static", domain="static", claims=[claim])}
        line = "[analysts: dynamic] DYNAMIC differs from STATIC Claim 1. [blocking: x]"

        _feedback, peers = contested_input(
            "dynamic", FINDING, [line], NAMES, {n: f"{n} first" for n in NAMES}, isrs
        )

        summary_line = isrs["static"].to_text_summary().splitlines()[2].strip()
        assert peers == {"static": summary_line}
        assert "T1547.001" in summary_line and "(revised)" in summary_line
        assert "Confidence: 0.70" in summary_line


class TestTheNamesStayOutOfModelInput:
    def test_the_history_a_prompt_carries_reads_the_same_with_or_without_them(self) -> None:
        read = _mediator(revise=["static"], note="")
        unread = _mediator(revise=None, note=ANALYSTS_FIELD_MISSING_NOTE)
        legacy = AgentArgument(
            agent_name="Mediator",
            finding=FINDING,
            confidence_score=0.6,
            contradictions=[LINE_STATIC_R2, LINE_STATIC],
            not_blocking=[LINE_NOT_BLOCKING],
        )

        assert str([read]) == str([legacy]) == str([unread])
        assert "revise" not in str([read]) and "revise" not in repr(unread)


class TestTheFieldMayStandAnywhere:
    @pytest.mark.parametrize(
        "line",
        [
            "[analysts: network] NETWORK calls the host live. [not blocking: wording only]",
            "NETWORK calls the host live. [not blocking: wording only] [analysts: network]",
            "NETWORK calls the host live [analysts: network]. [not blocking: wording only]",
        ],
    )
    def test_a_not_blocking_mark_is_read_wherever_the_field_stands(self, line: str) -> None:
        from maljan.pipeline.debate_facts import read_marks

        (mark,) = read_marks([line])

        assert (mark.blocking, mark.marked, mark.unread) == (False, True, False)
        assert mark.line == line
        assert read_analysts_field(line) == ["network"]

    @pytest.mark.parametrize(
        "line",
        [
            "[analysts: static] STATIC says no mutex. [blocking: the ledger refutes it]",
            "STATIC says no mutex. [blocking: the ledger refutes it] [analysts: static]",
        ],
    )
    def test_a_blocking_mark_is_read_wherever_the_field_stands(self, line: str) -> None:
        from maljan.pipeline.debate_facts import read_marks

        (mark,) = read_marks([line])

        assert (mark.blocking, mark.marked, mark.unread) == (True, True, False)
        assert mark.reason == "the ledger refutes it"
        assert analysts_to_revise([line], NAMES) == (["static"], "")


class TestAPeerIsNamedAsItsReportIsHeaded:
    def test_plain_words_that_spell_an_analyst_key_name_no_peer(self) -> None:
        line = (
            "[analysts: dynamic] DYNAMIC Claim 1 says the string is static, the network "
            "traffic dynamic. [blocking: x]"
        )

        _feedback, peers = contested_input(
            "dynamic", FINDING, [line], NAMES, {n: f"{n} first" for n in NAMES}, IN_FORCE
        )

        assert peers == {}

    def test_the_heading_forms_name_a_peer(self) -> None:
        line = (
            "[analysts: dynamic] DYNAMIC differs from Static Analyst and from NETWORK. "
            "[blocking: x]"
        )

        _feedback, peers = contested_input(
            "dynamic", FINDING, [line], NAMES, {n: f"{n} first" for n in NAMES}, IN_FORCE
        )

        assert set(peers) == {"static", "network"}
