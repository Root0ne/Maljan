"""A contested point naming a function the run never listed is put to its analysts as a fact.

The platform states, for each blocking line of the mediator's final block,
the functions the line names (directly, or through the claims it names) that
the run knows (a row of the function index, or a function a decompile or
disassembly call listed), and whether the ledger holds a listing of each. The
analysts the line names are told it in their revision. An analyst whose tools
take an address is told it can read the function in this round, and its
revision is given its tools: a built-in analyst's revision runs its tool loop
instead of its one tools-free call. The model decides whether to read; the
platform adopts and rejects nothing.

Every value is synthetic.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import create_model

from maljan.pipeline.debate_facts import (
    NO_LISTING,
    PLACE_FACTS_HEAD,
    PLACE_READ_OFFER,
    names_an_unlisted_place,
    place_facts,
    place_facts_for,
    tools_taking_an_address,
    with_place_facts,
)
from maljan.pipeline.nodes import RevisionInput, make_negotiation_node, make_revision_node
from maljan.pipeline.state import AgentArgument
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

NAMES = ["static", "reverser", "dynamic"]


def _ledger() -> list[LedgerEntry]:
    return [
        LedgerEntry(
            id="ev_0001",
            agent="pipeline",
            tool="function_index",
            structured={"rows": [{"offset": "0x1000"}, {"offset": "0x2000"}, {"offset": "0x3000"}]},
        ),
        LedgerEntry(
            id="ev_0002",
            agent="reverser",
            tool="decompile_function",
            args={"address": "0x1000"},
            output="void FUN_00001000(void) { return; }",
        ),
    ]


def _isrs() -> dict[str, AgentISR]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(claim="Opens a key.", evidence_ref="[ev_0001]", confidence=0.6),
                ClaimEvidence(
                    claim="Routine 0x3000 deletes the file on close.",
                    evidence_ref="[ev_0001] 0x3000",
                    confidence=0.6,
                ),
            ],
        ),
        "reverser": AgentISR(agent_id="reverser", domain="reverser", claims=[]),
        "dynamic": AgentISR(agent_id="dynamic", domain="dynamic", claims=[]),
    }


LINE_UNREAD = (
    "[analysts: STATIC] STATIC claim 2 places a delete-on-close in a routine; "
    "the index row [ev_0001] lists no such call. [blocking: not established]"
)
LINE_READ = (
    "[analysts: REVERSER] REVERSER says 0x1000 returns at once, against 0x2000's call. "
    "[blocking: refuted]"
)
LINE_NO_PLACE = "[analysts: DYNAMIC] DYNAMIC says no mutex was made. [blocking: refuted]"


class TestThePlacesALineNames:
    def test_a_function_named_through_a_claim_is_stated_unlisted(self) -> None:
        (fact,) = place_facts([LINE_UNREAD], _isrs(), _ledger(), NAMES)

        assert fact.startswith(f'For the line "{LINE_UNREAD}": ')
        assert "0x3000 is a function of the run's function index [ev_0001]" in fact
        assert NO_LISTING in fact

    def test_a_listed_function_names_the_entries_that_hold_its_listing(self) -> None:
        (fact,) = place_facts([LINE_READ], _isrs(), _ledger(), NAMES)

        assert "0x1000 is listed in ev_0002" in fact
        assert "0x2000 is a function of the run's function index [ev_0001]" in fact

    def test_a_line_naming_no_known_function_gets_no_fact(self) -> None:
        assert place_facts([LINE_NO_PLACE], _isrs(), _ledger(), NAMES) == []

    def test_an_address_the_run_does_not_know_as_a_function_is_not_named(self) -> None:
        line = "[analysts: STATIC] The seed 0x33445566 differs. [blocking: x]"

        assert place_facts([line], _isrs(), _ledger(), NAMES) == []

    def test_an_offset_and_its_virtual_address_are_one_function(self) -> None:
        ledger = [
            LedgerEntry(
                id="ev_0001",
                tool="function_index",
                structured={"image_base": "0x180000000", "rows": [{"offset": "0x3000"}]},
            )
        ]
        line = "[analysts: STATIC] 0x180003000 and 0x3000 differ. [blocking: x]"

        (fact,) = place_facts([line], {}, ledger, NAMES)

        assert fact.count(NO_LISTING) == 1

    def test_ledger_rows_as_stored_are_read(self) -> None:
        rows = [entry.model_dump(mode="json") for entry in _ledger()]

        assert place_facts([LINE_READ], _isrs(), rows, NAMES) == place_facts(
            [LINE_READ], _isrs(), _ledger(), NAMES
        )

    def test_no_function_index_and_no_listing_states_nothing(self) -> None:
        assert place_facts([LINE_READ], _isrs(), [], NAMES) == []

    def test_a_hostile_line_is_read_in_linear_time(self) -> None:
        timings = []
        for n in (300, 3000):
            line = "[analysts: STATIC] " + " ".join(f"0x{1000 + i:x}" for i in range(n))
            start = time.perf_counter()
            place_facts([line], _isrs(), _ledger(), NAMES)
            timings.append(time.perf_counter() - start)
        assert timings[1] < timings[0] * 10 * 4 + 0.5


class TestWhoIsTold:
    def test_a_fact_goes_to_the_analysts_its_line_names(self) -> None:
        facts = place_facts([LINE_UNREAD, LINE_READ], _isrs(), _ledger(), NAMES)

        assert place_facts_for("static", facts, NAMES) == [facts[0]]
        assert place_facts_for("reverser", facts, NAMES) == [facts[1]]
        assert place_facts_for("dynamic", facts, NAMES) == []

    def test_a_line_with_no_field_goes_to_every_analyst(self) -> None:
        facts = ['For the line "0x3000 is wrong [blocking: x]": 0x3000 is listed in ev_0002.']

        assert all(place_facts_for(name, facts, NAMES) == facts for name in NAMES)

    def test_only_a_fact_naming_an_unlisted_function_offers_a_reading(self) -> None:
        facts = place_facts([LINE_UNREAD, LINE_READ], _isrs(), _ledger(), NAMES)

        assert names_an_unlisted_place([facts[0]])
        assert names_an_unlisted_place([facts[1]])
        read_only = ['For the line "x": 0x1000 is listed in ev_0002.']
        assert not names_an_unlisted_place(read_only)

    def test_the_directive_carries_the_facts_and_the_offer(self) -> None:
        facts = place_facts([LINE_UNREAD], _isrs(), _ledger(), NAMES)

        said = with_place_facts("feedback", facts, can_read=True)

        assert said.startswith("feedback\n\n" + PLACE_FACTS_HEAD)
        assert facts[0] in said
        assert said.endswith(PLACE_READ_OFFER)

    def test_an_analyst_that_cannot_read_is_told_the_facts_alone(self) -> None:
        facts = place_facts([LINE_UNREAD], _isrs(), _ledger(), NAMES)

        said = with_place_facts("feedback", facts, can_read=False)

        assert facts[0] in said
        assert PLACE_READ_OFFER not in said

    def test_no_fact_leaves_the_directive_as_it_was(self) -> None:
        assert with_place_facts("feedback", [], can_read=True) == "feedback"


def _tool(name: str, **fields: Any) -> Any:
    tool = MagicMock()
    tool.name = name
    tool.args_schema = create_model(f"{name}Args", **{k: (str, ...) for k in fields})
    return tool


class TestToolsThatTakeAnAddress:
    def test_read_from_each_tool_s_declared_arguments(self) -> None:
        tools = [
            _tool("decompile", address="x"),
            _tool("disasm_at", ea="x"),
            _tool("sandbox_processes", task_id="x"),
        ]

        assert tools_taking_an_address(tools) == ["decompile", "disasm_at"]

    def test_a_tool_with_no_schema_takes_nothing(self) -> None:
        tool = MagicMock(spec=["name"])
        tool.name = "plain"

        assert tools_taking_an_address([tool]) == []


# ---------------------------------------------------------------------------
# The negotiation states the facts, the revision passes them on
# ---------------------------------------------------------------------------


def _argument(lines: list[str]) -> AgentArgument:
    return AgentArgument(
        agent_name="Mediator",
        finding=f"Summary.\n\nContradictions: {'; '.join(lines)}\nConfidence: 0.50",
        confidence_score=0.5,
        contradictions=lines,
    )


def _negotiate(argument: AgentArgument, events: list[Any]) -> dict[str, Any]:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda *a: events.append(a)
    container.analyst_keys.return_value = NAMES
    judge = MagicMock()
    judge.mediate = AsyncMock(return_value=(argument, False))
    container.get_judge_agent.return_value = judge
    state = {
        "iteration_count": 0,
        "reports": {name: f"{name} report" for name in NAMES},
        "isr_reports": _isrs(),
        "evidence_ledger": [entry.model_dump(mode="json") for entry in _ledger()],
    }
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("maljan.pipeline.nodes.pack_text", lambda *a: "")
        mp.setattr("maljan.pipeline.nodes.render_run_state", lambda *a: "")
        mp.setattr("maljan.pipeline.nodes.detect_sycophancy", lambda *a, **k: False)
        update = asyncio.run(make_negotiation_node(container)(state))
    return {**state, **update}


class TestTheNegotiationStatesThePlaces:
    def test_the_facts_ride_on_the_mediation_and_are_said_to_the_room(self) -> None:
        events: list[Any] = []
        state = _negotiate(_argument([LINE_UNREAD, LINE_NO_PLACE]), events)

        (mediation,) = state["discussion_history"]
        assert len(mediation.place_facts) == 1
        assert NO_LISTING in mediation.place_facts[0]
        assert "place_facts" not in repr(mediation)
        said = [str(e) for e in events if NO_LISTING in str(e)]
        assert said

    def test_a_mediation_with_no_blocking_line_states_none(self) -> None:
        state = _negotiate(_argument([]), [])

        assert state["discussion_history"][0].place_facts == []


def _revision_container(tools: dict[str, list[Any]]) -> tuple[Any, dict[str, Any]]:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda *_a: None
    container.analyst_keys.return_value = NAMES
    container.agent_role.side_effect = lambda n: n
    container.config.llm.parallel_analysts = False
    container.config.agents.definitions = {}
    agents: dict[str, Any] = {}
    for name in NAMES:
        agent = MagicMock()
        agent.tools = tools.get(name, [])
        agent.safe_revise_isr.return_value = (f"{name} revised", _isrs()[name])
        agent.drain_evidence_entries.return_value = []
        agent.validation_findings = []
        agent.validation_retries = 0
        agent.validation_fed_back = {}
        agent.validation_not_run = []
        agents[name] = agent
    container.get_agent.side_effect = lambda n: agents[n]
    return container, agents


def _revise(argument: AgentArgument, tools: dict[str, list[Any]]) -> dict[str, Any]:
    container, agents = _revision_container(tools)
    state = {
        "iteration_count": 1,
        "is_consensus": False,
        "consensus_applicable": True,
        "reports": {name: f"{name} first" for name in NAMES},
        "revised_reports": {},
        "isr_reports": _isrs(),
        "sycophancy_detected": False,
        "discussion_history": [argument],
    }
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("maljan.pipeline.nodes._revision_input", lambda *a: RevisionInput(text="data"))
        asyncio.run(make_revision_node(container)(state))
    return agents


class TestTheRevisionPassesThemOn:
    def _argument(self) -> AgentArgument:
        argument = _argument([LINE_UNREAD, LINE_READ])
        argument.revise = ["static", "reverser"]
        argument.place_facts = place_facts([LINE_UNREAD, LINE_READ], _isrs(), _ledger(), NAMES)
        return argument

    def test_an_analyst_that_can_read_is_offered_and_given_its_tools(self) -> None:
        agents = _revise(self._argument(), {"static": [_tool("decompile", address="x")]})

        args, kwargs = agents["static"].safe_revise_isr.call_args
        assert NO_LISTING in args[3]
        assert PLACE_READ_OFFER in args[3]
        assert kwargs == {"read_places": True}

    def test_an_analyst_with_no_address_tool_is_told_the_facts_alone(self) -> None:
        agents = _revise(self._argument(), {"static": [_tool("sandbox", task_id="x")]})

        args, kwargs = agents["static"].safe_revise_isr.call_args
        assert NO_LISTING in args[3]
        assert PLACE_READ_OFFER not in args[3]
        assert kwargs == {}

    def test_a_line_naming_another_analyst_is_not_its_fact(self) -> None:
        agents = _revise(self._argument(), {"reverser": [_tool("decompile", address="x")]})

        args, kwargs = agents["reverser"].safe_revise_isr.call_args
        assert "0x1000 is listed in ev_0002" in args[3]
        assert "0x3000" not in args[3].split(PLACE_FACTS_HEAD)[-1]
        # Its own line names an unlisted function too: 0x2000.
        assert kwargs == {"read_places": True}

    def test_a_mediation_with_no_place_facts_passes_the_old_call(self) -> None:
        argument = _argument([LINE_UNREAD])
        argument.revise = ["static"]
        agents = _revise(argument, {"static": [_tool("decompile", address="x")]})

        args, kwargs = agents["static"].safe_revise_isr.call_args
        assert PLACE_FACTS_HEAD not in args[3]
        assert kwargs == {}


# ---------------------------------------------------------------------------
# A built-in analyst's revision runs its tool loop only when it may read
# ---------------------------------------------------------------------------


def _static_analyst(tools: list[Any]) -> Any:
    from maljan.agents.static_analyst import StaticAnalyst

    analyst = StaticAnalyst.__new__(StaticAnalyst)
    analyst.name = "static"
    analyst.tools = tools
    analyst.logger = MagicMock()
    return analyst


class TestABuiltInRevisionReads:
    def test_the_tool_loop_runs_when_it_may_read(self) -> None:
        from langchain_core.messages import HumanMessage, SystemMessage

        analyst = _static_analyst([_tool("decompile", address="x")])
        analyst._revision_reads = True
        analyst.execute_tool_loop = MagicMock(return_value="CLAIM: read it")
        analyst.ask_the_model = MagicMock(return_value="unused")

        said = analyst.revision_answer([SystemMessage(content="s"), HumanMessage(content="h")])

        assert said == "CLAIM: read it"
        analyst.execute_tool_loop.assert_called_once_with([("system", "s"), ("human", "h")])
        analyst.ask_the_model.assert_not_called()
        assert analyst.revision_tools() is None

    def test_one_tools_free_call_otherwise(self) -> None:
        from langchain_core.messages import HumanMessage

        analyst = _static_analyst([_tool("decompile", address="x")])
        analyst.execute_tool_loop = MagicMock()
        analyst.ask_the_model = MagicMock(return_value="CLAIM: as before")
        analyst.frame_messages = lambda messages, **_k: messages

        said = analyst.revision_answer([HumanMessage(content="h")])

        assert said == "CLAIM: as before"
        analyst.execute_tool_loop.assert_not_called()
        assert analyst.revision_tools() == ()

    def test_no_tools_is_one_tools_free_call_even_when_it_may_read(self) -> None:
        analyst = _static_analyst([])
        analyst._revision_reads = True

        assert analyst.revision_tools() == ()

    def test_safe_revise_isr_clears_the_offer_after_the_round(self) -> None:
        analyst = _static_analyst([_tool("decompile", address="x")])
        seen: list[bool] = []

        def revise_isr(*_a: Any, **_k: Any) -> Any:
            seen.append(analyst._revision_may_read())
            raise RuntimeError("stop")

        analyst.revise_isr = revise_isr
        analyst._truncate_input = lambda data, *a, **k: data
        analyst.current_round = 0
        with pytest.raises(Exception, match="stop"):
            analyst.safe_revise_isr("d", "r", {}, "f", 1, read_places=True)

        assert seen == [True]
        assert analyst._revision_may_read() is False
