"""The debate does not spend its rounds on a count the ledger answers, or on wording.

A debate ran to its round limit on a rule-match count: one analyst's tool
listed two matches, a rule scan listed none of its 31 rules, and the mediator
kept the line blocking every round. The ledger states such a line: its cited
entries state each count it states ("0 hits", "31 rules") in keys naming its
nouns, including the length of a match list, as one record that agrees with
itself. Once an earlier mediation told the analysts those facts, the line is
recorded as stated and told. It stays a blocking line, the next mediation is
shown it, and when every blocking line of a mediation is one, the debate ends
as ``ledger_stated``, never as consensus. A line setting one entry's count
against another's count of something else, or citing entries that disagree,
is never stated.

A round whose every revision states the claims in force again, wording aside
(the same values, entry ids and techniques), ends the debate: another round
would argue over words. And a revision that repeats an identical call of an
earlier round is answered from the entry that holds it, with no tool run.

Every value is synthetic.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel

from maljan.agents.base_agent import own_earlier_entries, repeatable_earlier_entries
from maljan.agents.evidence_recorder import (
    EARLIER_CHUNK,
    EARLIER_ROUND,
    earlier_chunk_answer,
    earlier_chunk_sentence,
    seeded_repeat_guard,
)
from maljan.agents.judge_agent import _last_ledger_facts
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.pipeline.claim_drops import unchanged_in_substance
from maljan.pipeline.debate_facts import (
    LEDGER_STATED_HEAD,
    fact_atoms,
    ledger_count_facts,
    ledger_stated,
    ledger_stated_sentence,
    with_ledger_stated,
)
from maljan.pipeline.nodes import _ledger_stated_lines
from maljan.pipeline.routing import LEDGER_STATED, NO_CONSENSUS, REWORDED, debate_route
from maljan.pipeline.state import AgentArgument
from maljan.schemas.evidence import build_entry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

AGENTS = ["alpha", "beta", "gamma"]
SCAN = {"id": "ev_0007", "tool": "rule_scan", "structured": {"matches": [], "rule_count": 31}}
RESCAN = {"id": "ev_0009", "tool": "rule_scan", "structured": {"matches": [], "rule_count": 31}}
LINE = (
    "[analysts: ALPHA] ALPHA claim 6 reports two rule matches (ev_0005) while ev_0007 "
    "reports 0 hits of 31 rules. [blocking: the match count conflicts]"
)
REWORDED_LINE = (
    "[analysts: ALPHA] ALPHA claim 9 still reports matches at 0x5f0c, against 0 hits in "
    "ev_0007 over its 31 rules. [blocking: the rule sets are not reconciled]"
)
WITH_RESCAN = (
    "[analysts: ALPHA] ALPHA claim 9 reports matches, against 0 hits in ev_0007 and "
    "ev_0009 over 31 rules. [blocking: x]"
)
UNANSWERED = (
    "[analysts: BETA] BETA claim 2 says 5 exports while ev_0007 shows 0 hits. [blocking: x]"
)
NO_COUNT = "[analysts: GAMMA] GAMMA claim 1 cites ev_0007 for a command line. [blocking: x]"


class TestAListFieldIsACount:
    def test_a_match_list_s_length_is_stated(self) -> None:
        [fact] = ledger_count_facts([LINE], {}, [SCAN], AGENTS)
        assert "entry ev_0007 (rule_scan) states matches = 0 items, rule_count = 31" in fact

    def test_the_atoms_of_a_stated_fact_are_read_back(self) -> None:
        facts = ledger_count_facts([LINE], {}, [SCAN], AGENTS)
        assert fact_atoms(facts) == {
            ("ev_0007", "matches = 0 items"),
            ("ev_0007", "rule_count = 31"),
        }

    def test_a_list_whose_key_names_another_noun_is_not_stated(self) -> None:
        parsed = {"id": "ev_0011", "tool": "parse", "structured": {"imports": ["a", "b", "c"]}}
        line = "[analysts: BETA] BETA claim 2 counts 3 sections in ev_0011. [blocking: x]"
        assert ledger_count_facts([line], {}, [parsed], AGENTS) == []

    def test_a_count_key_is_stated_as_before(self) -> None:
        listed = {"id": "ev_0011", "tool": "parse", "structured": {"total": 3}}
        line = "[analysts: BETA] BETA claim 2 counts 3 sections in ev_0011. [blocking: x]"
        [fact] = ledger_count_facts([line], {}, [listed], AGENTS)
        assert "states total = 3" in fact


CONNECTIONS = {"id": "ev_0012", "tool": "sandbox", "structured": {"connections": []}}
DOMAINS = {"id": "ev_0020", "tool": "dns", "structured": {"domains": ["a.test", "b.test"]}}
C2_CONTACT = (
    "[analysts: BETA, GAMMA] The BETA analyst sees 0 connections [ev_0012] while the GAMMA "
    "analyst claims 2 C2 domains contacted [ev_0020]; whether C2 contact happened is "
    "disputed [blocking: the contact is not established]"
)
SCANNER_A = {"id": "ev_0030", "tool": "scan_a", "structured": {"matches": []}}
SCANNER_B = {"id": "ev_0031", "tool": "scan_b", "structured": {"matches": ["r1", "r2"]}}
SCANNERS = (
    "[analysts: ALPHA, BETA] ALPHA finds 0 matches [ev_0030] while BETA finds 2 matches "
    "[ev_0031]. [blocking: the scanners disagree]"
)


class TestALineTheLedgerStates:
    def test_it_is_stated_once_the_facts_were_told(self) -> None:
        told = ledger_count_facts([LINE], {}, [SCAN], AGENTS)
        [(line, facts)] = ledger_stated([REWORDED_LINE], {}, [SCAN], AGENTS, told)
        assert line == REWORDED_LINE
        assert facts == ("entry ev_0007 (rule_scan) states matches = 0 items, rule_count = 31",)
        assert "Stated by the ledger and told" in ledger_stated_sentence(line, facts)

    def test_it_is_not_stated_before_the_facts_were_told(self) -> None:
        assert ledger_stated([LINE], {}, [SCAN], AGENTS, []) == []

    def test_a_fact_not_told_before_keeps_it_out_one_round(self) -> None:
        told = ledger_count_facts([LINE], {}, [SCAN], AGENTS)
        assert ledger_stated([WITH_RESCAN], {}, [SCAN, RESCAN], AGENTS, told) == []
        told += ledger_count_facts([WITH_RESCAN], {}, [SCAN, RESCAN], AGENTS)
        assert ledger_stated([WITH_RESCAN], {}, [SCAN, RESCAN], AGENTS, told)

    @pytest.mark.parametrize("line", [UNANSWERED, NO_COUNT])
    def test_a_line_the_ledger_cannot_answer_is_never_stated(self, line: str) -> None:
        told = ledger_count_facts([LINE, line], {}, [SCAN], AGENTS)
        assert ledger_stated([line], {}, [SCAN], AGENTS, told) == []

    def test_a_dispute_about_contact_is_not_stated_by_two_counts(self) -> None:
        ledger = [CONNECTIONS, DOMAINS]
        told = ledger_count_facts([C2_CONTACT], {}, ledger, AGENTS)
        assert told, "each count is still stated to the analysts"
        assert ledger_stated([C2_CONTACT], {}, ledger, AGENTS, told) == []

    def test_scanners_that_disagree_are_not_stated(self) -> None:
        ledger = [SCANNER_A, SCANNER_B]
        told = ledger_count_facts([SCANNERS], {}, ledger, AGENTS)
        assert told
        assert ledger_stated([SCANNERS], {}, ledger, AGENTS, told) == []

    def test_the_node_keeps_the_line_and_records_it(self) -> None:
        told = ledger_count_facts([LINE], {}, [SCAN], AGENTS)
        earlier = AgentArgument(agent_name="Mediator", finding="x", ledger_facts=told)
        now = AgentArgument(
            agent_name="Mediator", finding="y", contradictions=[REWORDED_LINE, UNANSWERED]
        )
        state: dict[str, Any] = {
            "discussion_history": [earlier],
            "evidence_ledger": [SCAN],
            "isr_reports": {},
        }
        stated = _ledger_stated_lines(state, AGENTS, now)  # type: ignore[arg-type]
        assert [line for line, _facts in stated] == [REWORDED_LINE]
        assert now.contradictions == [REWORDED_LINE, UNANSWERED]

    def test_the_run_summary_records_it(self) -> None:
        sentence = ledger_stated_sentence(REWORDED_LINE, ("entry ev_0007 states matches = 0",))
        mediator = AgentArgument(agent_name="Mediator", finding="x", ledger_stated=[sentence])
        state: dict[str, Any] = {
            "iteration_count": 2,
            "discussion_history": [mediator],
            "confidence_history": [0.6],
        }
        summary = RunSummaryBuilder(start_time=0.0).set_negotiation(state, max_iterations=5).build()
        assert summary.negotiation.ledger_stated == [sentence]
        assert summary.to_dict()["negotiation"]["ledger_stated"] == [sentence]

    def test_the_next_mediation_is_shown_the_stated_lines(self) -> None:
        sentence = ledger_stated_sentence(REWORDED_LINE, ("entry ev_0007 states matches = 0",))
        mediator = AgentArgument(agent_name="Mediator", finding="x", ledger_stated=[sentence])
        shown = with_ledger_stated("", _last_ledger_facts([mediator], "ledger_stated"))
        assert shown.startswith(LEDGER_STATED_HEAD)
        assert sentence in shown
        assert with_ledger_stated("", []) == ""
        assert "ledger_stated" not in repr(mediator)


def _mediations(*blocking: list[str], stated: int = 0) -> dict[str, Any]:
    """A debate whose last mediation lists ``blocking[-1]``, the first ``stated`` of it stated."""
    history = []
    for k, lines in enumerate(blocking):
        last = k == len(blocking) - 1
        history.append(
            AgentArgument(
                agent_name="Mediator",
                finding=f"m{k}",
                contradictions=list(lines),
                ledger_stated=[ledger_stated_sentence(line, ("f",)) for line in lines[:stated]]
                if last
                else [],
            )
        )
    return {
        "iteration_count": len(blocking),
        "is_consensus": False,
        "consensus_applicable": True,
        "confidence_history": [0.6] * len(blocking),
        "discussion_history": history,
        "revision_rounds": [],
    }


class TestTheDebateEndsWhenTheLedgerStatedEveryBlockingLine:
    def test_a_scan_line_told_before_ends_the_debate_without_consensus(self) -> None:
        state = _mediations([LINE], [REWORDED_LINE], stated=1)
        assert debate_route(state, max_rounds=5) == ("judge", LEDGER_STATED)
        assert state["is_consensus"] is False
        assert state["discussion_history"][-1].contradictions == [REWORDED_LINE]

    def test_one_line_the_ledger_does_not_state_goes_on(self) -> None:
        state = _mediations([LINE], [REWORDED_LINE, UNANSWERED], stated=1)
        assert debate_route(state, max_rounds=5) == ("revision", NO_CONSENSUS)

    def test_the_whole_path_ends_after_the_line_was_told(self) -> None:
        told = ledger_count_facts([LINE], {}, [SCAN], AGENTS)
        first = AgentArgument(
            agent_name="Mediator", finding="x", contradictions=[LINE], ledger_facts=told
        )
        second = AgentArgument(agent_name="Mediator", finding="y", contradictions=[REWORDED_LINE])
        state: dict[str, Any] = {
            "iteration_count": 2,
            "is_consensus": False,
            "consensus_applicable": True,
            "confidence_history": [0.6, 0.6],
            "discussion_history": [first, second],
            "evidence_ledger": [SCAN],
            "isr_reports": {},
            "revision_rounds": [],
        }
        assert debate_route(state, max_rounds=5) == ("revision", NO_CONSENSUS)
        second.ledger_stated = [
            ledger_stated_sentence(line, facts)
            for line, facts in _ledger_stated_lines(state, AGENTS, second)  # type: ignore[arg-type]
        ]
        assert debate_route(state, max_rounds=5) == ("judge", LEDGER_STATED)


def _claim(
    text: str, ref: str = "[ev_0004]", technique: str | None = "T1027", confidence: float = 0.7
) -> ClaimEvidence:
    return ClaimEvidence(
        claim=text, evidence_ref=ref, confidence=confidence, technique_id=technique
    )


def _isr(*claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id="alpha", domain="static", claims=list(claims))


class TestARoundOfWordingOnly:
    def test_other_words_for_the_same_values_ids_and_technique_are_unchanged(self) -> None:
        before = _isr(_claim("Routine 0x1400 decodes 57 blobs with key 'k7q2'."))
        after = _isr(_claim("The decoder at 0x1400 handles all 57 blobs; its key is 'k7q2'."))
        assert unchanged_in_substance(before, after)

    @pytest.mark.parametrize(
        "after",
        [
            _isr(_claim("Routine 0x1400 decodes 56 blobs with key 'k7q2'.")),
            _isr(_claim("Routine 0x1400 decodes 57 blobs with key 'k7q2'.", ref="[ev_0005]")),
            _isr(_claim("Routine 0x1400 decodes 57 blobs with key 'k7q2'.", technique="T1140")),
            _isr(),
        ],
    )
    def test_a_changed_value_entry_or_technique_is_a_change(self, after: AgentISR) -> None:
        before = _isr(_claim("Routine 0x1400 decodes 57 blobs with key 'k7q2'."))
        assert not unchanged_in_substance(before, after)

    def test_another_algorithm_is_a_change(self) -> None:
        before = _isr(_claim("Strings are decrypted with RC4."))
        after = _isr(_claim("Strings are decrypted with XOR."))
        assert not unchanged_in_substance(before, after)

    def test_a_negation_with_a_lower_confidence_is_a_change(self) -> None:
        before = _isr(_claim("The sample injects into the shell process.", confidence=0.9))
        after = _isr(_claim("The sample does not inject into the shell process.", confidence=0.2))
        assert not unchanged_in_substance(before, after)

    def test_a_negation_alone_is_a_change(self) -> None:
        before = _isr(_claim("The sample injects into the shell process."))
        after = _isr(_claim("The sample doesn't inject into the shell process."))
        assert not unchanged_in_substance(before, after)

    def test_a_confidence_beyond_its_step_is_a_change(self) -> None:
        before = _isr(_claim("Routine 0x1400 decodes the blobs.", confidence=0.7))
        assert not unchanged_in_substance(
            before, _isr(_claim("The blobs are decoded by 0x1400.", confidence=0.5))
        )
        assert unchanged_in_substance(
            before, _isr(_claim("The blobs are decoded by 0x1400.", confidence=0.71))
        )

    def test_an_answer_with_no_claim_is_never_reworded(self) -> None:
        assert not unchanged_in_substance(_isr(), _isr())

    @staticmethod
    def _state(reworded: bool) -> dict[str, Any]:
        return {
            "iteration_count": 2,
            "is_consensus": False,
            "consensus_applicable": True,
            "confidence_history": [0.6, 0.6],
            "discussion_history": [
                AgentArgument(agent_name="Mediator", finding="x", contradictions=[UNANSWERED]),
                AgentArgument(agent_name="Mediator", finding="y", contradictions=[NO_COUNT]),
            ],
            "revision_rounds": [
                {"round": 1, "made": 2, "identical": False, "reworded": reworded, "revised": []}
            ],
        }

    def test_a_round_that_only_reworded_ends_the_debate(self) -> None:
        assert debate_route(self._state(True), max_rounds=5) == ("judge", REWORDED)

    def test_a_round_that_changed_a_claim_goes_on(self) -> None:
        assert debate_route(self._state(False), max_rounds=5) == ("revision", NO_CONSENSUS)

    def test_a_record_written_before_the_field_existed_goes_on(self) -> None:
        state = self._state(False)
        del state["revision_rounds"][0]["reworded"]
        assert debate_route(state, max_rounds=5) == ("revision", NO_CONSENSUS)


def _entry(seq: int, agent: str, tool: str, address: str, output: str) -> Any:
    return build_entry(
        entry_id=f"ev_{seq:04d}",
        seq=seq,
        agent=agent,
        tool=tool,
        args={"address": address},
        server="decompiler",
        output=output,
    )


class TestARepeatOfAnEarlierRound:
    def test_the_revision_s_guard_answers_it_from_the_held_entry(self) -> None:
        held = _entry(12, "beta", "decompile_function", "0x1400", "undefined8 FUN_1400(void)")
        guard = seeded_repeat_guard(None, earlier_rounds=[held])
        assert guard.answered_by("decompile_function", {"address": "0x1400"}) == "ev_0012"
        entry_id, text = guard.recorded_answer("decompile_function", {"address": "0x1400"}) or (
            "",
            "",
        )
        assert (entry_id, text) == ("ev_0012", "undefined8 FUN_1400(void)")
        assert guard.origin_of("ev_0012") == EARLIER_ROUND
        answer = earlier_chunk_answer(
            "decompile_function", entry_id, text, origin=guard.origin_of(entry_id)
        )
        assert "made in an earlier round of this analysis" in answer
        assert "undefined8 FUN_1400(void)" in answer

    def test_a_chunk_s_answer_reads_as_before(self) -> None:
        assert earlier_chunk_sentence("strings", "ev_0003") == (
            "This call to strings with these arguments was made in an earlier chunk of this "
            "input and is not run again: the text above is the result recorded in [ev_0003]."
        )
        assert seeded_repeat_guard([]).origin_of("ev_0001") == EARLIER_CHUNK

    def test_a_call_with_other_arguments_runs(self) -> None:
        held = _entry(12, "beta", "decompile_function", "0x1400", "listing")
        guard = seeded_repeat_guard(None, earlier_rounds=[held])
        assert guard.answered_by("decompile_function", {"address": "0x1800"}) is None

    def test_the_agent_s_own_earlier_entries_come_from_the_briefed_state(self) -> None:
        rows = [
            _entry(1, "pipeline", "identify_file", "", "{}").model_dump(mode="json"),
            _entry(2, "beta", "decompile_function", "0x1400", "x").model_dump(mode="json"),
            _entry(3, "gamma", "decompile_function", "0x1400", "y").model_dump(mode="json"),
        ]
        agent = SimpleNamespace(name="beta", run_state_source={"evidence_ledger": rows})
        assert [e.id for e in own_earlier_entries(agent)] == ["ev_0002"]
        assert own_earlier_entries(SimpleNamespace(name="beta")) == []


def _tool(name: str, *, server_read_only: bool = False) -> Any:
    from langchain_core.tools import StructuredTool

    from maljan.agents.tool_pinning import READ_ONLY_METADATA_KEY

    async def _run(**_kwargs: Any) -> str:
        return ""

    return StructuredTool.from_function(
        func=None,
        coroutine=_run,
        name=name,
        description=name,
        **({"metadata": {READ_ONLY_METADATA_KEY: True}} if server_read_only else {}),
    )


class TestOnlyAToolThatAnswersTheSameIsSeeded:
    @staticmethod
    def _agent(*tools: Any) -> Any:
        rows = [
            # The rename and the poll come first: a state change after the
            # decompile would make its answer stale.
            _entry(2, "beta", "rename_function", "0x1400", "renamed").model_dump(mode="json"),
            _entry(3, "beta", "task_status", "", "pending").model_dump(mode="json"),
            _entry(4, "beta", "decompile_function", "0x1400", "x").model_dump(mode="json"),
        ]
        return SimpleNamespace(
            name="beta", tools=list(tools), run_state_source={"evidence_ledger": rows}
        )

    def test_a_read_only_decompile_is_seeded_and_a_rename_and_a_poll_are_not(self) -> None:
        agent = self._agent(
            _tool("decompile_function", server_read_only=True),
            _tool("rename_function"),
            _tool("task_status"),
        )
        assert [e.tool for e in repeatable_earlier_entries(agent)] == ["decompile_function"]
        guard = seeded_repeat_guard(None, earlier_rounds=repeatable_earlier_entries(agent))
        assert guard.answered_by("decompile_function", {"address": "0x1400"}) == "ev_0004"
        assert guard.answered_by("rename_function", {"address": "0x1400"}) is None
        assert guard.answered_by("task_status", {"address": ""}) is None

    def test_a_tool_its_declaration_marks_read_only_is_seeded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.tool_declarations import ToolFacts

        monkeypatch.setattr(
            "maljan.agents.tool_pinning.declared_facts_of",
            lambda tool: ToolFacts(read_only=True) if tool.name == "task_status" else None,
        )
        agent = self._agent(
            _tool("rename_function"),
            _tool("task_status"),
            _tool("decompile_function", server_read_only=True),
        )
        assert [e.tool for e in repeatable_earlier_entries(agent)] == [
            "task_status",
            "decompile_function",
        ]

    def test_an_agent_with_no_such_tool_seeds_nothing(self) -> None:
        agent = self._agent(_tool("decompile_function"), _tool("rename_function"))
        assert repeatable_earlier_entries(agent) == []

    def test_the_server_s_read_only_mark_rides_on_its_tool(self) -> None:
        from maljan.agents.mcp_client import MCPLangChainToolkit
        from maljan.agents.tool_pinning import READ_ONLY_METADATA_KEY, answers_again

        def listed(name: str, annotations: Any) -> Any:
            return SimpleNamespace(
                name=name,
                description=name,
                inputSchema={"properties": {}, "required": []},
                annotations=annotations,
            )

        client = MCPLangChainToolkit.__new__(MCPLangChainToolkit)
        client._categories = {}
        reader = client._create_langchain_tool(
            listed("read_thing", SimpleNamespace(readOnlyHint=True))
        )
        writer = client._create_langchain_tool(
            listed("set_thing", SimpleNamespace(readOnlyHint=False))
        )
        bare = client._create_langchain_tool(listed("poll_thing", None))
        assert (reader.metadata or {}).get(READ_ONLY_METADATA_KEY) is True
        assert answers_again(reader)
        assert not answers_again(writer)
        assert not answers_again(bare)


class TestLinearTime:
    def test_ten_times_the_lines_and_the_ledger_cost_at_most_ten_times(self) -> None:
        def cost(scale: int) -> float:
            ledger = [
                {"id": f"ev_{n:04d}", "tool": "t", "structured": {"matches": [], "total": n}}
                for n in range(1, scale + 1)
            ]
            lines = [
                f"[analysts: ALPHA] ALPHA claim 1 says {n} hits and 0 rules in ev_{n:04d}. "
                "[blocking: x]"
                for n in range(1, scale + 1)
            ]
            told = ledger_count_facts(lines, {}, ledger, AGENTS)
            start = time.perf_counter()
            ledger_stated(lines, {}, ledger, AGENTS, told)
            return time.perf_counter() - start

        cost(10)
        small = cost(100)
        large = cost(1_000)
        assert large <= max(small, 1e-3) * 30


class _Address(BaseModel):
    address: str = ""


def _server_tool(name: str, server: str, calls: list[str], *, read_only: bool) -> Any:
    from langchain_core.tools import StructuredTool

    from maljan.agents.tool_pinning import READ_ONLY_METADATA_KEY, SERVER_METADATA_KEY

    def _run(address: str = "") -> str:
        calls.append(f"{name}@{server}")
        return f"{name} answer"

    metadata: dict[str, Any] = {SERVER_METADATA_KEY: server}
    if read_only:
        metadata[READ_ONLY_METADATA_KEY] = True
    return StructuredTool.from_function(
        func=_run,
        name=name,
        description=name,
        args_schema=_Address,
        infer_schema=False,
        metadata=metadata,
    )


def _held(seq: int, tool: str, server: str, output: str = "undefined8 FUN_1400(void)") -> Any:
    return build_entry(
        entry_id=f"ev_{seq:04d}",
        seq=seq,
        agent="beta",
        tool=tool,
        args={"address": "0x1400"},
        server=server,
        output=output,
    )


class TestAStateChangeMakesAnEarlierRoundsAnswerStale:
    """A seeded answer holds only while no call that is not read-only ran on its server since."""

    def _loop(self, *, earlier: list[Any]) -> tuple[dict[str, Any], list[str]]:
        from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
        from maljan.schemas.evidence import EvidenceCounter

        calls: list[str] = []
        tools = [
            _server_tool("decompile_function", "dis", calls, read_only=True),
            _server_tool("rename_function", "dis", calls, read_only=False),
            _server_tool("rename_function_elsewhere", "other", calls, read_only=False),
        ]
        agent = SimpleNamespace(
            name="beta",
            tools=tools,
            run_state_source={"evidence_ledger": [e.model_dump(mode="json") for e in earlier]},
        )
        guard = seeded_repeat_guard(None, earlier_rounds=repeatable_earlier_entries(agent))
        recorder = EvidenceRecorder("beta", counter=EvidenceCounter())
        wrapped = {t.name: t for t in record_tools(tools, recorder, guard)}
        return wrapped, calls

    def test_no_state_change_keeps_the_seed(self) -> None:
        wrapped, calls = self._loop(earlier=[_held(2, "decompile_function", "dis")])
        answer = wrapped["decompile_function"].invoke({"address": "0x1400"})
        assert calls == []
        assert "earlier round" in answer

    def test_a_rename_in_an_earlier_round_makes_the_decompile_run(self) -> None:
        earlier = [
            _held(2, "decompile_function", "dis"),
            _held(3, "rename_function", "dis", output="renamed"),
        ]
        wrapped, calls = self._loop(earlier=earlier)
        wrapped["decompile_function"].invoke({"address": "0x1400"})
        assert calls == ["decompile_function@dis"]

    def test_a_rename_in_this_round_makes_the_next_decompile_run(self) -> None:
        wrapped, calls = self._loop(earlier=[_held(2, "decompile_function", "dis")])
        wrapped["decompile_function"].invoke({"address": "0x1400"})
        wrapped["rename_function"].invoke({"address": "0x1400"})
        wrapped["decompile_function"].invoke({"address": "0x1400"})
        assert calls == ["rename_function@dis", "decompile_function@dis"]

    def test_a_state_change_on_another_server_keeps_the_seed(self) -> None:
        earlier = [
            _held(2, "decompile_function", "dis"),
            _held(3, "rename_function_elsewhere", "other", output="renamed"),
        ]
        wrapped, calls = self._loop(earlier=earlier)
        wrapped["rename_function_elsewhere"].invoke({"address": "0x1400"})
        answer = wrapped["decompile_function"].invoke({"address": "0x1400"})
        assert calls == ["rename_function_elsewhere@other"]
        assert "earlier round" in answer

    def test_the_guard_drops_only_that_server_s_round_seeds(self) -> None:
        guard = seeded_repeat_guard(
            [_held(5, "decompile_function", "dis")],
            earlier_rounds=[_held(2, "decompile_function", "other")],
        )
        assert guard.forget_round_seeds("dis") == 0, "a chunk's seed is kept"
        assert guard.forget_round_seeds("other") == 1
