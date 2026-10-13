"""The debate does not spend its rounds on a count the ledger answers, or on wording.

A debate ran to its round limit on a rule-match count: one analyst's tool
listed two matches, a rule scan listed none of its 31 rules, and the mediator
kept the line blocking every round. The ledger answers such a line: its cited
entries state each count it states ("0 hits", "31 rules"), including the length
of a match list. Once an earlier mediation stated those facts to the analysts,
the line is not argued again: it no longer blocks, and the run records it with
its facts. A line with a count no entry states is never settled.

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

from maljan.agents.base_agent import own_earlier_entries
from maljan.agents.evidence_recorder import (
    EARLIER_CHUNK,
    EARLIER_ROUND,
    earlier_chunk_answer,
    earlier_chunk_sentence,
    seeded_repeat_guard,
)
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.pipeline.claim_drops import unchanged_in_substance
from maljan.pipeline.debate_facts import (
    fact_atoms,
    ledger_count_facts,
    settled_by_ledger,
    settled_sentence,
)
from maljan.pipeline.nodes import _settled_lines
from maljan.pipeline.routing import NO_CONSENSUS, REWORDED, debate_route
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


class TestALineTheLedgerAnswers:
    def test_it_is_settled_once_the_facts_were_told(self) -> None:
        told = ledger_count_facts([LINE], {}, [SCAN], AGENTS)
        [(line, facts)] = settled_by_ledger([REWORDED_LINE], {}, [SCAN], AGENTS, told)
        assert line == REWORDED_LINE
        assert facts == ("entry ev_0007 (rule_scan) states matches = 0 items, rule_count = 31",)
        assert "Settled by the ledger" in settled_sentence(line, facts)

    def test_it_is_not_settled_before_the_facts_were_told(self) -> None:
        assert settled_by_ledger([LINE], {}, [SCAN], AGENTS, []) == []

    def test_a_fact_not_told_before_keeps_it_blocking_one_round(self) -> None:
        told = ledger_count_facts([LINE], {}, [SCAN], AGENTS)
        assert settled_by_ledger([WITH_RESCAN], {}, [SCAN, RESCAN], AGENTS, told) == []
        told += ledger_count_facts([WITH_RESCAN], {}, [SCAN, RESCAN], AGENTS)
        assert settled_by_ledger([WITH_RESCAN], {}, [SCAN, RESCAN], AGENTS, told)

    @pytest.mark.parametrize("line", [UNANSWERED, NO_COUNT])
    def test_a_line_the_ledger_cannot_answer_is_never_settled(self, line: str) -> None:
        told = ledger_count_facts([LINE, line], {}, [SCAN], AGENTS)
        assert settled_by_ledger([line], {}, [SCAN], AGENTS, told) == []

    def test_the_node_sets_a_settled_line_aside_and_keeps_the_rest(self) -> None:
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
        settled = _settled_lines(state, AGENTS, now)  # type: ignore[arg-type]
        assert [line for line, _facts in settled] == [REWORDED_LINE]

    def test_the_run_summary_records_it(self) -> None:
        sentence = settled_sentence(REWORDED_LINE, ("entry ev_0007 states matches = 0 items",))
        mediator = AgentArgument(agent_name="Mediator", finding="x", settled_by_ledger=[sentence])
        state: dict[str, Any] = {
            "iteration_count": 2,
            "discussion_history": [mediator],
            "confidence_history": [0.6],
        }
        summary = RunSummaryBuilder(start_time=0.0).set_negotiation(state, max_iterations=5).build()
        assert summary.negotiation.settled_by_ledger == [sentence]
        assert summary.to_dict()["negotiation"]["settled_by_ledger"] == [sentence]

    def test_the_mediator_s_prompt_does_not_carry_the_field(self) -> None:
        mediator = AgentArgument(agent_name="Mediator", finding="x", settled_by_ledger=["s"])
        assert "settled_by_ledger" not in repr(mediator)


def _claim(text: str, ref: str = "[ev_0004]", technique: str | None = "T1027") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref, confidence=0.7, technique_id=technique)


def _isr(*claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id="alpha", domain="static", claims=list(claims))


class TestARoundOfWordingOnly:
    def test_other_words_for_the_same_values_ids_and_technique_are_unchanged(self) -> None:
        before = _isr(_claim("Routine 0x1400 decodes 101 blobs with key '12345'."))
        after = _isr(_claim("The decoder at 0x1400 handles all 101 blobs; its key is '12345'."))
        assert unchanged_in_substance(before, after)

    @pytest.mark.parametrize(
        "after",
        [
            _isr(_claim("Routine 0x1400 decodes 100 blobs with key '12345'.")),
            _isr(_claim("Routine 0x1400 decodes 101 blobs with key '12345'.", ref="[ev_0005]")),
            _isr(_claim("Routine 0x1400 decodes 101 blobs with key '12345'.", technique="T1140")),
            _isr(),
        ],
    )
    def test_a_changed_value_entry_or_technique_is_a_change(self, after: AgentISR) -> None:
        before = _isr(_claim("Routine 0x1400 decodes 101 blobs with key '12345'."))
        assert not unchanged_in_substance(before, after)

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
            settled_by_ledger(lines, {}, ledger, AGENTS, told)
            return time.perf_counter() - start

        cost(10)
        small = cost(100)
        large = cost(1_000)
        assert large <= max(small, 1e-3) * 30
