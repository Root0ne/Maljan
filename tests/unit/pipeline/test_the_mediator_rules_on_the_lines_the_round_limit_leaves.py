"""The blocking lines the round limit leaves are ruled on by the mediator, and the rulings kept.

haiku11's last mediation raised a real line (an anti-debug absence against an
entry the reverser read in the debate) and the round limit ended the debate
before any analyst answered it: nobody decided it, and the report printed the
absence. When the router would open another round and the limit forbids it,
the mediator is now asked once more, in its own conversation, with
``read_evidence`` over the run's ledger, to rule on each blocking line; each
ruling is written onto the claims the line names as a note, the claim
standing as written, and every ruling, unruled line and unplaced reference is
a sentence of the run summary. Nothing is asked when the debate goes on, or
when another rule ends it.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage

from maljan.agents.judge_agent import (
    LIMIT_RULING_QUESTION,
    LIMIT_RULING_QUESTION_WITHOUT_TOOLS,
    MEDIATION_ENTRY_CHECK,
    MEDIATOR_HUMAN_CLOSING,
    JudgeAgent,
)
from maljan.core.config import Settings
from maljan.pipeline.limit_rulings import (
    REASON_LIMIT,
    LimitRulings,
    Ruling,
    clean_quote,
    ends_at_the_limit,
    lines_text,
    mark_claims,
    read_rulings,
    round_limit,
    rule_at_the_limit,
)
from maljan.pipeline.state import AgentArgument
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, carried_note

NAMES = ["network", "triage"]
LINE_1 = (
    "[analysts: NETWORK ANALYST] Claim 2 cites [ev_0017] for six TLS SNI names; ev_0017 holds "
    "totals only and the names are in ev_0139. [blocking: the cited entry does not hold them.]"
)
LINE_2 = (
    "[analysts: TRIAGE ANALYST] Claim 1 says no PEB+2 read was recovered, which holds for 0x8690 "
    "only; ev_0143 shows 0x309c reading the byte at PEB+2. [blocking: the absence is wider.]"
)


def _isrs() -> dict[str, AgentISR]:
    return {
        "network": AgentISR(
            agent_id="network",
            domain="network",
            claims=[
                ClaimEvidence(
                    claim="The capture carries DNS query names.",
                    evidence_ref="[ev_0113] 12 names",
                    confidence=0.9,
                ),
                ClaimEvidence(
                    claim="Neither configured host name appears in DNS, HTTP or TLS SNI.",
                    evidence_ref="[ev_0113] names. [ev_0017] six TLS SNI names, all Microsoft.",
                    confidence=0.75,
                ),
            ],
        ),
        "triage": AgentISR(
            agent_id="triage",
            domain="triage",
            claims=[
                ClaimEvidence(
                    claim="No BeingDebugged read was recovered at 0x8690.",
                    evidence_ref="[ev_0088]",
                    confidence=0.6,
                )
            ],
        ),
    }


class TestTheAnswerIsRead:
    def test_each_line_s_ruling_and_its_reason_are_read(self) -> None:
        answer = (
            "Having read ev_0017 and ev_0139:\n"
            "L1: UPHELD: ev_0017 holds no SNI names; ev_0139 does.\n"
            "- **L2** - NOT UPHELD - ev_0143 is a different routine."
        )

        assert read_rulings(answer, 2) == {
            1: Ruling(1, True, "ev_0017 holds no SNI names; ev_0139 does."),
            2: Ruling(2, False, "ev_0143 is a different routine."),
        }

    def test_two_different_rulings_give_none_and_a_number_outside_the_block_is_stated(
        self,
    ) -> None:
        answer = (
            "L1: NOT UPHELD: first\nL1: UPHELD: second\nL2: UPHELD: a\nL2: UPHELD: again\n"
            "L3: UPHELD: no such line\nL0: UPHELD"
        )

        read = read_rulings(answer, 2)

        assert read == {2: Ruling(2, True, "a")}
        assert any("two different rulings on blocking line L1" in s for s in read.stated)
        assert any("ruled on L3, which is no blocking line" in s for s in read.stated)
        assert any("ruled on L0, which is no blocking line" in s for s in read.stated)

    def test_the_block_s_own_numbers_are_the_lines_read(self) -> None:
        read = read_rulings("L1: UPHELD: a\nL3: NOT UPHELD: b", [3])

        assert read == {3: Ruling(3, False, "b")}
        assert any("ruled on L1" in s for s in read.stated)

    def test_a_network_value_in_a_reason_is_written_defanged(self) -> None:
        (ruling,) = read_rulings("L1: UPHELD: see http://evil.com/a and 185.220.101.45", 1).values()

        assert "evil[.]com" in ruling.reason and "185[.]220[.]101[.]45" in ruling.reason
        assert "http://" not in ruling.reason

    def test_prose_that_names_a_line_is_no_ruling(self) -> None:
        assert read_rulings("I think L1 should be upheld, maybe.\nNothing more.", 2) == {}

    def test_a_reason_is_one_bounded_line_with_no_bracket_or_markup(self) -> None:
        reason = clean_quote("[ev_0017] | <b>`x`</b>\n" + "y" * 1000, REASON_LIMIT)

        assert "[" not in reason and "|" not in reason and "<" not in reason
        assert "\n" not in reason and len(reason) == REASON_LIMIT

    def test_the_question_lists_the_lines_as_the_block_numbered_them(self) -> None:
        assert lines_text([LINE_1, "two\nlines"]) == f"Blocking lines:\nL1: {LINE_1}\nL2: two lines"

    def test_the_question_lists_no_line_marked_not_blocking_and_keeps_the_numbers(self) -> None:
        quiet = "[analysts: dynamic] claim 1 wording ev_0005 [not blocking: wording only]"

        assert lines_text([quiet, LINE_1]) == f"Blocking lines:\nL2: {LINE_1}"
        assert lines_text([(4, LINE_1)]) == f"Blocking lines:\nL4: {LINE_1}"


class TestTheRulingsAreWrittenOntoTheClaims:
    def test_each_ruling_is_a_note_on_the_claims_its_line_names_and_the_claim_stands(
        self,
    ) -> None:
        isrs = _isrs()
        rulings = {1: Ruling(1, True, "ev_0139 holds the names"), 2: Ruling(2, False, "other")}

        out = mark_claims([LINE_1, LINE_2], rulings, isrs, NAMES, 5)

        network = out.isrs["network"].claims
        assert [c.claim for c in network] == [c.claim for c in isrs["network"].claims]
        assert network[0] is isrs["network"].claims[0]
        assert network[1].limit_rulings == [
            "at the round limit the mediator ruled blocking line L1 of the round-5 mediation, "
            "which names this claim, UPHELD: ev_0139 holds the names (the mediator's ruling)"
        ]
        assert out.isrs["triage"].claims[0].limit_rulings == [
            "at the round limit the mediator ruled blocking line L2 of the round-5 mediation, "
            "which names this claim, NOT UPHELD: other (the mediator's ruling)"
        ]
        # The answers the node read are not changed.
        assert not isrs["network"].claims[1].limit_rulings
        assert any("upheld blocking line L1" in s for s in out.sentences)
        assert any("did not uphold blocking line L2" in s for s in out.sentences)
        assert any("onto claim 2 of the network analyst" in s for s in out.sentences)

    def test_a_claim_sharing_no_id_or_address_with_its_line_is_not_marked_and_is_stated(
        self,
    ) -> None:
        # haiku10's last line named claims by numbers whose claims in force are
        # about other things: a ruling about a loop is never noted on them.
        line = (
            "[analysts: TRIAGE ANALYST] Claim 1 says the loop at 0x1030 polls; ev_0056 shows "
            "one pass. [blocking: the loop reading is wrong.]"
        )

        out = mark_claims([line], {1: Ruling(1, True, "r")}, _isrs(), NAMES, 5)

        assert out.isrs == {}
        assert any(
            "claim 1 of the triage analyst" in s and "shares no ledger id or address" in s
            for s in out.sentences
        )
        assert not any("names no claim the platform reads" in s for s in out.sentences)

    def test_both_sides_of_a_line_carry_the_same_neutral_note(self) -> None:
        # The review's probe: a two-sided line names the claim it supports
        # too; the note never says the ruling is against it.
        isrs = {
            "static": AgentISR(
                agent_id="static",
                domain="x",
                claims=[
                    ClaimEvidence(claim="PE is a DLL", evidence_ref="ev_0001", confidence=0.8),
                    ClaimEvidence(
                        claim="Imports IsDebuggerPresent at 0x401000",
                        evidence_ref="ev_0005",
                        confidence=0.8,
                    ),
                ],
            ),
            "dynamic": AgentISR(
                agent_id="dynamic",
                domain="x",
                claims=[
                    ClaimEvidence(
                        claim="No anti-debug behaviour seen", evidence_ref="ev_0005", confidence=0.8
                    )
                ],
            ),
        }
        line = (
            "[analysts: static, dynamic] static claim 2 says anti-debug via ev_0005; dynamic "
            "claim 1 says none was seen in ev_0005 [blocking: contested]"
        )

        out = mark_claims(
            [line], {1: Ruling(1, True, "ev_0005 shows the import")}, isrs, ["static", "dynamic"], 5
        )

        notes = [
            out.isrs["static"].claims[1].limit_rulings,
            out.isrs["dynamic"].claims[0].limit_rulings,
        ]
        assert notes[0] == notes[1]
        assert "against" not in notes[0][0] and "which names this claim, UPHELD" in notes[0][0]

    def test_a_line_marked_not_blocking_is_never_ruled_on(self) -> None:
        # The review's probe: a not-blocking sibling is neither listed nor noted.
        quiet = "[analysts: NETWORK ANALYST] Claim 1 wording [ev_0113] [not blocking: wording]"

        out = mark_claims(
            [LINE_1, quiet],
            read_rulings("L1: UPHELD: a\nL2: UPHELD: b", 2),
            _isrs(),
            NAMES,
            5,
        )

        assert not out.isrs["network"].claims[0].limit_rulings
        assert out.isrs["network"].claims[1].limit_rulings
        assert not any("line L2" in s and "upheld" in s for s in out.sentences)
        assert any("ruled on L2, which is no blocking line" in s for s in out.sentences)

    def test_a_line_with_no_ruling_is_stated_and_marks_nothing(self) -> None:
        out = mark_claims([LINE_1, LINE_2], {1: Ruling(1, True, "r")}, _isrs(), NAMES, 5)

        assert "triage" not in out.isrs
        assert any("L2" in s and "gave no ruling on it" in s for s in out.sentences)

    def test_a_reference_that_names_no_claim_is_stated_and_marks_nothing(self) -> None:
        line = (
            "[analysts: NETWORK ANALYST] Round-4 claim 2 cites the wrong entry for the names. "
            "[blocking: wrong entry.]"
        )

        out = mark_claims([line], {1: Ruling(1, True, "r")}, _isrs(), NAMES, 5)

        assert out.isrs == {}
        assert any("its ruling is written onto no claim" in s for s in out.sentences)

    def test_a_number_read_for_its_owner_by_a_shared_entry_is_marked(self) -> None:
        # As the merge reads it (``debate_facts.OwnedClaim``): the claim shares
        # the reference's ledger id, and no other claim of the answer writes it.
        line = (
            "[analysts: NETWORK ANALYST] Round-4 claim 2 cites [ev_0017] for the names. "
            "[blocking: wrong entry.]"
        )

        out = mark_claims([line], {1: Ruling(1, True, "r")}, _isrs(), NAMES, 5)

        assert out.isrs["network"].claims[1].limit_rulings

    def test_no_ruling_at_all_marks_nothing_and_says_so_per_line(self) -> None:
        out = mark_claims([LINE_1, LINE_2], {}, _isrs(), NAMES, 5)

        assert out.isrs == {}
        assert sum("gave no ruling on it" in s for s in out.sentences) == 2

    def test_a_network_value_in_a_sentence_is_written_defanged(self) -> None:
        line = "[analysts: NETWORK ANALYST] Claim 2 names evil.example.com. [blocking: x]"

        ruling = Ruling(1, True, "evil.example.com is absent")

        out = mark_claims([line], {1: ruling}, _isrs(), NAMES, 5)

        assert out.sentences and all("evil.example.com" not in s for s in out.sentences)


class TestTheRulingsReachTheRecord:
    SENTENCE = "At the round limit the mediator upheld blocking line L1: r."

    def test_the_run_summary_records_them_in_its_dict_and_its_markdown(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder

        mediator = AgentArgument(agent_name="Mediator", finding="x", limit_rulings=[self.SENTENCE])
        state: dict[str, Any] = {
            "iteration_count": 5,
            "discussion_history": [mediator],
            "confidence_history": [0.6],
        }

        summary = RunSummaryBuilder(start_time=0.0).set_negotiation(state, max_iterations=5).build()

        assert summary.to_dict()["negotiation"]["limit_rulings"] == [self.SENTENCE]
        assert self.SENTENCE in summary.to_markdown()

    def test_a_run_with_none_records_no_key(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder

        state: dict[str, Any] = {
            "iteration_count": 1,
            "discussion_history": [AgentArgument(agent_name="Mediator", finding="x")],
            "confidence_history": [0.6],
        }

        summary = RunSummaryBuilder(start_time=0.0).set_negotiation(state, max_iterations=5).build()

        assert "limit_rulings" not in summary.to_dict()["negotiation"]

    def test_the_report_s_run_appendix_states_them(self) -> None:
        from maljan.reporting.builder import MalwareReportBuilder
        from maljan.reporting.renderers.markdown import MarkdownRenderer
        from tests.unit.reporting.test_renderers_markdown import _build

        report = _build(
            run_summary={
                "elapsed_seconds": 1.0,
                "final_decision": "Malware",
                "negotiation": {
                    "rounds_completed": 5,
                    "termination_reason": "hard_limit",
                    "limit_rulings": [self.SENTENCE],
                },
            }
        )

        md = MarkdownRenderer().render(MalwareReportBuilder.apply_fallback_narrative(report))

        assert self.SENTENCE in md


class TestARulingReasonRoutesNothing:
    """An entry or a function named only in a ruling's reason is no citation of the claim."""

    REASON_NOTE = (
        "at the round limit the mediator ruled blocking line L1 of the round-5 mediation, "
        "which names this claim, UPHELD: ev_0099 shows the encrypt loop at 0x401500 "
        "(the mediator's ruling)"
    )

    def _claims(self, ruled: bool, carried: int | None = None) -> list[dict[str, str]]:
        from maljan.reporting.evidence_bundles import _claims_text

        claim = ClaimEvidence(
            claim="The packer stub at 0x401000 decodes the payload.",
            evidence_ref="[ev_0012] decode listing",
            confidence=0.7,
            carried_since_round=carried,
            limit_rulings=[self.REASON_NOTE] if ruled else [],
        )
        isrs = {"static": AgentISR(agent_id="static", domain="static", claims=[claim])}
        return _claims_text(None, isrs)  # type: ignore[arg-type]

    def test_the_cited_entries_and_the_picked_functions_are_the_claim_s_own(self) -> None:
        from maljan.reporting.evidence_bundles import FunctionCode, _claimed_rows, cited_entry_ids

        own, ruled = self._claims(False), self._claims(True)
        rows = {
            "ev_0012": [FunctionCode(key="a", where="0x401000", tool="t", code="c")],
            "ev_0099": [FunctionCode(key="b", where="0x401500", tool="t", code="d")],
        }
        by_address = {0x401000: rows["ev_0012"], 0x401500: rows["ev_0099"]}

        assert cited_entry_ids(ruled) == cited_entry_ids(own) == {"ev_0012"}
        assert [r.key for r in _claimed_rows(ruled[0], by_address, rows, ())] == ["a"]
        assert [r.key for r in _claimed_rows(own[0], by_address, rows, ())] == ["a"]

    def test_a_keyword_only_in_the_reason_pulls_the_claim_into_no_section(self) -> None:
        from maljan.reporting.evidence_bundles import _filter_claims

        own, ruled = self._claims(False), self._claims(True)

        assert _filter_claims(ruled, ("encrypt",)) == _filter_claims(own, ("encrypt",)) == []
        # A keyword of the claim's own still does.
        assert _filter_claims(ruled, ("pack",)) == ruled

    def test_a_carried_and_ruled_claim_routes_on_its_evidence_and_carried_note(self) -> None:
        from maljan.reporting.evidence_bundles import ROUTED_REF, _routed
        from maljan.schemas.isr_models import carried_marker

        (claim,) = self._claims(True, carried=2)

        carried = carried_marker(2)
        assert claim[ROUTED_REF] == f"[ev_0012] decode listing ({carried})"
        assert claim["evidence_ref"] == f"[ev_0012] decode listing ({carried}; {self.REASON_NOTE})"
        assert carried in _routed(claim) and "ev_0099" not in _routed(claim)

    def test_the_section_s_text_still_carries_the_note_whole(self) -> None:
        import json

        (claim,) = self._claims(True)

        assert claim["evidence_ref"] == f"[ev_0012] decode listing ({self.REASON_NOTE})"
        assert self.REASON_NOTE in json.dumps(claim)

    def test_a_claim_with_no_ruling_is_the_row_it_always_was(self) -> None:
        (claim,) = self._claims(False, carried=2)

        assert list(claim) == ["claim", "evidence_ref", "agent", "label"]


class TestTheNoteTravelsWithTheClaim:
    def test_the_note_reaches_the_judge_s_summary_and_the_event_payload(self) -> None:
        from maljan.pipeline.events import claims_to_payload

        claim = ClaimEvidence(
            claim="c", evidence_ref="[ev_0001]", confidence=0.5, limit_rulings=["ruled: r"]
        )
        isr = AgentISR(agent_id="a", domain="static", claims=[claim])

        assert carried_note(claim) == "ruled: r"
        assert "(ruled: r)" in isr.to_text_summary()
        (row,) = claims_to_payload([claim])
        assert row["limit_rulings"] == ["ruled: r"] and row["carried_note"] == "ruled: r"

    def test_a_carried_claim_s_note_keeps_its_carried_words_first(self) -> None:
        claim = ClaimEvidence(
            claim="c",
            evidence_ref="[ev_0001]",
            confidence=0.5,
            carried_since_round=2,
            limit_rulings=["ruled: r"],
        )

        assert carried_note(claim) == (
            "carried forward: the round-2 revision neither wrote it again nor withdrew it; ruled: r"
        )

    def test_a_claim_with_no_ruling_serialises_and_reads_as_before(self) -> None:
        from maljan.pipeline.events import claims_to_payload

        claim = ClaimEvidence(claim="c", evidence_ref="[ev_0001]", confidence=0.5)

        assert "limit_rulings" not in claim.model_dump(mode="json")
        assert carried_note(claim) == ""
        assert "limit_rulings" not in claims_to_payload([claim])[0]


def _state(iteration: int, *, revised: bool = True) -> dict[str, Any]:
    """A debate state before mediation ``iteration + 1``: the last round revised analysts."""
    rounds = (
        [{"round": iteration, "made": 1, "revised": ["network"], "identical": False}]
        if revised
        else []
    )
    return {
        "iteration_count": iteration,
        "confidence_history": [0.4] * iteration,
        "discussion_history": [],
        "revision_rounds": rounds,
        "isr_reports": _isrs(),
    }


def _update(iteration: int, lines: list[str], *, consensus: bool = False) -> dict[str, Any]:
    argument = AgentArgument(
        agent_name="Mediator",
        finding="f",
        confidence_score=0.4,
        contradictions=lines,
        revise=[] if not lines else ["network"],
    )
    return {
        "iteration_count": iteration + 1,
        "is_consensus": consensus,
        "consensus_applicable": True,
        "confidence_history": [0.4],
        "discussion_history": [argument],
    }


class TestOnlyTheLimitAsks:
    def test_the_last_round_the_limit_allows_with_a_blocking_line_asks(self) -> None:
        assert ends_at_the_limit(_state(4), _update(4, [LINE_1]), None, 5) is True

    def test_a_debate_that_goes_on_asks_nothing(self) -> None:
        assert ends_at_the_limit(_state(3), _update(3, [LINE_1]), None, 5) is False

    def test_a_debate_another_rule_ends_asks_nothing(self) -> None:
        # Consensus, and no contested point, end the debate whatever the limit.
        assert ends_at_the_limit(_state(4), _update(4, [], consensus=True), None, 5) is False
        assert ends_at_the_limit(_state(4), _update(4, []), None, 5) is False

    def test_a_stage_s_own_limit_and_the_shipped_settings_are_read(self) -> None:
        settings = Settings()
        stage = SimpleNamespace(debate=SimpleNamespace(max_rounds=3))

        assert round_limit(settings, None) == int(settings.negotiation.max_iterations)
        assert round_limit(settings, stage) == 3

    def test_a_stage_s_first_mediation_counts_from_where_it_began(self) -> None:
        state = {**_state(4), "debate_starts": {"first": {"mediations": 0}}}

        # A second debate opening at the run's fifth mediation has held none.
        assert ends_at_the_limit(state, _update(4, [LINE_1]), "second", 5) is False
        assert ends_at_the_limit(state, _update(4, [LINE_1]), "second", 1) is True


class _Judge:
    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.asked: list[tuple[str, Any]] = []

    async def rule_on_standing_lines(self, text: str, ledger: Any) -> str:
        self.asked.append((text, ledger))
        if isinstance(self.answer, BaseException):
            raise self.answer
        return str(self.answer)


async def _run(question: Any) -> str:
    return str(await question)


class TestTheQuestionIsAskedOnce:
    def _rule(self, judge: _Judge) -> LimitRulings:
        return asyncio.run(
            rule_at_the_limit(judge, [LINE_1, LINE_2], _isrs(), NAMES, 5, ["ledger"], _run)
        )

    def test_the_lines_and_the_run_s_ledger_are_put_once(self) -> None:
        judge = _Judge("L1: UPHELD: ev_0139 holds them\nL2: NOT UPHELD: no")

        out = self._rule(judge)

        assert judge.asked == [(lines_text([LINE_1, LINE_2]), ["ledger"])]
        assert set(out.isrs) == {"network", "triage"}

    @pytest.mark.parametrize(
        ("answer", "recorded", "why"),
        [
            (TimeoutError(), "", "it failed: TimeoutError"),
            ("", "", "the question was not answered"),
            (
                "",
                "the question was refused by the job's spend ceiling",
                "the question was refused by the job's spend ceiling",
            ),
            ("", "no mediation answered in this agent", "no mediation answered in this agent"),
        ],
    )
    def test_a_question_with_no_answer_changes_no_claim_and_says_why(
        self, answer: Any, recorded: str, why: str
    ) -> None:
        judge = _Judge(answer)
        judge.limit_ruling_failure = recorded

        out = self._rule(judge)

        assert out.isrs == {}
        (sentence,) = out.sentences
        assert why in sentence and "stand as written" in sentence


class _ReadingLlm:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any], **_kwargs: Any) -> Any:
        self.calls.append(list(messages))
        return AIMessage(content=self._answers.pop(0))


class TestTheJudgeAsksInItsOwnConversation:
    def test_the_question_follows_the_mediation_s_answer(self) -> None:
        llm = _ReadingLlm("L1: UPHELD: r")
        judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
        judge._mediation_turns = ([("system", "You mediate."), ("human", "Reports.")], "Answer.")

        text = asyncio.run(judge.rule_on_standing_lines("Blocking lines:\nL1: x", None))

        assert text == "L1: UPHELD: r"
        (sent,) = llm.calls
        assert [m.content for m in sent[-2:]] == [
            "Answer.",
            f"{LIMIT_RULING_QUESTION_WITHOUT_TOOLS}\n\nBlocking lines:\nL1: x",
        ]
        assert judge._mediation_ledger is None

    def test_with_the_run_s_ledger_the_question_may_read_it(self) -> None:
        from tests.unit.agents.test_the_judges_calls_may_read_the_ledger import (
            LEDGER,
        )
        from tests.unit.agents.test_the_judges_calls_may_read_the_ledger import (
            _ReadingLlm as _BindingLlm,
        )

        llm = _BindingLlm("L1: NOT UPHELD: r")
        judge = JudgeAgent(llm=llm)
        judge._mediation_turns = ([("human", "Mediate.")], "Answer.")

        text = asyncio.run(judge.rule_on_standing_lines("Blocking lines:\nL1: x", list(LEDGER)))

        assert text == "L1: NOT UPHELD: r"
        names, sent = llm.calls[0]
        assert names and sent[-1].content == f"{LIMIT_RULING_QUESTION}\n\nBlocking lines:\nL1: x"

    def test_no_mediation_answered_asks_nothing_and_says_why(self) -> None:
        llm = _ReadingLlm()
        judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]

        assert asyncio.run(judge.rule_on_standing_lines("Blocking lines:\nL1: x", None)) == ""
        assert llm.calls == []
        assert judge.limit_ruling_failure == "no mediation answered in this agent"

    def test_a_question_the_spend_ceiling_refuses_says_so(self) -> None:
        from maljan.core.spend import SpendCeilingStop

        llm = _ReadingLlm()
        judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
        judge._mediation_turns = ([("human", "Mediate.")], "Answer.")

        def _refuse(*_args: Any, **_kwargs: Any) -> Any:
            raise SpendCeilingStop("the ceiling is reached")

        with patch.object(judge, "_spend_admits", side_effect=_refuse):
            text = asyncio.run(judge.rule_on_standing_lines("Blocking lines:\nL1: x", None))

        assert text == "" and llm.calls == []
        assert judge.limit_ruling_failure == "the question was refused by the job's spend ceiling"

    def test_a_question_that_fails_names_the_class(self) -> None:
        class _Failing:
            async def ainvoke(self, *_args: Any, **_kwargs: Any) -> Any:
                raise ConnectionError("host went away")

        judge = JudgeAgent(llm=_Failing())  # type: ignore[arg-type]
        judge._mediation_turns = ([("human", "Mediate.")], "Answer.")

        assert asyncio.run(judge.rule_on_standing_lines("Blocking lines:\nL1: x", None)) == ""
        assert judge.limit_ruling_failure == "the question failed: ConnectionError"


def _human_turn(ledger: Any) -> str:
    judge = JudgeAgent(llm=MagicMock())
    seen: list[Any] = []

    async def _loop(messages: list[Any]) -> str:
        seen.append(messages)
        return ""

    with (
        patch.object(judge, "_initialize_mcp_client"),
        patch.object(judge, "execute_tool_loop", side_effect=_loop),
    ):
        asyncio.run(judge.mediate({"static": "a", "dynamic": "b"}, [], ledger=ledger))
    return str(seen[0][1][1])


class TestTheMediatorIsAskedToReadTheEntryALineTurnsOn:
    def test_with_the_run_s_ledger_the_closing_asks_it_to_read_the_entry(self) -> None:
        text = _human_turn([{"id": "ev_0001", "agent": "static", "tool": "t", "output": "o"}])

        assert text.endswith(f"{MEDIATION_ENTRY_CHECK} {MEDIATOR_HUMAN_CLOSING}")

    def test_without_a_ledger_the_turn_is_the_one_it_always_was(self) -> None:
        text = _human_turn(None)

        assert text.endswith(MEDIATOR_HUMAN_CLOSING)
        assert MEDIATION_ENTRY_CHECK not in text


def _node_run(
    iteration: int,
    max_rounds: int,
    lines: list[str] | None = None,
    answer: Any = "L1: UPHELD: r1\nL2: NOT UPHELD: r2",
) -> tuple[dict[str, Any], Any, list[Any]]:
    from unittest.mock import AsyncMock

    from maljan.pipeline.nodes import make_negotiation_node

    events: list[Any] = []
    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda t, d: events.append((t, d))
    container.analyst_keys.return_value = list(NAMES)
    container.config.negotiation.max_iterations = max_rounds
    argument = AgentArgument(
        agent_name="Mediator",
        finding="f",
        confidence_score=0.4,
        contradictions=[LINE_1, LINE_2] if lines is None else lines,
    )
    judge = MagicMock()
    judge.mediate = AsyncMock(return_value=(argument, False))
    judge.rule_on_standing_lines = AsyncMock(
        side_effect=answer if isinstance(answer, BaseException) else None,
        return_value=answer,
    )
    judge.limit_ruling_failure = ""
    container.get_judge_agent.return_value = judge
    state = {
        **_state(iteration),
        "reports": {"network": "n", "triage": "t"},
        "evidence_ledger": [{"id": "ev_0017", "agent": "network", "tool": "t", "output": "o"}],
    }
    result = asyncio.run(make_negotiation_node(container)(state))
    return result, judge, events


class TestTheNegotiationNodeRulesAtTheLimit:
    def test_at_the_limit_the_rulings_reach_the_claims_the_record_and_the_room(self) -> None:
        result, judge, events = _node_run(4, 5)

        judge.rule_on_standing_lines.assert_awaited_once()
        assert judge.rule_on_standing_lines.await_args.args[1][0]["id"] == "ev_0017"
        (argument,) = result["discussion_history"]
        assert any("upheld blocking line L1" in s for s in argument.limit_rulings)
        assert "Rulings at the round limit:" in argument.finding
        assert result["isr_reports"]["network"].claims[1].limit_rulings
        assert result["isr_reports"]["triage"].claims[0].limit_rulings
        texts = [d.get("text", "") for t, d in events if t == "agent_message"]
        assert any("did not uphold blocking line L2" in text for text in texts)

    def test_a_not_blocking_sibling_is_not_put_and_keeps_no_number(self) -> None:
        quiet = "[analysts: TRIAGE ANALYST] Claim 1 at 0x8690 [not blocking: wording only]"

        result, judge, _events = _node_run(4, 5, [quiet, LINE_1], "L2: UPHELD: r")

        (text, _ledger) = judge.rule_on_standing_lines.await_args.args
        assert text == f"Blocking lines:\nL2: {LINE_1}"
        assert set(result["isr_reports"]) == {"network"}
        (argument,) = result["discussion_history"]
        assert any("upheld blocking line L2" in s for s in argument.limit_rulings)

    def test_a_ruling_that_raises_leaves_the_mediation_complete_and_says_so(self) -> None:
        from unittest.mock import patch as _patch

        with _patch("maljan.pipeline.nodes.rule_at_the_limit", side_effect=RuntimeError("boom")):
            result, _judge, _events = _node_run(4, 5)

        (argument,) = result["discussion_history"]
        assert argument.status == "complete"
        assert result["is_consensus"] is False
        assert "isr_reports" not in result
        (sentence,) = argument.limit_rulings
        assert "it failed: RuntimeError" in sentence and "boom" not in sentence

    def test_before_the_limit_nothing_is_asked_and_no_claim_changes(self) -> None:
        result, judge, _events = _node_run(3, 5)

        judge.rule_on_standing_lines.assert_not_called()
        assert "isr_reports" not in result
        (argument,) = result["discussion_history"]
        assert argument.limit_rulings == [] and argument.finding == "f"
