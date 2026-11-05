"""A blocking line that sets an analyst's claim against its own dispute entry is settled by rule.

A mediation can block on a line whose whole point is one analyst holding a
claim at one confidence while its own dispute entry, in the same answer, holds
the point at a lower figure. A revision round spent on it asks the analyst to
pick one of its own two figures. The platform picks the lower one, holds the
claim at it, records the settlement, and opens no round for the line:

- the line has one ``[analysts: ...]`` field, says the contradiction is with
  the analyst's own words, and names nobody else;
- each named analyst's claim, the line and a dispute entry of the same answer
  share a ledger id, an address or a quoted value, and the entry states a
  figure the line states too, below the claim's;
- when every blocking line is settled, the debate ends as ``settled_by_rule``;
  otherwise only the analysts of the other lines revise.

And "its claim N" on a line whose field names one analyst is that analyst's
claim, so withdraw-by-rule can act on it.

Every value is synthetic.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from maljan.core.config import Settings
from maljan.pipeline.debate_facts import (
    NO_ANALYST_NAMED,
    as_not_blocking,
    claims_named_by_lines,
    read_claim_references,
    read_marks,
)
from maljan.pipeline.nodes import make_negotiation_node
from maljan.pipeline.own_entries import (
    SETTLED_HEAD,
    SETTLED_REASON,
    settle_own_entry_lines,
    with_settled_by_rule,
)
from maljan.pipeline.routing import (
    HARD_LIMIT,
    NO_CONSENSUS,
    SETTLED_BY_RULE,
    ConsensusRouter,
    debate_route,
)
from maljan.pipeline.state import AgentArgument
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

NAMES = ["static", "packer_scan_x2", "dynamic"]


def _claim(text: str, confidence: float, ref: str = "") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref, confidence=confidence)


def _isr(name: str, claims: list[ClaimEvidence], dissent: list[str]) -> AgentISR:
    return AgentISR(agent_id=name, domain="static", claims=claims, dissent_items=dissent)


# Claim 2 holds the event name at 0.85; the analyst's own dispute entry holds it at 0.40.
PACKER = _isr(
    "packer_scan_x2",
    [
        _claim("The file is a 64-bit DLL.", 0.9, "ev_0001"),
        _claim(
            'Routine 0x4410 opens the event "qzvent" through slot 0x10c60.',
            0.85,
            "ev_0031 (0x4410 listing)",
        ),
        _claim("The key is applied to the request body.", 0.8, "ev_0040"),
        _claim("No key use on the traffic is shown.", 0.9, "ev_0040"),
    ],
    [
        'Static claim 5 (event "qzvent" at 0.85): disputed. ev_0031 shows two arguments only. '
        "I hold the name link at 0.40 until the disassembly is read.",
        "Dynamic claim 2 (the thread start): not disputed.",
    ],
)
STATIC = _isr(
    "static",
    [_claim('Routine 0x4410 names the event "qzvent".', 0.8, "ev_0031")],
    ['Packer claim 2 ("qzvent" at 0.85): my figure for the name link is 0.55 (ev_0031).'],
)
ISRS = {"static": STATIC, "packer_scan_x2": PACKER, "dynamic": _isr("dynamic", [], [])}

OWN_LINE = (
    '[analysts: PACKER_SCAN_X2 ANALYST] [new] Claim 2 gives the event name "qzvent" at 0.85. '
    "Its own dispute entry holds the name link at 0.40, and ev_0031 shows two arguments only. "
    "[blocking: the claim's confidence contradicts its own dispute entry]"
)
REAL_LINE = (
    "[analysts: DYNAMIC ANALYST] Claim 4 says both paths start the thread; ev_0086 shows "
    "ExitProcess first. [blocking: the claim conflicts with ev_0086]"
)


class TestTheLineIsSettled:
    def test_the_claim_is_held_at_the_lower_figure_and_the_input_is_left_alone(self) -> None:
        settled, held = settle_own_entry_lines([OWN_LINE], NAMES, ISRS)

        [line] = settled
        assert line.line == 1 and line.text == OWN_LINE
        [claim] = line.claims
        assert (claim.analyst, claim.claim, claim.was, claim.now) == (
            "packer_scan_x2",
            2,
            0.85,
            0.4,
        )
        assert [c.confidence for c in held["packer_scan_x2"].claims] == [0.9, 0.4, 0.8, 0.9]
        assert PACKER.claims[1].confidence == 0.85

    def test_the_sentence_names_the_claim_both_figures_and_the_entry(self) -> None:
        [line], _held = settle_own_entry_lines([OWN_LINE], NAMES, ISRS)

        sentence = line.sentence(3)
        assert sentence.startswith("Settled by rule after the round-3 mediation")
        assert "blocking line L1" in sentence
        assert "claim 2 is held at 0.40 (it stated 0.85" in sentence
        assert "I hold the name link at 0.40" in sentence
        assert "[" not in sentence and "\n" not in sentence

    def test_a_long_model_text_is_quoted_capped(self) -> None:
        long_line = OWN_LINE.replace("ev_0031 shows", "ev_0031 shows " + "x " * 400)
        [line], _held = settle_own_entry_lines([long_line], NAMES, ISRS)
        assert "…" in line.sentence(1)
        assert len(line.sentence(1)) < 1200

    def test_two_analysts_each_against_their_own_entries(self) -> None:
        line = (
            "[analysts: PACKER_SCAN_X2 ANALYST, STATIC ANALYST] Packer claim 2 and static "
            'claim 1 give the event "qzvent" at 0.85 and 0.80, while their own dispute entries '
            "hold the link at 0.40 and 0.55. [blocking: each restates its own figure]"
        )
        [settled], held = settle_own_entry_lines([line], NAMES, ISRS)

        assert {(c.analyst, c.claim, c.now) for c in settled.claims} == {
            ("packer_scan_x2", 2, 0.4),
            ("static", 1, 0.55),
        }
        assert held["static"].claims[0].confidence == 0.55

    def test_a_short_form_beside_another_participant_s_name_is_the_field_s(self) -> None:
        # "static" names a participant of its own, and stands right before the
        # packer's own claim number as part of a short form.
        participants = ["static", "static_x2"]
        isrs = {
            "static_x2": _isr(
                "static_x2",
                [_claim('Slot 0x10c60 names "qzvent".', 0.8, "ev_0031")],
                ['My own figure for "qzvent" is 0.55.'],
            )
        }
        line = (
            '[analysts: STATIC_X2 ANALYST] Static x2 claim 1 gives "qzvent" at 0.80 while its own '
            "dispute entry holds 0.55. [blocking: restate it]"
        )
        [settled], _held = settle_own_entry_lines([line], participants, isrs)
        assert settled.claims[0].analyst == "static_x2"

    def test_the_rule_reads_any_agent_key(self) -> None:
        participants = ["Some-Odd_key 7", "other"]
        isrs = {
            "Some-Odd_key 7": _isr(
                "Some-Odd_key 7",
                [_claim("Address 0x5a10 decodes the key.", 0.9)],
                ["0x5a10 decoding is held at 0.60 by me."],
            )
        }
        line = (
            "[analysts: some_odd_key_7] Claim 1 states 0x5a10 at 0.90, against its own entry "
            "at 0.60. [blocking: one figure]"
        )
        [settled], _held = settle_own_entry_lines([line], participants, isrs)
        assert settled.claims[0].analyst == "Some-Odd_key 7"


class TestALineThatIsNotOnlyTheAnalystsOwnStaysForTheAgents:
    def _settled(self, line: str, isrs: dict[str, AgentISR] | None = None) -> list[Any]:
        return settle_own_entry_lines([line], NAMES, isrs or ISRS)[0]

    def test_a_line_against_the_ledger(self) -> None:
        assert self._settled(REAL_LINE) == []

    def test_a_line_that_does_not_say_own(self) -> None:
        line = OWN_LINE.replace("Its own", "A").replace("its own", "a")
        assert self._settled(line) == []

    def test_a_line_naming_another_analyst(self) -> None:
        line = OWN_LINE.replace("Its own", "DYNAMIC ANALYST disagrees, and its own")
        assert self._settled(line) == []

    def test_a_line_naming_another_analyst_s_claim(self) -> None:
        line = OWN_LINE.replace("Its own", "Dynamic claim 3 differs, and its own")
        assert self._settled(line) == []

    def test_a_line_with_two_fields(self) -> None:
        line = OWN_LINE.replace("Its own", "Against [analysts: STATIC ANALYST], its own")
        assert self._settled(line) == []

    def test_a_figure_the_line_does_not_state(self) -> None:
        assert self._settled(OWN_LINE.replace("at 0.40", "lower")) == []

    def test_an_entry_about_another_point(self) -> None:
        isrs = {
            **ISRS,
            "packer_scan_x2": PACKER.model_copy(
                update={"dissent_items": ["Static claim 9 (the export count): I hold 0.40."]}
            ),
        }
        assert self._settled(OWN_LINE, isrs) == []

    def test_a_figure_above_the_claim_is_never_raised_to(self) -> None:
        line = OWN_LINE.replace("at 0.85", "at 0.30").replace("at 0.40", "at 0.90")
        isrs = {
            **ISRS,
            "packer_scan_x2": PACKER.model_copy(
                update={
                    "claims": [
                        PACKER.claims[0],
                        PACKER.claims[1].model_copy(update={"confidence": 0.3}),
                    ],
                    "dissent_items": ['"qzvent": I hold 0.90 (ev_0031).'],
                }
            ),
        }
        assert self._settled(line, isrs) == []

    def test_a_line_not_blocking(self) -> None:
        line = OWN_LINE.replace("[blocking:", "[not blocking:")
        assert settle_own_entry_lines([line], NAMES, ISRS) == ([], {})

    def test_a_claim_the_answer_does_not_hold(self) -> None:
        assert self._settled(OWN_LINE.replace("Claim 2", "Claim 9")) == []


class TestItsClaimIsTheFieldAnalysts:
    LINE = (
        "[analysts: PACKER_SCAN_X2 ANALYST] [new] Claim 3 states the key is applied at 0.80, "
        "while its claim 4 says no key use is shown, and its revision notes lower claim 3 to "
        "0.50. [blocking: one reading at one confidence]"
    )

    def test_its_claim_and_the_claim_written_again_are_read_for_the_analyst(self) -> None:
        refs = read_claim_references([self.LINE], NAMES)

        assert sorted(refs.named["packer_scan_x2"]) == [3, 4]
        assert refs.unplaced == ()

    def test_a_claim_number_with_no_possessive_stays_unplaced(self) -> None:
        # Without "its" no analyst is read for the number, as before.
        refs = read_claim_references([self.LINE.replace("its claim 4", "claim 4 of it")], NAMES)
        assert any(u.why == NO_ANALYST_NAMED and u.claims == "claim 4" for u in refs.unplaced)

    def test_its_claim_after_another_participant_is_not_bound(self) -> None:
        line = self.LINE.replace("while its claim 4", "while STATIC ANALYST and its claim 4")
        refs = read_claim_references([line], NAMES)
        assert 4 not in refs.named.get("packer_scan_x2", {})

    def test_its_claim_on_a_line_naming_two_analysts_is_not_bound(self) -> None:
        line = self.LINE.replace("PACKER_SCAN_X2 ANALYST", "PACKER_SCAN_X2 ANALYST, STATIC ANALYST")
        refs = read_claim_references([line], NAMES)
        assert 4 not in refs.named.get("packer_scan_x2", {})


class TestTheRevisionRoundReadsASettledLineAsNotBlocking:
    def test_the_line_keeps_its_place_and_blocks_nothing(self) -> None:
        lines = [as_not_blocking(OWN_LINE, SETTLED_REASON), REAL_LINE]
        marks = read_marks(lines)

        assert [m.blocking for m in marks] == [False, True]
        assert marks[0].reason == SETTLED_REASON
        named = claims_named_by_lines(lines, NAMES)
        assert named["packer_scan_x2"][2] == [(1, False)]
        assert named["dynamic"][4] == [(2, True)]

    def test_the_next_mediation_is_told_and_nothing_else_changes(self) -> None:
        assert with_settled_by_rule("facts", []) == "facts"
        told = with_settled_by_rule("facts", ["one"])
        assert told == f"facts\n\n{SETTLED_HEAD}\n- one"


def _container(argument: AgentArgument) -> Any:
    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = list(NAMES)
    container.analyst_keys.return_value = list(NAMES)
    judge = MagicMock()
    judge.mediate = AsyncMock(return_value=(argument, False))
    container.get_judge_agent.return_value = judge
    return container


STATE: dict[str, Any] = {
    "iteration_count": 2,
    "reports": {n: f"{n} report" for n in NAMES},
    "isr_reports": dict(ISRS),
}


def _mediated(lines: list[str]) -> dict[str, Any]:
    argument = AgentArgument(
        agent_name="Mediator", finding="lines", confidence_score=0.7, contradictions=lines
    )
    with patch("maljan.pipeline.nodes.detect_sycophancy", return_value=False):
        return asyncio.run(make_negotiation_node(_container(argument))(STATE))


class TestTheNegotiationSettlesAndAsksOnlyTheRest:
    def test_a_settled_line_asks_nobody_and_the_rest_asks_its_analyst(self) -> None:
        result = _mediated([OWN_LINE, REAL_LINE])

        [argument] = result["discussion_history"]
        assert argument.settled_lines == [OWN_LINE]
        assert len(argument.settled_by_rule) == 1
        assert argument.revise == ["dynamic"]
        assert result["isr_reports"]["packer_scan_x2"].claims[1].confidence == 0.4
        state = {**STATE, **result}
        assert debate_route(state, max_rounds=5) == ("revision", NO_CONSENSUS)

    def test_every_line_settled_ends_the_debate_on_its_own_reason(self) -> None:
        result = _mediated([OWN_LINE])

        [argument] = result["discussion_history"]
        assert argument.revise == []
        state = {**STATE, **result}
        assert debate_route(state, max_rounds=5) == ("judge", SETTLED_BY_RULE)
        assert ConsensusRouter(Settings()).should_continue(state) == "judge"

    def test_the_last_mediation_the_limit_allows_is_settled_too(self) -> None:
        result = _mediated([OWN_LINE])
        state = {**STATE, **result}
        assert debate_route(state, max_rounds=3) == ("judge", SETTLED_BY_RULE)
        mixed = {**STATE, **_mediated([OWN_LINE, REAL_LINE])}
        assert debate_route(mixed, max_rounds=3) == ("judge", HARD_LIMIT)
        assert mixed["isr_reports"]["packer_scan_x2"].claims[1].confidence == 0.4

    def test_the_room_is_told(self) -> None:
        argument = AgentArgument(
            agent_name="Mediator", finding="lines", confidence_score=0.7, contradictions=[OWN_LINE]
        )
        with (
            patch("maljan.pipeline.nodes.detect_sycophancy", return_value=False),
            patch("maljan.pipeline.nodes.emit_agent_message") as emitted,
        ):
            asyncio.run(make_negotiation_node(_container(argument))(STATE))
        said = [
            call.kwargs
            for call in emitted.call_args_list
            if str(call.kwargs.get("text") or "").startswith("Settled by rule")
        ]
        assert len(said) == 1
        assert said[0]["role"] == "system" and said[0]["round_index"] == 3

    def test_no_settled_line_leaves_the_round_as_before(self) -> None:
        result = _mediated([REAL_LINE])

        [argument] = result["discussion_history"]
        assert argument.settled_lines == [] and argument.settled_by_rule == []
        assert "isr_reports" not in result
        assert argument.revise == ["dynamic"]


class TestTheRunSummaryAndTheReportKeepEverySettlement:
    def test_the_summary_records_the_sentences(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder

        result = _mediated([OWN_LINE])
        state = {**STATE, **result}
        summary = RunSummaryBuilder(start_time=0.0).set_negotiation(state, max_iterations=5).build()
        negotiation = summary.to_dict()["negotiation"]
        assert negotiation["termination_reason"] == SETTLED_BY_RULE
        assert negotiation["settled_by_rule"] == result["discussion_history"][0].settled_by_rule
        assert "Blocking lines settled by rule" in summary.to_markdown()
