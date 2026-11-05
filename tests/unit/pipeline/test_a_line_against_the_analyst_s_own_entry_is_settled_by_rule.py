"""A blocking line that sets an analyst's claim against its own dispute entry is settled by rule.

A mediation can block on a line whose whole point is one analyst holding a
claim at one confidence while its own dispute entry, in the same answer, holds
the point at a lower figure. A revision round spent on it asks the analyst to
pick one of its own two figures. The platform picks the lower one, holds the
claim at it, records the settlement, and opens no round for the line:

- the line's one ``[analysts: ...]`` field names one analyst, the line says
  the contradiction is with the analyst's own words, names nobody else (by
  key, label or as "the ... analyst") and writes no claim number it cannot
  settle;
- the claim, the line and a dispute entry of the same answer share a ledger
  id, an address or a quoted value (four characters or more, whole words),
  and the entry's own sentences state exactly one figure, as a confidence,
  that the line states too and that is below the claim's;
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

import pytest

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
    SETTLED_FOR_YOU_HEAD,
    SETTLED_HEAD,
    SETTLED_REASON,
    raised_again,
    settle_own_entry_lines,
    with_settled_by_rule,
)
from maljan.pipeline.routing import (
    HARD_LIMIT,
    NO_CONSENSUS,
    SETTLED_BY_RULE,
    ConsensusRouter,
    debate_route,
    only_settled_by_rule,
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


# The review's false positives: each is a line or an entry the rule must leave
# to the agents.
_LINE_A = (
    '[analysts: packer_scan_x2] Claim 2 holds "qzvent" at 0.85 (ev_0031) while its own dispute '
    "entry cites 0.50 [blocking: own words]"
)
_LINE_B = (
    '[analysts: packer_scan_x2] Claim 2 holds "qzvent" at 0.85 while its own dispute entry moved '
    "from 0.40 to 0.95 on ev_0031 [blocking: own]"
)
_LINE_C = (
    '[analysts: packer_scan_x2] Claim 2 holds "qzvent" at 0.85 though its own dispute entry says '
    "0.40 (ev_0031); claim 3 contradicts ledger ev_0040 which shows no key [blocking: own]"
)
_LINE_D = (
    '[analysts: packer_scan_x2] Claim 2 holds "qzvent" at 0.85 against its own entry at 0.40, and '
    "the sandbox analyst's report shows no such event (ev_0031) [blocking: own]"
)
_LINE_E = (
    '[analysts: packer_scan_x2] Claim 2 holds "qzvent" at 0.85 but its own dispute entry notes the '
    "ev_0031 section entropy ratio 0.30 contradicts packing [blocking: own]"
)
_LINE_F = (
    '[analysts: packer_scan_x2, dynamic] packer claim 2 rates "qzvent" at 0.85 and dynamic claim 1 '
    "at 0.60, each against its own dispute entry, which say 0.40 and 0.30 (ev_0031) "
    "[blocking: own]"
)
_HELD_040 = ['ev_0031: "qzvent" link held at 0.40.']


def _packer_with(dissent: list[str], claim_2: str = "") -> dict[str, AgentISR]:
    update: dict[str, Any] = {"dissent_items": dissent}
    if claim_2:
        update["claims"] = [PACKER.claims[0], _claim(claim_2, 0.85)]
    return {**ISRS, "packer_scan_x2": PACKER.model_copy(update=update)}


@pytest.mark.parametrize(
    ("line", "isrs", "labels"),
    [
        pytest.param(
            _LINE_A,
            _packer_with(
                ['Dynamic\'s claim 3 rates "qzvent" (ev_0031) at 0.50; I disagree and hold 0.85.']
            ),
            None,
            id="the entry quotes a peer's figure",
        ),
        pytest.param(
            _LINE_B,
            _packer_with(
                ['ev_0031: I raised "qzvent" from 0.40 to 0.95 after reading the listing.']
            ),
            None,
            id="the entry raised its figure",
        ),
        pytest.param(_LINE_C, _packer_with(_HELD_040), None, id="the line disputes another claim"),
        pytest.param(_LINE_D, _packer_with(_HELD_040), None, id="a peer named as an analyst"),
        pytest.param(
            _LINE_D.replace("the sandbox analyst's report", "Detonation's trace"),
            _packer_with(_HELD_040),
            {"dynamic": ["Detonation"]},
            id="a peer named by its label",
        ),
        pytest.param(
            _LINE_E,
            _packer_with(
                ['ev_0031: "qzvent" region shows ratio 0.30 of printable bytes; it stands.']
            ),
            None,
            id="a figure that is no confidence",
        ),
        pytest.param(
            _LINE_F,
            {
                **_packer_with(_HELD_040),
                "dynamic": _isr(
                    "dynamic",
                    [_claim('Event "qzvent" seen.', 0.6, "ev_0031")],
                    ['ev_0031 "qzvent": held at 0.30 by me'],
                ),
            },
            None,
            id="a field of two analysts",
        ),
        pytest.param(
            OWN_LINE.replace('"qzvent"', '"dll"').replace("ev_0031 shows", "it shows"),
            _packer_with(['The "dll" link: I hold 0.40.'], 'Routine 0x4410 opens the "dll".'),
            None,
            id="a quoted value of three characters",
        ),
    ],
)
def test_the_review_s_false_positives_are_left_to_the_agents(
    line: str, isrs: dict[str, AgentISR], labels: dict[str, list[str]] | None
) -> None:
    assert settle_own_entry_lines([line], NAMES, isrs, labels) == ([], {})


def test_a_quoted_value_is_matched_as_a_whole_word() -> None:
    line = OWN_LINE.replace("ev_0031 shows", "it shows").replace("qzvent", "evnt1")
    isrs = _packer_with(['"evnt12" is another name: I hold 0.40.'], 'Routine opens "evnt1".')
    assert settle_own_entry_lines([line], NAMES, isrs) == ([], {})
    isrs = _packer_with(['"evnt1" is the name: I hold 0.40.'], 'Routine opens "evnt1".')
    assert settle_own_entry_lines([line], NAMES, isrs)[0]


def test_a_not_blocking_sibling_does_not_keep_the_debate_open() -> None:
    sibling = "[analysts: STATIC ANALYST] claim 1 wording differs [not blocking: wording only]"
    argument = AgentArgument(
        agent_name="Mediator",
        finding="x",
        contradictions=[OWN_LINE, sibling],
        settled_lines=[OWN_LINE],
    )
    assert only_settled_by_rule({"discussion_history": [argument]})
    blocking_left = AgentArgument(
        agent_name="Mediator",
        finding="x",
        contradictions=[OWN_LINE, REAL_LINE],
        settled_lines=[OWN_LINE],
    )
    assert not only_settled_by_rule({"discussion_history": [blocking_left]})


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


class TestTheHeldFigureReachesTheAnalyst:
    def test_a_revision_stating_the_claim_again_higher_is_recorded(self) -> None:
        [line], held = settle_own_entry_lines([OWN_LINE], NAMES, ISRS)
        records = line.records(3)
        assert records[0]["claim_sentence"] == PACKER.claims[1].claim

        assert raised_again("packer_scan_x2", 4, records, held["packer_scan_x2"]) == []
        [said] = raised_again("packer_scan_x2", 4, records, PACKER)
        assert "states claim" in said and "at 0.85 again, above the 0.40" in said
        assert raised_again("static", 4, records, PACKER) == []

    def test_the_revision_is_told_and_the_raise_is_said(self) -> None:
        [line], held = settle_own_entry_lines([OWN_LINE], NAMES, ISRS)
        other = (
            "[analysts: PACKER_SCAN_X2 ANALYST] Claim 1 says a DLL; ev_0001 shows an EXE. "
            "[blocking: the type conflicts with ev_0001]"
        )
        mediation = AgentArgument(
            agent_name="Mediator",
            finding=f"Summary.\n\nContradictions: {OWN_LINE}; {other}\nConfidence: 0.5",
            confidence_score=0.5,
            contradictions=[OWN_LINE, other],
            settled_lines=[OWN_LINE],
            settled_by_rule=[line.sentence(3)],
            settled_claims=line.records(3),
        )
        mediation.revise = ["packer_scan_x2"]
        update, agent = _revise_after(mediation, {**ISRS, **held})

        directive = agent.safe_revise_isr.call_args.args[3]
        assert SETTLED_FOR_YOU_HEAD in directive and line.sentence(3) in directive
        said = update["revision_replacements"]
        assert any("above the 0.40 it was held at by rule" in s for s in said)
        # The settled line withdraws nothing by rule.
        assert not any(
            "withdrawn by rule" in row["sentence"] for row in update.get("dropped_claims") or []
        )


def _revise_after(mediation: AgentArgument, in_force: dict[str, AgentISR]) -> tuple[Any, Any]:
    from maljan.pipeline.nodes import RevisionInput, make_revision_node

    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda *_a: None
    container.analyst_keys.return_value = list(NAMES)
    container.agent_role.side_effect = lambda n: n
    container.config.llm.parallel_analysts = False
    container.config.agents.definitions = {}
    agents: dict[str, Any] = {}
    for name in NAMES:
        agent = MagicMock()
        agent.tools = []
        # The revision states every claim again as its first answer had them.
        agent.safe_revise_isr.return_value = (f"{name} revised", ISRS[name])
        agent.drain_evidence_entries.return_value = []
        agent.validation_findings = []
        agent.validation_retries = 0
        agent.validation_fed_back = {}
        agent.validation_not_run = []
        agent.revision_entries_shown = ()
        agents[name] = agent
    container.get_agent.side_effect = lambda n: agents[n]
    state = {
        "iteration_count": 3,
        "is_consensus": False,
        "consensus_applicable": True,
        "reports": {name: f"{name} first" for name in NAMES},
        "revised_reports": {},
        "isr_reports": in_force,
        "sycophancy_detected": False,
        "discussion_history": [mediation],
        "evidence_ledger": [],
    }
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("maljan.pipeline.nodes._revision_input", lambda *a: RevisionInput(text="data"))
        mp.setattr("maljan.pipeline.nodes.pack_text", lambda *a: "[ev_0001] identity: pe")
        update = asyncio.run(make_revision_node(container)(state))
    return update, agents["packer_scan_x2"]


def test_the_report_prints_each_settlement() -> None:
    from maljan.reporting.models import MalwareReport
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    [line], _held = settle_own_entry_lines([OWN_LINE], NAMES, ISRS)
    report = MalwareReport.model_validate(
        {
            "identity": {"hashes": {"sha256": "0" * 64}},
            "run_summary": {
                "negotiation": {
                    "rounds_completed": 3,
                    "termination_reason": SETTLED_BY_RULE,
                    "settled_by_rule": [line.sentence(3)],
                }
            },
        }
    )
    rendered = MarkdownRenderer()._appendix_run(report)
    assert line.sentence(3) in rendered
