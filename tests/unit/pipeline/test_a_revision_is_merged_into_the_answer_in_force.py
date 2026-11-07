"""A debate revision is merged into the answer in force by claim, and never shrinks it silently.

A claim the revision writes again replaces its predecessor; a claim it
withdraws (a ``WITHDRAW CLAIM`` line, or a block under the claim's number that
declares the withdrawal) is removed with its reason; a claim it does not
mention stays as the answer in force wrote it, marked carried forward from the
round. A revision that numbers its blocks is placed by those numbers; any
other is placed by what its claims state. A revision that writes again or
withdraws every claim in force stands as written, as it always did.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

from malspark.agents.base_agent import read_claim_blocks
from malspark.pipeline.nodes import make_revision_node
from malspark.pipeline.revision_merge import merge_revision
from malspark.pipeline.validation import claim_block_indexes
from malspark.schemas.isr_models import AgentISR, ClaimEvidence, claim_summary_line


def _block(sentence: str, technique: str = "NONE", number: int | None = None) -> str:
    head = "CLAIM:" if number is None else f"CLAIM {number}:"
    return f"{head} {sentence}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: {technique}\n---\n"


def _isr(text: str) -> AgentISR:
    isr = AgentISR(agent_id="static", domain="static", claims=read_claim_blocks(text).claims)
    isr.note_answer_text(text)
    return isr


def _sentences(isr: Any) -> list[str]:
    return [c.claim for c in isr.claims]


MUTEX = "0x401000 creates the mutex Global\\qx7 before anything else."
BEACON = "0x402000 beacons every 600 seconds to the configured host."
CRYPTO = "0x403000 decrypts the configuration with the key 0x5a."
PERSIST = "0x404000 writes the Run key value qx7svc."
FIRST = _block(MUTEX) + _block(BEACON, "T1071.001") + _block(CRYPTO) + _block(PERSIST)
FIXED_BEACON = "0x402000 beacons every 900 seconds to the configured host."
NEW = "0x405000 enumerates the running processes with a snapshot."


class TestARevisionIsMergedByClaimNumber:
    def test_a_claim_written_again_replaces_it_and_the_rest_are_carried(self) -> None:
        answer = _block(FIXED_BEACON, "T1071.001", number=2)

        merge = merge_revision(_isr(FIRST), _isr(answer), answer, 3)

        assert merge.placed_by == "number" and merge.merged is not None
        assert _sentences(merge.merged) == [MUTEX, FIXED_BEACON, CRYPTO, PERSIST]
        assert merge.replaced == (2,) and merge.added == 0 and merge.withdrawn == ()
        assert [n for n, _s in merge.carried] == [1, 3, 4]
        marks = [c.carried_since_round for c in merge.merged.claims]
        assert marks == [3, None, 3, 3]

    def test_a_new_number_is_added_after_the_claims_in_force(self) -> None:
        answer = _block(FIXED_BEACON, "T1071.001", number=2) + _block(NEW, number=5)

        merge = merge_revision(_isr(FIRST), _isr(answer), answer, 1)

        assert merge.merged is not None
        assert _sentences(merge.merged) == [MUTEX, FIXED_BEACON, CRYPTO, PERSIST, NEW]
        assert merge.added == 1

    def test_the_numbers_stay_stable_for_the_next_round(self) -> None:
        answer = _block(FIXED_BEACON, "T1071.001", number=2)

        merged = merge_revision(_isr(FIRST), _isr(answer), answer, 1).merged

        # Claim N of the answer in force is claim N of the merged answer.
        assert merged is not None
        assert [i + 1 for i in claim_block_indexes(merged.claims)] == [1, 2, 3, 4]
        again = _block(MUTEX.replace("Global", "Local"), number=1)
        second = merge_revision(merged, _isr(again), again, 2)
        assert second.merged is not None
        assert second.replaced == (1,)
        # The beacon claim round 1 wrote is carried from round 2 on.
        assert [c.carried_since_round for c in second.merged.claims] == [None, 2, 1, 1]

    def test_a_number_that_shares_nothing_with_its_claim_is_not_trusted(self) -> None:
        # A fresh answer numbered from 1: its numbers do not name the claims
        # in force, so it is placed by what it states.
        answer = _block(NEW, number=1) + _block(FIXED_BEACON, "T1071.001", number=2)

        merge = merge_revision(_isr(FIRST), _isr(answer), answer, 1)

        assert merge.placed_by == "statement"
        assert merge.merged is not None
        assert _sentences(merge.merged) == [MUTEX, FIXED_BEACON, CRYPTO, PERSIST, NEW]
        assert merge.replaced == (2,)


class TestAWithdrawalIsExplicit:
    def test_a_withdraw_line_removes_the_claim_with_its_reason(self) -> None:
        answer = (
            _block(FIXED_BEACON, "T1071.001", number=2)
            + "WITHDRAW CLAIM 4: the Run key write is a peer's, not this sample's.\n"
        )

        merge = merge_revision(_isr(FIRST), _isr(answer), answer, 2)

        assert merge.merged is not None
        assert _sentences(merge.merged) == [MUTEX, FIXED_BEACON, CRYPTO]
        assert merge.withdrawn == (
            (4, PERSIST, "the Run key write is a peer's, not this sample's."),
        )
        said = merge.sentences("static", 2)
        assert said[-1] == (
            "The static analyst's round-2 revision withdrew claim 4 "
            f"(\"{PERSIST}\"): the Run key write is a peer's, not this sample's."
        )

    def test_a_block_under_a_claim_s_number_may_declare_its_withdrawal(self) -> None:
        answer = _block(FIXED_BEACON, "T1071.001", number=2) + _block(
            "This claim is withdrawn: the key was read from a peer's listing.", number=3
        )

        merge = merge_revision(_isr(FIRST), _isr(answer), answer, 1)

        assert merge.merged is not None
        assert _sentences(merge.merged) == [MUTEX, FIXED_BEACON, PERSIST]
        assert [(n, s) for n, s, _r in merge.withdrawn] == [(3, CRYPTO)]
        assert "withdrawn" in merge.withdrawn[0][2]

    def test_an_explicit_mass_withdrawal_still_shrinks_the_answer(self) -> None:
        answer = _block(FIXED_BEACON, "T1071.001") + (
            "WITHDRAW CLAIMS 1, 3-4: each rests on a listing this round showed is a peer's.\n"
        )

        merge = merge_revision(_isr(FIRST), _isr(answer), answer, 4)

        # Nothing is carried: the revision stands as written, and every
        # withdrawal is recorded with its reason.
        assert merge.merged is None and merge.carried == ()
        assert [n for n, _s, _r in merge.withdrawn] == [1, 3, 4]
        assert all(r.startswith("each rests on") for _n, _s, r in merge.withdrawn)
        assert len(merge.sentences("static", 4)) == 3

    def test_a_claim_written_again_is_not_withdrawn_by_a_line(self) -> None:
        answer = _block(FIXED_BEACON, "T1071.001", number=2) + "WITHDRAW CLAIM 2: superseded.\n"

        merge = merge_revision(_isr(FIRST), _isr(answer), answer, 1)

        assert merge.merged is not None and merge.withdrawn == ()
        assert FIXED_BEACON in _sentences(merge.merged)


class TestAnUnnumberedRevisionIsPlacedByWhatItStates:
    def test_a_revision_that_restates_every_claim_stands_as_written(self) -> None:
        answer = (
            _block(PERSIST) + _block(CRYPTO) + _block(FIXED_BEACON, "T1071.001") + _block(MUTEX)
        )

        merge = merge_revision(_isr(FIRST), _isr(answer), answer, 1)

        # The answer as dev took it: nothing carried, nothing merged.
        assert merge.merged is None and merge.carried == ()
        assert merge.sentences("static", 1) == []

    def test_a_corrected_value_replaces_the_claim_rather_than_carrying_it(self) -> None:
        answer = (
            _block(MUTEX) + _block(FIXED_BEACON, "T1071.001") + _block(CRYPTO) + _block(PERSIST)
        )

        merge = merge_revision(_isr(FIRST), _isr(answer), answer, 1)

        # "600" left the beacon claim, but it states most of what it did.
        assert merge.merged is None and merge.carried == ()

    def test_a_claim_split_over_two_revision_claims_is_restated(self) -> None:
        split = (
            _block("0x403000 decrypts the configuration.")
            + _block("The configuration key is 0x5a.")
            + _block(MUTEX)
            + _block(BEACON, "T1071.001")
            + _block(PERSIST)
        )

        merge = merge_revision(_isr(FIRST), _isr(split), split, 1)

        assert merge.merged is None


class TestTheHaiku8ShapeKeepsWhatTheRevisionLeftOut:
    """A revision of 10 claims against 69 in force, with no withdrawal (haiku8, D3)."""

    @staticmethod
    def _shape() -> tuple[AgentISR, AgentISR, str]:
        first = "".join(
            _block(f"Routine 0x{0x410000 + n * 0x100:x} reads the value {1000 + n}.")
            for n in range(69)
        )
        # The revision restates ten of them, each with a changed wording, and
        # numbers none.
        revised = "".join(
            _block(f"The value {1000 + n} is read by routine 0x{0x410000 + n * 0x100:x}.")
            for n in range(0, 69, 7)
        )
        return _isr(first), _isr(revised), revised

    def test_sixty_nine_claims_stand_with_ten_replaced(self) -> None:
        in_force, revision, answer = self._shape()

        merge = merge_revision(in_force, revision, answer, 4)

        assert len(revision.claims) == 10
        assert merge.merged is not None
        assert len(merge.merged.claims) == 69
        assert len(merge.replaced) == 10 and merge.added == 0 and merge.withdrawn == ()
        assert len(merge.carried) == 59
        carried = [c for c in merge.merged.claims if c.carried_since_round == 4]
        assert len(carried) == 59
        assert {c.claim for c in revision.claims} <= set(_sentences(merge.merged))

    def test_the_merge_is_said_once_with_each_carried_number(self) -> None:
        in_force, revision, answer = self._shape()

        [said] = merge_revision(in_force, revision, answer, 4).sentences("static", 4)

        assert said.startswith(
            "The static analyst's round-4 revision wrote 10 claim(s) against 69 in force: "
            "by what they state, they restate 10 of those and add 0; it withdrew 0, and the "
            "other 59 stand carried forward unchanged (claims 2-7, 9-14, 16-21, 23-28, 30-35,"
        )

    def test_the_input_answers_are_not_changed(self) -> None:
        in_force, revision, answer = self._shape()
        before = [c.model_dump() for c in in_force.claims]

        merge_revision(in_force, revision, answer, 4)

        assert [c.model_dump() for c in in_force.claims] == before
        assert all(c.carried_since_round is None for c in revision.claims)


class TestACarriedClaimSaysSo:
    def test_the_summary_line_marks_it(self) -> None:
        claim = ClaimEvidence(claim="A.", evidence_ref="[ev_0001]", confidence=0.5)
        claim.carried_since_round = 2

        line = claim_summary_line(1, claim)

        assert line.endswith(
            "(carried forward: the round-2 revision neither wrote it again nor withdrew it)"
            " | Confidence: 0.50"
        )

    def test_an_unmarked_claim_serialises_as_before(self) -> None:
        claim = ClaimEvidence(claim="A.", evidence_ref="[ev_0001]", confidence=0.5)

        assert "carried_since_round" not in claim.model_dump()

    def test_a_carried_claim_is_its_own_block(self) -> None:
        one = ClaimEvidence(
            claim="A.", evidence_ref="[ev_0001]", confidence=0.5, technique_id="T1027"
        )
        two = one.model_copy(update={"technique_id": "T1140"})
        two.carried_since_round = 1

        assert claim_block_indexes([one, two]) == [0, 1]

    def test_no_claim_on_either_side_merges_nothing(self) -> None:
        empty = AgentISR(agent_id="static", domain="static", claims=[])

        assert merge_revision(empty, _isr(FIRST), FIRST, 1).merged is None
        assert merge_revision(_isr(FIRST), empty, "", 1).merged is None


def _node_run(in_force: AgentISR, revision: AgentISR, written: str) -> dict[str, Any]:
    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = ["static"]
    container.analyst_keys.return_value = ["static"]
    container.agent_role.side_effect = lambda n: n
    container.config.llm.parallel_analysts = False
    agent = MagicMock()
    agent.safe_revise_isr.return_value = (written, revision)
    container.get_agent.return_value = agent
    container.load_chunked.return_value = [MagicMock(content="data")]
    container.load_data.return_value = "data"
    node = make_revision_node(container)
    state = {
        "file_hash": "abc",
        "iteration_count": 1,
        "discussion_history": [],
        "reports": {"static": FIRST},
        "isr_reports": {"static": in_force},
    }
    return asyncio.run(node(state))


class TestTheRevisionNodeMerges:
    def test_the_answer_in_force_holds_the_carried_claims_and_says_so(self) -> None:
        answer = _block(FIXED_BEACON, "T1071.001", number=2) + "DISPUTES: NONE\n"

        out = _node_run(_isr(FIRST), _isr(answer), answer)

        stands = out["isr_reports"]["static"]
        assert _sentences(stands) == [MUTEX, FIXED_BEACON, CRYPTO, PERSIST]
        report = out["revised_reports"]["static"]
        # Rendered numbered, the carried claims marked, the disputes after.
        assert "Claim 2: " + FIXED_BEACON in report
        assert report.count("carried forward: the round-1 revision") == 3
        assert "DISPUTES: NONE" in report
        [said] = out["revision_replacements"]
        assert "the other 3 stand carried forward unchanged (claims 1, 3-4 of" in said
        record = out["revision_rounds"][0]
        assert record["made"] == 1 and not record["identical"] and not record["reworded"]

    def test_a_revision_that_restates_every_claim_is_taken_as_before(self) -> None:
        answer = (
            _block(MUTEX)
            + _block(FIXED_BEACON, "T1071.001")
            + _block(CRYPTO)
            + _block(PERSIST)
            + "DISPUTES: NONE\n"
        )
        revision = _isr(answer)

        out = _node_run(_isr(FIRST), revision, answer)

        assert out["isr_reports"]["static"] is revision
        assert out["revised_reports"]["static"] == answer
        assert "revision_replacements" not in out

    def test_carried_claims_neither_fake_a_change_nor_block_convergence(self) -> None:
        answer = _block(BEACON, "T1071.001", number=2)

        out = _node_run(_isr(FIRST), _isr(answer), answer)

        assert out["revision_rounds"][0]["reworded"] is True


class TestOnlyARealRestatementReplacesAClaim:
    def test_a_small_number_in_common_restates_nothing(self) -> None:
        debugger = "Init returns 0 when the PEB BeingDebugged byte at 0x309c is set."
        first = _block(debugger) + _block(PERSIST)
        answer = _block("The export returns 0 when its init routine fails.") + _block(PERSIST)

        merge = merge_revision(_isr(first), _isr(answer), answer, 1)

        assert merge.merged is not None
        assert [n for n, _s in merge.carried] == [1]

    def test_words_are_never_pooled_over_blocks(self) -> None:
        claim = "No persistence mechanism is established by the sample code."
        first = _block(claim) + _block(PERSIST)
        # Every word of the claim is written, but spread over three blocks.
        answer = (
            _block("No packer is named.")
            + _block("The persistence key is read at run time.")
            + _block("The mechanism is established by the sample code path.")
            + _block(PERSIST)
        )

        merge = merge_revision(_isr(first), _isr(answer), answer, 1)

        assert merge.merged is not None
        assert [n for n, _s in merge.carried] == [1]

    def test_one_block_with_four_fifths_of_the_words_restates_it(self) -> None:
        claim = "No persistence mechanism is established by the sample code."
        first = _block(claim) + _block(PERSIST)
        answer = _block("No persistence mechanism is established by the sample's code.")
        answer += _block(PERSIST)

        assert merge_revision(_isr(first), _isr(answer), answer, 1).merged is None

    def test_a_third_of_the_values_with_the_technique_restates_a_correction(self) -> None:
        first = _block("0x405000 runs net view through 0x1030 into net_view.", "T1018")
        first += _block(PERSIST)
        answer = _block("0x405000 runs nltest and ipconfig through a hidden runner.", "T1018")
        answer += _block(PERSIST)

        assert merge_revision(_isr(first), _isr(answer), answer, 1).merged is None

    def test_a_number_that_restates_only_small_values_is_not_trusted(self) -> None:
        first = _block("Init returns 0 at 0x309c.") + _block(PERSIST)
        answer = _block("The export returns 0 on failure.", number=1) + _block(PERSIST, number=2)

        merge = merge_revision(_isr(first), _isr(answer), answer, 1)

        assert merge.placed_by == "statement"


THREE = _block(MUTEX) + _block(BEACON, "T1071.001") + _block(CRYPTO)


class TestAContestedClaimLeftUnansweredIsNamed:
    def test_a_claim_a_blocking_line_named_is_withdrawn_by_rule(self) -> None:
        answer = _block(MUTEX)

        merge = merge_revision(_isr(THREE), _isr(answer), answer, 3, {2: [(4, True)]})

        assert merge.merged is not None
        assert _sentences(merge.merged) == [MUTEX, CRYPTO]
        assert merge.withdrawn_by_rule == (
            (
                2,
                BEACON,
                "named by blocking line L4 of the round-3 mediation; the revision did not "
                "restate it",
            ),
        )
        assert [c.claim for c in merge.ruled_claims] == [BEACON]
        said = merge.sentences("static", 3)
        assert "withdrew 0 and 1 were withdrawn by rule" in said[0]
        assert said[-1].startswith("Claim 2 of the static analyst's answer in force")

    def test_a_claim_only_a_line_that_does_not_block_named_is_carried_with_it(self) -> None:
        answer = _block(MUTEX)

        merge = merge_revision(_isr(THREE), _isr(answer), answer, 3, {3: [(5, False)]})

        assert merge.merged is not None
        crypto = merge.merged.claims[-1]
        assert crypto.carried_contested_by == ["L5 (round 3)"]
        assert "contested by L5 (round 3) and not answered" in claim_summary_line(3, crypto)

    def test_a_claim_the_revision_restates_is_never_withdrawn_by_rule(self) -> None:
        answer = _block(MUTEX) + _block(FIXED_BEACON, "T1071.001")

        merge = merge_revision(_isr(THREE), _isr(answer), answer, 1, {2: [(1, True)]})

        assert merge.withdrawn_by_rule == ()

    def test_the_lines_name_claims_by_name_by_field_and_by_short_form(self) -> None:
        from malspark.pipeline.debate_facts import claims_named_by_lines

        names = ["static", "all_tools_static_r2", "all_tools_reverser_ghidra", "dynamic"]
        lines = [
            "[analysts: ALL_TOOLS_STATIC_R2 ANALYST] Claims 30 and 62 say a thing, versus "
            "DYNAMIC ANALYST claim 32. [blocking: the cited listing does not contain it.] [new]",
            "[analysts: ALL_TOOLS_STATIC_R2 ANALYST, ALL_TOOLS_REVERSER_GHIDRA ANALYST] Static R2 "
            "claim 3 and Reverser claims 1 and 9 say a gate tests a return. [blocking: the "
            "listing shows another call.] [new]",
            "[analysts: STATIC ANALYST] STATIC ANALYST claim 7 is loose. "
            "[not blocking: the reading is the same.]",
        ]

        named = claims_named_by_lines(lines, names)

        assert named["all_tools_static_r2"] == {30: [(1, True)], 62: [(1, True)], 3: [(2, True)]}
        assert named["all_tools_reverser_ghidra"] == {1: [(2, True)], 9: [(2, True)]}
        assert named["static"] == {7: [(3, False)]}
        # Dynamic is not in the first line's field: no question was put to it.
        assert "dynamic" not in named

    def test_the_node_withdraws_by_rule_and_records_the_values(self) -> None:
        from malspark.core.config import MEDIATOR_AGENT_NAME
        from malspark.pipeline.state import AgentArgument

        answer = _block(MUTEX)
        container = MagicMock()
        container.is_mock = False
        container.agent_registry.list_agents.return_value = ["static"]
        container.analyst_keys.return_value = ["static"]
        container.agent_role.side_effect = lambda n: n
        container.config.llm.parallel_analysts = False
        agent = MagicMock()
        agent.safe_revise_isr.return_value = (answer, _isr(answer))
        container.get_agent.return_value = agent
        container.load_chunked.return_value = [MagicMock(content="data")]
        container.load_data.return_value = "data"
        mediation = AgentArgument(
            agent_name=MEDIATOR_AGENT_NAME,
            finding="revise",
            contradictions=[
                "[analysts: STATIC ANALYST] Claim 2 says the beacon waits 600 s, versus the "
                "listing. [blocking: the listing shows 900 s.]",
                "[analysts: STATIC ANALYST] Claim 3 names the key loosely. "
                "[not blocking: the reading is the same.]",
            ],
            revise=["static"],
        )
        state = {
            "file_hash": "abc",
            "iteration_count": 2,
            "discussion_history": [mediation],
            "reports": {"static": THREE},
            "isr_reports": {"static": _isr(THREE)},
        }

        out = asyncio.run(make_revision_node(container)(state))

        stands = out["isr_reports"]["static"].claims
        assert [c.claim for c in stands] == [MUTEX, CRYPTO]
        assert stands[1].carried_contested_by == ["L2 (round 2)"]
        [row] = [r for r in out["dropped_claims"] if r["claim"] == BEACON]
        assert row["missing"] and "withdrawn by rule" in row["sentence"]
        assert any("blocking line L1" in s for s in out["revision_replacements"])

    def test_a_claim_the_revision_argues_in_its_disputes_is_carried_not_withdrawn(self) -> None:
        answer = _block(MUTEX)
        revision = _isr(answer)
        revision.dissent_items = ["I keep claim 2: the listing the line cites is another call."]

        merge = merge_revision(_isr(THREE), revision, answer, 3, {2: [(4, True)]})

        assert merge.withdrawn_by_rule == ()
        assert merge.merged is not None
        beacon = next(c for c in merge.merged.claims if c.claim == BEACON)
        assert beacon.carried_contested_by == ["L4 (round 3)"]

    def test_a_dispute_that_restates_the_claim_answers_the_line_too(self) -> None:
        answer = _block(MUTEX)
        revision = _isr(answer)
        revision.dissent_items = [f"The beacon stands as written: {BEACON}"]

        merge = merge_revision(_isr(THREE), revision, answer, 3, {2: [(4, True)]})

        assert merge.withdrawn_by_rule == ()


class TestAShortFormNamesOneAnalystOnly:
    PARTICIPANTS = (
        "triage",
        "static",
        "all_tools_static_r2",
        "all_tools_qu1cksc0pe",
        "all_tools_reverser_ghidra",
        "dynamic",
        "network",
    )

    def _named(self, line: str) -> dict[str, Any]:
        from malspark.pipeline.debate_facts import claims_named_by_lines

        return {
            name: sorted(claims)
            for name, claims in claims_named_by_lines([line], list(self.PARTICIPANTS)).items()
        }

    def test_a_whole_name_is_that_analyst_even_beside_a_longer_one(self) -> None:
        line = (
            "[analysts: ALL_TOOLS_STATIC_R2 ANALYST] Static claim 3 says X, versus Static R2 "
            "claim 5. [blocking: x]"
        )

        # "Static claim 3" is the static analyst's, which the field does not name.
        assert self._named(line) == {"all_tools_static_r2": [5]}

    def test_both_analysts_in_the_field_keep_their_own_numbers(self) -> None:
        line = (
            "[analysts: STATIC ANALYST, ALL_TOOLS_STATIC_R2 ANALYST] Static claim 3 says X, "
            "versus Static R2 claim 5. [blocking: x]"
        )

        assert self._named(line) == {"static": [3], "all_tools_static_r2": [5]}

    def test_a_short_word_of_prose_names_no_analyst(self) -> None:
        line = (
            "[analysts: ALL_TOOLS_QU1CKSC0PE ANALYST, ALL_TOOLS_STATIC_R2 ANALYST] The ledger "
            "runs contrary to claim 7. [blocking: x]"
        )

        assert self._named(line) == {}

    def test_a_whole_part_of_two_letters_still_names_its_analyst(self) -> None:
        line = (
            "[analysts: ALL_TOOLS_STATIC_R2 ANALYST] As stated in claim 12 of the triage report, "
            "R2's claim 3 is wrong. [blocking: q]"
        )

        assert self._named(line) == {"all_tools_static_r2": [3]}


def _carried_claim() -> ClaimEvidence:
    claim = ClaimEvidence(claim="A.", evidence_ref="[ev_0001]", confidence=0.5)
    claim.carried_since_round = 2
    claim.carried_contested_by = ["L3 (round 2)"]
    return claim


class TestACarriedClaimSaysSoOnEverySurface:
    def test_the_event_payload_carries_it(self) -> None:
        from malspark.pipeline.events import claims_to_payload

        [row] = claims_to_payload([_carried_claim()])

        assert row["carried_since_round"] == 2
        assert row["carried_note"].endswith("contested by L3 (round 2) and not answered")

    def test_an_unmarked_claim_s_payload_is_unchanged(self) -> None:
        from malspark.pipeline.events import claims_to_payload

        claim = ClaimEvidence(claim="A.", evidence_ref="[ev_0001]", confidence=0.5)

        assert set(claims_to_payload([claim])[0]) == {
            "claim",
            "evidence_ref",
            "confidence",
            "technique_id",
        }

    def test_the_upstream_findings_carry_it(self) -> None:
        from types import SimpleNamespace

        from malspark.pipeline.nodes import upstream_findings

        container = MagicMock()
        container.active_profile.return_value = SimpleNamespace(
            stages=[SimpleNamespace(key="static", agents=["static"])]
        )
        container.config.reporting.upstream_findings_max_chars = 100_000
        stage = SimpleNamespace(inject_upstream="findings", depends_on=["static"])
        isr = AgentISR(agent_id="static", domain="static", claims=[_carried_claim()])

        text = upstream_findings(stage, {"isr_reports": {"static": isr}}, container)

        assert "carried forward: the round-2 revision" in text

    def test_the_claims_in_force_carry_the_round_for_the_report(self) -> None:
        from malspark.reporting.claim_coverage import claims_in_force

        isr = AgentISR(agent_id="static", domain="static", claims=[_carried_claim()])

        [row] = claims_in_force({"static": isr})

        assert row.carried_since_round == 2


class TestTheReportCountsCarriedClaims:
    def test_carried_claims_are_one_count_line_per_analyst_and_others_are_listed(self) -> None:
        from malspark.reporting.claim_coverage import claims_not_discussed
        from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
        from malspark.reporting.renderers.markdown import MarkdownRenderer

        own = ClaimEvidence(
            claim="Routine 0x33ac copies the file.", evidence_ref="[ev_0004]", confidence=0.7
        )
        kept = [
            ClaimEvidence(
                claim=f"Routine 0x{0x7B00 + n:x} reads a path.",
                evidence_ref="[ev_0004]",
                confidence=0.7,
            )
            for n in range(3)
        ]
        for claim in kept:
            claim.carried_since_round = 2
        isrs = {"reverser": AgentISR(agent_id="reverser", domain="reverser", claims=[own, *kept])}
        report = MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)))
        report.claims_not_discussed = claims_not_discussed(report, isrs)

        markdown = MarkdownRenderer().render(report)

        assert "0x33ac" in markdown
        assert "0x7b01" not in markdown
        assert (
            "3 claims carried forward unwritten by a revision (from round 2) are not "
            "discussed in the body" in markdown
        )

    def test_a_technique_only_carried_claims_name_says_so_in_the_matrix(self) -> None:
        from malspark.extractors.capability_matrix import build_capability_matrix

        claim = ClaimEvidence(
            claim="Persists through the Run key.",
            evidence_ref="[ev_0001]",
            confidence=0.7,
            technique_id="T1547.001",
        )
        claim.carried_since_round = 3
        cells, _maps = build_capability_matrix(
            stix_output=None,
            isr_reports={"static": AgentISR(agent_id="static", domain="static", claims=[claim])},
            ledger=[],
        )

        [cell] = [c for c in cells if c.technique_id == "T1547.001"]
        assert "carried forward: the round-3 revision" in cell.note


class TestTwoRoundsInARow:
    def test_the_earliest_round_is_kept_and_a_restated_claim_loses_the_mark(self) -> None:
        once = _block(FIXED_BEACON, "T1071.001", number=2)
        first = merge_revision(_isr(FIRST), _isr(once), once, 1).merged
        assert first is not None
        local = MUTEX.replace("Global", "Local")
        twice = _block(local, number=1) + _block(CRYPTO, number=3)

        second = merge_revision(first, _isr(twice), twice, 2).merged

        assert second is not None
        marks = {c.claim: c.carried_since_round for c in second.claims}
        # Claim 4 carried since round 1; claim 2, restated in round 1, carried
        # from round 2; claims 1 and 3, restated in round 2, unmarked.
        assert marks == {local: None, FIXED_BEACON: 2, CRYPTO: None, PERSIST: 1}
