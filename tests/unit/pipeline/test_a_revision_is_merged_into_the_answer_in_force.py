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

from maljan.agents.base_agent import read_claim_blocks
from maljan.pipeline.nodes import make_revision_node
from maljan.pipeline.revision_merge import merge_revision
from maljan.pipeline.validation import claim_block_indexes
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, claim_summary_line


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
            "other 59 stand carried forward unchanged (claims 2, 3, 4, 5, 6, 7, 9,"
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
        assert "the other 3 stand carried forward unchanged (claims 1, 3, 4" in said
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
