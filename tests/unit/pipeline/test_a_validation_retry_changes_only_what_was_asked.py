"""A validation retry is merged into the answer it fixes by claim number, and changes only that.

A claim the retry writes again under its number replaces the earlier one, a
``WITHDRAW CLAIM`` line takes one out, a new number is added and every other
claim stays as written. A claim the question was about that the retry neither
wrote again nor withdrew stays too, and is the one item left to ask about.
Where the numbers do not decide which claim is which, nothing is merged and
the reason is given. The merge chooses versions; it never writes a word.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import time
import tracemalloc
from collections.abc import Callable
from typing import Any

from maljan.agents.base_agent import read_claim_blocks
from maljan.pipeline.retry_merge import (
    flagged_claim_indexes,
    merge_retry,
    numbering_unsettled,
    read_withdrawals,
)
from maljan.pipeline.validation import Violation
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, Finding

_FIELDS: dict[str, Any] = {
    "claim": "Built by hand.",
    "evidence_ref": "[ev_0001]",
    "confidence": 0.5,
}


def _block(sentence: str, technique: str = "NONE", number: int | None = None) -> str:
    head = "CLAIM:" if number is None else f"CLAIM {number}:"
    return f"{head} {sentence}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: {technique}\n---\n"


def _isr(text: str, findings: list[Finding] | None = None) -> AgentISR:
    read = read_claim_blocks(text)
    isr = AgentISR(agent_id="static", domain="static", claims=read.claims)
    isr.note_parse(
        blocks_without_confidence=read.without_confidence,
        confidence_unreadable=read.confidence_unreadable,
    )
    isr.findings = list(findings or [])
    isr.note_answer_text(text)
    return isr


MUTEX = "0x401000 creates the mutex Global\\qx7 before anything else."
BEACON = "0x402000 beacons every 600 seconds to the configured host."
CRYPTO = "0x403000 decrypts the configuration with the key 0x5a."
PERSIST = "0x404000 writes the Run key value qx7svc."
FIRST = (
    _block(MUTEX)
    + _block(BEACON, "T1071.001")
    + _block(CRYPTO, "T1027, T1140")
    + _block(PERSIST, "T1547.001")
)


class TestTheRetryChangesWhatItWrites:
    def test_a_claim_written_again_replaces_the_earlier_one_and_the_rest_stay(self) -> None:
        first = _isr(FIRST)
        fixed = "0x402000 beacons every 600 seconds over HTTP to the configured host."
        answer = _block(fixed, "T1071.001", number=2)
        retried = _isr(answer)

        merge = merge_retry(first, retried, answer, flagged=[1])

        assert merge.merged is not None, merge.why
        assert [c.claim for c in merge.merged.claims] == [MUTEX, fixed, CRYPTO, CRYPTO, PERSIST]
        assert merge.replaced == ("2",) and merge.unchanged == 3
        assert merge.unplaced == ()

    def test_the_merge_keeps_each_claim_as_the_answer_that_wrote_it(self) -> None:
        first = _isr(FIRST)
        answer = _block("0x402000 beacons every 600 seconds over HTTP.", "T1071.001", number=2)
        retried = _isr(answer)

        merged = merge_retry(first, retried, answer, flagged=[1]).merged

        assert merged is not None
        assert merged.claims[0] is first.claims[0]
        assert merged.claims[1] is retried.claims[0]
        assert merged.claims[4] is first.claims[4]

    def test_a_block_of_several_techniques_is_replaced_as_one(self) -> None:
        first = _isr(FIRST)
        answer = _block(CRYPTO, "T1140", number=3)
        retried = _isr(answer)

        merged = merge_retry(first, retried, answer, flagged=[2]).merged

        assert merged is not None
        assert [c.technique_id for c in merged.claims] == [None, "T1071.001", "T1140", "T1547.001"]

    def test_a_withdrawn_claim_is_taken_out(self) -> None:
        first = _isr(FIRST)
        answer = "WITHDRAW CLAIM 4: the Run key is not in the evidence.\n"

        merge = merge_retry(first, _isr(answer), answer, flagged=[4])

        assert merge.merged is not None, merge.why
        assert PERSIST not in [c.claim for c in merge.merged.claims]
        assert merge.withdrawn == ("4",) and merge.unplaced == ()

    def test_a_new_number_is_added_after_the_claims_it_follows(self) -> None:
        first = _isr(FIRST)
        new = "0x405000 deletes its own file through cmd.exe."
        answer = _block(new, "T1070.004", number=5)

        merge = merge_retry(first, _isr(answer), answer)

        assert merge.merged is not None, merge.why
        assert merge.merged.claims[-1].claim == new and merge.added == ("5",)

    def test_an_unflagged_claim_the_retry_does_not_mention_is_no_drop(self) -> None:
        first = _isr(FIRST)
        answer = _block("0x402000 beacons every 600 seconds over HTTP.", "T1071.001", number=2)

        merge = merge_retry(first, _isr(answer), answer, flagged=[1])

        assert merge.merged is not None
        assert merge.unplaced == ()
        assert {c.claim for c in merge.merged.claims} >= {MUTEX, CRYPTO, PERSIST}

    def test_a_flagged_claim_left_as_it_was_stays_and_is_the_one_item_left(self) -> None:
        first = _isr(FIRST)
        answer = _block("0x402000 beacons every 600 seconds over HTTP.", "T1071.001", number=2)

        merge = merge_retry(first, _isr(answer), answer, flagged=[1, 4], asked_about=["T1547.001"])

        assert merge.merged is not None
        assert PERSIST in [c.claim for c in merge.merged.claims]
        ((claim, missing),) = merge.unplaced
        assert claim is first.claims[4]
        assert "T1547.001" not in missing and "0x404000" in missing


class TestFindingsByTitle:
    def test_findings_are_replaced_withdrawn_added_and_kept_by_title(self) -> None:
        first = _isr(
            FIRST,
            [
                Finding(title="Mutex guard", detail="first"),
                Finding(title="Run key persistence", detail="first"),
                Finding(title="Encrypted configuration", detail="first"),
            ],
        )
        answer = "WITHDRAW FINDING: Run key persistence\n"
        retried = _isr(
            answer,
            [
                Finding(title="mutex  GUARD", detail="retry"),
                Finding(title="Self deletion", detail="retry"),
            ],
        )

        merge = merge_retry(first, retried, answer)

        assert merge.merged is not None, merge.why
        assert [(f.title, f.detail) for f in merge.merged.findings] == [
            ("mutex  GUARD", "retry"),
            ("Encrypted configuration", "first"),
            ("Self deletion", "retry"),
        ]
        assert (merge.findings_replaced, merge.findings_withdrawn, merge.findings_added) == (
            1,
            1,
            1,
        )
        assert len(merge.merged.claims) == len(first.claims)


class TestWhereTheNumbersDoNotDecide:
    def test_a_retry_block_without_a_number_merges_nothing(self) -> None:
        answer = _block("0x402000 beacons over HTTP.", "T1071.001")

        merge = merge_retry(_isr(FIRST), _isr(answer), answer)

        assert merge.merged is None
        assert merge.why == "the retry wrote a claim block without its number"

    def test_a_number_written_twice_merges_nothing(self) -> None:
        answer = _block(BEACON, number=2) + _block("0x402000 beacons over HTTP.", number=2)

        merge = merge_retry(_isr(FIRST), _isr(answer), answer)

        assert merge.merged is None and "claim 2 twice" in merge.why

    def test_a_retry_that_numbers_its_claims_afresh_merges_nothing(self) -> None:
        answer = _block(MUTEX, number=1) + _block(CRYPTO, "T1027", number=2)

        merge = merge_retry(_isr(FIRST), _isr(answer), answer)

        assert merge.merged is None
        assert "claim 3's sentence as claim 2" in merge.why

    def test_a_claim_sharing_no_value_with_the_one_it_replaces_merges_nothing(self) -> None:
        answer = _block("0x409999 reads the keyboard state 25 times.", number=1)

        merge = merge_retry(_isr(FIRST), _isr(answer), answer)

        assert merge.merged is None and "states none of the values" in merge.why

    def test_a_withdrawal_of_a_claim_the_answer_has_not_merges_nothing(self) -> None:
        answer = "WITHDRAW CLAIM 9: gone.\n"

        assert merge_retry(_isr(FIRST), _isr(answer), answer).merged is None

    def test_a_claim_both_written_again_and_withdrawn_merges_nothing(self) -> None:
        answer = _block(BEACON, number=2) + "WITHDRAW CLAIM 2: no longer held.\n"

        merge = merge_retry(_isr(FIRST), _isr(answer), answer)

        assert merge.merged is None and "both wrote claim 2" in merge.why

    def test_a_retry_with_nothing_to_read_merges_nothing(self) -> None:
        answer = "I have reviewed the claims."

        merge = merge_retry(_isr(FIRST), _isr(answer), answer)

        assert merge.merged is None
        assert merge.why == "the retry wrote no claim block, finding or withdrawal"

    def test_a_retry_with_an_unread_block_merges_nothing(self) -> None:
        answer = "CLAIM 2: 0x402000 beacons.\nEVIDENCE: [ev_0001]\nTECHNIQUE: T1071.001\n"

        merge = merge_retry(_isr(FIRST), _isr(answer), answer)

        assert merge.merged is None and merge.why.startswith("in the retry,")

    def test_a_first_answer_numbered_out_of_its_order_is_not_merged(self) -> None:
        first = _isr(_block(MUTEX, number=1) + _block(BEACON, number=3))

        assert numbering_unsettled(first) == (
            "the answer being fixed numbered a claim 3 where it is claim 2"
        )

    def test_a_first_answer_numbered_in_its_order_is_merged(self) -> None:
        first = _isr(_block(MUTEX, number=1) + _block(BEACON, number=2))

        assert numbering_unsettled(first) == ""

    def test_answers_read_apart_and_put_together_are_not_merged(self) -> None:
        one, two = _isr(_block(MUTEX)), _isr(_block(BEACON) + _block(CRYPTO))
        together = AgentISR(agent_id="static", domain="static", claims=one.claims + two.claims)

        assert numbering_unsettled(together) == "two claim blocks were read under one place"

    def test_answers_put_together_that_repeat_a_place_are_not_merged(self) -> None:
        one, two = _isr(_block(MUTEX) + _block(PERSIST)), _isr(_block(BEACON) + _block(CRYPTO))
        together = AgentISR(agent_id="static", domain="static", claims=one.claims + two.claims)

        assert numbering_unsettled(together) == "the answer being fixed wrote claim 1 twice"

    def test_claims_built_without_the_reader_are_not_merged(self) -> None:
        first = _isr(FIRST)
        built = AgentISR(
            agent_id="static",
            domain="static",
            claims=[c.model_copy() for c in first.claims] + [ClaimEvidence(**_FIELDS)],
        )

        assert numbering_unsettled(built) == "a claim was not read from a claim block"

    def test_a_first_answer_with_no_claim_is_not_merged(self) -> None:
        assert numbering_unsettled(_isr("prose")) == "the answer being fixed has no claim"

    def test_a_first_answer_with_a_block_left_unread_is_not_merged(self) -> None:
        first = _isr(FIRST + "CLAIM: 0x406000 reads the clock.\nEVIDENCE: [ev_0001]\n")

        assert numbering_unsettled(first).startswith("in the answer being fixed,")


class TestTheLinesItReads:
    def test_withdraw_lines_are_read_in_their_written_forms(self) -> None:
        text = (
            "WITHDRAW CLAIM 3: not held.\n"
            "- **WITHDRAW CLAIMS 05, 7 and 9**: superseded.\n"
            "WITHDRAW FINDING: Run key persistence\n"
            "I withdraw claim 11 because it repeats claim 2.\n"
            "withdraw claim 12: lower case is prose.\n"
        )

        read = read_withdrawals(text)

        assert read.claims == ("3", "5", "7", "9")
        assert read.findings == ("run key persistence",)

    def test_a_withdraw_line_is_not_read_into_the_claim_before_it(self) -> None:
        text = _block(BEACON, number=2) + "WITHDRAW CLAIM 4: not held.\n"

        (claim,) = read_claim_blocks(text).claims

        assert "WITHDRAW" not in claim.claim + claim.evidence_ref

    def test_a_flag_names_its_claim_by_its_path_once(self) -> None:
        flags = [
            Violation(code="a", message="m", path="static.claims[5].T1041"),
            Violation(code="b", message="m", path="claims[5]"),
            Violation(code="c", message="m", path="claims[2]"),
            Violation(code="d", message="m"),
        ]

        assert flagged_claim_indexes(flags) == [5, 2]


def _answers(count: int) -> tuple[AgentISR, AgentISR, str]:
    first = "".join(_block(f"0x{0x400000 + n:x} does step {n}.", "T1027") for n in range(count))
    retry = "".join(
        _block(f"0x{0x400000 + n:x} does step {n} again.", "T1027", number=n + 1)
        for n in range(count)
    )
    return _isr(first), _isr(retry), retry


def _seconds(call: Callable[[], Any]) -> float:
    best = float("inf")
    for _ in range(2):
        started = time.perf_counter()
        call()
        best = min(best, time.perf_counter() - started)
    return best


def _peak(call: Callable[[], Any]) -> int:
    tracemalloc.start()
    try:
        call()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


class TestAHostileRetryCostsALinearMerge:
    def test_a_retry_of_ten_thousand_claims_is_merged(self) -> None:
        first, retried, answer = _answers(10_000)

        merge = merge_retry(first, retried, answer, flagged=range(10_000))

        assert merge.merged is not None, merge.why
        assert len(merge.merged.claims) == 10_000 and merge.unplaced == ()

    def test_ten_times_the_claims_cost_at_most_ten_times_the_time(self) -> None:
        small = _answers(1_000)
        large = _answers(10_000)

        def run(answers: tuple[AgentISR, AgentISR, str]) -> Callable[[], Any]:
            first, retried, answer = answers
            return lambda: merge_retry(first, retried, answer, flagged=range(len(first.claims)))

        assert _seconds(run(large)) <= 10 * _seconds(run(small)) * 1.5 + 0.1

    def test_ten_times_the_claims_hold_at_most_ten_times_the_memory(self) -> None:
        small = _answers(300)
        large = _answers(3_000)

        def run(answers: tuple[AgentISR, AgentISR, str]) -> Callable[[], Any]:
            first, retried, answer = answers
            return lambda: merge_retry(first, retried, answer, flagged=range(len(first.claims)))

        assert _peak(run(large)) <= 10 * _peak(run(small)) * 1.5 + 65_536

    def test_ten_thousand_unplaced_claims_cost_a_linear_search(self) -> None:
        small = _answers(1_000)
        large = _answers(10_000)

        def run(answers: tuple[AgentISR, AgentISR, str]) -> Callable[[], Any]:
            first, _retried, _answer = answers
            answer = "WITHDRAW CLAIM 1: gone.\n"
            withdrawn = _isr(answer)
            return lambda: merge_retry(first, withdrawn, answer, flagged=range(len(first.claims)))

        assert _seconds(run(large)) <= 10 * _seconds(run(small)) * 1.5 + 0.1
