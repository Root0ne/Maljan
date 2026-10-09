"""A validation retry is merged into the answer it fixes by claim block, and changes only that.

A claim the retry writes again under its number replaces that block, a
``WITHDRAW CLAIM`` line takes one out with its reason, a new number is added
and every other claim stays as written. A claim a question was about that the
retry neither wrote again nor withdrew stays too, and is left to ask about, as
is a finding left unwritten beside a new title. The merged answer is the first
answer with those changes: its disputes stay. Where the numbers do not place
the retry beyond doubt, nothing is merged and the reason is given. The merge
chooses versions; it never writes a word.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import time
import tracemalloc
from collections.abc import Callable
from typing import Any

from maljan.agents.base_agent import read_claim_blocks
from maljan.pipeline.retry_merge import (
    flagged_blocks,
    merge_retry,
    numbering_unsettled,
    read_withdrawals,
)
from maljan.pipeline.validation import Violation, retry_drop_row, retry_drop_sentences
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
# Four blocks, the third listing two techniques: five claims.
FIRST = (
    _block(MUTEX)
    + _block(BEACON, "T1071.001")
    + _block(CRYPTO, "T1027, T1140")
    + _block(PERSIST, "T1547.001")
)
FIXED_BEACON = "0x402000 beacons every 600 seconds over HTTP to the configured host."


class TestTheRetryChangesWhatItWrites:
    def test_a_claim_written_again_replaces_the_earlier_one_and_the_rest_stay(self) -> None:
        first = _isr(FIRST)
        answer = _block(FIXED_BEACON, "T1071.001", number=2)

        merge = merge_retry(first, _isr(answer), answer, asked=[1])

        assert merge.merged is not None, merge.why
        assert [c.claim for c in merge.merged.claims] == [
            MUTEX,
            FIXED_BEACON,
            CRYPTO,
            CRYPTO,
            PERSIST,
        ]
        assert merge.replaced == ("2",) and merge.unchanged == 3
        assert merge.unplaced == ()

    def test_the_merge_keeps_each_claim_as_the_answer_that_wrote_it(self) -> None:
        first = _isr(FIRST)
        answer = _block(FIXED_BEACON, "T1071.001", number=2)
        retried = _isr(answer)

        merged = merge_retry(first, retried, answer, asked=[1]).merged

        assert merged is not None
        assert merged.claims[0] is first.claims[0]
        assert merged.claims[1] is retried.claims[0]
        assert merged.claims[4] is first.claims[4]

    def test_the_merged_answer_keeps_the_first_answer_s_disputes(self) -> None:
        first = _isr(FIRST)
        first.dissent_items = ["The dynamic analyst's beacon interval is not in its capture."]
        answer = _block(FIXED_BEACON, "T1071.001", number=2)

        merged = merge_retry(first, _isr(answer), answer, asked=[1]).merged

        assert merged is not None
        assert merged.dissent_items == first.dissent_items
        assert merged.answer_text == first.answer_text

    def test_headings_under_disputes_stand_as_the_answer_wrote_them_unless_moved(self) -> None:
        first = _isr(FIRST)
        first.note_claims_under_disputes(1)
        fix = _block(FIXED_BEACON, "T1071.001", number=2)
        moved = _block("0x405000 is the peer's loader, read here.", "NONE", number=5)

        kept = merge_retry(first, _isr(fix), fix, asked=[1]).merged
        written = merge_retry(first, _isr(moved), moved).merged

        assert kept is not None and kept.claims_under_disputes == 1
        assert written is not None and written.claims_under_disputes == 0

    def test_a_block_of_several_techniques_is_replaced_as_one(self) -> None:
        first = _isr(FIRST)
        answer = _block(CRYPTO, "T1140", number=3)

        merged = merge_retry(first, _isr(answer), answer, asked=[2]).merged

        assert merged is not None
        assert [c.technique_id for c in merged.claims] == [None, "T1071.001", "T1140", "T1547.001"]

    def test_a_withdrawn_claim_is_taken_out_with_its_reason(self) -> None:
        first = _isr(FIRST)
        answer = "WITHDRAW CLAIM 4: the Run key is not in the evidence.\n"

        merge = merge_retry(first, _isr(answer), answer, asked=[3])

        assert merge.merged is not None, merge.why
        assert PERSIST not in [c.claim for c in merge.merged.claims]
        ((kind, item, reason),) = merge.withdrawn
        assert (kind, item, reason) == (
            "claim",
            first.claims[4],
            "the Run key is not in the evidence.",
        )
        assert merge.unplaced == ()

    def test_a_withdrawn_block_takes_every_claim_it_read(self) -> None:
        first = _isr(FIRST)
        answer = "withdraw claims 2-3 - superseded by the decoder claim\n"

        merge = merge_retry(first, _isr(answer), answer)

        assert merge.merged is not None, merge.why
        assert [c.claim for c in merge.merged.claims] == [MUTEX, PERSIST]
        assert [item for _kind, item, _reason in merge.withdrawn] == first.claims[1:4]

    def test_a_new_number_is_added_after_the_claims_it_follows(self) -> None:
        first = _isr(FIRST)
        new = "0x405000 deletes its own file through cmd.exe."
        answer = _block(new, "T1070.004", number=5)

        merge = merge_retry(first, _isr(answer), answer)

        assert merge.merged is not None, merge.why
        assert merge.merged.claims[-1].claim == new and merge.added == ("5",)

    def test_a_claim_no_question_was_about_that_the_retry_leaves_is_no_drop(self) -> None:
        first = _isr(FIRST)
        answer = _block(FIXED_BEACON, "T1071.001", number=2)

        merge = merge_retry(first, _isr(answer), answer, asked=[1])

        assert merge.merged is not None
        assert merge.unplaced == ()
        assert {c.claim for c in merge.merged.claims} >= {MUTEX, CRYPTO, PERSIST}

    def test_a_claim_asked_about_and_left_stays_and_is_the_one_item_left(self) -> None:
        first = _isr(FIRST)
        answer = _block(FIXED_BEACON, "T1071.001", number=2)

        merge = merge_retry(first, _isr(answer), answer, asked=[1, 3], asked_about=["T1547.001"])

        assert merge.merged is not None
        assert PERSIST in [c.claim for c in merge.merged.claims]
        ((kind, claim, missing),) = merge.unplaced
        assert kind == "claim" and claim is first.claims[4]
        assert "T1547.001" not in missing and "0x404000" in missing

    def test_the_block_a_flag_names_after_a_block_of_two_techniques_is_its_own(self) -> None:
        first = _isr(FIRST)
        flags = [
            Violation(code="attck.claim_does_not_describe", message="m", path="static.claims[1]"),
            Violation(code="isr.ungrounded_technique", message="m", path="static.claims[3]"),
        ]
        answer = _block(FIXED_BEACON, "T1071.001", number=2)

        merge = merge_retry(first, _isr(answer), answer, asked=flagged_blocks(flags))

        assert merge.merged is not None and merge.why == ""
        ((_kind, claim, _missing),) = merge.unplaced
        assert claim.claim == PERSIST


class TestFindingsByTitle:
    def _first(self) -> AgentISR:
        return _isr(
            FIRST,
            [
                Finding(title="Mutex guard", detail="first"),
                Finding(title="Run key persistence", detail="first"),
                Finding(title="Encrypted configuration", detail="first"),
            ],
        )

    def test_findings_are_replaced_withdrawn_and_kept_by_title(self) -> None:
        first = self._first()
        answer = 'WITHDRAW FINDING "Run key persistence": not in the evidence\n'
        retried = _isr(answer, [Finding(title="mutex  GUARD", detail="retry")])

        merge = merge_retry(first, retried, answer)

        assert merge.merged is not None, merge.why
        assert [(f.title, f.detail) for f in merge.merged.findings] == [
            ("mutex  GUARD", "retry"),
            ("Encrypted configuration", "first"),
        ]
        ((kind, item, reason),) = merge.withdrawn
        assert kind == "finding" and item is first.findings[1] and reason == "not in the evidence"
        assert merge.unplaced == ()

    def test_a_finding_left_beside_a_new_title_is_left_to_ask_about(self) -> None:
        first = self._first()
        answer = "Findings rewritten."
        retried = _isr(answer, [Finding(title="Configuration encrypted at rest", detail="retry")])

        merge = merge_retry(first, retried, answer)

        assert merge.merged is not None, merge.why
        assert merge.findings_added == 1
        assert [item.title for kind, item, _m in merge.unplaced if kind == "finding"] == [
            "Mutex guard",
            "Run key persistence",
            "Encrypted configuration",
        ]


class TestWhereTheNumbersDoNotPlaceTheRetry:
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

    def test_a_one_claim_retry_numbered_from_one_merges_nothing(self) -> None:
        first = _isr(
            _block("The loader checks for a debugger with IsDebuggerPresent.", "T1622")
            + _block(BEACON, "T1071.001")
            + _block("The loader injects into explorer.exe.", "T1055")
        )
        fix = "The loader writes its payload into explorer.exe with WriteProcessMemory."
        answer = _block(fix, "T1055", number=1)

        merge = merge_retry(first, _isr(answer), answer, asked=[2])

        assert merge.merged is None
        assert "claim 1, which no question was about" in merge.why

    def test_a_claim_no_question_was_about_written_with_a_shared_value_beside_a_left_one(
        self,
    ) -> None:
        answer = _block("0x401000 creates the mutex Global\\qx8.", number=1)

        merge = merge_retry(_isr(FIRST), _isr(answer), answer, asked=[3])

        assert merge.merged is None
        assert "left claim 4" in merge.why

    def test_a_claim_sharing_no_value_with_the_one_it_replaces_merges_nothing(self) -> None:
        answer = _block("0x409999 reads the keyboard state 25 times.", number=1)

        merge = merge_retry(_isr(FIRST), _isr(answer), answer)

        assert merge.merged is None and "no value in common" in merge.why

    def test_a_withdrawal_of_a_claim_the_answer_has_not_merges_nothing(self) -> None:
        answer = "WITHDRAW CLAIM 9: gone.\n"

        merge = merge_retry(_isr(FIRST), _isr(answer), answer)

        assert merge.merged is None and "claim 9" in merge.why

    def test_a_withdraw_line_not_read_exactly_merges_nothing(self) -> None:
        answer = _block(FIXED_BEACON, number=2) + "Withdraw the mutex claim, it repeats.\n"

        merge = merge_retry(_isr(FIRST), _isr(answer), answer, asked=[1])

        assert merge.merged is None
        assert merge.why == "a line of the retry that withdraws could not be read exactly"

    def test_a_withdrawal_written_as_prose_merges_nothing(self) -> None:
        for prose in (
            "I withdraw claim 2.",
            "Also, please withdraw claims 1 and 3 since they repeat.",
            "Claim 2 is withdrawn.",
            "Claim 2: withdrawn, no evidence.",
            "Retract claim 2.",
            "Remove claim 2 - unsupported.",
            "Drop claim 2.",
            "CLAIM 3 (REVISED - retracts claim 2): the decoder is 0x403000.",
        ):
            answer = _block(FIXED_BEACON, number=2) + prose + "\n"

            merge = merge_retry(_isr(FIRST), _isr(answer), answer, asked=[1])

            assert merge.merged is None, prose
            assert merge.why == "a line of the retry that withdraws could not be read exactly"

    def test_an_upper_case_claim_line_that_withdraws_merges_nothing(self) -> None:
        for prose in (
            "CLAIM 2 is withdrawn.",
            "CLAIMS 2 and 3 are withdrawn.",
            "**CLAIM 2** withdrawn",
            "- CLAIM 2 removed",
        ):
            answer = _block(FIXED_BEACON, number=2) + prose + "\n"

            merge = merge_retry(_isr(FIRST), _isr(answer), answer, asked=[1])

            assert read_withdrawals(answer).unread == 1, prose
            assert merge.merged is None, prose
            assert merge.why == "a line of the retry that withdraws could not be read exactly"

    def test_a_heading_that_withdraws_its_own_claim_merges_nothing(self) -> None:
        for head in ("CLAIM 2 (withdrawn):", "CLAIM 2 [dropped]:", "CLAIM 2 — withdrawn:"):
            answer = (
                f"{head} 0x402000 beacons every 600 seconds.\n"
                "EVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
            )

            merge = merge_retry(_isr(FIRST), _isr(answer), answer, asked=[1])

            assert read_withdrawals(answer).unread == 1, head
            assert merge.merged is None, head
            assert merge.why == "a line of the retry that withdraws could not be read exactly"

    def test_a_heading_sentence_that_withdraws_its_own_claim_merges_nothing(self) -> None:
        for sentence in (
            "[WITHDRAWN] B 0x20.",
            "(Withdrawn) B 0x20 is not supported.",
            "~~B 0x20.~~ Retracted.",
            "This claim is withdrawn because no entry holds 0x20.",
            "I retract this: 0x20 is not held.",
            "N/A - withdrawn",
            "Removed as unsupported; 0x20 is not in the ledger.",
            "Dropped from this answer: 0x20 is not held.",
        ):
            answer = _block(sentence, number=2)

            merge = merge_retry(_isr(FIRST), _isr(answer), answer, asked=[1])

            assert read_withdrawals(answer).unread == 1, sentence
            assert merge.merged is None, sentence
            assert merge.why == "a line of the retry that withdraws could not be read exactly"

    def test_a_heading_whose_sentence_opens_with_what_the_code_does_is_merged(self) -> None:
        for sentence in (
            "0x405000 drops a.exe to %TEMP% and runs it.",
            "Drops a.exe to %TEMP% and runs it.",
            "Deletes its own file after it runs.",
            "Removes the Run key value qx7svc on uninstall.",
            "Dropped payload a.exe runs at logon.",
            "Deleted files are recovered from the shadow copy.",
        ):
            answer = _block(FIXED_BEACON, number=2) + _block(sentence, number=5)

            merge = merge_retry(_isr(FIRST), _isr(answer), answer, asked=[1])

            assert read_withdrawals(answer).unread == 0, sentence
            assert merge.merged is not None, (sentence, merge.why)

    def test_a_note_that_names_a_withdrawn_claim_is_a_doubt(self) -> None:
        answer = _block(FIXED_BEACON, number=2) + "My round-0 claim 21 was withdrawn.\n"

        assert read_withdrawals(answer).unread == 1

    def test_a_claim_heading_s_own_number_beside_a_deleting_sentence_is_no_doubt(self) -> None:
        answer = _block("0x405000 deletes its own file after it runs.", number=5)

        assert read_withdrawals(answer).unread == 0

    def test_what_a_retry_not_merged_withdrew_is_still_named(self) -> None:
        first = _isr(FIRST)
        answer = _block("0x402000 beacons.", number=2) + "WITHDRAW CLAIM 4: not held.\n"
        answer += "WITHDRAW CLAIM 2: superseded.\n"

        merge = merge_retry(first, _isr(answer), answer)

        assert merge.merged is None and "both wrote claim 2" in merge.why
        assert [item for _k, item, _r in merge.withdrawn] == [first.claims[1], first.claims[4]]

    def test_a_retry_with_nothing_to_read_merges_nothing(self) -> None:
        answer = "I have reviewed the claims."

        merge = merge_retry(_isr(FIRST), _isr(answer), answer)

        assert merge.merged is None
        assert merge.why == "the retry wrote no claim block, finding or withdrawal"

    def test_a_retry_with_an_unread_block_merges_nothing(self) -> None:
        answer = "CLAIM 2: 0x402000 beacons.\nEVIDENCE: [ev_0001]\nTECHNIQUE: T1071.001\n"

        merge = merge_retry(_isr(FIRST), _isr(answer), answer)

        assert merge.merged is None and merge.why.startswith("in the retry,")


class TestTheAnswerBeingFixed:
    def test_numbered_out_of_its_order_it_is_not_merged(self) -> None:
        first = _isr(_block(MUTEX, number=1) + _block(BEACON, number=3))

        assert numbering_unsettled(first) == (
            "the answer being fixed numbered a claim 3 where it is claim 2"
        )

    def test_numbered_in_its_order_it_is_merged(self) -> None:
        first = _isr(_block(MUTEX, number=1) + _block(BEACON, number=2))

        assert numbering_unsettled(first) == ""

    def test_with_no_claim_it_is_not_merged(self) -> None:
        assert numbering_unsettled(_isr("prose")) == "the answer being fixed has no claim"

    def test_with_a_block_left_unread_it_is_not_merged(self) -> None:
        first = _isr(FIRST + "CLAIM: 0x406000 reads the clock.\nEVIDENCE: [ev_0001]\n")

        assert numbering_unsettled(first).startswith("in the answer being fixed,")

    def test_answers_read_apart_and_put_together_are_not_merged(self) -> None:
        one, two = _isr(_block(MUTEX)), _isr(_block(BEACON) + _block(CRYPTO))
        together = AgentISR(agent_id="static", domain="static", claims=one.claims + two.claims)
        together.note_answer_text("written")

        assert numbering_unsettled(together) == (
            "the answer's claim blocks are not one answer's blocks in order"
        )

    def test_an_answer_with_claims_set_aside_is_not_merged(self) -> None:
        first = _isr(FIRST)
        first.note_gate_removed(["0x407000 talks to a host the evidence never names."])

        assert numbering_unsettled(first).startswith("claims of the answer being fixed")

    def test_claims_built_without_the_reader_are_not_merged(self) -> None:
        first = _isr(FIRST)
        built = AgentISR(
            agent_id="static",
            domain="static",
            claims=[c.model_copy() for c in first.claims] + [ClaimEvidence(**_FIELDS)],
        )
        built.note_answer_text("written")

        assert numbering_unsettled(built) == "a claim was not read from a claim block"

    def test_an_answer_not_written_as_one_is_not_merged(self) -> None:
        first = _isr(FIRST)
        first.note_answer_text("")

        assert numbering_unsettled(first) == (
            "the answer being fixed was not written as one answer"
        )


class TestTheLinesItReads:
    def test_withdraw_lines_are_read_in_their_written_forms(self) -> None:
        text = (
            "WITHDRAW CLAIM 3: not held.\n"
            "- **WITHDRAW CLAIMS 05, 7 and 9**: superseded.\n"
            "withdraw claims 10-12 because the decoder claim covers them\n"
            "Withdraw claim 14 to 15.\n"
            'WITHDRAW FINDING "Run key persistence": not held\n'
            "WITHDRAW FINDING: Mutex guard\n"
        )

        read = read_withdrawals(text)

        assert read.unread == 0
        assert [(low, high) for low, high, _r in read.claims] == [
            ("3", "3"),
            ("5", "5"),
            ("7", "7"),
            ("9", "9"),
            ("10", "12"),
            ("14", "15"),
        ]
        assert read.claims[4][2] == "the decoder claim covers them"
        assert [(t, r) for t, _w, r in read.findings] == [
            ("run key persistence", "not held"),
            ("mutex guard", ""),
        ]

    def test_a_withdraw_line_that_is_not_one_of_its_forms_is_counted_unread(self) -> None:
        read = read_withdrawals("Withdraw the claim about the mutex.\nI withdraw claim 11.\n")

        assert read.unread == 2 and read.claims == ()

    def test_a_withdrawn_claim_takes_only_the_reason_of_the_lines_that_name_it(self) -> None:
        first = _isr(FIRST)
        answer = (
            "WITHDRAW CLAIM 1: the mutex is the decoder's.\n"
            "WITHDRAW CLAIM 3\n"
            "WITHDRAW CLAIMS 3-4: covered by the beacon claim\n"
        )

        merge = merge_retry(first, _isr(answer), answer)

        reasons = {item.claim: reason for _kind, item, reason in merge.withdrawn}
        assert reasons == {
            MUTEX: "the mutex is the decoder's.",
            CRYPTO: "covered by the beacon claim",
            PERSIST: "covered by the beacon claim",
        }

    def test_a_claim_only_reasonless_lines_name_has_no_reason(self) -> None:
        first = _isr(FIRST)
        answer = "WITHDRAW CLAIM 1: the mutex is the decoder's.\nWITHDRAW CLAIM 3\n"

        merge = merge_retry(first, _isr(answer), answer)

        reasons = {item.claim: reason for _kind, item, reason in merge.withdrawn}
        assert reasons == {MUTEX: "the mutex is the decoder's.", CRYPTO: ""}

    def test_a_withdraw_line_is_not_read_into_the_claim_before_it(self) -> None:
        text = _block(BEACON, number=2) + "WITHDRAW CLAIM 4: not held.\n"

        (claim,) = read_claim_blocks(text).claims

        assert "WITHDRAW" not in claim.claim + claim.evidence_ref

    def test_a_flag_names_its_block_by_its_path_once(self) -> None:
        flags = [
            Violation(code="a", message="m", path="static.claims[5].T1041"),
            Violation(code="b", message="m", path="claims[5]"),
            Violation(code="c", message="m", path="claims[2]"),
            Violation(code="d", message="m"),
        ]

        assert flagged_blocks(flags) == [5, 2]


class TestALeftItemPrintsOnceAsItsRetryLeftIt:
    def test_rows_of_one_item_a_merged_retry_left_print_once_as_merged(self) -> None:
        rows = [
            retry_drop_row("static", n, "claim", MUTEX, ["0x401000"], "it stays", "", merged=True)
            for n in (1, 2)
        ]

        (sentence,) = retry_drop_sentences(rows)

        assert sentence.startswith("The static analyst's merged validation retry neither wrote")
        assert sentence.endswith("The record holds it 2 times, from revision rounds 1, 2.")

    def test_a_merged_and_a_kept_retry_s_row_of_one_item_print_apart(self) -> None:
        rows = [
            retry_drop_row("static", 1, "claim", MUTEX, ["0x401000"], "it stays", "", merged=True),
            retry_drop_row("static", 2, "claim", MUTEX, ["0x401000"], "it stays", ""),
        ]

        merged, kept = retry_drop_sentences(rows)

        assert "merged validation retry" in merged and "kept validation retry" in kept


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


def _run(answers: tuple[AgentISR, AgentISR, str]) -> Callable[[], Any]:
    first, retried, answer = answers
    return lambda: merge_retry(first, retried, answer, asked=range(len(first.claims)))


class TestAHostileRetryCostsALinearMerge:
    def test_a_retry_of_ten_thousand_claims_is_merged(self) -> None:
        first, retried, answer = _answers(10_000)

        merge = merge_retry(first, retried, answer, asked=range(10_000))

        assert merge.merged is not None, merge.why
        assert len(merge.merged.claims) == 10_000 and merge.unplaced == ()

    def test_ten_times_the_claims_cost_at_most_ten_times_the_time(self) -> None:
        assert _seconds(_run(_answers(10_000))) <= 10 * _seconds(_run(_answers(1_000))) * 1.5 + 0.1

    def test_ten_times_the_claims_hold_at_most_ten_times_the_memory(self) -> None:
        assert _peak(_run(_answers(3_000))) <= 10 * _peak(_run(_answers(300))) * 1.5 + 65_536

    def test_ten_thousand_withdrawn_ranges_cost_a_linear_read(self) -> None:
        def run(count: int) -> Callable[[], Any]:
            first = _answers(count)[0]
            answer = "".join(f"WITHDRAW CLAIMS 1-{count}: all superseded.\n" for _ in range(count))
            withdrawn = _isr(answer)
            return lambda: merge_retry(first, withdrawn, answer, asked=range(count))

        assert _seconds(run(10_000)) <= 10 * _seconds(run(1_000)) * 1.5 + 0.1

    def test_reasonless_withdraw_lines_cost_a_linear_read_in_time_and_memory(self) -> None:
        def run(count: int) -> Callable[[], Any]:
            first = _answers(count)[0]
            answer = "".join(f"WITHDRAW CLAIM {n}\n" for n in range(1, count + 1))
            withdrawn = _isr(answer)
            return lambda: merge_retry(first, withdrawn, answer)

        small, large = run(2_000), run(20_000)

        assert _seconds(large) <= 10 * _seconds(small) * 1.5 + 0.1
        assert _peak(large) <= 10 * _peak(small) * 1.5 + 65_536

    def test_a_long_line_of_withdraw_words_costs_a_linear_read(self) -> None:
        def run(size: int) -> Callable[[], Any]:
            text = "withdraw " * size
            return lambda: read_withdrawals(text)

        assert _seconds(run(100_000)) <= 10 * _seconds(run(10_000)) * 1.5 + 0.1

    def test_long_lines_that_do_not_open_with_the_word_cost_a_linear_read(self) -> None:
        for line in (
            lambda size: "x " + "removed claim " * size,
            lambda size: "CLAIM 1: " + "drop " * size + "claim 2",
            lambda size: "CLAIM 1 (" + "retract " * size + "):",
            lambda size: "**CLAIM 2** " + "claim 7 " * size + "withdrawn",
            lambda size: "CLAIM 2: " + "[(~>" * size + "removed",
            lambda size: "CLAIM 2: " + "removed " * size + "x",
            lambda size: "CLAIM 2: " + "x " * size + "retract",
        ):

            def run(size: int, line: Callable[[int], str] = line) -> Callable[[], Any]:
                text = line(size)
                return lambda: read_withdrawals(text)

            small, large = run(10_000), run(100_000)

            assert _seconds(large) <= 10 * _seconds(small) * 1.5 + 0.1
            assert _peak(large) <= 10 * _peak(small) * 1.5 + 65_536

    def test_ten_thousand_unplaced_claims_cost_a_linear_search(self) -> None:
        def run(count: int) -> Callable[[], Any]:
            first = _answers(count)[0]
            answer = "WITHDRAW CLAIM 1: gone.\n"
            withdrawn = _isr(answer)
            return lambda: merge_retry(first, withdrawn, answer, asked=range(count))

        assert _seconds(run(10_000)) <= 10 * _seconds(run(1_000)) * 1.5 + 0.1
