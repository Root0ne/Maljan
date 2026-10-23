"""A claim heading that writes a label before its number is read as a claim.

Revision answers name their claims apart from the round they revise: ``CLAIM
R1:`` … ``CLAIM R12:``, ``CLAIM N1 (was round-0 claim 1):``. The heading rule
read ``CLAIM`` with digits only, so such an answer with every field written
read as no claim at all; the loop asked once for a report, the retry was made
without the answer, and the claims it held were lost.

The label is part of the claim's name, never dropped: ``CLAIM R7:`` names
``R7``, which a validation retry never confuses with claim 7. The streaming
repeat reader follows the same rule, and a plain heading reads as before.
"""

from __future__ import annotations

import time

import pytest

from maljan.agents.base_agent import read_claim_blocks
from maljan.agents.claim_headings import (
    CLAIM_HEAD_RE,
    count_claims_begun,
    heading_number,
    heading_sentence,
)
from maljan.agents.repeat_watch import ClaimRepeatReader
from maljan.pipeline.retry_merge import _first_blocks
from tests.claim_block_counts import begun_and_distinct

LABELLED = """[REVERSER ANALYST — round 2]

**U1. String decoder. OUTCOME: CONFIRMED.**

CLAIM R1: Routine 0x1400 decodes the sample's own strings with a rolling key.
EVIDENCE: [ev_0042]
CONFIDENCE: 0.9
TECHNIQUE: T1140

CLAIM R2: The key schedule at 0x1800 builds a 256-byte identity table.
EVIDENCE: [ev_0043]
CONFIDENCE: 0.8
TECHNIQUE: NONE

CLAIM R10: The beacon loop at 0x2000 sends the encoded buffer.
EVIDENCE: [ev_0044], [ev_0045]
CONFIDENCE: 0.75
TECHNIQUE: T1071.001

CLAIM N4 (round-0 claim 4, affirmed): The sandbox shows three hosts.
EVIDENCE: [ev_0046]
CONFIDENCE: 0.7
TECHNIQUE: NONE

DISPUTES: NONE
"""


class TestALabelledHeadingIsAClaim:
    def test_every_labelled_claim_is_read(self) -> None:
        read = read_claim_blocks(LABELLED)
        assert read.begun == 4
        assert [c.claim for c in read.claims] == [
            "Routine 0x1400 decodes the sample's own strings with a rolling key.",
            "The key schedule at 0x1800 builds a 256-byte identity table.",
            "The beacon loop at 0x2000 sends the encoded buffer.",
            "The sandbox shows three hosts.",
        ]
        assert [c.confidence for c in read.claims] == [0.9, 0.8, 0.75, 0.7]

    def test_the_label_stays_in_the_claim_s_name(self) -> None:
        read = read_claim_blocks(LABELLED)
        assert [c.number for c in read.claims] == ["R1", "R2", "R10", "N4"]

    def test_the_note_after_a_labelled_number_is_kept_beside_the_claim(self) -> None:
        read = read_claim_blocks(LABELLED)
        assert read.claims[3].heading_note == "(round-0 claim 4, affirmed)"
        assert read.claims[3].claim == "The sandbox shows three hosts."

    @pytest.mark.parametrize(
        ("line", "number", "sentence"),
        [
            ("CLAIM R1: x", "R1", "x"),
            ("CLAIM r07: x", "r7", "x"),
            ("**CLAIM U14:** x", "U14", "x"),
            ("CLAIM #R3: x", "R3", "x"),
            ("- CLAIM N2 (reframed): x", "N2", "x"),
            ("CLAIM 3: x", "3", "x"),
            ("CLAIM: x", None, "x"),
        ],
    )
    def test_the_heading_gives_its_number_and_sentence(
        self, line: str, number: str | None, sentence: str
    ) -> None:
        match = CLAIM_HEAD_RE.match(line)
        assert match is not None
        assert heading_number(match) == number
        assert heading_sentence(line, match) == sentence

    @pytest.mark.parametrize(
        "line",
        [
            "CLAIMS: x",
            "CLAIMR1: x",
            "CLAIM R: x",
            "CLAIM Routine 0x1400: x",
            "CLAIM 1a: x",
            "The CLAIM R1: x",
        ],
    )
    def test_a_line_that_is_no_heading_stays_none(self, line: str) -> None:
        assert CLAIM_HEAD_RE.match(line) is None

    @pytest.mark.parametrize("piece", [1, 3, 17, 10_000])
    def test_the_streaming_reader_counts_them_as_the_check_does(self, piece: int) -> None:
        reader = ClaimRepeatReader(None)
        for start in range(0, len(LABELLED), piece):
            reader.feed(LABELLED[start : start + piece])
        count = reader.count()
        assert (count.begun, count.distinct) == begun_and_distinct(LABELLED)
        assert begun_and_distinct(LABELLED)[0] == count_claims_begun(LABELLED) == 4

    def test_a_labelled_answer_is_not_merged_by_place_number(self) -> None:
        from maljan.schemas.isr_models import AgentISR

        read = read_claim_blocks(LABELLED)
        isr = AgentISR(
            agent_id="reverser", domain="static", claims=read.claims, answer_text=LABELLED
        )
        assert "numbered a claim R1 where it is claim 1" in _first_blocks(isr)[1]


class TestAPlainHeadingReadsAsBefore:
    def test_numbers_and_plain_headings_are_unchanged(self) -> None:
        text = (
            "CLAIM 1: a\nEVIDENCE: ev_0001\nCONFIDENCE: 0.5\n---\n"
            "CLAIM: b\nEVIDENCE: ev_0002\nCONFIDENCE: 0.5\n"
        )
        read = read_claim_blocks(text)
        assert [c.number for c in read.claims] == ["1", None]


class TestLinearTime:
    @pytest.mark.parametrize(
        "line",
        [
            "CLAIM " + " " * 2_000 + "R" * 2_000 + ":",
            "CLAIM " + ("R" * 50 + " ") * 40,
            "CLAIM R" + "1" * 4_000 + " (" + "x" * 2_000,
        ],
    )
    def test_ten_times_the_line_costs_at_most_ten_times_the_time(self, line: str) -> None:
        def cost(text: str) -> float:
            start = time.perf_counter()
            for _ in range(20):
                CLAIM_HEAD_RE.match(text)
                reader = ClaimRepeatReader(None)
                reader.feed(text)
            return time.perf_counter() - start

        small = cost(line)
        large = cost(line * 10)
        assert large <= max(small, 1e-3) * 30
