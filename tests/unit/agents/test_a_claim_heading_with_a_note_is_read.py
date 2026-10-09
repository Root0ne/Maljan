"""A claim heading with a note before its colon is read, and the note is kept.

Revision answers number their claims and say what each one is to the claim it
revises, between the number and the colon: ``CLAIM 1 [REVISED — retracts
claim 31 …]: …`` or, with the note as the whole heading, ``CLAIM 1 (REVISED —
not exercised on the wire)`` with the fields on the lines after it. A square
bracket was never a heading, and a round one with nothing after it was not
either, so two whole revision answers with every field written read as no
claim at all and were asked again.

The note is the model's own words and says what the claim is (a revision, a
retraction): it is kept verbatim, brackets and all, ahead of the claim's
sentence, where every reader of the claim already looks. The heading's number
is never part of the claim, and no number is made up for a heading without one.
"""

from __future__ import annotations

import time
import tracemalloc
from collections.abc import Callable
from typing import Any

import pytest

from maljan.agents.base_agent import read_claim_blocks
from maljan.agents.claim_headings import (
    CLAIM_HEAD_RE,
    claim_heading_counts,
    count_claims_begun,
    heading_text,
)
from maljan.agents.repeat_watch import ClaimRepeatReader

# An answer shaped like the reverser's revision: numbered claims, each with a
# square-bracketed note before the colon, the fields on their own lines.
SQUARE_NOTED = """[REVERSER ANALYST — round 1]

I keep most of my first reading; two of my own claims are refuted below.

CLAIM 1 [REVISED — retracts round-0 claim 7 "no debugger check exists"]: A debugger check is \
present: the routine at 0x1400 reads the flag byte through the process environment block \
and the init gate aborts when it is set.
EVIDENCE: [ev_0004], [ev_0009]; function rows 0x1400 / 0x1800 [ev_0011].
CONFIDENCE: 0.70
TECHNIQUE: T1622

CLAIM 2 [REVISED — retracts round-0 claim 6 "0x2000 reads another process's memory"]: The routine \
at 0x2000 reads only its own image.
EVIDENCE: [ev_0012]
CONFIDENCE: 0.65
TECHNIQUE: NONE

DISPUTES: NONE
"""

# An answer shaped like the network analyst's revision: each heading is its
# note alone, ``---`` between claims, and a TECHNIQUE line with a qualifier.
ROUND_NOTED = """[NETWORK ANALYST — negotiation round]

CLAIM 1 (REVISED — no live contact; the beacon was not exercised on the wire)
EVIDENCE: Capture view: name extraction over all packets yields only vendor names [ev_0021]; \
no request line names the decoded paths [ev_0022].
RENEGOTIATION NOTE: the peer's timing places one contact window inside the capture.
CONFIDENCE: 0.85
TECHNIQUE: T1071.001 (channel capability; not exercised)

---
CLAIM 2 (REAFFIRMED — the hard-coded endpoints are flagged infrastructure)
EVIDENCE: reputation reports for both decoded hosts [ev_0023], [ev_0024].
CONFIDENCE: 0.80
TECHNIQUE: NONE
"""


def _claims(text: str) -> list[Any]:
    return read_claim_blocks(text, require_evidence=True).claims


class TestTheRevisionAnswersReadAsTheirClaims:
    def test_a_square_bracketed_note_before_the_colon(self) -> None:
        read = read_claim_blocks(SQUARE_NOTED, require_evidence=True)

        assert read.begun == 2 and len(read.claims) == 2
        first, second = read.claims
        assert first.claim.startswith(
            '[REVISED — retracts round-0 claim 7 "no debugger check exists"] A debugger check'
        )
        assert first.claim.endswith("aborts when it is set.")
        assert first.confidence == 0.70 and first.technique_id == "T1622"
        assert "[ev_0011]" in first.evidence_ref
        assert second.claim.startswith("[REVISED — retracts round-0 claim 6")
        assert second.technique_id is None

    def test_a_round_bracketed_note_that_is_the_whole_heading(self) -> None:
        read = read_claim_blocks(ROUND_NOTED, require_evidence=True)

        assert read.begun == 2 and len(read.claims) == 2
        first, second = read.claims
        assert first.claim == (
            "(REVISED — no live contact; the beacon was not exercised on the wire)"
        )
        assert "RENEGOTIATION NOTE" in first.evidence_ref
        assert first.confidence == 0.85
        # A TECHNIQUE line with a qualifier is the analyst's line, asked about once.
        assert first.technique_id is None
        assert first.technique_line == "T1071.001 (channel capability; not exercised)"
        assert second.claim == (
            "(REAFFIRMED — the hard-coded endpoints are flagged infrastructure)"
        )

    def test_the_repeat_reader_counts_them_as_the_check_does(self) -> None:
        for text in (SQUARE_NOTED, ROUND_NOTED):
            reader = ClaimRepeatReader(None)
            for at in range(0, len(text), 7):
                reader.feed(text[at : at + 7])
            count = reader.count()
            assert (count.begun, count.distinct) == claim_heading_counts(text) == (2, 2)


class TestEachHeadingForm:
    @pytest.mark.parametrize(
        ("line", "said"),
        [
            ("CLAIM 3: It reads a file.", "It reads a file."),
            ("CLAIM: It reads a file.", "It reads a file."),
            ("CLAIM 3 [revised]: It reads a file.", "[revised] It reads a file."),
            ("CLAIM 3 (revised): It reads a file.", "(revised) It reads a file."),
            ("CLAIM [new]: It reads a file.", "[new] It reads a file."),
            ("CLAIM (new): It reads a file.", "(new) It reads a file."),
            ("**CLAIM 4 [KEPT]:** It reads a file.", "[KEPT] It reads a file."),
            ("CLAIM 5 [KEPT] — It reads a file.", "[KEPT] It reads a file."),
            ("CLAIM 6 (it reads a file)", "(it reads a file)"),
            ("- CLAIM [it reads a file] **", "[it reads a file]"),
        ],
    )
    def test_the_heading_says_its_note_then_its_sentence(self, line: str, said: str) -> None:
        heading = CLAIM_HEAD_RE.match(line)

        assert heading is not None
        assert heading_text(line, heading) == said

    @pytest.mark.parametrize(
        "line",
        [
            "CLAIM 1 [",
            "CLAIM 1 [revised",
            "CLAIM (a)(b): it reads a file",
            "CLAIM (a) it reads a file",
            "CLAIM 1",
            "CLAIM",
            "claim [new]: it reads a file",
        ],
    )
    def test_a_line_that_is_no_heading_stays_none(self, line: str) -> None:
        assert CLAIM_HEAD_RE.match(line) is None

    def test_no_number_is_made_up_or_moved(self) -> None:
        text = (
            "CLAIM 7 [revises claim 2]: It reads a file.\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.5\n"
            "CLAIM [new]: It writes a file.\nEVIDENCE: [ev_0002]\nCONFIDENCE: 0.5\n"
        )

        claims = _claims(text)

        assert [c.claim for c in claims] == [
            "[revises claim 2] It reads a file.",
            "[new] It writes a file.",
        ]


# The hostile line: an opened note that never closes, and no colon.
def _hostile(size: int) -> str:
    return "CLAIM 1 [" + "a" * size


_READERS: dict[str, Callable[[str], Any]] = {
    "read_claim_blocks": lambda text: read_claim_blocks(text),
    "count_claims_begun": count_claims_begun,
    "claim_heading_counts": claim_heading_counts,
}


def _repeat_reader(text: str) -> Any:
    reader = ClaimRepeatReader(None)
    for at in range(0, len(text), 4096):
        reader.feed(text[at : at + 4096])
    return reader.count()


_READERS["repeat_reader"] = _repeat_reader


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


# The streaming reader steps an automaton per character while a line is
# undecided, so it is timed and traced on a tenth of the line the parsers get.
_SIZES = {"repeat_reader": (20_000, 200_000)}


def _sizes(name: str) -> tuple[str, str]:
    small, large = _SIZES.get(name, (100_000, 1_000_000))
    return _hostile(small), _hostile(large)


class TestAnUnclosedNoteCostsALinearRead:
    @pytest.mark.parametrize("name", sorted(_READERS))
    def test_it_is_no_heading(self, name: str) -> None:
        text = _hostile(1 << 20)

        assert CLAIM_HEAD_RE.match(text) is None
        assert count_claims_begun(text) == 0
        assert _READERS[name](text) is not None

    @pytest.mark.parametrize("name", sorted(_READERS))
    def test_ten_times_the_line_costs_at_most_ten_times_the_time(self, name: str) -> None:
        read = _READERS[name]
        small, large = _sizes(name)

        assert _seconds(lambda: read(large)) <= 10 * _seconds(lambda: read(small)) * 1.5 + 0.1

    @pytest.mark.parametrize("name", sorted(set(_READERS) - set(_SIZES)))
    def test_ten_times_the_line_holds_at_most_ten_times_the_memory(self, name: str) -> None:
        read = _READERS[name]
        small, large = _sizes(name)

        assert _peak(lambda: read(large)) <= 10 * _peak(lambda: read(small)) * 1.5 + 65_536

    def test_the_streaming_reader_holds_nothing_of_the_line(self) -> None:
        small, large = (_hostile(2_000), _hostile(20_000))

        held = _peak(lambda: _repeat_reader(large))
        assert held < max(2 * _peak(lambda: _repeat_reader(small)), 64 * 1024)
