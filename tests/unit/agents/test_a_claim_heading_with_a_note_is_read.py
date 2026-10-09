"""A claim heading with a note before its colon is read, and the note is kept.

Revision answers number their claims and say what each one is to the claim it
revises, between the number and the colon: ``CLAIM 1 [REVISED — retracts
claim 31 …]: …`` or, with the note as the whole heading, ``CLAIM 1 (REVISED —
not exercised on the wire)`` with the fields on the lines after it. A square
bracket was never a heading, and a round one with nothing after it was not
either, so two whole revision answers with every field written read as no
claim at all and were asked again.

The note is the model's own words and says what the claim is to the debate (a
revision, a retraction): it is kept verbatim, brackets and all, beside the claim
(``ClaimEvidence.heading_note``), never in its sentence, so every check that
reads the sentence reads what it read before and no published text carries
debate bookkeeping. A heading that is its note alone has that note as its
sentence, the only one it writes. The heading's number is never part of the
claim, and no number is made up for a heading without one.
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
    heading_note,
    heading_sentence,
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
        assert first.claim.startswith("A debugger check is present: the routine at 0x1400")
        assert first.claim.endswith("aborts when it is set.")
        assert first.heading_note == (
            '[REVISED — retracts round-0 claim 7 "no debugger check exists"]'
        )
        assert first.confidence == 0.70 and first.technique_id == "T1622"
        assert "[ev_0011]" in first.evidence_ref
        assert second.claim == "The routine at 0x2000 reads only its own image."
        assert second.heading_note.startswith("[REVISED — retracts round-0 claim 6")
        assert second.technique_id is None

    def test_a_round_bracketed_note_that_is_the_whole_heading(self) -> None:
        read = read_claim_blocks(ROUND_NOTED, require_evidence=True)

        assert read.begun == 2 and len(read.claims) == 2
        first, second = read.claims
        assert first.claim == (
            "(REVISED — no live contact; the beacon was not exercised on the wire)"
        )
        # The note is the sentence here, so it is not repeated beside it.
        assert first.heading_note is None
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
        ("line", "said", "note"),
        [
            ("CLAIM 3: It reads a file.", "It reads a file.", None),
            ("CLAIM: It reads a file.", "It reads a file.", None),
            ("CLAIM 3 [revised]: It reads a file.", "It reads a file.", "[revised]"),
            ("CLAIM 3 (revised): It reads a file.", "It reads a file.", "(revised)"),
            ("CLAIM [new]: It reads a file.", "It reads a file.", "[new]"),
            ("CLAIM (new): It reads a file.", "It reads a file.", "(new)"),
            ("**CLAIM 4 [KEPT]:** It reads a file.", "It reads a file.", "[KEPT]"),
            ("CLAIM 5 [KEPT] — It reads a file.", "It reads a file.", "[KEPT]"),
            ("CLAIM 6 (it reads a file)", "(it reads a file)", None),
            ("- CLAIM [it reads a file] **", "[it reads a file]", None),
        ],
    )
    def test_the_heading_gives_its_sentence_and_its_note(
        self, line: str, said: str, note: str | None
    ) -> None:
        heading = CLAIM_HEAD_RE.match(line)

        assert heading is not None
        assert heading_sentence(line, heading) == said
        assert heading_note(heading) == note

    def test_a_bracketed_citation_before_the_colon_is_the_heading_s_note(self) -> None:
        (claim,) = _claims(
            "CLAIM [ev_0003]: It reads a file.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.5"
        )

        assert claim.claim == "It reads a file."
        assert claim.heading_note == "[ev_0003]"

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

        assert [(c.claim, c.heading_note) for c in claims] == [
            ("It reads a file.", "[revises claim 2]"),
            ("It writes a file.", "[new]"),
        ]


class TestTheNoteStaysOutOfWhatTheSentenceIsCheckedFor:
    """A note that names an absence (a retraction) is not read as the claim's own words."""

    @pytest.mark.parametrize(
        ("heading", "sentence", "technique"),
        [
            (
                "CLAIM 2 (REVISED — the earlier claim that no persistence exists is withdrawn)",
                "The sample writes a Run key that starts its copy at logon.",
                "T1547.001",
            ),
            (
                "CLAIM 3 (REVISED — no process injection after all)",
                "The loader writes its payload into a suspended child and resumes its thread.",
                "T1055",
            ),
            (
                "CLAIM 4 [ACCEPTED from the decompiler — module bases without imports]",
                "The routine walks the loader's module list and resolves exports by hash.",
                "T1027.007",
            ),
        ],
    )
    def test_an_affirmative_claim_under_a_negative_note_is_no_absence(
        self, heading: str, sentence: str, technique: str
    ) -> None:
        from maljan.pipeline.validation import absence_claim_violation

        text = (
            f"{heading}: {sentence}\nEVIDENCE: [ev_0004]\nCONFIDENCE: 0.8\nTECHNIQUE: {technique}"
        )
        (claim,) = _claims(text)

        assert claim.claim == sentence
        assert claim.heading_note == heading[heading.index(" ", 6) + 1 :]
        assert absence_claim_violation(claim, technique) is None


class TestNoteOnlyClaimsAreToldApartByTheirNotes:
    TEXT = (
        "CLAIM 1 (REVISED — the first beacon window is empty)\n"
        "EVIDENCE: [ev_0002]\nCONFIDENCE: 0.7\nTECHNIQUE: NONE\n"
        "CLAIM 2 (REVISED — the second beacon window is empty)\n"
        "EVIDENCE: [ev_0002]\nCONFIDENCE: 0.7\nTECHNIQUE: NONE\n"
    )

    def test_two_notes_with_the_same_fields_are_two_distinct_claims(self) -> None:
        assert claim_heading_counts(self.TEXT) == (2, 2)
        assert len({c.claim for c in _claims(self.TEXT)}) == 2

    @pytest.mark.parametrize("piece", [1, 3, 7, 64])
    def test_the_streaming_reader_counts_them_the_same(self, piece: int) -> None:
        reader = ClaimRepeatReader(None)
        for at in range(0, len(self.TEXT), piece):
            reader.feed(self.TEXT[at : at + piece])
            count = reader.count()
            assert (count.begun, count.distinct) == claim_heading_counts(self.TEXT[: at + piece])

    def test_the_same_note_twice_is_one_claim_repeated(self) -> None:
        twice = self.TEXT.split("CLAIM 2")[0] * 2
        assert claim_heading_counts(twice) == (2, 1)


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


def _sizes(name: str) -> tuple[str, str]:
    return _hostile(100_000), _hostile(1_000_000)


class TestAnUnclosedNoteCostsALinearRead:
    """The streaming reader reads an open note's characters up to its bracket at once."""

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

    @pytest.mark.parametrize("name", sorted(_READERS))
    def test_ten_times_the_line_holds_at_most_ten_times_the_memory(self, name: str) -> None:
        read = _READERS[name]
        small, large = _sizes(name)

        assert _peak(lambda: read(large)) <= 10 * _peak(lambda: read(small)) * 1.5 + 65_536

    def test_the_streaming_reader_holds_nothing_of_the_line(self) -> None:
        small, large = (_hostile(100_000), _hostile(1_000_000))

        held = _peak(lambda: _repeat_reader(large))
        assert held < max(2 * _peak(lambda: _repeat_reader(small)), 64 * 1024)


class TestWhereTheNoteIsShown:
    def _claim(self, note: str | None) -> Any:
        from maljan.schemas.isr_models import ClaimEvidence

        return ClaimEvidence(
            claim="It reads a file.",
            evidence_ref="[ev_0001]",
            confidence=0.5,
            heading_note=note,
        )

    def test_a_claim_without_a_note_serialises_as_before(self) -> None:
        assert "heading_note" not in self._claim(None).model_dump()
        assert "heading_note" not in self._claim(None).model_dump_json()

    def test_a_claim_with_a_note_carries_it(self) -> None:
        assert self._claim("[REVISED]").model_dump()["heading_note"] == "[REVISED]"

    def test_the_judge_s_listing_shows_it_beside_the_claim_number(self) -> None:
        from maljan.schemas.isr_models import AgentISR

        isr = AgentISR(agent_id="a", domain="static", claims=[self._claim("[REVISED]")])

        assert "Claim 1 [REVISED]: It reads a file." in isr.to_text_summary()

    def test_the_claim_events_show_it_only_when_there_is_one(self) -> None:
        from maljan.pipeline.events import claims_to_payload

        noted, plain = claims_to_payload([self._claim("[REVISED]"), self._claim(None)])

        assert noted["heading_note"] == "[REVISED]"
        assert noted["claim"] == "It reads a file."
        assert "heading_note" not in plain
