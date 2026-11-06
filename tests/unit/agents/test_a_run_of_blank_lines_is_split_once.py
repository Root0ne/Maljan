"""A long run of blank lines costs the claim reader one walk, not one per line.

The ``---`` separator was tried at every newline of a whitespace run, and each
try walked the rest of the run before finding no dashes: an answer from a
model stuck repeating newlines took seconds to split. A separator now begins
only where the whitespace before it begins, and back-to-back ``---`` lines are
one separator, so what an answer reads as is unchanged: the same blocks, with
the same heading notes and numbers.
"""

from __future__ import annotations

from malspark.agents.base_agent import _blocks_with_notes, read_claim_blocks
from tests.linear_cost import assert_scales

_CLAIM = "CLAIM: a [ev_0001]\nCONFIDENCE: 0.5"


def _split(text: str) -> list[tuple[str, str | None, str | None]]:
    return _blocks_with_notes(text, [])


def test_a_run_of_blank_lines_is_split_in_linear_time() -> None:
    assert_scales(lambda n: "CLAIM: a" + "\n" * n + "b", 2_000, _split)
    assert_scales(lambda n: "CLAIM: a" + "\n  " * n + "b", 2_000, _split)
    # Chains of separators: the old pattern was linear on these. They guard
    # the new pattern's chain of ``---`` lines against backtracking.
    assert_scales(lambda n: "CLAIM: a" + "\n---" * n + "x\n" + _CLAIM, 2_000, _split)
    assert_scales(lambda n: "CLAIM: a" + "\n---\n\n  " * n + "b", 2_000, _split)


def test_an_answer_with_a_run_of_blank_lines_is_read_in_linear_time() -> None:
    assert_scales(lambda n: "CLAIM: a" + "\n" * n + "b", 2_000, read_claim_blocks)
    assert_scales(lambda n: "CLAIM: a" + "\n  " * n + "b", 2_000, read_claim_blocks)
    assert_scales(lambda n: "x" + "\n" * n + "y\n---\n" + _CLAIM, 2_000, read_claim_blocks)
    assert_scales(lambda n: "x" + "\n  " * n + "y\n---\n" + _CLAIM, 2_000, read_claim_blocks)
    # Guards the new pattern's chain against backtracking, not the old bug.
    assert_scales(lambda n: "x" + "\n---\n  " * n + "y\n---\n" + _CLAIM, 2_000, read_claim_blocks)


def _claims(text: str) -> list[tuple[str, float]]:
    return [(c.claim, c.confidence) for c in read_claim_blocks(text).claims]


def test_back_to_back_separators_are_one_and_hold_no_claim() -> None:
    text = (
        "CLAIM: one [ev_0001]\nCONFIDENCE: 0.5\n---\n---\n  ---  \n\n---\n"
        "CLAIM: two [ev_0002]\nCONFIDENCE: 0.6"
    )
    blocks = [block.strip() for block, _, _ in _split(text) if block.strip()]
    assert blocks == [
        "CLAIM: one [ev_0001]\nCONFIDENCE: 0.5",
        "CLAIM: two [ev_0002]\nCONFIDENCE: 0.6",
    ]
    assert _claims(text) == [("one [ev_0001]", 0.5), ("two [ev_0002]", 0.6)]


def test_a_dash_line_with_text_after_it_ends_no_separator_chain() -> None:
    # The separator before the ``---x`` line still splits; ``---x`` itself is
    # text of the block that follows.
    text = (
        "CLAIM: one [ev_0001]\nCONFIDENCE: 0.5\n---\n---\n---x\n"
        "CLAIM: two [ev_0002]\nCONFIDENCE: 0.6"
    )
    blocks = [block.strip() for block, _, _ in _split(text) if block.strip()]
    assert blocks == [
        "CLAIM: one [ev_0001]\nCONFIDENCE: 0.5",
        "---x\nCLAIM: two [ev_0002]\nCONFIDENCE: 0.6",
    ]
    assert [claim for claim, _ in _claims(text)] == ["one [ev_0001]", "two [ev_0002]"]


def test_crlf_separators_split_as_lf_ones() -> None:
    text = (
        "CLAIM: one [ev_0001]\r\nCONFIDENCE: 0.5\r\n---\r\n\r\n---\r\n"
        "CLAIM: two [ev_0002]\r\nCONFIDENCE: 0.6"
    )
    blocks = [block.strip() for block, _, _ in _split(text) if block.strip()]
    assert blocks == [
        "CLAIM: one [ev_0001]\r\nCONFIDENCE: 0.5",
        "CLAIM: two [ev_0002]\r\nCONFIDENCE: 0.6",
    ]
    assert _claims(text) == _claims(text.replace("\r\n", "\n"))
    assert _claims(text) == [("one [ev_0001]", 0.5), ("two [ev_0002]", 0.6)]


def test_a_heading_note_stays_with_its_block_across_a_chain() -> None:
    text = (
        "CLAIM 1 (first note): one [ev_0001]\nCONFIDENCE: 0.5\n---\n\n---\n"
        "CLAIM 2 [second note]: two [ev_0002]\nCONFIDENCE: 0.6"
    )
    read = read_claim_blocks(text)
    assert [(c.heading_note, c.claim) for c in read.claims] == [
        ("(first note)", "one [ev_0001]"),
        ("[second note]", "two [ev_0002]"),
    ]
    assert read.read == read.begun == 2
