"""The grounding corpus records what it held, not only what it missed.

A run could say how many answers its corpus could not keep and never how many
it did, so a reader could not tell a run with room to spare from one that all
but filled its ceiling — only that neither had overflowed.

What is held is printed where it tells a reader something: a corpus that went
partial, or one past half its ceiling. Otherwise the figures stay on the
record and the surfaces stay quiet. A run that recorded nothing about them
reads as absent, never as a corpus that held nothing.
"""

from __future__ import annotations

from typing import Any

from maljan.agents.run_evidence_corpus import RunEvidenceCorpus, held_by
from maljan.analysis.run_summary import RunSummaryBuilder, corpus_held_sentence
from maljan.core.truncation_ledger import TruncationLedger


def _summary(snapshot: dict[str, Any]) -> dict[str, Any]:
    builder = RunSummaryBuilder(start_time=0.0)
    return builder.set_truncation(snapshot).build().to_dict()["truncation"]


def test_the_corpus_counts_the_answers_and_the_bytes_it_is_holding() -> None:
    corpus = RunEvidenceCorpus(1000)
    corpus.remember("ev_0001", "strings", "ABCDE")
    corpus.remember("ev_0002", "capa", "FGH")

    held = corpus.held()

    assert (held.answers, held.bytes_held, held.ceiling) == (2, 8, 1000)
    assert held_by(corpus) == held
    assert held_by(None) is None


def test_an_answer_the_ceiling_refused_is_missed_and_not_held() -> None:
    corpus = RunEvidenceCorpus(4)
    corpus.remember("ev_0001", "strings", "ABCD")
    corpus.remember("ev_0002", "strings", "EFGH")

    held = corpus.held()

    assert (held.answers, held.bytes_held) == (1, 4)
    assert corpus.state().missing_answers == 1


def test_a_run_that_recorded_nothing_about_its_corpus_reads_as_absent() -> None:
    ledger = TruncationLedger()
    ledger.record_tool_output(chars_in=10, chars_kept=10, over_limit=False)
    ledger.record_evidence_corpus(missing_answers=0, missing_tools=(), reason="")

    truncation = _summary(ledger.snapshot())

    assert "evidence_corpus_answers" not in truncation
    assert "evidence_corpus_bytes_held" not in truncation
    assert "evidence_corpus_bytes_ceiling" not in truncation


def test_what_the_corpus_held_reaches_the_run_summary() -> None:
    corpus = RunEvidenceCorpus(1000)
    corpus.remember("ev_0001", "strings", "A" * 100)
    ledger = TruncationLedger()
    ledger.record_tool_output(chars_in=10, chars_kept=10, over_limit=False)
    ledger.record_evidence_corpus(
        missing_answers=0, missing_tools=(), reason="", held=held_by(corpus)
    )

    truncation = _summary(ledger.snapshot())

    assert truncation["evidence_corpus_answers"] == 1
    assert truncation["evidence_corpus_bytes_held"] == 100
    assert truncation["evidence_corpus_bytes_ceiling"] == 1000


class _Held:
    """Only the fields the sentence reads."""

    def __init__(self, answers: int, held: int, ceiling: int, reason: str = "") -> None:
        self.evidence_corpus_answers = answers
        self.evidence_corpus_bytes_held = held
        self.evidence_corpus_bytes_ceiling = ceiling
        self.evidence_corpus_partial_reason = reason


def test_a_corpus_with_room_to_spare_is_carried_silently() -> None:
    assert corpus_held_sentence(_Held(12, 1000, 16_777_216)) == ""


def test_a_corpus_past_half_its_ceiling_says_what_it_held() -> None:
    assert corpus_held_sentence(_Held(12, 600, 1000)) == (
        "The grounding corpus held 12 answers, 600 of 1000 bytes."
    )


def test_a_partial_corpus_says_what_it_held_however_small() -> None:
    assert corpus_held_sentence(_Held(1, 4, 1000, reason="ceiling reached")) == (
        "The grounding corpus held 1 answer, 4 of 1000 bytes."
    )


def test_a_run_with_no_figures_says_nothing() -> None:
    assert corpus_held_sentence(_Held(0, 0, 0)) == ""
    assert corpus_held_sentence(object()) == ""


def test_the_report_prints_the_sentence_the_run_earned() -> None:
    ledger = TruncationLedger()
    ledger.record_tool_output(chars_in=10, chars_kept=10, over_limit=False)
    corpus = RunEvidenceCorpus(100)
    corpus.remember("ev_0001", "strings", "A" * 80)
    ledger.record_evidence_corpus(
        missing_answers=0, missing_tools=(), reason="", held=held_by(corpus)
    )

    builder = RunSummaryBuilder(start_time=0.0)
    markdown = builder.set_truncation(ledger.snapshot()).build().to_markdown()

    assert "The grounding corpus held 1 answer, 80 of 100 bytes." in markdown
