"""A retry answer the first answer is kept over is kept, whole, in the run record.

Three validation retries in one local run came back with no claim block or
with fewer blocks than the first answer, the first answer was kept each time,
and the retries' text was in no artefact: the time they took was spent with
no way to tell why. Every retry answer a first answer is kept over now goes
to ``run_summary.validation.discarded_retry_answers``, whole and masked as
model text in the record is, with why the first answer was kept. The answers
no claim could be read from (``unparsed_answers``) now reach the stored
summary too.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BaseAnalyst
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.pipeline.validation import validation_metrics
from maljan.schemas.isr_models import AgentISR


def _block(n: int, technique: str = "NONE") -> str:
    return (
        f"CLAIM: The file carries configuration string number {n}.\n"
        "EVIDENCE: [ev_0001] strings\n"
        "CONFIDENCE: 0.8\n"
        f"TECHNIQUE: {technique}\n"
        "---\n"
    )


# One claim whose technique line is asked about, so a retry is asked for.
FIRST = _block(1, "T1055 or T1106") + "".join(_block(n) for n in range(2, 5))
PROSE_RETRY = "I looked again and the file only reads its own configuration. " * 60
SHORT_RETRY = _block(1, "T1055") + _block(2)


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[str]) -> None:
        super().__init__(llm=MagicMock(), name="static")
        self.pack_ledger_ids = ["ev_0001"]
        self._replies = list(replies)

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        text = self._replies.pop(0)
        self._record_usage(AIMessage(content=text))
        return text


def _check(analyst: _Analyst) -> AgentISR:
    isr = analyst._text_to_isr(FIRST, 0)
    with (
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
    ):
        return analyst._validate_isr(isr, "evidence")


def test_a_retry_with_no_claim_block_is_kept_once_whole() -> None:
    analyst = _Analyst([PROSE_RETRY])

    result = _check(analyst)

    assert len(result.claims) == 4
    # Prose no claim could be read from is kept as such, once.
    (row,) = analyst.drain_unparsed_answers()
    assert "record" not in row
    assert row["answer"].strip() == PROSE_RETRY.strip()


def test_a_retry_with_claims_the_first_answer_is_kept_over_is_kept_whole() -> None:
    retry = _block(1, "T1055") + "And nothing else holds. " * 20
    analyst = _Analyst([retry])

    _check(analyst)

    (row,) = analyst.drain_unparsed_answers()
    assert row["record"] == "discarded_retry"
    assert row["agent"] == "static"
    assert row["answer"].strip() == retry.strip()
    assert "the retry answered 1 claim(s) in 1 claim block(s)" in row["why"]
    assert "the first answer is kept" in row["why"]


def test_a_retry_with_fewer_blocks_is_kept_whole() -> None:
    analyst = _Analyst([SHORT_RETRY])

    _check(analyst)

    (row,) = analyst.drain_unparsed_answers()
    assert row["answer"].strip() == SHORT_RETRY.strip()
    assert "2 claim block(s)" in row["why"]


def test_a_retry_that_is_kept_leaves_no_discarded_row() -> None:
    analyst = _Analyst([_block(1, "T1055") + "".join(_block(n) for n in range(2, 5))])

    _check(analyst)

    assert analyst.drain_unparsed_answers() == []


def test_the_stored_summary_carries_both_kinds_of_kept_answer() -> None:
    analyst = _Analyst([SHORT_RETRY])
    _check(analyst)
    rows = analyst.drain_unparsed_answers()
    unparsed = {"agent": "network", "round": "1", "answer": "prose no claim was read from"}

    metrics = validation_metrics(1, [], unparsed_answers=[unparsed, *rows])
    summary = (
        RunSummaryBuilder(start_time=0.0).set_validation(metrics).build().to_dict()["validation"]
    )

    assert summary["unparsed_answers"] == [unparsed]
    (kept,) = summary["discarded_retry_answers"]
    assert kept["answer"].strip() == SHORT_RETRY.strip()
    assert "record" not in kept
