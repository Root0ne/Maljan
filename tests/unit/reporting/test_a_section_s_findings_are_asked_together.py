"""A section's findings are asked together in its one retry, and a late one says it was not asked.

A reference run's host-identifier section spent its one retry on a schema
question, and the answer to that retry wrote one row twice. The repeat was
recorded as unresolved, which reads as a question the model was put and did
not fix; it was never put. Findings the first answer raises are asked together,
in one question; a finding only the retry's answer raises is recorded as not
asked, with the reason, and its marks say so.
"""

from __future__ import annotations

import json

from langchain_core.messages import AIMessage

from maljan.pipeline.validation import REPEATED_ITEMS_CODE
from maljan.reporting.composer import ONLY_IN_THE_RETRY
from tests.unit.reporting.test_a_repeated_item_is_asked_about_once import (
    _DISTINCT,
    _LOOPING,
    _answer,
    _Answers,
    _compose,
)


def _not_json() -> AIMessage:
    return AIMessage(content="The identifiers are listed below.", response_metadata={})


def _with_a_broken_row(*rows: dict) -> AIMessage:
    broken = {"kind": "String", "evidence_refs": ["ev_0001"]}
    return AIMessage(
        content=json.dumps({"identifiers": [*rows, broken]}),
        response_metadata={"finish_reason": "stop"},
    )


class TestFoundTogether:
    def test_a_schema_problem_and_a_repeat_are_asked_in_one_question(self) -> None:
        llm = _Answers(_with_a_broken_row(*_LOOPING), _answer(*_DISTINCT))

        _result, composer = _compose(llm)

        assert len(llm.seen) == 2
        question = str(llm.seen[1][-1].content)
        assert "composer.schema" in question
        assert REPEATED_ITEMS_CODE in question
        assert composer.validation_tally.unresolved == []


class TestFoundOnlyInTheRetry:
    def test_a_repeat_the_retry_raises_is_recorded_as_not_asked(self) -> None:
        llm = _Answers(_not_json(), _answer(*_LOOPING))

        result, composer = _compose(llm)

        assert len(llm.seen) == 2
        assert REPEATED_ITEMS_CODE not in str(llm.seen[1][-1].content)
        assert [row.value for row in result.identifiers] == [row["value"] for row in _LOOPING]
        (row,) = composer.validation_tally.unresolved
        assert row["code"] == REPEATED_ITEMS_CODE
        assert row["message"].endswith(ONLY_IN_THE_RETRY)

    def test_a_repeat_that_was_asked_and_kept_reads_as_asked(self) -> None:
        llm = _Answers(_answer(*_LOOPING), _answer(*_LOOPING))

        _result, composer = _compose(llm)

        (row,) = composer.validation_tally.unresolved
        assert ONLY_IN_THE_RETRY not in row["message"]
