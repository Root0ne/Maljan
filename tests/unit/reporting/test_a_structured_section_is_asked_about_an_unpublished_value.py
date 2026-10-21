"""The structured path asks the unpublished-value question too, with a retry turn.

The question (``report.unpublished_value``) was asked only where the model's
answer went through the validation loop; a provider that takes the structured
path recorded the finding as not asked and the report marked the sentence
"not asked". The raw answer now stands for the loop's first answer and its
retry turn is sent, as on the manual path. A section with no such finding
costs no second call.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import patch

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from pydantic import BaseModel

from maljan.pipeline.validation import UNPUBLISHED_VALUE_CODE
from maljan.reporting.composer import ReportComposer, _ProseOut
from maljan.reporting.narrative_agent import published_answers
from tests.unit.reporting.test_an_unpublished_value_in_prose_carries_its_state import (
    PUBLISHED,
    REFUSED,
    _body,
    _report,
)


class _Structured:
    def __init__(self, llm: _Model, schema: type[BaseModel]) -> None:
        self.llm = llm
        self.schema = schema

    async def ainvoke(self, turns: list[BaseMessage], **_: Any) -> dict[str, Any]:
        self.llm.sent.append(list(turns))
        text = self.llm.answers.pop(0)
        return {
            "raw": AIMessage(content=text),
            "parsed": self.schema.model_validate(json.loads(text)),
            "parsing_error": None,
        }


class _Model:
    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.sent: list[list[BaseMessage]] = []

    def with_structured_output(self, schema: type[BaseModel], **_: Any) -> _Structured:
        return _Structured(self, schema)


def _invoke(*answers: str) -> tuple[Any, _Model, Any]:
    llm = _Model(*answers)
    report = _report()
    comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
    comp._report = report
    comp._answers = published_answers(report)
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=True):
        result = asyncio.run(
            comp._invoke(
                [HumanMessage(content="write it")], _ProseOut, section="command_and_control"
            )
        )
    return result, llm, report


def test_a_structured_answer_naming_an_unpublished_value_is_asked_once() -> None:
    wrong = json.dumps(_body(f"It uses {REFUSED} as C2."))
    right = json.dumps(_body(f"It uses {PUBLISHED} as C2."))

    result, llm, report = _invoke(wrong, right)

    assert len(llm.sent) == 2
    assert result is not None and PUBLISHED in result.body
    assert report.flagged_statements == []


def test_a_kept_sentence_is_marked_after_the_question_was_asked() -> None:
    wrong = json.dumps(_body(f"It uses {REFUSED} as C2."))

    result, llm, report = _invoke(wrong, wrong)

    assert len(llm.sent) == 2
    assert result is not None and REFUSED in result.body
    (row,) = report.flagged_statements
    assert row.code == UNPUBLISHED_VALUE_CODE
    assert row.asked is True


def test_a_clean_structured_answer_costs_no_second_call() -> None:
    clean = json.dumps(_body(f"It uses {PUBLISHED} as C2."))

    result, llm, _report_ = _invoke(clean)

    assert len(llm.sent) == 1
    assert result is not None and PUBLISHED in result.body


def test_a_refusing_retry_never_replaces_the_first_answer() -> None:
    wrong = json.dumps(_body(f"It uses {REFUSED} as C2."))

    result, llm, report = _invoke(wrong, json.dumps({}))

    assert len(llm.sent) == 2
    assert result is not None and REFUSED in result.body
    (row,) = report.flagged_statements
    assert row.code == UNPUBLISHED_VALUE_CODE


def test_an_empty_retry_never_replaces_the_first_answer() -> None:
    wrong = json.dumps(_body(f"It uses {REFUSED} as C2."))

    result, llm, report = _invoke(wrong, json.dumps(_body("")))

    assert len(llm.sent) == 2
    assert result is not None and REFUSED in result.body
    assert len(report.flagged_statements) == 1
