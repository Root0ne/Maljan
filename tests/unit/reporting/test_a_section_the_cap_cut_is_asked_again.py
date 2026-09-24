"""A report section the output cap cut is told so and asked once for a shorter answer.

Both answers of a benchmark report's host-identifier section ran to exactly
8,192 tokens, the section's output budget. The first was cut before its JSON
closed, the retry was told only that the answer "was not JSON at all", and it
wrote the same long answer into the same cap; the section was dropped. The
answers themselves were not kept anywhere, so nothing said whether the budget
went on many rows or on one row written again and again.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from maljan.pipeline.validation import SECTION_CUT_CODE, section_cut_violation
from maljan.reporting.composer import (
    _INSTRUCTIONS,
    ReportComposer,
    _HostIdentifiersOut,
    cut_answer_shape,
    section_contract,
)

_CUT_ROW = '{"kind": "String", "value": "same-value", "purpose": "", "evidence_refs": ["ev_0001"]}'
_CUT = '{"identifiers": [' + ", ".join([_CUT_ROW] * 40) + ', {"kind": "Str'
_WHOLE = (
    '{"identifiers": [{"kind": "File name", "value": "state.example.bin", '
    '"purpose": "", "evidence_refs": ["ev_0001"]}]}'
)


class _Answers:
    """A model that answers in turn and keeps every conversation it was sent."""

    model_name = "m"

    def __init__(self, *answers: AIMessage) -> None:
        self.answers = list(answers)
        self.seen: list[list[Any]] = []

    async def ainvoke(self, messages: Any) -> AIMessage:
        self.seen.append(list(messages))
        return self.answers.pop(0)


def _cut() -> AIMessage:
    return AIMessage(content=_CUT, response_metadata={"finish_reason": "length"})


def _whole() -> AIMessage:
    return AIMessage(content=_WHOLE, response_metadata={"finish_reason": "stop"})


def _compose(llm: _Answers) -> tuple[Any, ReportComposer]:
    composer = ReportComposer(llm=llm, section_max_tokens=8192)  # type: ignore[arg-type]
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "maljan.reporting.composer.structured_output_supported_for_llm", lambda _l: False
        )
        result = asyncio.run(
            composer._invoke(
                [HumanMessage(content="x")], _HostIdentifiersOut, section="host_identifiers"
            )
        )
    return result, composer


class TestTheQuestion:
    def test_a_cut_answer_is_told_the_cap_and_asked_once(self) -> None:
        llm = _Answers(_cut(), _whole())

        result, composer = _compose(llm)

        assert isinstance(result, _HostIdentifiersOut)
        assert [row.value for row in result.identifiers] == ["state.example.bin"]
        retry_turn = str(llm.seen[1][-1].content)
        assert retry_turn == _feedback_turn_for(8192)
        assert composer.validation_tally.by_code.get(SECTION_CUT_CODE) == 1
        assert composer.degradations == []

    def test_a_second_cut_is_recorded_with_how_far_each_got(self) -> None:
        llm = _Answers(_cut(), _cut())

        result, composer = _compose(llm)

        assert result is None
        assert len(llm.seen) == 2
        (reason,) = composer.degradations
        assert "report section 'host_identifiers' is missing" in reason
        assert "reached the output cap of 8192 tokens" in reason
        assert "40 item(s) begun, at most 1 of them distinct" in reason
        assert "asked once for a shorter answer, which was cut too" in reason

    def test_an_answer_inside_the_cap_is_not_told_about_it(self) -> None:
        llm = _Answers(_whole())

        result, composer = _compose(llm)

        assert isinstance(result, _HostIdentifiersOut)
        assert len(llm.seen) == 1
        assert SECTION_CUT_CODE not in composer.validation_tally.by_code


def _feedback_turn_for(cap: int) -> str:
    from maljan.pipeline.validation import feedback_text

    return feedback_text([section_cut_violation(cap)])


class TestTheShapeOfACutAnswer:
    def test_rows_written_again_and_again_show_as_few_distinct(self) -> None:
        assert cut_answer_shape(_CUT).endswith("40 item(s) begun, at most 1 of them distinct")

    def test_many_different_rows(self) -> None:
        rows = ", ".join(f'{{"kind": "String", "value": "v{n}", "purpose": ""}}' for n in range(30))
        assert "30 item(s) begun, at most 30 of them distinct" in cut_answer_shape(
            '{"identifiers": [' + rows
        )

    def test_text_with_no_string_field_says_its_length(self) -> None:
        assert cut_answer_shape("not json at all") == "15 characters"


class TestTheContract:
    def test_the_kind_is_what_the_entry_shows(self) -> None:
        """Configuration-panel paths were typed as registry keys, an address as a domain."""
        text = _INSTRUCTIONS["host_identifiers"]

        assert "registry hive" in text
        assert "'String' when the entry does not show what the value is" in text
        assert "Write each value once" in text

    def test_a_list_contract_asks_for_each_item_once_and_compact(self) -> None:
        contract = section_contract("host_identifiers", _HostIdentifiersOut)

        assert "Each item is written once" in contract
        assert "without indentation" in contract
