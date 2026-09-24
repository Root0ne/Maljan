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

from maljan.pipeline.validation import SECTION_CUT_CODE
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
        retry = llm.seen[1]
        assert retry_turn_is_the_question(retry)
        assert "It ran to 3,550 characters with 40 item(s) begun" in str(retry[-1].content)
        assert all(_CUT not in str(turn.content) for turn in retry), "the cut answer is not re-sent"
        assert len(retry) == 2
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


def retry_turn_is_the_question(turns: list[Any]) -> bool:
    return SECTION_CUT_CODE in str(turns[-1].content) and "8192 tokens" in str(turns[-1].content)


def _compose_in_window(llm: _Answers, prompt_chars: int, window: int, cap: int) -> Any:
    composer = ReportComposer(llm=llm, section_max_tokens=cap)  # type: ignore[arg-type]
    composer.window_tokens = window
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "maljan.reporting.composer.structured_output_supported_for_llm", lambda _l: False
        )
        result = asyncio.run(
            composer._invoke(
                [HumanMessage(content="x" * prompt_chars)],
                _HostIdentifiersOut,
                section="host_identifiers",
            )
        )
    return result, composer


class TestTheRetryIsSizedToTheWindow:
    """The retry is the first prompt and one short turn, sent only when it fits."""

    WINDOW = 4000
    CAP = 1000

    def _cut_at(self, cap: int) -> AIMessage:
        return AIMessage(content=_CUT, response_metadata={"finish_reason": "length"})

    def test_a_prompt_above_half_the_window_still_gets_its_question(self) -> None:
        # 2,200 tokens of prompt in a 4,000-token window: above half, and the
        # cut answer re-sent beside it would not have left the budget free.
        llm = _Answers(self._cut_at(self.CAP), _whole())

        result, composer = _compose_in_window(llm, 6600, self.WINDOW, self.CAP)

        assert isinstance(result, _HostIdentifiersOut)
        assert len(llm.seen) == 2
        assert sum(len(str(t.content)) for t in llm.seen[1]) <= (self.WINDOW - self.CAP) * 3

    def test_a_question_that_would_not_fit_is_not_asked_and_is_recorded(self) -> None:
        llm = _Answers(self._cut_at(self.CAP))

        result, composer = _compose_in_window(llm, 8900, self.WINDOW, self.CAP)

        assert result is None
        assert len(llm.seen) == 1
        (reason,) = composer.degradations
        assert "not asked again: the question would not fit its model's window" in reason


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
        assert "Software\\, System\\" in text
        assert "'String' when the entry does not show what the value is" in text
        assert "Write each value once" in text

    def test_a_list_contract_asks_for_each_item_once_and_compact(self) -> None:
        contract = section_contract("host_identifiers", _HostIdentifiersOut)

        assert "Each item is written once" in contract
        assert "without indentation" in contract


def test_a_schema_question_near_the_room_is_still_asked() -> None:
    """Only the cut question is sized to the window; a schema question keeps its retry."""
    broken = AIMessage(
        content='{"identifiers": [{"kind": "String", "value": null, "evidence_refs": []}]}',
        response_metadata={"finish_reason": "stop"},
    )
    llm = _Answers(broken, _whole())

    result, composer = _compose_in_window(llm, 8900, 4000, 1000)

    assert isinstance(result, _HostIdentifiersOut)
    assert len(llm.seen) == 2
    assert composer.degradations == []
