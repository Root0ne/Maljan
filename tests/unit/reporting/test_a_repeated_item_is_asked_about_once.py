"""A section answer that writes an item again is asked about once, and never deduplicated.

A reference run's host-identifier answer began 161 items within its output
budget, of which at most 19 differed: the model wrote the same values again and
again until the cap cut it off. Every list section's contract already says each
item is written once. An answer that repeats items is told how many repeat and
which values, once; what comes back is kept as the model wrote it, repeats and
all, with the finding recorded. A cut answer's question says the same about the
items it began.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from maljan.pipeline.validation import (
    REPEATED_ITEMS_CODE,
    SECTION_CUT_CODE,
    repeated_item_violations,
    section_cut_violation,
)
from maljan.reporting.composer import ReportComposer, _ConfigOut, _HostIdentifiersOut


def _identifier(value: str, purpose: str = "") -> dict[str, Any]:
    return {"kind": "String", "value": value, "purpose": purpose, "evidence_refs": ["ev_0001"]}


def _answer(*rows: dict[str, Any], cut: bool = False) -> AIMessage:
    text = json.dumps({"identifiers": list(rows)})
    return AIMessage(
        content=text[:-40] if cut else text,
        response_metadata={"finish_reason": "length" if cut else "stop"},
    )


_LOOPING = [_identifier("state.example.bin")] * 5 + [
    _identifier("marker-one"),
    _identifier("marker-one", "written again with another purpose"),
    _identifier("marker-two"),
]
_DISTINCT = [_identifier("state.example.bin"), _identifier("marker-one"), _identifier("marker-two")]


class _Answers:
    model_name = "m"

    def __init__(self, *answers: AIMessage) -> None:
        self.answers = list(answers)
        self.seen: list[list[Any]] = []

    async def ainvoke(self, messages: Any) -> AIMessage:
        self.seen.append(list(messages))
        return self.answers.pop(0)


def _compose(llm: _Answers, schema: Any = _HostIdentifiersOut) -> tuple[Any, ReportComposer]:
    composer = ReportComposer(llm=llm, section_max_tokens=8192)  # type: ignore[arg-type]
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "maljan.reporting.composer.structured_output_supported_for_llm", lambda _l: False
        )
        result = asyncio.run(
            composer._invoke([HumanMessage(content="x")], schema, section="host_identifiers")
        )
    return result, composer


class TestTheCheck:
    def test_it_counts_the_repeats_and_names_the_values(self) -> None:
        (found,) = repeated_item_violations({"identifiers": _LOOPING}, {"identifiers": ("value",)})

        assert found.code == REPEATED_ITEMS_CODE
        assert found.path == "identifiers"
        assert "5 of the 8 items in 'identifiers' repeat an item already written" in found.message
        assert "3 are distinct" in found.message
        assert "'state.example.bin' 5 times" in found.message
        assert "'marker-one' 2 times" in found.message
        assert "'marker-two'" not in found.message

    def test_distinct_items_raise_nothing(self) -> None:
        assert (
            repeated_item_violations({"identifiers": _DISTINCT}, {"identifiers": ("value",)}) == []
        )

    def test_no_fields_compares_whole_items(self) -> None:
        steps = [{"step": "reads its settings"}, {"step": "reads its settings"}]

        (found,) = repeated_item_violations({"steps": steps}, {"steps": ()})

        assert "1 of the 2 items" in found.message

    def test_a_configuration_key_with_two_values_is_two_items(self) -> None:
        items = [
            {"key": "Endpoint", "value": "a.example.org"},
            {"key": "Endpoint", "value": "b.example.org"},
        ]

        assert repeated_item_violations({"items": items}, {"items": ("key", "value")}) == []


class TestTheSection:
    def test_a_repeating_answer_is_asked_once_and_the_answer_that_follows_is_kept(self) -> None:
        llm = _Answers(_answer(*_LOOPING), _answer(*_DISTINCT))

        result, composer = _compose(llm)

        assert len(llm.seen) == 2
        assert REPEATED_ITEMS_CODE in str(llm.seen[1][-1].content)
        assert [row.value for row in result.identifiers] == [
            "state.example.bin",
            "marker-one",
            "marker-two",
        ]
        assert composer.validation_tally.by_code == {REPEATED_ITEMS_CODE: 1}
        assert composer.validation_tally.unresolved == []

    def test_a_repeating_answer_kept_after_the_question_is_printed_whole(self) -> None:
        llm = _Answers(_answer(*_LOOPING), _answer(*_LOOPING))

        result, composer = _compose(llm)

        assert len(llm.seen) == 2
        assert [row.value for row in result.identifiers] == [row["value"] for row in _LOOPING]
        assert [row["code"] for row in composer.validation_tally.unresolved] == [
            REPEATED_ITEMS_CODE
        ]
        assert composer.validation_tally.unresolved[0]["agent"] == "composer:host_identifiers"

    def test_a_distinct_answer_is_asked_nothing(self) -> None:
        llm = _Answers(_answer(*_DISTINCT))

        _result, composer = _compose(llm)

        assert len(llm.seen) == 1
        assert REPEATED_ITEMS_CODE not in composer.validation_tally.by_code

    def test_a_configuration_answer_is_checked_the_same_way(self) -> None:
        item = {"key": "Endpoint", "value": "a.example.org", "how_obtained": "static-string"}
        looping = AIMessage(
            content=json.dumps({"items": [item, item, item]}),
            response_metadata={"finish_reason": "stop"},
        )
        llm = _Answers(looping, looping)

        result, composer = _compose(llm, _ConfigOut)

        assert len(result.items) == 3
        assert REPEATED_ITEMS_CODE in composer.validation_tally.by_code


class TestTheCutAnswer:
    def test_the_cut_question_says_how_many_items_repeat(self) -> None:
        llm = _Answers(_answer(*_LOOPING, cut=True), _answer(*_DISTINCT))

        _result, _composer = _compose(llm)

        question = str(llm.seen[1][-1].content)
        assert SECTION_CUT_CODE in question
        assert "at most 3 of them distinct, so at least" in question
        assert "repeat an item already written" in question

    def test_a_cut_answer_of_distinct_items_says_nothing_of_repeats(self) -> None:
        message = section_cut_violation(8192, chars=900, begun=12, distinct=12).message

        assert "repeat" not in message
        assert "12 item(s) begun" in message
