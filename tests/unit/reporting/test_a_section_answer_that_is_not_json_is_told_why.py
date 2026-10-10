"""A section answer the JSON reader cannot take is told why, in words the model can act on.

A paid run's ``payloads`` section was skipped after its one retry, told both
times "the answer was not JSON at all". It was JSON: a decoded string the
sample holds, ``init -zzzz="%s\\%s"``, was written with its backslash left
unescaped, which the decoder refuses as an invalid escape. Told nothing about
where, the model wrote the same string the same way again. The retry now
names the decoder's complaint, the character it is at and the text there, and
how a quote and a backslash are written inside a JSON string. An answer that
holds no text is told that, and is never sent back as the answer it corrects:
its retry is the question alone, at the end of the turn before it, so it is
never the request that was just answered. An answer whose JSON sits in a fence
or between sentences is read as the shared reader reads it, with no retry.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage

from maljan.pipeline.validation import Violation, _with_feedback, schema_violations
from maljan.reporting.composer import _HostIdentifiersOut
from maljan.utils import json_cleaner
from tests.credential_shapes import prefixed_key
from tests.unit.reporting.test_a_repeated_item_is_asked_about_once import (
    _DISTINCT,
    _answer,
    _Answers,
    _compose,
)

_GOOD = json.dumps({"identifiers": _DISTINCT})
# The paid run's two shapes: a backslash left unescaped (``\%``), and a double
# quote left unescaped inside a string.
_BAD_ESCAPE = (
    '{"identifiers": [{"kind": "String", "value": "init -zzzz=\\"%s\\%s\\"", '
    '"purpose": "", "evidence_refs": ["ev_0001"]}]}'
)
_BAD_QUOTE = (
    '{"identifiers": [{"kind": "String", "value": "The "Update_%x" template", '
    '"purpose": "", "evidence_refs": ["ev_0001"]}]}'
)


def _said(text: Any) -> AIMessage:
    return AIMessage(content=text, response_metadata={"finish_reason": "stop"})


def _question(llm: _Answers) -> str:
    last = llm.seen[1][-1]
    content = last.content
    if isinstance(content, list):
        return " ".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
    return str(content)


class TestABrokenJsonAnswer:
    def test_a_backslash_left_unescaped_is_named_where_it_is(self) -> None:
        llm = _Answers(_said(_BAD_ESCAPE), _answer(*_DISTINCT))

        result, _composer = _compose(llm)

        question = _question(llm)
        assert "not JSON at all" not in question
        assert "Invalid \\escape" in question
        assert "at character 62 of the JSON" in question
        assert "%s\\%s" in question
        assert "a backslash as two backslashes" in question
        assert [row.value for row in result.identifiers] == [r["value"] for r in _DISTINCT]

    def test_a_quote_left_unescaped_is_named_where_it_is(self) -> None:
        llm = _Answers(_said(_BAD_QUOTE), _answer(*_DISTINCT))

        _compose(llm)

        question = _question(llm)
        assert "Expecting ',' delimiter" in question
        assert "Update_%x" in question
        assert 'a double quote as \\"' in question

    def test_the_text_it_quotes_carries_no_credential(self) -> None:
        key = prefixed_key("ghs_")
        broken = '{"identifiers": [{"value": "http://operator:' + key + '@host.example/\\%"}]}'
        llm = _Answers(_said(broken), _answer(*_DISTINCT))

        _compose(llm)

        question = _question(llm)
        assert "Invalid \\escape" in question
        assert key not in question

    def test_the_broken_answer_is_still_sent_back_to_be_fixed(self) -> None:
        llm = _Answers(_said(_BAD_ESCAPE), _answer(*_DISTINCT))

        _compose(llm)

        assert isinstance(llm.seen[1][-2], AIMessage)
        assert llm.seen[1][-2].content == _BAD_ESCAPE


class TestAnAnswerWithNoText:
    def test_an_empty_answer_is_told_it_held_no_text(self) -> None:
        llm = _Answers(_said(""), _answer(*_DISTINCT))

        result, _composer = _compose(llm)

        question = _question(llm)
        assert "the answer held no text" in question
        assert "not JSON at all" not in question
        assert result is not None

    def test_whitespace_alone_is_no_text_either(self) -> None:
        llm = _Answers(_said("\n\n  "), _answer(*_DISTINCT))

        _compose(llm)

        assert "the answer held no text" in _question(llm)

    def test_it_is_never_sent_back_and_the_retry_is_a_new_request(self) -> None:
        for empty in ("", "\n\n", [""], ["", {"type": "text", "text": " "}]):
            llm = _Answers(_said(empty), _answer(*_DISTINCT))

            _compose(llm)

            first, retry = llm.seen
            assert not any(isinstance(turn, AIMessage) for turn in retry), repr(empty)
            assert retry != first
            assert isinstance(retry[-1], HumanMessage)

    def test_the_retry_turn_builder_leaves_it_out_on_both_wires(self) -> None:
        asked = [HumanMessage(content="write the section")]
        found = [Violation(code="composer.schema", message="m")]

        for answer in (_said(""), _said(" \n"), _said([""]), _said(["", {"type": "text"}])):
            turns = _with_feedback(asked, answer, found)

            assert len(turns) == 1, repr(answer.content)
            assert "m" in str(turns[0].content)
            assert turns != asked


class TestJsonInsideOtherText:
    def test_a_fenced_answer_is_read_with_no_retry(self) -> None:
        llm = _Answers(_said(f"```json\n{_GOOD}\n```"))

        result, _composer = _compose(llm)

        assert len(llm.seen) == 1
        assert [row.value for row in result.identifiers] == [r["value"] for r in _DISTINCT]

    def test_an_answer_between_sentences_is_read_with_no_retry(self) -> None:
        llm = _Answers(_said(f"Here is the section.\n{_GOOD}\nThat is all."))

        result, _composer = _compose(llm)

        assert len(llm.seen) == 1
        assert [row.value for row in result.identifiers] == [r["value"] for r in _DISTINCT]


class TestTheReason:
    def test_the_reader_names_nothing_for_json_it_reads(self) -> None:
        assert json_cleaner.json_error(_GOOD) == ""
        assert json_cleaner.json_error(f"```json\n{_GOOD}\n```") == ""

    def test_the_reader_names_the_decoder_s_complaint(self) -> None:
        why = json_cleaner.json_error(_BAD_ESCAPE)

        assert why.startswith("Invalid \\escape at character 62 of the JSON")

    def test_a_caller_without_the_answer_keeps_its_words(self) -> None:
        (found,) = schema_violations(_HostIdentifiersOut, None, code="composer.schema")

        assert found.message == "the answer was not JSON at all."

    def test_an_answer_that_reads_as_nothing_the_schema_takes_says_so(self) -> None:
        (found,) = schema_violations(_HostIdentifiersOut, None, code="composer.schema", answer="[]")

        assert found.message == "the answer holds no JSON object."
