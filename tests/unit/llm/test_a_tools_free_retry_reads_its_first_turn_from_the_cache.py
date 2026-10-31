"""On Claude, a tools-free retry's first turn is cached once and read by the questions after it.

A validation retry is built from text: the evidence as its first user turn,
the answer it fixes, the question. The drops question and the whole-answer
question that follow it send the same first turn again (the whole-answer
question the retry's question too). A turn written as one string carries no
breakpoint, so each of these requests paid its whole prompt uncached; the
turn before a request's newest assistant turn is now sent as one text block
holding the same text, with the breakpoint the conversation's policy puts on
it, and keeps that shape on every later request of the model. The model reads
the same text; only the cache marker and the block shape differ. A turn a
thinking block was written after as a string keeps its shape, so the local
prefix check and the cache prefix bytes stay unchanged, and the binding
digest reads a string and its one text block as the same turn, as the API
does; any other turn, the newest included, is listed only where an earlier
request listed it.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from maljan.core.config import Settings
from maljan.llm import anthropic_history
from maljan.llm.anthropic_provider import AnthropicProvider

from .anthropic_wire import MODEL, Wire, _unmarked, install, message

USAGE = {"input_tokens": 10, "output_tokens": 5}
SYSTEM = "You are a static analyst. No tools are attached to this request."
EVIDENCE = "Static output:\n[ev_0001] identity: pe windows\n" + "evidence line\n" * 40
FIRST = "CLAIM: it reads a file\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.6\nTECHNIQUE: NONE\n"
RETRY_QUESTION = "Your previous answer had these problems: claim 1 cites no entry. Fix it."
RETRY = "CLAIM: it reads a file [ev_0001]\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.6\nTECHNIQUE: NONE\n"
DROPS_QUESTION = "Your retry no longer states these items. KEEP or WITHDRAW each."
WHOLE_QUESTION = "Write your whole corrected answer."
MARK = {"type": "ephemeral"}


def _thinking(turn: int) -> dict[str, Any]:
    return {"type": "thinking", "thinking": "", "signature": f"EoBsig{turn}/+=" * 8}


def _reply(body: dict[str, Any]) -> dict[str, Any]:
    turn = len(body["messages"])
    return message([_thinking(turn), {"type": "text", "text": RETRY}], stop="end_turn", usage=USAGE)


@pytest.fixture
def wire(monkeypatch: pytest.MonkeyPatch) -> Wire:
    found = Wire(_reply)
    install(monkeypatch, found)
    return found


def _model() -> Any:
    settings = Settings(
        _env_file=None,
        llm={"provider": "anthropic", "anthropic": {"api_key": "test-anthropic-key"}},
    )
    return AnthropicProvider(settings).build_model(MODEL, 0.1, max_tokens=4096)


def _retry() -> list[Any]:
    return [
        SystemMessage(content=SYSTEM),
        HumanMessage(content=EVIDENCE),
        AIMessage(content=FIRST),
        HumanMessage(content=RETRY_QUESTION),
    ]


def _drops() -> list[Any]:
    return [*_retry()[:2], AIMessage(content=RETRY), HumanMessage(content=DROPS_QUESTION)]


def _whole() -> list[Any]:
    return [*_retry(), AIMessage(content=RETRY), HumanMessage(content=WHOLE_QUESTION)]


def _text(turn: dict[str, Any]) -> str:
    content = turn["content"]
    if isinstance(content, str):
        return content
    return "".join(block.get("text", "") for block in content)


def _marked(body: dict[str, Any]) -> list[int]:
    return [
        index
        for index, turn in enumerate(body["messages"])
        if isinstance(turn["content"], list)
        and any("cache_control" in block for block in turn["content"])
    ]


def _prefix(body: dict[str, Any], turns: int) -> Any:
    return _unmarked({"system": body.get("system"), "messages": body["messages"][:turns]})


class TestTheRetryChain:
    def _run(self, wire: Wire) -> list[dict[str, Any]]:
        model = _model()
        for turns in (_retry(), _drops(), _whole()):
            model.invoke(turns)
        assert wire.refused == []
        assert wire.dropped == []
        return wire.bodies

    def test_the_retry_writes_its_first_turn_as_one_marked_block(self, wire: Wire) -> None:
        retry = self._run(wire)[0]
        assert retry["messages"][0]["content"] == [
            {"type": "text", "text": EVIDENCE, "cache_control": MARK}
        ]
        assert _marked(retry) == [0], "the newest turn is left as it was written"
        assert retry["messages"][2]["content"] == RETRY_QUESTION

    def test_the_drops_question_reads_the_same_prefix(self, wire: Wire) -> None:
        retry, drops, _whole_ = self._run(wire)
        assert _prefix(drops, 1) == _prefix(retry, 1)
        assert _marked(drops) == [0]

    def test_the_whole_answer_question_reads_the_retry_s_question_too(self, wire: Wire) -> None:
        retry, _drops_, whole = self._run(wire)
        assert _prefix(whole, 3) == _unmarked(
            {
                "system": retry.get("system"),
                "messages": [
                    *retry["messages"][:2],
                    {"role": "user", "content": [{"type": "text", "text": RETRY_QUESTION}]},
                ],
            }
        )
        assert whole["messages"][0]["content"] == [{"type": "text", "text": EVIDENCE}], (
            "listed once, the first turn keeps its shape unmarked"
        )
        assert _marked(whole) == [2]

    def test_every_turn_reads_as_it_was_written(self, wire: Wire) -> None:
        bodies = self._run(wire)
        for body, turns in zip(bodies, (_retry(), _drops(), _whole()), strict=True):
            assert [_text(t) for t in body["messages"]] == [str(m.content) for m in turns[1:]]
            assert body["system"] == SYSTEM or _text({"content": body["system"]}) == SYSTEM


class TestTheShapeRules:
    def test_a_single_shot_call_is_sent_as_written(self) -> None:
        payload = {"messages": [{"role": "user", "content": EVIDENCE}], "system": SYSTEM}
        sent = anthropic_history.prepared(
            payload, anthropic_history.Memory(), bound=True, cache_marker=MARK
        )
        assert sent["messages"] == [{"role": "user", "content": EVIDENCE}]

    def test_a_turn_a_thinking_block_was_written_after_keeps_its_shape(self) -> None:
        answer = {"role": "assistant", "content": [_thinking(1), {"type": "text", "text": FIRST}]}
        payload = {
            "messages": [
                {"role": "user", "content": EVIDENCE},
                answer,
                {"role": "user", "content": RETRY_QUESTION},
            ]
        }
        sent = anthropic_history.prepared(
            payload, anthropic_history.Memory(), bound=True, cache_marker=MARK
        )
        assert sent["messages"][0] == {"role": "user", "content": EVIDENCE}
        assert sent["messages"][2]["content"] == RETRY_QUESTION

    def test_the_last_request_carries_no_marker_but_keeps_a_listed_shape(self) -> None:
        memory = anthropic_history.Memory()
        turns = [
            {"role": "user", "content": EVIDENCE},
            {"role": "assistant", "content": FIRST},
            {"role": "user", "content": RETRY_QUESTION},
        ]
        anthropic_history.prepared({"messages": list(turns)}, memory, bound=True, cache_marker=MARK)
        last = anthropic_history.prepared(
            {"messages": list(turns)}, memory, bound=True, cache_marker=MARK, last=True
        )
        assert last["messages"][0]["content"] == [{"type": "text", "text": EVIDENCE}]
        assert _marked(last) == []

    def test_a_thinking_block_written_after_a_listed_turn_stays_valid(self, wire: Wire) -> None:
        model = _model()
        first = model.invoke(_retry())
        # The retry's answer sent back as it came, thinking block and all.
        model.invoke([*_retry(), first, HumanMessage(content=WHOLE_QUESTION)])
        assert wire.refused == []
        assert wire.dropped == []
        later = wire.bodies[1]
        # Neither string turn can carry a breakpoint, so the one goes on the
        # first turn, whose entry the retry wrote: a read, and nothing written.
        assert later["messages"][0]["content"] == [
            {"type": "text", "text": EVIDENCE, "cache_control": MARK}
        ]
        assert _marked(later) == [0]
        assert later["messages"][2]["content"] == RETRY_QUESTION, (
            "sent as a string when the block was written, it stays one"
        )

    def test_a_turn_listed_by_one_branch_keeps_another_branch_s_block_valid(
        self, wire: Wire
    ) -> None:
        model = _model()
        opening = [SystemMessage(content=SYSTEM), HumanMessage(content=EVIDENCE)]
        # Branch P: the turn alone, answered with a thinking block.
        answered = model.invoke(opening)
        # Branch Q lists the same turn as the one before its newest answer.
        model.invoke([*opening, AIMessage(content=FIRST), HumanMessage(content=RETRY_QUESTION)])
        # Branch P goes on with its answer as received, thinking block and all.
        model.invoke([*opening, answered, HumanMessage(content=WHOLE_QUESTION)])
        assert wire.refused == []
        assert wire.dropped == [], "the turn in either shape is the same turn"
        later = wire.bodies[2]
        assert "block_binding" not in json.dumps(later.get("thinking") or {})
        assert _unmarked(later["messages"][0]["content"]) == [{"type": "text", "text": EVIDENCE}]

    def test_a_newest_turn_listed_before_is_sent_listed(self) -> None:
        memory = anthropic_history.Memory()
        turns = [
            {"role": "user", "content": EVIDENCE},
            {"role": "assistant", "content": FIRST},
            {"role": "user", "content": RETRY_QUESTION},
        ]
        anthropic_history.prepared({"messages": turns}, memory, bound=True, cache_marker=MARK)
        alone = anthropic_history.prepared(
            {"messages": [{"role": "user", "content": EVIDENCE}]},
            memory,
            bound=True,
            cache_marker=MARK,
        )
        assert alone["messages"][0]["content"] == [{"type": "text", "text": EVIDENCE}]
        assert _marked(alone) == [], "a single-shot call still writes no entry"

    def test_two_conversations_on_one_model_keep_their_own_shapes(self) -> None:
        memory = anthropic_history.Memory()
        other = "Network output:\n[ev_0002] sandbox network: hosts 2\n"

        def _sent(first: str) -> dict[str, Any]:
            turns = [
                {"role": "user", "content": first},
                {"role": "assistant", "content": FIRST},
                {"role": "user", "content": RETRY_QUESTION},
            ]
            return anthropic_history.prepared(
                {"messages": turns}, memory, bound=True, cache_marker=MARK
            )

        one, two = _sent(EVIDENCE), _sent(other)
        assert one["messages"][0]["content"] == [
            {"type": "text", "text": EVIDENCE, "cache_control": MARK}
        ]
        assert two["messages"][0]["content"] == [
            {"type": "text", "text": other, "cache_control": MARK}
        ]
        single = anthropic_history.prepared(
            {"messages": [{"role": "user", "content": "unrelated"}]},
            memory,
            bound=True,
            cache_marker=MARK,
        )
        assert single["messages"] == [{"role": "user", "content": "unrelated"}]
