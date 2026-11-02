"""On Claude, the triage pack at the head of a turn has a breakpoint of its own, for an hour.

An agent's debate rounds send the same tools, system prompt and pack again,
twelve to thirty minutes apart in haiku8, so every revision's first turn wrote
the whole prefix and read none of it: the only breakpoint was on the newest
user turn, whose entry lives five minutes. The pack, noted with its length
where the platform puts it at the head of the turn
(``technique_facts.STANDING_FACTS_CHARS``), is sent as its own text block
with a breakpoint at ``llm.anthropic.pack_cache_ttl`` (an hour by default);
every other breakpoint keeps ``prompt_cache_ttl``. The two blocks' texts
joined are the turn's text, the longer-lived breakpoint stands first, as the
API requires, and no request carries more than four.
"""

from __future__ import annotations

import copy
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from maljan.agents.technique_facts import STANDING_FACTS_CHARS
from maljan.core.config import Settings
from maljan.llm.anthropic_history import (
    MAX_BREAKPOINTS,
    Memory,
    _within_breakpoint_limit,
    prepared,
    standing_marker,
)
from maljan.llm.anthropic_provider import AnthropicProvider, cache_control

from .anthropic_wire import MODEL, Wire, install, message

PACK = (
    "Facts established before analysis (ledger ids in brackets; cite them)\n"
    + "[ev_0001] x\n" * 400
)
TASK = "\n\nRevise your analysis addressing the contradictions above. " + "r" * 2_000
HOUR = {"type": "ephemeral", "ttl": "1h"}
FIVE = {"type": "ephemeral"}


def _request(*turns: dict[str, Any]) -> dict[str, Any]:
    return {"system": "You analyse.", "messages": list(turns)}


def _markers(payload: dict[str, Any]) -> list[dict[str, str]]:
    return [
        block["cache_control"]
        for turn in payload["messages"]
        if isinstance(turn.get("content"), list)
        for block in turn["content"]
        if isinstance(block, dict) and "cache_control" in block
    ]


class TestTheMarker:
    def test_the_pack_lives_an_hour_by_default_and_never_less_than_the_rest(self) -> None:
        assert Settings(_env_file=None).llm.anthropic.pack_cache_ttl == "1h"
        assert standing_marker("5m", "1h") == HOUR
        assert standing_marker("5m", "5m") == FIVE
        assert standing_marker("1h", "5m") == HOUR
        assert standing_marker("5m", "off") is None


class TestTheRequest:
    def test_a_single_shot_turn_sends_the_pack_as_its_own_block_with_the_hour_marker(self) -> None:
        text = PACK + TASK
        sent = prepared(
            _request({"role": "user", "content": text}),
            Memory(),
            bound=False,
            cache_marker=cache_control("5m"),
            standing={text: len(PACK)},
            standing_marker=HOUR,
        )
        content = sent["messages"][0]["content"]
        assert [block["text"] for block in content] == [PACK, TASK]
        assert "".join(block["text"] for block in content) == text
        assert _markers(sent) == [HOUR]

    def test_a_loop_turn_keeps_its_own_breakpoint_after_the_pack(self) -> None:
        text = PACK + TASK
        sent = prepared(
            _request({"role": "user", "content": text}),
            Memory(),
            bound=False,
            cache_marker=cache_control("5m"),
            loop=True,
            standing={text: len(PACK)},
            standing_marker=HOUR,
        )
        # The hour's entry first, the five minutes' after it.
        assert _markers(sent) == [HOUR, FIVE]
        assert sent["messages"][0]["content"][1]["cache_control"] == FIVE

    def test_off_sends_the_request_byte_for_byte_as_before(self) -> None:
        text = PACK + TASK
        request = _request({"role": "user", "content": text})
        before = prepared(
            copy.deepcopy(request), Memory(), bound=False, cache_marker=FIVE, loop=True
        )
        after = prepared(
            copy.deepcopy(request),
            Memory(),
            bound=False,
            cache_marker=FIVE,
            loop=True,
            standing={text: len(PACK)},
            standing_marker=standing_marker("5m", "off"),
        )
        assert after == before

    def test_a_turn_rebuilt_without_its_note_keeps_the_shape_sent_before(self) -> None:
        memory = Memory()
        text = PACK + TASK
        first = prepared(
            _request({"role": "user", "content": text}),
            memory,
            bound=False,
            cache_marker=FIVE,
            standing={text: len(PACK)},
            standing_marker=HOUR,
        )
        again = prepared(
            _request({"role": "user", "content": text}),
            memory,
            bound=False,
            cache_marker=FIVE,
            standing={},
            standing_marker=HOUR,
        )
        assert again["messages"] == first["messages"]

    def test_a_turn_without_the_pack_is_left_as_it_is(self) -> None:
        sent = prepared(
            _request({"role": "user", "content": "Expert reports: " + "r" * 5_000}),
            Memory(),
            bound=False,
            cache_marker=FIVE,
            standing={},
            standing_marker=HOUR,
        )
        assert isinstance(sent["messages"][0]["content"], str)


class TestTheLimit:
    def test_past_four_breakpoints_the_earliest_after_the_first_are_left_out(self) -> None:
        turns = [
            {"role": "user", "content": [{"type": "text", "text": f"t{i}", "cache_control": FIVE}]}
            for i in range(MAX_BREAKPOINTS + 2)
        ]
        kept = _within_breakpoint_limit(turns)
        marked = [i for i, turn in enumerate(kept) if "cache_control" in turn["content"][0]]
        assert marked == [0, 3, 4, 5]


class TestOnTheWire:
    """The provider's own model, from the shipped settings, over a stand-in API."""

    def _bodies(self, monkeypatch: Any, **anthropic: Any) -> list[dict[str, Any]]:
        wire = Wire(
            lambda _body: message(
                [{"type": "text", "text": "ok"}], stop="end_turn", usage={"input_tokens": 1}
            )
        )
        install(monkeypatch, wire)
        settings = Settings(
            _env_file=None,
            llm={
                "provider": "anthropic",
                "anthropic": {"api_key": "test-anthropic-key", **anthropic},
            },
        )
        model = AnthropicProvider(settings).build_model(MODEL, 0.1, max_tokens=1024)
        turn = HumanMessage(
            content=PACK + TASK, response_metadata={STANDING_FACTS_CHARS: len(PACK)}
        )
        model.invoke([SystemMessage(content="You analyse."), turn])
        assert not wire.refused
        return wire.bodies

    def test_the_shipped_settings_cache_the_pack_for_an_hour(self, monkeypatch: Any) -> None:
        (body,) = self._bodies(monkeypatch)
        content = body["messages"][0]["content"]
        assert content[0] == {"type": "text", "text": PACK, "cache_control": HOUR}
        assert content[1] == {"type": "text", "text": TASK}

    def test_off_leaves_the_turn_whole(self, monkeypatch: Any) -> None:
        (body,) = self._bodies(monkeypatch, pack_cache_ttl="off")
        content = body["messages"][0]["content"]
        text = content if isinstance(content, str) else "".join(b["text"] for b in content)
        assert text == PACK + TASK
        assert "cache_control" not in repr(body)
