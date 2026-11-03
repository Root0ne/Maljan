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

import pytest
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

    def test_an_hour_after_five_minutes_asks_for_five_minutes(self) -> None:
        turns = [
            {"role": "user", "content": [{"type": "text", "text": "a", "cache_control": FIVE}]},
            {"role": "user", "content": [{"type": "text", "text": "b", "cache_control": HOUR}]},
        ]
        kept = _within_breakpoint_limit(turns)
        assert [turn["content"][0]["cache_control"] for turn in kept] == [FIVE, FIVE]

    def test_only_the_first_user_turn_s_facts_are_split(self) -> None:
        """A later turn that begins with a pack is no head: the hour stays first."""
        head = "HEAD " * 300
        first = head + "rest " * 100
        later = PACK + TASK
        sent = prepared(
            _request(
                {"role": "user", "content": first},
                {"role": "assistant", "content": "ok"},
                {"role": "user", "content": later},
            ),
            Memory(),
            bound=False,
            cache_marker=FIVE,
            heads={first: len(head)},
            standing={later: len(PACK)},
            standing_marker=HOUR,
        )
        assert HOUR not in _markers(sent)
        content = sent["messages"][2]["content"]
        assert content == later or [b["text"] for b in content] == [later]


class TestALostNote:
    """A turn sent again without its note is split where it was split, never at a guessed head."""

    def test_two_heads_of_one_model_never_cross(self) -> None:
        memory = Memory()
        ident = "=== SAMPLE IDENTITY\nsha256 abc\n\n"
        analyst = PACK + "\n\nAnalyse." + "a" * 500
        mediation = PACK + "\n\n" + ident + "=== RUN STATE ...\n\nExpert Reports: " + "r" * 500
        head = len(PACK) + 2 + len(ident)
        for text, size in ((analyst, len(PACK)), (mediation, head)):
            prepared(
                _request({"role": "user", "content": text}),
                memory,
                bound=False,
                cache_marker=FIVE,
                standing={text: size},
                standing_marker=HOUR,
            )
        again = prepared(
            _request({"role": "user", "content": mediation}),
            memory,
            bound=False,
            cache_marker=FIVE,
            standing={},
            standing_marker=HOUR,
        )
        assert again["messages"][0]["content"][0]["text"] == mediation[:head]

    def test_a_turn_never_noted_is_never_split(self) -> None:
        """The verdict and the technique question begin with the pack and carry no note."""
        memory = Memory()
        noted = PACK + TASK
        prepared(
            _request({"role": "user", "content": noted}),
            memory,
            bound=False,
            cache_marker=FIVE,
            standing={noted: len(PACK)},
            standing_marker=HOUR,
        )
        verdict = PACK + "\n\nReturn a JSON STIX 2.1 Bundle."
        sent = prepared(
            _request({"role": "user", "content": verdict}),
            memory,
            bound=False,
            cache_marker=FIVE,
            standing={},
            standing_marker=HOUR,
        )
        assert sent["messages"][0]["content"] == verdict


class TestABoundLoop:
    """On a model that binds thinking to its prefix, a loop's first turn is sent as it was."""

    def test_the_second_request_resends_the_first_turn_with_its_run_state(self) -> None:
        run_state = "\n\n=== RUN STATE ===\nsteps 5\n=== END RUN STATE ==="
        body = "\n\nAnalyse the sample." + "a" * 500
        memory = Memory()
        first_text = PACK + body + run_state
        first = prepared(
            _request({"role": "user", "content": first_text}),
            memory,
            bound=True,
            cache_marker=FIVE,
            attached=run_state,
            loop=True,
            standing={first_text: len(PACK)},
            standing_marker=HOUR,
        )
        answer = {
            "role": "assistant",
            "content": [
                {"type": "thinking", "thinking": "t", "signature": "sig1"},
                {"type": "tool_use", "id": "tu1", "name": "x", "input": {}},
            ],
        }
        reply = {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": "tu1", "content": "out" + run_state}
            ],
        }
        second = prepared(
            _request({"role": "user", "content": PACK + body}, answer, reply),
            memory,
            bound=True,
            cache_marker=FIVE,
            attached=run_state,
            loop=True,
            standing={PACK + body: len(PACK)},
            standing_marker=HOUR,
        )

        def bare(turn: dict[str, Any]) -> list[dict[str, Any]]:
            return [{k: v for k, v in b.items() if k != "cache_control"} for b in turn["content"]]

        assert bare(second["messages"][0]) == bare(first["messages"][0])
        assert second["messages"][0]["content"][0]["cache_control"] == HOUR
        assert "betas" not in second and "thinking" not in second


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

    def test_a_streamed_pack_write_is_charged_at_the_hour_s_price(self, monkeypatch: Any) -> None:
        """A stream's closing usage carries no split by lifetime; its opening event does."""
        from maljan.core.spend import SpendMeter, table_prices
        from maljan.core.token_ledger import turn_usage

        written = 2_000
        usage = {
            "input_tokens": 10,
            "output_tokens": 5,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": written,
            "cache_creation": {
                "ephemeral_5m_input_tokens": 0,
                "ephemeral_1h_input_tokens": written,
            },
        }
        wire = Wire(
            lambda _body: message([{"type": "text", "text": "ok"}], stop="end_turn", usage=usage)
        )
        install(monkeypatch, wire)
        settings = Settings(
            _env_file=None,
            llm={
                "provider": "anthropic",
                "expert_model": MODEL,
                "anthropic": {
                    "api_key": "test-anthropic-key",
                    "expert_model": MODEL,
                    "judge_model": MODEL,
                },
            },
        )
        model = AnthropicProvider(settings).build_model(
            MODEL, 0.1, max_tokens=1024, streaming=True, stream_usage=True
        )
        turn = HumanMessage(
            content=PACK + TASK, response_metadata={STANDING_FACTS_CHARS: len(PACK)}
        )
        answer = model.invoke([SystemMessage(content="You analyse."), turn])
        assert wire.bodies[0]["stream"] is True
        charged = turn_usage(answer)
        assert charged is not None
        assert charged["cache_write_1h_input_tokens"] == written
        row = table_prices()[MODEL]
        five = {k: v for k, v in charged.items() if k != "cache_write_1h_input_tokens"}
        extra = row.cost(charged) - row.cost(five)
        assert extra == pytest.approx(written * (0.20 - 0.125) / 1_000_000)
        # A call is admitted at the hour's write price while the pack's entry may live an hour.
        assert SpendMeter.from_settings(settings).writes_hour_caches(MODEL) is True

    @staticmethod
    def _settled(monkeypatch: Any, usage: dict[str, Any], *, streaming: bool) -> float:
        """What the shipped settings' meter settles one answer reporting ``usage`` at."""
        from maljan.core.spend import SpendMeter
        from maljan.core.token_ledger import turn_usage

        wire = Wire(
            lambda _body: message([{"type": "text", "text": "ok"}], stop="end_turn", usage=usage)
        )
        install(monkeypatch, wire)
        settings = Settings(
            _env_file=None,
            llm={
                "provider": "anthropic",
                "expert_model": MODEL,
                "anthropic": {
                    "api_key": "test-anthropic-key",
                    "expert_model": MODEL,
                    "judge_model": MODEL,
                },
            },
        )
        extra = {"streaming": True, "stream_usage": True} if streaming else {}
        model = AnthropicProvider(settings).build_model(MODEL, 0.1, max_tokens=1024, **extra)
        answer = model.invoke([HumanMessage(content="hi")])
        assert bool(wire.bodies[0].get("stream")) is streaming
        charged = turn_usage(answer)
        assert charged is not None
        meter = SpendMeter.from_settings(settings)
        assert meter.writes_hour_caches(MODEL) is True
        meter.settle(charged, MODEL)
        return meter.spent()

    def _five_minutes(self, written: int) -> dict[str, Any]:
        return {
            "input_tokens": 10,
            "output_tokens": 5,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": written,
            "cache_creation": {
                "ephemeral_5m_input_tokens": written,
                "ephemeral_1h_input_tokens": 0,
            },
        }

    def test_a_streamed_five_minutes_write_is_charged_at_the_five_minutes_price(
        self, monkeypatch: Any
    ) -> None:
        written = 2_000
        spent = self._settled(monkeypatch, self._five_minutes(written), streaming=True)
        assert spent == pytest.approx((10 * 0.10 + written * 0.125 + 5 * 0.50) / 1_000_000)

    def test_a_whole_answer_s_split_with_no_hour_is_charged_at_the_five_minutes_price(
        self, monkeypatch: Any
    ) -> None:
        written = 2_000
        spent = self._settled(monkeypatch, self._five_minutes(written), streaming=False)
        assert spent == pytest.approx((10 * 0.10 + written * 0.125 + 5 * 0.50) / 1_000_000)

    def test_a_write_split_nowhere_is_settled_at_the_hour_s_price(self, monkeypatch: Any) -> None:
        written = 2_000
        usage = {
            "input_tokens": 10,
            "output_tokens": 5,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": written,
        }
        spent = self._settled(monkeypatch, usage, streaming=True)
        assert spent == pytest.approx((10 * 0.10 + written * 0.20 + 5 * 0.50) / 1_000_000)

    def test_off_leaves_the_turn_whole(self, monkeypatch: Any) -> None:
        (body,) = self._bodies(monkeypatch, pack_cache_ttl="off")
        content = body["messages"][0]["content"]
        text = content if isinstance(content, str) else "".join(b["text"] for b in content)
        assert text == PACK + TASK
        assert "cache_control" not in repr(body)
