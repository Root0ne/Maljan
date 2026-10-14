"""The judge's tool loop says it is one after its first tool round, so a re-sent prefix is cached.

The mediator's calls were billed with no cached input: the analysts' loop turns
note themselves as loop turns (``anthropic_history.TOOL_LOOP_TURN``), which
gives the first user turn a breakpoint and every later turn a read of it, and
the judge's loop turns did not. Most mediations and every verdict answer on
their first request, so that request is not noted and pays no write premium;
every turn after the loop's first tool round carries the note, on the request
alone, never on the loop's own messages: the second request writes the prefix
and every later one reads it.
"""

from __future__ import annotations

import asyncio
import copy
from typing import Any

from langchain_core.outputs import ChatResult

from maljan.llm.anthropic_history import TOOL_LOOP_TURN, Memory, prepared
from maljan.llm.anthropic_provider import cache_control
from tests.unit.agents.test_the_judge_s_loop_is_budgeted import (
    PROMPT,
    _budget,
    _judge,
    _Server,
    _settings,
)


class _Recording(_Server):
    noted: list[bool] = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **kw: Any
    ) -> ChatResult:
        sent = list(messages)
        self.noted.append(bool((sent[-1].response_metadata or {}).get(TOOL_LOOP_TURN)))
        return super()._generate(messages, stop, run_manager, **kw)


class TestTheJudgeLoopIsNoted:
    def test_every_turn_after_the_first_tool_round_is_sent_as_a_loop_turn(self) -> None:
        model = _Recording(chars_per_token=3.0)
        model.noted = []
        judge = _judge(_budget(), model)
        with _settings():
            asyncio.run(judge.execute_tool_loop(PROMPT))
        loop_turns = model.noted[:-1]  # the last request is the salvage, sent outside the loop
        assert len(loop_turns) >= 2
        assert loop_turns[0] is False
        assert all(loop_turns[1:])

    def test_a_first_request_alone_carries_no_breakpoint(self) -> None:
        marker = cache_control("5m")
        first: dict[str, Any] = {
            "system": "You mediate.",
            "messages": [{"role": "user", "content": "Expert reports: " + "r" * 5_000}],
        }
        one = prepared(first, Memory(), bound=False, cache_marker=marker, loop=False)
        assert "cache_control" not in repr(one)

    def test_the_turn_after_the_first_tool_round_writes_the_prefix_the_next_reads(self) -> None:
        marker = cache_control("5m")
        memory = Memory()
        first: dict[str, Any] = {
            "system": "You mediate.",
            "messages": [{"role": "user", "content": "Expert reports: " + "r" * 5_000}],
        }

        def after(request: dict[str, Any], call: str) -> dict[str, Any]:
            later = copy.deepcopy(request)
            later["messages"] += [
                {
                    "role": "assistant",
                    "content": [{"type": "tool_use", "id": call, "name": "lookup", "input": {}}],
                },
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": call}]},
            ]
            return later

        second = after(first, "t1")
        third = after(second, "t2")
        two = prepared(second, memory, bound=False, cache_marker=marker, loop=True)
        three = prepared(third, memory, bound=False, cache_marker=marker, loop=True)
        assert two["messages"][0]["content"][-1].get("cache_control") == marker
        assert two["messages"][2]["content"][-1].get("cache_control") == marker

        # The third request's prefix is the second's, byte for byte, and its
        # breakpoint on the turn the second wrote reads that write.
        def text(request: dict[str, Any], upto: int) -> str:
            plain = copy.deepcopy(request["messages"][:upto])
            for message in plain:
                for block in message["content"] if isinstance(message["content"], list) else []:
                    block.pop("cache_control", None)
            return repr(plain)

        assert text(three, 3) == text(two, 3)
        assert three["messages"][2]["content"][-1].get("cache_control") == marker
        assert three["messages"][4]["content"][-1].get("cache_control") == marker
