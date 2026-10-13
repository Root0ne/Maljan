"""The judge's tool loop says it is one, so a provider that caches a re-sent prefix caches it.

The mediator's calls were billed with no cached input: the analysts' loop turns
note themselves as loop turns (``anthropic_history.TOOL_LOOP_TURN``), which
gives the first user turn a breakpoint on the first request and every later
turn a read of it, and the judge's loop turns did not. Each judge loop turn now
carries the note on the request alone, never on the loop's own messages.
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
    def test_every_turn_of_the_loop_is_sent_as_a_loop_turn(self) -> None:
        model = _Recording(chars_per_token=3.0)
        model.noted = []
        judge = _judge(_budget(), model)
        with _settings():
            asyncio.run(judge.execute_tool_loop(PROMPT))
        loop_turns = model.noted[:-1]  # the last request is the salvage, sent outside the loop
        assert loop_turns and all(loop_turns)

    def test_the_first_turn_writes_the_prefix_the_second_reads(self) -> None:
        marker = cache_control("5m")
        memory = Memory()
        first: dict[str, Any] = {
            "system": "You mediate.",
            "messages": [{"role": "user", "content": "Expert reports: " + "r" * 5_000}],
        }
        second = copy.deepcopy(first)
        second["messages"] += [
            {
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "t1", "name": "lookup", "input": {}}],
            },
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1"}]},
        ]
        one = prepared(first, memory, bound=False, cache_marker=marker, loop=True)
        two = prepared(second, memory, bound=False, cache_marker=marker, loop=True)
        assert one["messages"][0]["content"][-1].get("cache_control") == marker
        assert two["messages"][0]["content"] == one["messages"][0]["content"]
        assert two["messages"][2]["content"][-1].get("cache_control") == marker
