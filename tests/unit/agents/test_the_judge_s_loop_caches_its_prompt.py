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
from unittest.mock import MagicMock

from langchain_core.messages import HumanMessage
from langchain_core.outputs import ChatResult

from maljan.agents.technique_facts import STANDING_FACTS_CHARS
from maljan.llm.anthropic_history import TOOL_LOOP_TURN, Memory, prepared
from maljan.llm.anthropic_provider import cache_control
from maljan.pipeline.run_state import RUN_STATE_BEGIN
from tests.unit.agents.test_standing_blocks_reach_the_prompts import FACTS
from tests.unit.agents.test_standing_blocks_reach_the_prompts import _judge as _standing_judge
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


class TestEachRoundReadsThePack:
    """The mediation's turn leads with the pack and the identity, and notes how long they are.

    Every round sends the same tools, system prompt and head; only the run
    state, the reports and the history change. With the run state first,
    haiku8's five mediations shared about 920 characters; with the head
    first and noted (``STANDING_FACTS_CHARS``), the provider gives it a
    breakpoint of its own (``anthropic_history``) that each later round reads.
    """

    def _turns(self, run_state: str, report: str) -> list[Any]:
        seen: list[Any] = []
        judge = _standing_judge([])

        class _Model:
            async def ainvoke(self, messages: Any) -> Any:
                seen.append(list(messages))
                return MagicMock(content="No contradictions.")

        judge.llm = _Model()
        asyncio.run(
            judge.mediate(
                reports={"static": report},
                history=[],
                isr_reports={},
                reputation_asked=True,
                facts_block=FACTS,
                run_state=run_state,
            )
        )
        return seen[0]

    def test_two_rounds_share_the_noted_head_and_differ_after_it(self) -> None:
        heads = []
        for run_state, report in (("round 1 state", "first text"), ("round 2 state", "second")):
            human = next(m for m in self._turns(run_state, report) if isinstance(m, HumanMessage))
            size = human.response_metadata[STANDING_FACTS_CHARS]
            text = str(human.content)
            assert text.startswith(FACTS)
            assert text[size:].lstrip().startswith(RUN_STATE_BEGIN)
            heads.append(text[:size])
        assert heads[0] == heads[1]

    def test_the_first_request_writes_only_the_pack_for_an_hour(self) -> None:
        text = "Facts established before analysis\n" + "[ev_0001] x\n" * 300
        rest = "\n\n=== RUN STATE ===\nround 1\n=== END RUN STATE ===\n\nExpert Reports: r"
        hour = {"type": "ephemeral", "ttl": "1h"}
        sent = prepared(
            {"system": "You mediate.", "messages": [{"role": "user", "content": text + rest}]},
            Memory(),
            bound=False,
            cache_marker=cache_control("5m"),
            standing={text + rest: len(text)},
            standing_marker=hour,
        )
        content = sent["messages"][0]["content"]
        assert content[0] == {"type": "text", "text": text, "cache_control": hour}
        assert content[1] == {"type": "text", "text": rest}


class TestTheNotedText:
    """The mediation's turn text carries its note through a copy, a deep copy and a pickle."""

    def test_the_note_survives_copy_deepcopy_and_pickle(self) -> None:
        import pickle

        from maljan.agents.judge_agent import NotedText

        text = NotedText("head and rest", {STANDING_FACTS_CHARS: 4})
        for again in (
            copy.copy(text),
            copy.deepcopy(text),
            pickle.loads(pickle.dumps(text)),  # noqa: S301 — our own object, just made
        ):
            assert isinstance(again, NotedText)
            assert str(again) == "head and rest"
            assert again.notes == {STANDING_FACTS_CHARS: 4}
        assert NotedText("plain").notes == {}
