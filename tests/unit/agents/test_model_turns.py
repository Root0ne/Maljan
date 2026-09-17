"""The budget the model is told is in model turns, counted the way langgraph counts."""

from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from maljan.agents.base_agent import model_turns_left


def _tool_turn(n: int) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": "t", "args": {}, "id": str(n)}])


class TestModelTurnsLeft:
    def test_the_first_turn_reads_half_the_recursion_limit_rounded_up(self) -> None:
        assert model_turns_left(10, []) == 5
        assert model_turns_left(4, []) == 2
        assert model_turns_left(9, [HumanMessage(content="t")]) == 5

    def test_a_tool_round_costs_two_steps_and_a_plain_turn_one(self) -> None:
        one_round = [_tool_turn(1), ToolMessage(content="r", tool_call_id="1")]
        assert model_turns_left(10, one_round) == 4
        assert model_turns_left(10, [*one_round, AIMessage(content="done")]) == 4
        two_rounds = [*one_round, _tool_turn(2), ToolMessage(content="r", tool_call_id="2")]
        assert model_turns_left(10, two_rounds) == 3

    def test_the_budget_never_goes_negative(self) -> None:
        spent = [_tool_turn(i) for i in range(6)]
        assert model_turns_left(4, spent) == 0
