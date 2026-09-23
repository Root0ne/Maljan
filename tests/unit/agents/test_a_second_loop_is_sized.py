"""What a second loop needs, and the ceiling it runs under."""

from __future__ import annotations

from typing import Any

from maljan.agents.base_agent import (
    _SYNTHESIS_MIN_SECONDS,
    BaseAnalyst,
    BudgetCeiling,
    TurnPace,
    loop_limits,
)
from maljan.llm.generation_rate import TIMEOUT_MARGIN
from maljan.schemas.isr_models import AgentISR


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def _analyst() -> _Analyst:
    return _Analyst(llm=object(), name="static")  # type: ignore[arg-type]


class TestWhatALoopNeeds:
    def test_a_loop_that_measured_nothing_needs_the_salvage_minimum(self) -> None:
        assert _analyst().seconds_a_loop_needs() == float(_SYNTHESIS_MIN_SECONDS)

    def test_one_turn_and_the_final_answer_at_the_measured_pace(self) -> None:
        analyst = _analyst()
        pace = TurnPace()
        pace.current = "qwen"
        pace.turns["qwen"] = [140.0, 90.0]
        analyst._last_pace = pace

        assert analyst.seconds_a_loop_needs() == 140.0 + 140.0 * TIMEOUT_MARGIN

    def test_a_measured_rate_sizes_the_final_answer(self) -> None:
        analyst = _analyst()
        pace = TurnPace(lambda: 5.0)
        pace.current = "qwen"
        pace.turns["qwen"] = [100.0]
        analyst._last_pace = pace

        # A thousand tokens at five a second outweighs the 100 s turn.
        assert analyst.seconds_a_loop_needs() == 100.0 + 200.0 * TIMEOUT_MARGIN


class TestTheCeiling:
    def test_the_loop_runs_under_what_is_left_and_the_ceiling_is_given_back(self) -> None:
        analyst = _analyst()
        seen: list[Any] = []

        def _guarded(data: str) -> AgentISR:
            seen.append(analyst._budget_ceiling)
            seen.append(loop_limits(analyst.name, analyst._budget_ceiling))
            return AgentISR(agent_id="static", domain="static")

        analyst._analyze_isr_guarded = _guarded  # type: ignore[method-assign]
        _timeout, steps = loop_limits(analyst.name)

        analyst.safe_analyze_isr_within("data", 321.0)

        ceiling, limits = seen
        assert isinstance(ceiling, BudgetCeiling)
        assert (ceiling.seconds, ceiling.wall, ceiling.steps) == (321.0, 321.0, steps)
        assert limits == (321, steps)
        assert analyst._budget_ceiling is None
