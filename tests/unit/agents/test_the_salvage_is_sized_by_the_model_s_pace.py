"""The time-cap salvage sends what the time left can read and answer, at the model's pace.

On the small model the static analyst's loop ended on its time budget with
393 s left, and the salvage re-sent the whole conversation — about 50,000
characters, the tool definitions gone so nothing the server had cached could
be reused — to a model reading 110–240 tokens a second and writing 5.5. It ran
into its 423 s hard cap on all three PE samples, and the analyst ended with no
claim. The request is now sized from the two rates this job measured: what
the time left can read, after the time the answer takes to write.
"""

from __future__ import annotations

import asyncio
import logging
import time
from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from maljan.agents.base_agent import (
    FINAL_ANSWER_EXPECTED_TOKENS,
    BaseAnalyst,
    salvage_chars_at_pace,
)
from maljan.llm.generation_rate import (
    LLAMA_CPP_PROMPT_SOURCE,
    OLLAMA_PROMPT_SOURCE,
    TIMEOUT_MARGIN,
    GenerationRates,
    RateMeter,
    measured_prompt_read,
)

MODEL = "qwen3.8:27b @ http://127.0.0.1:11434"

# The small Latrodectus run: 393 s left, 5.455 tokens/s written (the run
# summary's measured rate), and a prompt read at 150 tokens/s, inside the
# 110–240 the Ollama journal recorded.
SECONDS_LEFT = 393.0
WRITES = 5.455
READS = 150.0


class TestTheArithmetic:
    def test_the_slow_run_s_numbers(self) -> None:
        chars = salvage_chars_at_pace(
            SECONDS_LEFT, generation_rate=WRITES, prompt_rate=READS, chars_per_token=3
        )

        reading = SECONDS_LEFT / TIMEOUT_MARGIN - FINAL_ANSWER_EXPECTED_TOKENS / WRITES
        assert chars == int(reading * READS * 3)
        # Well under the ~50,000 characters the run re-sent.
        assert 30_000 < chars < 40_000

    def test_an_unmeasured_rate_sizes_nothing(self) -> None:
        assert (
            salvage_chars_at_pace(393, generation_rate=None, prompt_rate=READS, chars_per_token=3)
            is None
        )
        assert (
            salvage_chars_at_pace(393, generation_rate=WRITES, prompt_rate=None, chars_per_token=3)
            is None
        )

    def test_a_time_that_cannot_hold_the_answer_holds_nothing(self) -> None:
        assert (
            salvage_chars_at_pace(60, generation_rate=WRITES, prompt_rate=READS, chars_per_token=3)
            == 0
        )


class TestTheReadingRateIsMeasured:
    def test_ollama_s_prompt_counts(self) -> None:
        message = SimpleNamespace(
            response_metadata={"prompt_eval_count": 8672, "prompt_eval_duration": 57_800_000_000}
        )

        assert measured_prompt_read(message) == (8672, 57.8, OLLAMA_PROMPT_SOURCE)

    def test_llama_cpp_s_timings(self) -> None:
        message = SimpleNamespace(
            response_metadata={"timings": {"prompt_n": 3751, "prompt_ms": 10186.17}}
        )

        assert measured_prompt_read(message) == (3751, 10.18617, LLAMA_CPP_PROMPT_SOURCE)

    def test_a_wall_clock_is_not_a_reading_rate(self) -> None:
        message = SimpleNamespace(response_metadata={}, usage_metadata={"input_tokens": 9000})

        assert measured_prompt_read(message) is None

    def test_the_meter_records_both_rates_and_the_snapshot_carries_them(self) -> None:
        rates = GenerationRates()
        meter = RateMeter(rates, MODEL)
        message = AIMessage(
            content="x",
            response_metadata={
                "eval_count": 120,
                "eval_duration": 22_000_000_000,
                "prompt_eval_count": 3000,
                "prompt_eval_duration": 20_000_000_000,
            },
        )
        run = SimpleNamespace(generations=[[SimpleNamespace(message=message, generation_info={})]])
        from uuid import uuid4

        meter.on_llm_end(run, run_id=uuid4())

        assert rates.prompt_rate(MODEL) == pytest.approx(150.0)
        row = rates.snapshot()["models"][MODEL]
        assert row["prompt_tokens_per_second"] == 150.0
        assert row["prompt_sources"] == [OLLAMA_PROMPT_SOURCE]


class _Rates:
    def __init__(self, generation: float | None, reading: float | None) -> None:
        self.generation, self.reading = generation, reading

    def rate(self, model: str) -> float | None:
        return self.generation

    def prompt_rate(self, model: str) -> float | None:
        return self.reading


class _Analyst(BaseAnalyst):
    """A stand-in that records the salvage request instead of sending it."""

    def __init__(self, rates: _Rates) -> None:
        super().__init__(llm=SimpleNamespace(model=MODEL), name="static")  # type: ignore[arg-type]
        self.logger = logging.getLogger("test.salvage_pace")
        self._container = SimpleNamespace(get_generation_rates=lambda: rates)
        self.sent: list[Any] = []
        self._note_budget({"stage": "analysis", "cap": "time"})

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float) -> str:
        self.sent = list(messages)
        return "CLAIM: x"


def _conversation(framing: int, tools: int, chars_each: int) -> list:
    msgs: list = [
        SystemMessage(content="S" * framing),
        HumanMessage(content="The pack and the task."),
    ]
    for i in range(tools):
        msgs.append(AIMessage(content="", tool_calls=[]))
        msgs.append(ToolMessage(content=f"tool-{i}-" + "x" * chars_each, tool_call_id=str(i)))
    return msgs


def _salvage(agent: _Analyst) -> dict[str, Any]:
    (row,) = agent.drain_budget_records()
    return row["salvage"]


# What the window allowed on that run: 32,768 tokens, four characters a token,
# two fifths of it (``synthesis_budget_chars``).
WINDOW_CHARS = 52_428


@pytest.fixture(autouse=True)
def _the_run_s_window(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "maljan.agents.base_agent.synthesis_budget_chars", lambda *a, **k: WINDOW_CHARS
    )


class TestTheSalvageAtThisPace:
    def test_the_request_fits_what_the_time_left_can_read(self) -> None:
        agent = _Analyst(_Rates(WRITES, READS))
        conversation = _conversation(9_000, 19, 2_500)

        answer = agent._force_final_synthesis(conversation, 1500, 1500 - SECONDS_LEFT)

        assert answer == "CLAIM: x"
        paced = salvage_chars_at_pace(
            SECONDS_LEFT, generation_rate=WRITES, prompt_rate=READS, chars_per_token=3
        )
        record = _salvage(agent)
        assert record["sized_by"] == "pace"
        assert record["budget_chars"] == paced
        assert record["sent_chars"] <= paced < record["conversation_chars"]
        assert record["outcome"] == "answered"
        # The framing and the latest evidence are what is kept.
        body = " ".join(str(m.content) for m in agent.sent)
        assert "The pack and the task." in body
        assert "tool-18-" in body
        assert "tool-0-" not in body

    def test_a_time_left_that_cannot_read_the_framing_sends_nothing_and_says_why(self) -> None:
        agent = _Analyst(_Rates(WRITES, READS))

        answer = agent._force_final_synthesis(_conversation(60_000, 3, 100), 1500, 1500 - 300.0)

        assert answer == ""
        assert agent.sent == []
        record = _salvage(agent)
        assert record["outcome"] == "not sent"
        assert "the task alone is" in record["detail"]

    def test_an_unmeasured_model_is_sized_by_its_window_alone(self) -> None:
        agent = _Analyst(_Rates(None, None))

        agent._force_final_synthesis(_conversation(1_000, 3, 100), 1500, 1500 - SECONDS_LEFT)

        record = _salvage(agent)
        assert record["sized_by"] == "window"
        assert record["sent_chars"] == record["conversation_chars"]

    def test_a_failed_salvage_says_how_it_ended(self) -> None:
        agent = _Analyst(_Rates(WRITES, READS))

        def _times_out(messages: list, timeout: float) -> str:
            raise TimeoutError("llm:static exceeded hard cap of 423s")

        agent._invoke_llm_with_timeout = _times_out  # type: ignore[method-assign]
        agent._force_final_synthesis(_conversation(1_000, 3, 100), 1500, 1500 - SECONDS_LEFT)

        record = _salvage(agent)
        assert (record["outcome"], record["detail"]) == ("failed", "TimeoutError")


class TestTheSummaryCarriesIt:
    def test_each_loop_s_salvage_is_listed_under_its_agent(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder

        salvage = {"outcome": "answered", "sent_chars": 30_000, "sized_by": "pace"}
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_budget(
                {"static": [{"cap": "time", "salvage": salvage}, {"cap": None, "steps_used": 2}]}
            )
            .build()
            .to_dict()
        )

        assert summary["budget"]["static"]["salvages"] == [salvage]


class _SlowModel:
    """A model whose answer never comes, and which notices when it is abandoned."""

    def __init__(self) -> None:
        self.cancelled = False

    async def ainvoke(self, messages: list, *args: Any, **kwargs: Any) -> AIMessage:
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return AIMessage(content="never")  # pragma: no cover

    def invoke(self, messages: list, *args: Any, **kwargs: Any) -> AIMessage:  # pragma: no cover
        raise AssertionError("the salvage must use the model's own async call")


class _Plain(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def test_a_salvage_that_runs_out_of_time_cancels_its_request() -> None:
    """The request is cancelled at the timeout, not left generating on the server."""
    model = _SlowModel()
    analyst = _Plain(llm=model, name="static")  # type: ignore[arg-type]

    started = time.monotonic()
    with pytest.raises(Exception):  # noqa: B017 — the wait's own timeout, however it is typed
        analyst._invoke_llm_with_timeout([HumanMessage(content="answer")], 0.2)
    deadline = time.monotonic() + 5
    while not model.cancelled and time.monotonic() < deadline:
        time.sleep(0.01)

    assert model.cancelled
    assert time.monotonic() - started < 5
