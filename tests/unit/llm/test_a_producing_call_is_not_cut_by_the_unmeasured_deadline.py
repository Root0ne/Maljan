"""A model call that is still producing is held to its own pace, not to 1800 s.

Until a model's pace is measured, each call's whole-call deadline was the
provider's request timeout, 1800 s. A dense 27B model split between GPU and
RAM generates about 2.3 output units a second with thinking on; its first call
was cut at 1800 s while it was still decoding, and the retry was given the same
1800 s, because a cut call left no measurement behind.

The rule now: before any generated piece arrives, silence is the only fact, and
the provider's request timeout bounds it. Once pieces arrive, the call's own
pieces over its wall clock (prompt read included) are a measured pace, and the
deadline becomes the output cap at that pace by the same arithmetic as a
measured model's. A call that stops producing is cut when that deadline passes,
and its measurement is recorded for the model, so the retry is sized from it.

The calls run on an event loop whose clock jumps to the next timer, so an hour
of a call takes milliseconds and nothing sleeps.
"""

from __future__ import annotations

import asyncio
import math
import threading
from typing import Any

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, AIMessageChunk, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult

from maljan.llm.generation_rate import (
    IN_CALL_SOURCE,
    TIMEOUT_MARGIN,
    WALL_CLOCK_SOURCE,
    GenerationRates,
    ModelCallDeadline,
    attach_rate_meter,
    call_deadline,
    with_sized_request_timeout,
)

from .virtual_time import run, run_expecting

_PACE = 2.3  # output units a second, as the slow local model generated
_CAP = 8192
_CLIENT = 1800.0


class _Slow(BaseChatModel):
    """A model that is silent for ``silent_for`` s, then sends ``pieces`` at ``pace`` a second.

    After ``stall_after`` pieces it sends nothing more, ever. ``streaming``
    routes a call through ``_astream``; without it ``_agenerate`` generates the
    pieces itself and reports each through the run manager, as a client that
    streams internally does (Ollama's).
    """

    request_timeout: float = _CLIENT
    max_tokens: int | None = _CAP
    pace: float = _PACE
    pieces: int = 10
    silent_for: float = 0.0
    stall_after: int | None = None
    streaming: bool = False

    @property
    def _llm_type(self) -> str:
        return "slow"

    async def _pieces(self) -> Any:
        if math.isinf(self.silent_for):
            await asyncio.Event().wait()
        await asyncio.sleep(self.silent_for)
        for index in range(self.pieces):
            if self.stall_after is not None and index >= self.stall_after:
                await asyncio.Event().wait()
            await asyncio.sleep(1.0 / self.pace)
            yield "x"

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any) -> Any:
        raise NotImplementedError

    async def _agenerate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> Any:
        text = ""
        async for piece in self._pieces():
            text += piece
            if run_manager:
                await run_manager.on_llm_new_token(piece)
        message = AIMessage(
            content=text,
            usage_metadata={
                "input_tokens": 10,
                "output_tokens": len(text),
                "total_tokens": 10 + len(text),
            },
        )
        return ChatResult(generations=[ChatGeneration(message=message)])

    async def _astream(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> Any:
        async for piece in self._pieces():
            yield ChatGenerationChunk(message=AIMessageChunk(content=piece))


def _model(**fields: Any) -> Any:
    return with_sized_request_timeout(_Slow)(**fields)


def _ask(model: Any) -> Any:
    return model.ainvoke([HumanMessage(content="hi")])


# The deadline a call producing steadily at 2.3 a second is given for its cap.
_AT_PACE = _CAP / _PACE * TIMEOUT_MARGIN


class TestASlowSteadyModelIsNotCut:
    @pytest.mark.parametrize("streaming", [True, False], ids=["streamed", "streamed-inside"])
    def test_it_answers_past_1800_s(self, streaming: bool) -> None:
        # 5,000 pieces at 2.3 a second: about 2,174 s, well inside its cap.
        answer, took = run(_ask(_model(pieces=5000, streaming=streaming)))

        assert took > _CLIENT
        assert took == pytest.approx(5000 / _PACE)
        assert answer.content == "x" * 5000

    def test_its_answer_is_measured_once_as_a_completed_call_s(self) -> None:
        rates = GenerationRates()
        model = attach_rate_meter(_model(pieces=5000), rates, "slow")

        run(_ask(model))

        row = rates.snapshot()["models"]["slow"]
        assert row["calls"] == 1
        assert row["sources"] == [WALL_CLOCK_SOURCE]


class TestASilentModelIsCutAtTheSilenceBound:
    @pytest.mark.parametrize("streaming", [True, False], ids=["streamed", "streamed-inside"])
    def test_nothing_ever_arrives(self, streaming: bool) -> None:
        exc, took = run_expecting(
            ModelCallDeadline, _ask(_model(silent_for=math.inf, streaming=streaming))
        )

        assert took == pytest.approx(_CLIENT)
        assert "silence before the first generated piece" in str(exc)
        assert "1800 s" in str(exc)

    def test_a_first_piece_after_the_bound_is_too_late(self) -> None:
        _exc, took = run_expecting(ModelCallDeadline, _ask(_model(silent_for=_CLIENT + 5)))

        assert took == pytest.approx(_CLIENT)

    def test_a_silent_call_records_no_pace(self) -> None:
        rates = GenerationRates()
        model = attach_rate_meter(_model(silent_for=math.inf), rates, "slow")

        run_expecting(ModelCallDeadline, _ask(model))

        assert rates.rate("slow") is None


class TestAModelThatStallsIsCutByItsMeasuredDeadline:
    @pytest.mark.parametrize("streaming", [True, False], ids=["streamed", "streamed-inside"])
    def test_the_cut_comes_at_its_cap_at_the_pace_it_showed(self, streaming: bool) -> None:
        # 100 pieces at 2.3 a second, then nothing: the pace this call showed
        # sizes its cap at about 5,343 s, and that is when it is cut.
        exc, took = run_expecting(
            ModelCallDeadline, _ask(_model(pieces=5000, stall_after=100, streaming=streaming))
        )

        assert took == pytest.approx(_AT_PACE, rel=1e-6)
        said = str(exc)
        assert "pace measured in this call" in said
        assert "100 generated pieces" in said
        assert f"{_CAP} output units" in said

    def test_the_stalled_call_s_pace_is_recorded_for_the_model(self) -> None:
        rates = GenerationRates()
        model = attach_rate_meter(_model(pieces=5000, stall_after=100), rates, "slow")

        run_expecting(ModelCallDeadline, _ask(model))

        assert rates.rate("slow") == pytest.approx(_PACE)
        assert rates.rate_source("slow") == [IN_CALL_SOURCE]

    def test_a_call_with_no_output_cap_has_nothing_to_size_and_keeps_the_timeout(self) -> None:
        exc, took = run_expecting(
            ModelCallDeadline, _ask(_model(pieces=5000, stall_after=100, max_tokens=None))
        )

        assert took == pytest.approx(_CLIENT)
        assert "no output cap" in str(exc)


class TestAfterACutTheRetryIsSizedFromTheMeasurement:
    def test_the_retry_gets_the_cap_at_the_measured_pace(self) -> None:
        rates = GenerationRates()
        model = attach_rate_meter(_model(pieces=5000, stall_after=100), rates, "slow")
        run_expecting(ModelCallDeadline, _ask(model))

        retry = attach_rate_meter(_model(silent_for=math.inf), rates, "slow")
        # The whole-call deadline is the cap at the recorded pace, before any
        # piece of the retry has arrived.
        assert call_deadline(retry, [], {}) == pytest.approx(_AT_PACE, rel=1e-6)
        exc, took = run_expecting(ModelCallDeadline, _ask(retry))

        assert took == pytest.approx(_AT_PACE, rel=1e-6)
        assert "the model's measured pace" in str(exc)

    def test_a_call_ended_from_outside_is_recorded_too(self) -> None:
        # The analyst's own loop budget ends the call before its deadline: the
        # pieces it produced are a measurement all the same.
        rates = GenerationRates()
        model = attach_rate_meter(_model(pieces=5000), rates, "slow")

        async def main() -> Any:
            return await asyncio.wait_for(_ask(model), 600.0)

        run_expecting(TimeoutError, main())

        assert rates.rate("slow") == pytest.approx(_PACE, rel=1e-2)


class TestAFastHostedModelIsUnchanged:
    def test_a_quick_answer_is_the_answer(self) -> None:
        answer, took = run(_ask(_model(pieces=40, pace=80.0, streaming=True)))

        assert answer.content == "x" * 40
        assert took == pytest.approx(0.5)

    def test_a_measured_fast_model_keeps_the_provider_timeout(self) -> None:
        rates = GenerationRates()
        rates.observe("fast", 800, 10.0, "server")
        model = attach_rate_meter(_model(silent_for=math.inf), rates, "fast")

        # 8,192 at 80 a second is 154 s: the provider's timeout is longer.
        assert call_deadline(model, [], {}) == _CLIENT
        exc, took = run_expecting(ModelCallDeadline, _ask(model))

        assert took == pytest.approx(_CLIENT)
        assert "silence before the first generated piece" in str(exc)

    def test_a_fast_stream_that_stalls_is_cut_at_the_provider_timeout(self) -> None:
        # 20 pieces at 80 a second, then nothing: its cap at that pace is
        # 154 s, shorter than the provider's timeout, which stands.
        exc, took = run_expecting(
            ModelCallDeadline, _ask(_model(pieces=40, pace=80.0, stall_after=20))
        )

        assert took == pytest.approx(_CLIENT)
        assert "the provider's request timeout" in str(exc)
        assert "silence before the first generated piece" not in str(exc)


class _ThroughItsStream(_Slow):
    """A client whose ``_agenerate`` reads its own ``_astream`` and reports each piece too."""

    async def _agenerate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> Any:
        text = ""
        async for chunk in self._astream(messages, stop=stop, run_manager=run_manager):
            text += str(chunk.message.content)
            if run_manager:
                await run_manager.on_llm_new_token(chunk.message.content, chunk=chunk)
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=text))])


class TestAClientThatStreamsThroughItself:
    def test_each_piece_is_counted_once(self) -> None:
        model = with_sized_request_timeout(_ThroughItsStream)(pieces=5000, stall_after=100)

        exc, took = run_expecting(ModelCallDeadline, _ask(model))

        assert "100 generated pieces" in str(exc)
        assert took == pytest.approx(_AT_PACE, rel=1e-6)


class _SyncStream(BaseChatModel):
    """A synchronous stream: ``pieces`` pieces at once, or nothing ever."""

    request_timeout: float = _CLIENT
    max_tokens: int | None = _CAP
    pieces: int = 3
    silent: bool = False
    streaming: bool = False

    @property
    def _llm_type(self) -> str:
        return "sync-stream"

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any) -> Any:
        raise NotImplementedError

    def _stream(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any) -> Any:
        if self.silent:
            threading.Event().wait()
        for _index in range(self.pieces):
            yield ChatGenerationChunk(message=AIMessageChunk(content="y"))


class TestTheSynchronousStreamIsHeldToo:
    def test_its_answer_is_the_answer(self) -> None:
        model = with_sized_request_timeout(_SyncStream)(streaming=True)

        answer = model.invoke([HumanMessage(content="hi")])

        assert answer.content == "yyy"

    def test_a_silent_one_is_cut_at_the_silence_bound(self) -> None:
        model = with_sized_request_timeout(_SyncStream)(
            streaming=True, silent=True, request_timeout=0.05
        )

        with pytest.raises(ModelCallDeadline, match="silence before the first generated piece"):
            model.invoke([HumanMessage(content="hi")])
