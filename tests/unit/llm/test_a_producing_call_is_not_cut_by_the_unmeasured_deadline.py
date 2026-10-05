"""A model call that is still producing is held to its own pace, not to 1800 s.

Until a model's pace is measured, each call's whole-call deadline was the
provider's request timeout, 1800 s. A dense 27B model split between GPU and
RAM generates about 2.3 output units a second with thinking on; its first call
was cut at 1800 s while it was still decoding, and the retry was given the same
1800 s, because a cut call left no measurement behind.

The rule now: before any generated piece arrives, silence is the only fact, and
the provider's request timeout bounds it. Once two pieces arrive, the call's
pace from its first piece to its last is measured, and the deadline becomes the
time to the first piece and the output cap at that pace, by the same arithmetic
as a measured model's. A call with no output cap is sized from the room its
model's window leaves after the prompt. A call that stops producing is cut when
that deadline passes, and its pace is recorded for the model, so the retry is
sized from it. Where nothing can be sized, a producing call is held only to the
silence after its last piece. The prompt read is never counted as generating,
and a call with a single piece records nothing.

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
    # A chunk naming only the role, sent when the silence ends, as llama.cpp's first.
    opening: bool = False

    @property
    def _llm_type(self) -> str:
        return "slow"

    async def _pieces(self) -> Any:
        if math.isinf(self.silent_for):
            await asyncio.Event().wait()
        await asyncio.sleep(self.silent_for)
        if self.opening:
            yield ""
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


# The deadline a model measured at 2.3 a second is given for its cap.
_AT_PACE = _CAP / _PACE * TIMEOUT_MARGIN
# The deadline a call sets itself by producing at 2.3 a second: its first piece
# 1 / 2.3 s in, then its cap at that pace, times the margin.
_STALL_CUT = (1 / _PACE + _CAP / _PACE) * TIMEOUT_MARGIN


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

        assert took == pytest.approx(_STALL_CUT, rel=1e-6)
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


class TestACallWithNoOutputCap:
    def test_with_no_known_window_it_is_held_to_the_silence_after_its_last_piece(
        self,
    ) -> None:
        exc, took = run_expecting(
            ModelCallDeadline, _ask(_model(pieces=5000, stall_after=100, max_tokens=None))
        )

        assert took == pytest.approx(100 / _PACE + _CLIENT)
        said = str(exc)
        assert "silence after the last generated piece" in said
        assert "no output cap" in said

    def test_with_no_known_window_a_steady_producer_is_not_cut(self) -> None:
        answer, took = run(_ask(_model(pieces=5000, max_tokens=None)))

        assert took == pytest.approx(5000 / _PACE)
        assert answer.content == "x" * 5000

    def test_with_a_known_window_it_is_sized_from_the_room_the_window_leaves(self) -> None:
        from maljan.llm.context_window import PROBED, WindowFact, record_built_window

        model = record_built_window(
            _model(pieces=5000, stall_after=100, max_tokens=None),
            WindowFact(32768, PROBED, "the server said so"),
        )

        exc, took = run_expecting(ModelCallDeadline, _ask(model))

        room = 32768 - 1  # "hi" is one unit at three characters a unit
        assert took == pytest.approx((1 / _PACE + room / _PACE) * TIMEOUT_MARGIN, rel=1e-6)
        assert "about 32767 output units, the room its model's 32768-unit window" in str(exc)


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

        assert rates.rate("slow") == pytest.approx(_PACE, rel=1e-6)

    def test_a_call_ended_behind_a_long_prompt_read_records_its_generation_pace(self) -> None:
        # 1,500 s of prompt read, then 100 s of generating at 2.3 a second,
        # ended from outside: the pace is 2.3 a second, not 230 over 1,600 s.
        rates = GenerationRates()
        model = attach_rate_meter(_model(pieces=5000, silent_for=1500.0), rates, "slow")

        async def main() -> Any:
            return await asyncio.wait_for(_ask(model), 1600.0)

        run_expecting(TimeoutError, main())

        assert rates.rate("slow") == pytest.approx(_PACE, rel=1e-6)


class TestACallTooShortToMeasureRecordsNothing:
    """1,500 s of prompt read, one piece, then silence: one piece is not a pace."""

    @pytest.mark.parametrize(
        ("opening", "pieces", "ends_at", "rule"),
        [
            (True, 0, _CLIENT, "silence before the first generated piece"),
            (False, 1, 1500 + 1 / _PACE + _CLIENT, "silence after the last generated piece"),
        ],
        ids=["a-role-chunk", "one-generated-piece"],
    )
    def test_the_next_call_keeps_the_bound_it_had(
        self, opening: bool, pieces: int, ends_at: float, rule: str
    ) -> None:
        rates = GenerationRates()
        model = attach_rate_meter(
            _model(
                pieces=5000,
                stall_after=pieces,
                silent_for=1500.0,
                opening=opening,
                streaming=True,
            ),
            rates,
            "slow",
        )

        exc, took = run_expecting(ModelCallDeadline, _ask(model))

        assert took == pytest.approx(ends_at)
        assert rule in str(exc)
        assert rates.rate("slow") is None
        retry = attach_rate_meter(_model(silent_for=math.inf), rates, "slow")
        assert call_deadline(retry, [], {}) == _CLIENT
        _exc, took = run_expecting(ModelCallDeadline, _ask(retry))
        assert took == pytest.approx(_CLIENT)


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
        assert took == pytest.approx(_STALL_CUT, rel=1e-6)


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

    def test_its_reader_stops_when_the_caller_is_done(self) -> None:
        # The client's iterator runs in a reader thread. Once the caller stops
        # reading, the reader closes it at its next piece, which ends the
        # request, rather than reading the rest of the answer.
        closed = threading.Event()
        next_piece = threading.Event()

        class _Endless(_SyncStream):
            def _stream(
                self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
            ) -> Any:
                try:
                    while True:
                        yield ChatGenerationChunk(message=AIMessageChunk(content="y"))
                        next_piece.wait()
                finally:
                    closed.set()

        model = with_sized_request_timeout(_Endless)(streaming=True)
        for _chunk in model.stream([HumanMessage(content="hi")]):
            break
        next_piece.set()

        assert closed.wait(timeout=5.0)


def _registry_settings(**openai: Any) -> Any:
    from maljan.core.config import Settings

    return Settings(
        _env_file=None,
        llm={
            "provider": "openai",
            "expert_model": "no-such-model-in-any-table",
            "openai": {"api_key": "not-a-key", "base_url": "http://127.0.0.1:8080/v1", **openai},
        },
    )


class TestTheBuiltModelCarriesItsKnownWindow:
    def test_the_registry_records_the_declared_window(self) -> None:
        from maljan.llm.context_window import built_window, forget_learned_windows
        from maljan.llm.registry import LLMProviderRegistry

        forget_learned_windows()
        model = LLMProviderRegistry(_registry_settings(context_size=16384)).build_model()

        fact = built_window(model)
        assert fact is not None
        assert fact.tokens == 16384

    def test_no_window_is_recorded_where_none_is_declared_or_probed(self) -> None:
        from maljan.llm.context_window import built_window, forget_learned_windows
        from maljan.llm.registry import LLMProviderRegistry

        forget_learned_windows()
        model = LLMProviderRegistry(_registry_settings()).build_model()

        assert built_window(model) is None


class _OllamaShaped(_Slow):
    """Streams inside ``_agenerate`` as Ollama's client does, and its transport times out.

    Reads its prompt for 60 s, sends ``pieces`` at 2.3 a second through the
    run manager, then is silent until the client's own read timeout ends the
    request (``httpx.ReadTimeout``), ``timeout_after`` seconds later.
    """

    timeout_after: float = _CLIENT

    async def _agenerate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> Any:
        import httpx

        await asyncio.sleep(60.0)
        for _index in range(self.pieces):
            await asyncio.sleep(1.0 / self.pace)
            if run_manager:
                await run_manager.on_llm_new_token("x")
        await asyncio.sleep(self.timeout_after)
        raise httpx.ReadTimeout("no data within the read timeout")

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any) -> Any:
        import httpx

        for _index in range(self.pieces):
            if run_manager:
                run_manager.on_llm_new_token("x")
        raise httpx.ReadTimeout("no data within the read timeout")


class TestAClientThatStreamsInsideItsCallAndTimesOut:
    def test_a_stall_after_pieces_ends_as_the_call_deadline(self) -> None:
        rates = GenerationRates()
        model = attach_rate_meter(
            with_sized_request_timeout(_OllamaShaped)(pieces=100), rates, "ollama"
        )

        exc, took = run_expecting(ModelCallDeadline, _ask(model))

        # A call deadline, so the loop salvages what it gathered; it ends when
        # the transport's silence bound after the last piece does, well inside
        # the deadline the call's own pace set, which is still the one sized.
        last = 60.0 + 100 / _PACE
        assert took == pytest.approx(last + _CLIENT)
        assert isinstance(exc, TimeoutError)
        said = str(exc)
        assert "silence after its last generated piece" in said
        assert "after piece 100" in said
        in_call = (60.0 + 1 / _PACE + _CAP / _PACE) * TIMEOUT_MARGIN
        assert took < in_call
        assert rates.rate("ollama") == pytest.approx(_PACE)

    def test_a_timeout_before_any_piece_is_raised_as_it_came(self) -> None:
        import httpx

        # The read timeout comes before the call's own silence bound: the
        # transport's error, as it came, as on dev.
        model = with_sized_request_timeout(_OllamaShaped)(pieces=0, timeout_after=100.0)

        exc, _took = run_expecting(httpx.ReadTimeout, _ask(model))

        assert not isinstance(exc, ModelCallDeadline)

    def test_the_synchronous_call_follows_the_same_rule(self) -> None:
        import httpx

        after = with_sized_request_timeout(_OllamaShaped)(pieces=3)
        before = with_sized_request_timeout(_OllamaShaped)(pieces=0)

        with pytest.raises(ModelCallDeadline, match="silence after its last generated piece"):
            after.invoke([HumanMessage(content="hi")])
        with pytest.raises(httpx.ReadTimeout):
            before.invoke([HumanMessage(content="hi")])
