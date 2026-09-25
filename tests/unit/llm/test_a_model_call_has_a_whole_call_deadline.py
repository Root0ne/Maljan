"""Every model request has a whole-call deadline Maljan enforces itself.

httpx reads a request timeout as the longest silence it waits through. A
server that trickles bytes — keep-alive lines while a request is queued, or a
slow steady answer — is never silent that long, so with no loop clock of its
own a call was held by nothing but the job timeout. Each request is now held
to its sized request timeout as a whole (the output cap at the model's measured
pace, or the client's own timeout where nothing is measured).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, AIMessageChunk, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult

from maljan.llm.generation_rate import ModelCallDeadline, call_deadline, with_sized_request_timeout


class _Trickling(BaseChatModel):
    """Sends a piece every few milliseconds and never finishes before ``finishes_after``."""

    request_timeout: float = 0.3
    finishes_after: float = 30.0

    @property
    def _llm_type(self) -> str:
        return "trickling"

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any) -> Any:
        time.sleep(self.finishes_after)
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="late"))])

    async def _agenerate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> Any:
        started = time.monotonic()
        while time.monotonic() - started < self.finishes_after:
            await asyncio.sleep(0.01)  # a byte, and another
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="late"))])

    async def _astream(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> Any:
        started = time.monotonic()
        while time.monotonic() - started < self.finishes_after:
            await asyncio.sleep(0.01)
            yield ChatGenerationChunk(message=AIMessageChunk(content="."))


def _model(**kwargs: Any) -> Any:
    return with_sized_request_timeout(_Trickling)(**kwargs)


class TestTheWholeCallIsBounded:
    def test_an_async_call_that_trickles_ends_at_its_deadline(self) -> None:
        started = time.monotonic()
        with pytest.raises(ModelCallDeadline):
            asyncio.run(_model().ainvoke([HumanMessage(content="hi")]))
        assert time.monotonic() - started < 5

    def test_a_streamed_call_that_trickles_ends_at_its_deadline(self) -> None:
        async def main() -> None:
            async for _chunk in _model().astream([HumanMessage(content="hi")]):
                pass

        started = time.monotonic()
        with pytest.raises(ModelCallDeadline):
            asyncio.run(main())
        assert time.monotonic() - started < 5

    def test_a_sync_call_ends_at_its_deadline(self) -> None:
        started = time.monotonic()
        with pytest.raises(ModelCallDeadline):
            _model(finishes_after=3.0).invoke([HumanMessage(content="hi")])
        assert time.monotonic() - started < 2.5

    def test_a_call_that_finishes_in_time_is_its_answer(self) -> None:
        answer = asyncio.run(
            _model(request_timeout=5.0, finishes_after=0.05).ainvoke([HumanMessage(content="hi")])
        )
        assert answer.content == "late"

    def test_the_deadline_is_a_timeout_a_model_list_moves_on_from(self) -> None:
        from maljan.llm.fallback import provider_failure

        assert provider_failure(ModelCallDeadline("x")) == "the provider timed out"

    def test_with_nothing_measured_the_deadline_is_the_client_s_own(self) -> None:
        assert call_deadline(_Trickling(request_timeout=42.0), [], {}) == 42.0
