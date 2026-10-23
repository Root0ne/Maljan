"""The sync stream pump holds a few pieces ahead of its caller, not the whole answer."""

from __future__ import annotations

import gc
import threading
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessageChunk, HumanMessage
from langchain_core.outputs import ChatGenerationChunk

from maljan.llm.generation_rate import with_sized_request_timeout

# Pieces the runaway stream has available; far past any read-ahead.
TOTAL = 5000


class _Runaway(BaseChatModel):
    request_timeout: float = 60.0
    max_tokens: int = 5
    counter: Any = None
    exhausted: Any = None
    closed: Any = None

    @property
    def _llm_type(self) -> str:
        return "runaway"

    def _generate(self, *_: Any, **__: Any) -> Any:
        raise NotImplementedError

    def _stream(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any) -> Any:
        try:
            for _n in range(TOTAL):
                self.counter["read"] += 1
                yield ChatGenerationChunk(message=AIMessageChunk(content="."))
            self.exhausted.set()
        finally:
            self.closed.set()  # the reader let go of the client's iterator


def _stream() -> tuple[Any, dict[str, int], threading.Event, threading.Event]:
    counter = {"read": 0}
    exhausted, closed = threading.Event(), threading.Event()
    model = with_sized_request_timeout(_Runaway)(
        counter=counter, exhausted=exhausted, closed=closed
    )
    return model.stream([HumanMessage(content="hi")]), counter, exhausted, closed


def test_a_runaway_stream_is_not_read_while_nobody_consumes_it() -> None:
    stream, counter, exhausted, closed = _stream()
    next(stream)
    # An unbounded reader would have read all of it by now.
    assert not exhausted.wait(1.0), "the whole stream was read in the background"
    assert counter["read"] < 100
    for _ in range(50):
        next(stream)
    assert counter["read"] >= 51, "reading goes on as the caller consumes"
    stream.close()
    assert closed.wait(5), "closing the stream ends the request"


def test_a_stream_dropped_without_close_is_not_read_on() -> None:
    stream, counter, exhausted, closed = _stream()
    next(stream)
    del stream
    gc.collect()
    assert closed.wait(5), "a collected stream ends the request"
    assert not exhausted.is_set() and counter["read"] < 100
