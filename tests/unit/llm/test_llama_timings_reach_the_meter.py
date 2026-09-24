"""llama.cpp's own reading and generation times reach the job's measured rates.

Every answer from llama.cpp and its forks carries a ``timings`` object beside
OpenAI's fields: ``prompt_n``/``prompt_ms`` for the prompt tokens it read and
``predicted_n``/``predicted_ms`` for the tokens it generated.
``langchain-openai`` builds the answer from OpenAI's fields only, so on the
default provider the prompt reading rate was never recorded (``prompt_tokens``
0, ``prompt_tokens_per_second`` null in every run) and the generation rate was
the wall clock's. The answers are driven here through a real ``ChatOpenAI``
over an in-process HTTP transport, the shape the server sends.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from langchain_core.messages import HumanMessage

from maljan.core.config import Settings
from maljan.llm.generation_rate import (
    LLAMA_CPP_PROMPT_SOURCE,
    LLAMA_CPP_SOURCE,
    GenerationRates,
    attach_rate_meter,
)
from maljan.llm.openai_provider import OpenAIProvider, forget_standard_only, server_timings_of

_TIMINGS = {
    "prompt_n": 10252,
    "prompt_ms": 27207.12,
    "predicted_n": 900,
    "predicted_ms": 22500.0,
}


def _answer(timings: dict[str, Any] | None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": "m",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "done"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10300, "completion_tokens": 900, "total_tokens": 11200},
    }
    if timings is not None:
        body["timings"] = timings
    return body


def _transport(timings: dict[str, Any] | None) -> httpx.MockTransport:
    def _handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(_answer(timings)).encode())

    return httpx.MockTransport(_handle)


def _settings(base_url: str) -> Settings:
    return Settings(
        _env_file=None,
        llm={"openai": {"api_key": "not-a-key", "base_url": base_url, "compat": "standard"}},
    )


@pytest.fixture(autouse=True)
def _forget() -> Any:
    forget_standard_only()
    yield
    forget_standard_only()


def _model(timings: dict[str, Any] | None, *, asynchronous: bool = False) -> Any:
    client_kwargs: dict[str, Any] = {"transport": _transport(timings)}
    extra = (
        {"http_async_client": httpx.AsyncClient(**client_kwargs)}
        if asynchronous
        else {"http_client": httpx.Client(**client_kwargs)}
    )
    return OpenAIProvider(_settings("http://127.0.0.1:8080/v1")).build_model("m", 0.0, **extra)


class TestTheServerTimingsAreKept:
    def test_the_prompt_reading_rate_is_recorded(self) -> None:
        rates = GenerationRates()
        model = attach_rate_meter(_model(_TIMINGS), rates, "m")

        model.invoke([HumanMessage(content="hi")])

        row = rates.snapshot()["models"]["m"]
        assert row["prompt_tokens"] == 10252
        assert row["prompt_seconds"] == pytest.approx(27.207, abs=1e-3)
        assert row["prompt_tokens_per_second"] == pytest.approx(376.81, abs=0.01)
        assert row["prompt_sources"] == [LLAMA_CPP_PROMPT_SOURCE]

    def test_the_generation_rate_is_the_server_s_own(self) -> None:
        rates = GenerationRates()
        model = attach_rate_meter(_model(_TIMINGS), rates, "m")

        model.invoke([HumanMessage(content="hi")])

        assert rates.rate("m") == pytest.approx(40.0)
        assert rates.rate_source("m") == [LLAMA_CPP_SOURCE]

    @pytest.mark.asyncio
    async def test_the_async_path_keeps_them_too(self) -> None:
        rates = GenerationRates()
        model = attach_rate_meter(_model(_TIMINGS, asynchronous=True), rates, "m")

        await model.ainvoke([HumanMessage(content="hi")])

        assert rates.prompt_rate("m") == pytest.approx(376.81, abs=0.01)

    def test_the_answer_itself_is_unchanged(self) -> None:
        answer = _model(_TIMINGS).invoke([HumanMessage(content="hi")])

        assert answer.content == "done"
        assert answer.response_metadata["timings"] == _TIMINGS

    def test_a_server_that_sends_none_records_no_reading_rate(self) -> None:
        rates = GenerationRates()
        model = attach_rate_meter(_model(None), rates, "m")

        answer = model.invoke([HumanMessage(content="hi")])

        assert "timings" not in answer.response_metadata
        assert rates.prompt_rate("m") is None


class TestReadingTheField:
    def test_from_a_plain_dict(self) -> None:
        assert server_timings_of({"timings": {"prompt_n": 1}}) == {"prompt_n": 1}

    def test_absent_or_malformed(self) -> None:
        assert server_timings_of({}) is None
        assert server_timings_of({"timings": "fast"}) is None
        assert server_timings_of(object()) is None
