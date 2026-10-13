"""Every retry is a row of the run summary, and every failed attempt is charged as billed.

A retry used to be written only on the answer that followed it, so the retries
of a call that was then lost (the analyst the change exists to save), or handed
to the next model of a list, were never counted. The job now attaches a
recorder to each model it builds; a retry is a row of the job's token ledger
the moment it is decided. A model built outside a job keeps its retries on the
answer, or on the error given up on, and the analyst records those when it
loses the call.

A failed attempt is charged to the spend ceiling as a provider bills it: a
failure before any of the answer arrived generated nothing and costs nothing;
a failure after pieces streamed costs the usage the error carries, or a stated
estimate of the prompt and the pieces.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from unittest.mock import MagicMock

import anthropic
import httpx
import openai
import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool

from maljan.agents.base_agent import BaseAnalyst
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.core.config import Settings
from maljan.core.exceptions import AnalystError
from maljan.core.token_ledger import TokenLedger
from maljan.llm.fallback import FallbackChatModel
from maljan.llm.generation_rate import note_pieces
from maljan.llm.transient import (
    FAILED_ATTEMPT_CALL,
    PIECES_ATTRIBUTE,
    RETRIES_KEY,
    attach_retry_recorder,
    retries_of,
    retry_on_connection_error,
    with_transient_retries,
)

from .anthropic_wire import message, streamed

USAGE = {"input_tokens": 3, "output_tokens": 1, "total_tokens": 4}
_REQUEST = httpx.Request("POST", "http://127.0.0.1:8080/v1")


def _status(status: int) -> Exception:
    response = httpx.Response(status, request=_REQUEST)
    return openai.APIStatusError(f"Error code: {status}", response=response, body=None)


def _streamed_then_failed(pieces: int, body: Any = None) -> Exception:
    failure = anthropic.APIStatusError(
        "Error code: 200", response=httpx.Response(200, request=_REQUEST), body=body
    )
    note_pieces(failure, pieces)
    return failure


@pytest.fixture(autouse=True)
def _no_real_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _instant)
    monkeypatch.setattr("maljan.llm.transient.time.sleep", lambda _s: None)


class _Spend:
    """A spend meter that keeps what it was asked to settle."""

    def __init__(self) -> None:
        self.settled: list[tuple[Any, str, str, Any]] = []

    def settle(self, usage: Any, model: str, call: str = "", *, estimated: Any = None) -> None:
        self.settled.append((usage, model, call, estimated))

    def failed_attempts(self) -> list[tuple[Any, str, str, Any]]:
        return [row for row in self.settled if row[2] == FAILED_ATTEMPT_CALL]


class _Scripted(BaseChatModel):
    """Answers from a script: ``"tool"`` calls ``peek``, a string answers, an exception raises."""

    script: list[Any] = []
    asked: list[int] = []
    model_name: str = "scripted"

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any):
        self.asked.append(1)
        step = self.script.pop(0) if self.script else "CLAIM: x\nEVIDENCE: ev_0001"
        if isinstance(step, BaseException):
            raise step
        if step == "tool":
            n = len(self.asked)
            answer = AIMessage(
                content="",
                tool_calls=[{"name": "peek", "args": {"n": n}, "id": f"c{n}"}],
                usage_metadata=dict(USAGE),
            )
        else:
            answer = AIMessage(content=step, usage_metadata=dict(USAGE))
        return ChatResult(generations=[ChatGeneration(message=answer)])


_Retrying = with_transient_retries(_Scripted)


def _model(script: list[Any], name: str = "scripted") -> Any:
    return _Retrying(script=list(script), asked=[], model_name=name)


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *a: Any, **k: Any) -> str:  # pragma: no cover - unused
        return ""


def _peek(n: int) -> str:
    """Peek."""
    return f"bytes {n}"


def _analyst(llm: Any, ledger: TokenLedger) -> _Analyst:
    tool = StructuredTool.from_function(func=_peek, name="peek", description="p")
    agent = _Analyst(llm=llm, name="static", tools=[tool])
    agent.token_ledger = ledger
    agent._container = MagicMock()
    agent._model_label = lambda: "openai/static-model"
    return agent


def _rows(ledger: TokenLedger) -> list[dict[str, str]]:
    return list(ledger.snapshot().get("retries") or [])


def _summary_text(ledger: TokenLedger) -> str:
    builder = RunSummaryBuilder(0.0)
    builder.set_token_usage(ledger.snapshot())
    return builder.build().to_markdown()


class TestALostCallIsCounted:
    def test_with_the_job_s_recorder(self) -> None:
        ledger = TokenLedger()
        llm = attach_retry_recorder(_model([_status(503)] * 3), ledger, "static")

        with pytest.raises(AnalystError):
            _analyst(llm, ledger).execute_tool_loop([("system", "s"), ("human", "h")])

        rows = _rows(ledger)
        assert len(rows) == 2, "the two retries the lost call made"
        assert {row["agent"] for row in rows} == {"static"}
        assert "2 model requests failed at the provider" in _summary_text(ledger)

    def test_without_one_the_analyst_records_them_when_it_loses_the_call(self) -> None:
        ledger = TokenLedger()
        llm = _model([_status(503)] * 3)

        with pytest.raises(AnalystError):
            _analyst(llm, ledger).execute_tool_loop([("system", "s"), ("human", "h")])

        assert len(_rows(ledger)) == 2

    def test_an_answered_call_s_retries_are_counted_once(self) -> None:
        ledger = TokenLedger()
        llm = attach_retry_recorder(
            _model([_status(503), "CLAIM: x\nEVIDENCE: ev_0001"]), ledger, "static"
        )

        _analyst(llm, ledger).execute_tool_loop([("system", "s"), ("human", "h")])

        assert len(_rows(ledger)) == 1


class TestACallHandedToTheNextModelIsCounted:
    @pytest.mark.asyncio
    async def test_with_the_job_s_recorder(self) -> None:
        ledger = TokenLedger()
        first, second = _model([_status(503)] * 3, "one"), _model(["from the second"], "two")
        models = FallbackChatModel(models=[first, second], labels=["a/one", "b/two"], agent="x")
        attach_retry_recorder(models, ledger, "static")

        answer = await models.ainvoke("hi")

        assert answer.content == "from the second"
        assert [row["model"] for row in _rows(ledger)] == ["one", "one"]
        assert not retries_of(answer), "counted once, by the recorder"

    @pytest.mark.asyncio
    async def test_without_one_the_answer_that_came_carries_them(self) -> None:
        first, second = _model([_status(503)] * 3, "one"), _model(["from the second"], "two")
        models = FallbackChatModel(models=[first, second], labels=["a/one", "b/two"], agent="x")

        answer = await models.ainvoke("hi")

        assert len(answer.response_metadata[RETRIES_KEY]) == 2


class TestAPolicyAroundTheModelWritesThroughItsRecorder:
    @pytest.mark.asyncio
    async def test_the_judge_s_retry_is_a_row_once(self) -> None:
        ledger = TokenLedger()
        llm = attach_retry_recorder(_model([_status(503), _status(503), "fine"]), ledger, "judge")

        answer = await retry_on_connection_error(lambda: llm.ainvoke("hi"), what="Judge verdict")

        assert answer.content == "fine"
        assert len(llm.asked) == 3
        rows = _rows(ledger)
        assert [row["agent"] for row in rows] == ["judge", "judge"]
        assert all(row["reason"].startswith("Judge verdict") for row in rows)
        assert not retries_of(answer)

    @pytest.mark.asyncio
    async def test_a_lost_judge_call_is_counted_too(self) -> None:
        ledger = TokenLedger()
        llm = attach_retry_recorder(_model([_status(503)] * 3), ledger, "judge")

        with pytest.raises(openai.APIStatusError):
            await retry_on_connection_error(lambda: llm.ainvoke("hi"), what="Judge verdict")

        assert len(_rows(ledger)) == 2


class TestAFailedAttemptIsChargedAsBilled:
    @pytest.mark.asyncio
    async def test_a_failure_before_any_piece_is_charged_nothing(self) -> None:
        spend = _Spend()
        ledger = TokenLedger(spend=spend)
        llm = attach_retry_recorder(_model([_status(503), "fine"]), ledger, "static")

        await llm.ainvoke("hi")

        assert spend.failed_attempts() == []

    @pytest.mark.asyncio
    async def test_a_failure_after_pieces_is_charged_a_stated_estimate(self) -> None:
        spend = _Spend()
        ledger = TokenLedger(spend=spend)
        llm = attach_retry_recorder(
            _model([_streamed_then_failed(12, {"type": "error", "error": {"type": "api_error"}})]),
            ledger,
            "static",
        )
        llm.script.append("fine")

        await llm.ainvoke("x" * 400)

        ((usage, model, _call, estimated),) = spend.failed_attempts()
        assert usage is None
        assert model == "scripted"
        assert estimated["output_tokens"] == 12
        assert estimated["input_tokens"] > 0
        assert "estimated" in estimated["source"]

    @pytest.mark.asyncio
    async def test_the_usage_an_error_carries_is_charged_as_reported(self) -> None:
        spend = _Spend()
        ledger = TokenLedger(spend=spend)
        body = {
            "type": "error",
            "error": {"type": "overloaded_error"},
            "usage": {"input_tokens": 50, "output_tokens": 7},
        }
        llm = attach_retry_recorder(
            _model([_streamed_then_failed(3, body), "fine"]), ledger, "static"
        )

        await llm.ainvoke("hi")

        ((usage, _model_name, _call, estimated),) = spend.failed_attempts()
        assert usage == {"input_tokens": 50, "output_tokens": 7}
        assert estimated is None

    @pytest.mark.asyncio
    async def test_the_last_attempt_of_a_lost_call_is_charged_too(self) -> None:
        spend = _Spend()
        ledger = TokenLedger(spend=spend)
        failures = [_streamed_then_failed(5, {"error": {"type": "api_error"}}) for _ in range(3)]
        llm = attach_retry_recorder(_model(failures), ledger, "static")

        with pytest.raises(anthropic.APIStatusError):
            await llm.ainvoke("hi")

        assert len(spend.failed_attempts()) == 3


class TestTheyReachThePerCallRecord:
    """The worker commits every record ``on_call`` hands it, so a killed worker keeps them."""

    @pytest.mark.asyncio
    async def test_a_retry_and_a_failed_attempt_s_estimate_are_records(self) -> None:
        records: list[dict[str, Any]] = []
        ledger = TokenLedger(spend=_Spend())
        ledger.on_call = records.append
        failure = _streamed_then_failed(9, {"type": "error", "error": {"type": "api_error"}})
        llm = attach_retry_recorder(_model([failure, "fine"]), ledger, "static")

        await llm.ainvoke("x" * 400)

        calls = [row["call"] for row in records]
        assert calls == [FAILED_ATTEMPT_CALL, "retry"]
        failed, retry = records
        assert failed["agent"] == "static" and failed["reported"] is False
        assert failed["estimated"]["output_tokens"] == 9
        assert failed["estimated"]["input_tokens"] > 0
        assert retry["agent"] == "static" and retry["reason"]

    @pytest.mark.asyncio
    async def test_the_usage_an_error_carries_is_a_reported_record(self) -> None:
        records: list[dict[str, Any]] = []
        ledger = TokenLedger(spend=_Spend())
        ledger.on_call = records.append
        body = {
            "error": {"type": "overloaded_error"},
            "usage": {"input_tokens": 50, "output_tokens": 7},
        }
        llm = attach_retry_recorder(
            _model([_streamed_then_failed(3, body), "fine"]), ledger, "static"
        )

        await llm.ainvoke("hi")

        (failed,) = [row for row in records if row["call"] == FAILED_ATTEMPT_CALL]
        assert failed["reported"] is True
        assert (failed["input_tokens"], failed["output_tokens"]) == (50, 7)
        assert "estimated" not in failed

    @pytest.mark.asyncio
    async def test_with_no_spend_ceiling_the_records_are_still_kept(self) -> None:
        records: list[dict[str, Any]] = []
        ledger = TokenLedger()
        ledger.on_call = records.append
        failure = _streamed_then_failed(4, {"error": {"type": "api_error"}})
        llm = attach_retry_recorder(_model([failure, "fine"]), ledger, "static")

        await llm.ainvoke("hi")

        assert [row["call"] for row in records] == [FAILED_ATTEMPT_CALL, "retry"]

    def test_a_record_of_a_failed_attempt_moves_no_call_count(self) -> None:
        ledger = TokenLedger()
        ledger.charge_failed_attempt(
            {"input_tokens": 5, "output_tokens": 1}, agent="static", model="m", call="x"
        )
        ledger.add_retry(agent="static", model="m", reason="r")
        assert ledger.calls == 0


# ---------------------------------------------------------------------------
# On the wire: the pieces an Anthropic stream carried before its error event


class _Scripts(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # noqa: D102 — quiet
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length") or 0)
        if length:
            self.rfile.read(length)
        script: list[bytes] = self.server.script  # type: ignore[attr-defined]
        data = script.pop(0)
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def server() -> Iterator[ThreadingHTTPServer]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Scripts)
    httpd.daemon_threads = True
    httpd.script = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(10)


def _event(kind: str, data: dict[str, Any]) -> str:
    return f"event: {kind}\ndata: {json.dumps({'type': kind, **data})}\n\n"


def _answer(text: str) -> dict[str, Any]:
    return message(
        [{"type": "text", "text": text}],
        stop="end_turn",
        usage={"input_tokens": 3, "output_tokens": 1},
    )


WORDS = ("CLAIM:", " it", " reads", " the")


def _text_then_overloaded(
    usage: dict[str, Any] | None = None,
    *,
    words: tuple[str, ...] = WORDS,
    closing_output: int | None = None,
) -> bytes:
    opening = {**_answer(""), "content": [], "stop_reason": None}
    if usage is not None:
        opening["usage"] = usage
    parts = [
        _event("message_start", {"message": opening}),
        _event("content_block_start", {"index": 0, "content_block": {"type": "text", "text": ""}}),
    ]
    for word in words:
        parts.append(
            _event(
                "content_block_delta",
                {"index": 0, "delta": {"type": "text_delta", "text": word}},
            )
        )
    if closing_output is not None:
        parts.append(
            _event(
                "message_delta",
                {
                    "delta": {"stop_reason": None, "stop_sequence": None},
                    "usage": {"output_tokens": closing_output},
                },
            )
        )
    error = {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}
    parts.append(f"event: error\ndata: {json.dumps(error)}\n\n")
    return "".join(parts).encode()


def _broken_then_answered(server: ThreadingHTTPServer, broken: bytes) -> _Spend:
    from maljan.llm.anthropic_provider import AnthropicProvider

    server.script = [broken, streamed(_answer("answered"))]  # type: ignore[attr-defined]
    host, port = server.server_address[:2]
    settings = Settings(_env_file=None, llm={"anthropic": {"api_key": "test-value"}})
    model = AnthropicProvider(settings).build_model(
        "claude-haiku-5-5", 0.0, base_url=f"http://{host}:{port}", max_tokens=64, streaming=True
    )
    spend = _Spend()
    ledger = TokenLedger(spend=spend)
    attach_retry_recorder(model, ledger, "static")
    answer = asyncio.run(model.ainvoke("hello"))
    assert "answered" in str(answer.content)
    assert len(_rows(ledger)) == 1
    return spend


def test_a_broken_anthropic_stream_is_charged_the_prompt_usage_it_reported(
    server: ThreadingHTTPServer,
) -> None:
    """``message_start`` stated the input; only the output that streamed is estimated."""
    from maljan.core.spend import OUTPUT_ESTIMATED
    from maljan.llm.context_window import CHARS_PER_TOKEN
    from maljan.llm.transient import FAILED_STREAM_OUTPUT_ESTIMATE

    opening = {
        "input_tokens": 40,
        "output_tokens": 1,
        "cache_read_input_tokens": 900,
        "cache_creation_input_tokens": 60,
    }
    spend = _broken_then_answered(server, _text_then_overloaded(opening))
    ((usage, _model_name, _call, estimated),) = spend.failed_attempts()
    assert usage == {
        "input_tokens": 1000,
        "cached_input_tokens": 900,
        "cache_write_input_tokens": 60,
    }
    streamed_chars = len("".join(WORDS))
    assert estimated == {
        "output_tokens": -(-streamed_chars // CHARS_PER_TOKEN),
        "source": FAILED_STREAM_OUTPUT_ESTIMATE,
        OUTPUT_ESTIMATED: True,
    }


def test_a_broken_stream_s_closing_usage_is_its_output(server: ThreadingHTTPServer) -> None:
    spend = _broken_then_answered(
        server, _text_then_overloaded({"input_tokens": 40, "output_tokens": 1}, closing_output=12)
    )
    ((usage, _model_name, _call, estimated),) = spend.failed_attempts()
    assert usage == {"input_tokens": 40, "output_tokens": 12}
    assert estimated is None


def test_a_stream_broken_before_its_answer_is_charged_its_prompt_alone(
    server: ThreadingHTTPServer,
) -> None:
    spend = _broken_then_answered(
        server, _text_then_overloaded({"input_tokens": 40, "output_tokens": 1}, words=())
    )
    ((usage, _model_name, _call, estimated),) = spend.failed_attempts()
    assert usage == {"input_tokens": 40, "output_tokens": 0}
    assert estimated is None


def test_an_output_estimate_is_priced_beside_the_reported_prompt() -> None:
    """The record says which part is estimated, and only that part counts as estimated."""
    from maljan.core.spend import OUTPUT_ESTIMATED, SpendMeter

    prices = {"m1": {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 4.0}}
    meter = SpendMeter(None, prices)
    ledger = TokenLedger(spend=meter)
    heard: list[dict[str, Any]] = []
    ledger.on_call = heard.append
    ledger.charge_failed_attempt(
        {"input_tokens": 1_000_000},
        agent="static",
        model="m1",
        call=FAILED_ATTEMPT_CALL,
        estimated={"output_tokens": 500_000, "source": "streamed", OUTPUT_ESTIMATED: True},
    )
    (row,) = heard
    assert row["reported"] is True
    assert row["input_tokens"] == 1_000_000
    assert row["priced_usd"] == pytest.approx(3.0)
    assert row["estimated_usd"] == pytest.approx(2.0)
    assert row["estimated_part"] == "output"
    assert row["estimated"][OUTPUT_ESTIMATED] is True
    assert meter.spent() == pytest.approx(3.0)


def test_an_openai_stream_broken_before_any_chunk_is_charged_nothing() -> None:
    spend = _Spend()
    ledger = TokenLedger(spend=spend)
    model = _model([_status(503), "CLAIM: x"])
    attach_retry_recorder(model, ledger, "static")
    model.invoke("hello")
    assert spend.failed_attempts() == []


def test_the_pieces_are_kept_on_the_error() -> None:
    failure = RuntimeError("x")
    note_pieces(failure, 4)
    note_pieces(failure, 2)
    assert getattr(failure, PIECES_ATTRIBUTE) == 4
    untouched = RuntimeError("y")
    note_pieces(untouched, 0)
    assert not hasattr(untouched, PIECES_ATTRIBUTE)
