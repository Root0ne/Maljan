"""Every retry is a row of the run summary.

A retry used to be written only on the answer that followed it, so the retries
of a call that was then lost (the analyst the change exists to save), or handed
to the next model of a list, were never counted. The job now attaches a
recorder to each model it builds; a retry is a row of the job's token ledger
the moment it is decided. A model built outside a job keeps its retries on the
answer, or on the error given up on, and the analyst records those when it
loses the call.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import httpx
import openai
import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool

from maljan.agents.base_agent import BaseAnalyst
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.core.exceptions import AnalystError
from maljan.core.token_ledger import TokenLedger
from maljan.llm.fallback import FallbackChatModel
from maljan.llm.transient import (
    RETRIES_KEY,
    attach_retry_recorder,
    retries_of,
    retry_on_connection_error,
    with_transient_retries,
)

USAGE = {"input_tokens": 3, "output_tokens": 1, "total_tokens": 4}
_REQUEST = httpx.Request("POST", "http://127.0.0.1:8080/v1")


def _status(status: int) -> Exception:
    response = httpx.Response(status, request=_REQUEST)
    return openai.APIStatusError(f"Error code: {status}", response=response, body=None)


@pytest.fixture(autouse=True)
def _no_real_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _instant)
    monkeypatch.setattr("maljan.llm.transient.time.sleep", lambda _s: None)


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
