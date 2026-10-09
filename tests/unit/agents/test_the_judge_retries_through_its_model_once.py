"""The judge's and the mediator's calls are retried by their model, by the one policy, once.

The judge wrapped its single calls in ``retry_on_connection_error`` because its
model did not retry. Every provider's model now asks again itself
(``llm.transient``), so the wrappers are gone: a 5xx at any of those calls is
attempted exactly the policy's number of times, never that number squared, and
the mediator's one re-ask of an empty answer is not a transient retry of its
own.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any

import httpx
import openai
import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from maljan.agents import judge_agent
from maljan.agents.judge_agent import JudgeAgent
from maljan.llm.transient import DEFAULT_ATTEMPTS, with_transient_retries

_REQUEST = httpx.Request("POST", "http://127.0.0.1:8080/v1")


def _status(status: int) -> Exception:
    return openai.APIStatusError(
        f"Error code: {status}", response=httpx.Response(status, request=_REQUEST), body=None
    )


@pytest.fixture(autouse=True)
def _no_real_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _instant)


class _Scripted(BaseChatModel):
    script: list[Any] = []
    asked: list[int] = []

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any):
        self.asked.append(1)
        step = self.script.pop(0) if self.script else _status(503)
        if isinstance(step, BaseException):
            raise step
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=step))])


def _model(script: list[Any]) -> Any:
    return with_transient_retries(_Scripted)(script=list(script), asked=[])


class TestTheMediatorsReAsk:
    def test_a_5xx_there_is_attempted_the_policy_s_number_of_times(self) -> None:
        model = _model([])
        judge = JudgeAgent(llm=model)

        answer, bound, why = asyncio.run(judge._ask_mediation_again([HumanMessage("x")], None))

        assert answer is None and bound is None
        assert "failed" in why
        assert len(model.asked) == DEFAULT_ATTEMPTS

    def test_a_5xx_then_an_answer_is_the_answer(self) -> None:
        model = _model([_status(503), "CONTRADICTIONS: NONE"])
        judge = JudgeAgent(llm=model)

        answer, _bound, why = asyncio.run(judge._ask_mediation_again([HumanMessage("x")], None))

        assert answer.content == "CONTRADICTIONS: NONE"
        assert why == ""
        assert len(model.asked) == 2


class TestNoJudgeCallIsWrappedAgain:
    def test_the_judge_module_holds_no_second_retry(self) -> None:
        assert "retry_on_connection_error" not in inspect.getsource(judge_agent)

    def test_the_verdict_s_5xx_is_attempted_the_policy_s_number_of_times(self) -> None:
        model = _model([])
        judge = JudgeAgent(llm=model)

        with pytest.raises(openai.APIStatusError):
            asyncio.run(judge.give_verdict(reports={"static": "nothing"}, history=[]))

        assert len(model.asked) == DEFAULT_ATTEMPTS
