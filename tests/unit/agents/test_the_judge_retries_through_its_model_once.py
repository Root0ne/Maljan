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


class TestARetryNamesTheCallItRetried:
    """The judge and the mediator are both filed under ``judge``: the row says which call."""

    def test_the_re_ask_s_retries_name_it(self, caplog: pytest.LogCaptureFixture) -> None:
        from maljan.core.token_ledger import TokenLedger
        from maljan.llm.transient import attach_retry_recorder

        ledger = TokenLedger()
        model = attach_retry_recorder(
            _model([_status(503), "CONTRADICTIONS: NONE"]), ledger, "judge"
        )
        judge = JudgeAgent(llm=model)

        with caplog.at_level("WARNING"):
            asyncio.run(judge._ask_mediation_again([HumanMessage("x")], None))

        (row,) = ledger.snapshot()["retries"]
        assert row["reason"].startswith("Mediator asked once more")
        assert any("Mediator asked once more" in record.getMessage() for record in caplog.records)

    def test_the_verdict_s_retries_name_it(self) -> None:
        from maljan.core.token_ledger import TokenLedger
        from maljan.llm.transient import attach_retry_recorder

        ledger = TokenLedger()
        model = attach_retry_recorder(_model([]), ledger, "judge")
        judge = JudgeAgent(llm=model)

        with pytest.raises(openai.APIStatusError):
            asyncio.run(judge.give_verdict(reports={"static": "nothing"}, history=[]))

        rows = ledger.snapshot()["retries"]
        assert len(rows) == DEFAULT_ATTEMPTS - 1
        assert all(row["reason"].startswith("Judge verdict") for row in rows)

    def test_a_call_with_no_name_is_a_model_call(self) -> None:
        from maljan.core.token_ledger import TokenLedger
        from maljan.llm.transient import attach_retry_recorder

        ledger = TokenLedger()
        model = attach_retry_recorder(_model([_status(503), "fine"]), ledger, "judge")

        asyncio.run(model.ainvoke("hi"))

        (row,) = ledger.snapshot()["retries"]
        assert row["reason"].startswith("model call")

    def test_nothing_sent_changes(self) -> None:
        seen: list[Any] = []

        class _Seen(_Scripted):
            def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kw):
                seen.append((messages, stop, dict(kw)))
                return super()._generate(messages, stop, run_manager, **kw)

        model = with_transient_retries(_Seen)(script=["a", "b"], asked=[])
        from maljan.llm.transient import as_call

        asyncio.run(model.ainvoke([HumanMessage("x")]))
        asyncio.run(as_call("Judge verdict", model.ainvoke([HumanMessage("x")])))

        assert seen[0] == seen[1]
