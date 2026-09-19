"""The judge's verdict runs on the loop that owns its client.

Every run in the second live trace opened with
``Judge verdict: connection error (attempt 1/3)`` and llama-server logged no
request at that second. The judge's model is one cached client and the
mediator has already used it from the shared agent loop, so its httpx pool
holds connections bound to that loop; awaiting the same client on the graph's
own loop raised ``RuntimeError: ... is bound to a different event loop`` inside
httpx, which the openai SDK reports as a bare
``APIConnectionError("Connection error.")``. The pool then dropped the dead
connection and the retry, opening a fresh one, always succeeded — a whole
wasted turn and a warning that read like a flaky network.

Two things are pinned. The verdict call goes onto the shared agent loop, the
way the mediator's already does. And the log line carries the cause chain,
because "Connection error." is the same sentence for a refused socket and for
a bug in this process.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest
from openai import APIConnectionError

from maljan.agents.base_agent import cause_chain, retry_on_connection_error


class TestTheCauseChainIsLogged:
    def test_it_names_the_loop_error_the_sdk_hides(self) -> None:
        inner = RuntimeError("<asyncio.locks.Event object> is bound to a different event loop")
        try:
            try:
                raise inner
            except RuntimeError as exc:
                raise APIConnectionError(request=MagicMock()) from exc
        except APIConnectionError as exc:
            chain = cause_chain(exc)

        assert "bound to a different event loop" in chain
        assert chain.startswith("RuntimeError(")

    def test_it_says_so_when_there_is_no_cause(self) -> None:
        assert cause_chain(APIConnectionError(request=MagicMock())) == "no cause recorded"

    @pytest.mark.asyncio
    async def test_the_retry_warning_carries_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _instant(_seconds: float) -> None:
            return None

        monkeypatch.setattr(asyncio, "sleep", _instant)

        lines: list[str] = []

        class _Log:
            def warning(self, fmt: str, *args: object) -> None:
                lines.append(fmt % args)

            def error(self, fmt: str, *args: object) -> None:  # pragma: no cover - unused
                lines.append(fmt % args)

        attempts = {"n": 0}

        async def _call() -> str:
            attempts["n"] += 1
            if attempts["n"] == 1:
                cause = RuntimeError("bound to a different event loop")
                raise APIConnectionError(request=MagicMock()) from cause
            return "ok"

        assert await retry_on_connection_error(_call, what="Judge verdict", log=_Log()) == "ok"
        assert len(lines) == 1
        assert "bound to a different event loop" in lines[0]


class TestTheVerdictRunsOnTheAgentLoop:
    @pytest.mark.asyncio
    async def test_the_model_is_awaited_on_the_shared_loop(self) -> None:
        """The client sees the agent loop, not the loop give_verdict was called on."""
        from maljan.agents import base_agent, judge_agent

        agent_loop = base_agent._get_agent_loop()
        assert asyncio.get_running_loop() is not agent_loop

        seen: list[asyncio.AbstractEventLoop] = []

        class _LLM:
            async def ainvoke(self, turns: object) -> object:
                seen.append(asyncio.get_running_loop())
                return MagicMock(content='{"type": "bundle", "objects": []}')

        judge = judge_agent.JudgeAgent.__new__(judge_agent.JudgeAgent)
        judge.llm = _LLM()
        judge.logger = MagicMock()
        judge.token_ledger = None
        judge.truncation_ledger = None

        verdict = await judge.give_verdict(reports={"static": "nothing"}, history=[])

        assert seen, "the verdict never called the model"
        assert all(loop is agent_loop for loop in seen)
        assert verdict.bundle is not None
