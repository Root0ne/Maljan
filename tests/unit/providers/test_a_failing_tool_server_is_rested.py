"""A tool server that keeps failing at the transport is rested, and says so.

Per job and per server: a run of calls the server did not answer opens the breaker, a call
while it is open is answered by the platform in the structured tool-error
shape, one call is let through after the cooldown and a success closes it. A
tool that answers with its own error has answered, and never trips anything.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

import anyio
import httpx
import pytest
from mcp.shared.exceptions import McpError
from mcp.types import CONNECTION_CLOSED, INVALID_PARAMS, ErrorData

from maljan.agents.mcp_client import MCPLangChainToolkit
from maljan.core.config import Settings
from maljan.providers.server_guard import ServerGuard, guard_from_settings, transport_failure
from maljan.tools.errors import SERVER_RESTING, error_parts


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _guard(**kwargs: Any) -> tuple[ServerGuard, _Clock, list[dict[str, Any]]]:
    clock = _Clock()
    opened: list[dict[str, Any]] = []
    guard = ServerGuard(
        "analysis",
        failures_to_open=kwargs.pop("failures_to_open", 3),
        cooldown_seconds=kwargs.pop("cooldown_seconds", 60.0),
        max_concurrent_calls=kwargs.pop("max_concurrent_calls", 2),
        on_open=opened.append,
        clock=clock,
    )
    return guard, clock, opened


class TestWhatCountsAsATransportFailure:
    def test_a_closed_connection_is_one(self) -> None:
        exc = McpError(ErrorData(code=CONNECTION_CLOSED, message="Connection closed"))
        assert transport_failure(exc) == "the connection to the server closed"

    def test_a_request_timeout_is_one(self) -> None:
        exc = McpError(ErrorData(code=408, message="Timed out"))
        assert transport_failure(exc) == "the server did not answer in time"

    def test_a_refused_connection_is_one(self) -> None:
        assert transport_failure(httpx.ConnectError("refused")) == "the server could not be reached"
        assert transport_failure(ConnectionRefusedError(111, "refused"))

    def test_the_process_gone_is_one(self) -> None:
        assert transport_failure(anyio.ClosedResourceError())
        assert transport_failure(anyio.BrokenResourceError())

    def test_the_server_rejecting_an_argument_is_not_one(self) -> None:
        exc = McpError(ErrorData(code=INVALID_PARAMS, message="bad argument"))
        assert transport_failure(exc) is None

    def test_an_ordinary_exception_is_not_one(self) -> None:
        assert transport_failure(FileNotFoundError("no such file")) is None


class TestTheBreaker:
    def test_it_opens_after_the_run_of_failures_and_records_the_opening(self) -> None:
        guard, _clock, opened = _guard()
        for _ in range(2):
            guard.failed("the server could not be reached")
            assert guard.refusal("pe_info") is None
        guard.failed("the server could not be reached")
        assert opened == [
            {
                "server": "analysis",
                "failures": 3,
                "cooldown_s": 60.0,
                "reason": "the server could not be reached",
            }
        ]
        answer = guard.refusal("pe_info")
        assert answer is not None
        code, message, remediation = error_parts(answer) or ("", "", "")
        assert code == SERVER_RESTING
        assert (
            "tool server 'analysis' is resting after 3 calls in a row it did not answer" in message
        )
        assert "it will be tried again in 60 s" in message
        assert remediation
        assert json.loads(answer)["tool"] == "pe_info"

    def test_an_answer_between_failures_starts_the_count_again(self) -> None:
        guard, _clock, opened = _guard()
        guard.failed("x")
        guard.failed("x")
        guard.answered()
        guard.failed("x")
        guard.failed("x")
        assert opened == [] and guard.refusal("t") is None

    def test_after_the_cooldown_one_call_is_let_through_and_a_success_closes_it(self) -> None:
        guard, clock, _opened = _guard()
        for _ in range(3):
            guard.failed("x")
        clock.now += 61
        assert guard.refusal("first") is None
        second = guard.refusal("second")
        assert second is not None and "one call has been let through" in second
        guard.answered()
        assert guard.refusal("third") is None

    def test_a_trial_that_fails_rests_the_server_again(self) -> None:
        guard, clock, opened = _guard()
        for _ in range(3):
            guard.failed("x")
        clock.now += 61
        assert guard.admit("trial") == (None, True)
        guard.failed("the server did not answer in time", trial=True)
        assert len(opened) == 2
        assert guard.refusal("next") is not None

    def test_a_trial_cut_short_hands_the_trial_to_the_next_caller(self) -> None:
        guard, clock, _opened = _guard()
        for _ in range(3):
            guard.failed("x")
        clock.now += 61
        assert guard.admit("trial") == (None, True)
        guard.abandoned(trial=True)
        assert guard.refusal("next") is None

    def test_the_thresholds_come_from_settings(self) -> None:
        settings = Settings()
        settings.mcp.breaker.failures_to_open = 5
        settings.mcp.breaker.cooldown_seconds = 12.0
        settings.mcp.breaker.max_concurrent_calls = 0
        guard = guard_from_settings("network", settings)
        assert (guard.failures_to_open, guard.cooldown_seconds, guard.max_concurrent_calls) == (
            5,
            12.0,
            0,
        )


class TestTheCap:
    def test_no_more_than_the_cap_are_in_flight_at_once(self) -> None:
        guard, _clock, _opened = _guard(max_concurrent_calls=2)
        state = {"now": 0, "most": 0}

        async def call() -> None:
            async with guard.slot():
                state["now"] += 1
                state["most"] = max(state["most"], state["now"])
                await asyncio.sleep(0.01)
                state["now"] -= 1

        async def main() -> None:
            await asyncio.gather(*(call() for _ in range(6)))

        asyncio.run(main())
        assert state["most"] == 2

    def test_zero_leaves_the_calls_uncapped(self) -> None:
        guard, _clock, _opened = _guard(max_concurrent_calls=0)
        state = {"now": 0, "most": 0}

        async def call() -> None:
            async with guard.slot():
                state["now"] += 1
                state["most"] = max(state["most"], state["now"])
                await asyncio.sleep(0.01)
                state["now"] -= 1

        async def main() -> None:
            await asyncio.gather(*(call() for _ in range(5)))

        asyncio.run(main())
        assert state["most"] == 5


class _Session:
    """A session whose ``call_tool`` follows a script of raises and answers."""

    def __init__(self, script: list[Any]) -> None:
        self.script = list(script)
        self.calls = 0

    async def call_tool(self, name: str, arguments: dict[str, Any], **_: Any) -> Any:
        self.calls += 1
        step = self.script.pop(0)
        if isinstance(step, BaseException):
            raise step
        return step


def _answer(text: str, *, error: bool = False) -> Any:
    return SimpleNamespace(isError=error, content=[SimpleNamespace(text=text)])


def _tool(toolkit: MCPLangChainToolkit) -> Any:
    spec = SimpleNamespace(
        name="pe_info",
        description="Read a PE header.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    )
    return toolkit._create_langchain_tool(spec)


class TestTheToolkitCallsThroughTheGuard:
    def _run(self, toolkit: MCPLangChainToolkit, times: int) -> list[str]:
        tool = _tool(toolkit)

        async def main() -> list[str]:
            return [await tool.ainvoke({}) for _ in range(times)]

        return asyncio.run(main())

    def test_a_server_that_keeps_dropping_is_not_called_while_it_rests(self) -> None:
        guard, _clock, opened = _guard()
        session = _Session([anyio.ClosedResourceError()] * 3 + [_answer("unused")])
        toolkit = MCPLangChainToolkit(guard=guard)
        toolkit.session = session  # type: ignore[assignment]
        answers = self._run(toolkit, 4)
        assert session.calls == 3
        assert len(opened) == 1
        assert error_parts(answers[3])[0] == SERVER_RESTING  # type: ignore[index]

    def test_a_tool_that_answers_with_its_own_error_never_trips_it(self) -> None:
        guard, _clock, opened = _guard(failures_to_open=1)
        bad_argument = McpError(ErrorData(code=INVALID_PARAMS, message="no such argument"))
        session = _Session(
            [_answer("file not found", error=True), bad_argument, _answer('{"ok": true}')]
        )
        toolkit = MCPLangChainToolkit(guard=guard)
        toolkit.session = session  # type: ignore[assignment]
        answers = self._run(toolkit, 3)
        assert session.calls == 3
        assert opened == []
        assert answers[2] == '{"ok": true}'

    def test_after_the_cooldown_the_trial_call_is_sent_and_a_success_ends_the_rest(self) -> None:
        guard, clock, _opened = _guard()
        session = _Session([anyio.ClosedResourceError()] * 3 + [_answer("back"), _answer("again")])
        toolkit = MCPLangChainToolkit(guard=guard)
        toolkit.session = session  # type: ignore[assignment]
        self._run(toolkit, 3)
        clock.now += 61
        answers = self._run(toolkit, 2)
        assert answers == ["back", "again"]
        assert session.calls == 5

    def test_a_call_that_failed_while_another_was_the_trial_does_not_rest_it_again(self) -> None:
        guard, clock, opened = _guard()
        for _ in range(3):
            guard.failed("x")
        clock.now += 61
        refused, trial = guard.admit("trial")
        assert refused is None and trial
        guard.failed("a call sent before the rest began", trial=False)
        assert len(opened) == 1
        guard.answered()
        assert guard.refusal("next") is None

    def test_without_a_guard_every_call_is_sent(self) -> None:
        session = _Session([anyio.ClosedResourceError()] * 5)
        toolkit = MCPLangChainToolkit()
        toolkit.session = session  # type: ignore[assignment]
        self._run(toolkit, 5)
        assert session.calls == 5


class TestTheRegistryHoldsOneGuardPerServer:
    def test_every_handle_has_the_job_guard_and_an_opening_is_kept_and_announced(self) -> None:
        from maljan.providers.servers import ServerRegistry

        events: list[tuple[str, dict[str, Any]]] = []
        settings = Settings()
        settings.mcp.breaker.failures_to_open = 1
        registry = ServerRegistry(
            settings, event_sink=lambda kind, data: events.append((kind, data))
        )
        handle = next(iter(registry._handles.values()))
        assert isinstance(handle.guard, ServerGuard)
        handle.guard.failed("the server could not be reached")
        assert registry.rests[0]["server"] == handle.name
        assert events == [
            (
                "tool_server_rested",
                {
                    "server": handle.name,
                    "failures": 1,
                    "cooldown_s": 60.0,
                    "reason": "the server could not be reached",
                },
            )
        ]


def test_the_run_summary_names_every_rest() -> None:
    from maljan.analysis.run_summary import RunSummaryBuilder

    summary = (
        RunSummaryBuilder(start_time=0.0)
        .set_sample("abc", None)
        .set_verdict("Benign", 0)
        .set_server_rests(
            [{"server": "analysis", "failures": 3, "cooldown_s": 60.0, "reason": "timed out"}]
        )
        .build()
    )
    assert summary.to_dict()["server_rests"][0]["server"] == "analysis"
    assert (
        "Tool server analysis was rested for 60 s after 3 calls in a row it did not answer "
        "(the last: timed out)." in summary.to_markdown()
    )


@pytest.mark.parametrize("failures", [1, 2])
def test_the_sentence_counts_in_words(failures: int) -> None:
    from maljan.analysis.run_summary import server_rest_sentence

    text = server_rest_sentence({"server": "s", "failures": failures, "cooldown_s": 5})
    assert (" call in a row" in text) == (failures == 1)


class TestTheHalfOpenPath:
    def test_a_trial_that_fails_after_another_call_closed_the_rest_does_not_reopen_it(self) -> None:
        guard, clock, opened = _guard()
        for _ in range(3):
            guard.failed("x")
        clock.now += 61
        _refused, trial = guard.admit("trial")
        assert trial
        guard.answered()
        guard.failed("the trial's own failure", trial=True)
        assert len(opened) == 1
        assert guard.refusal("next") is None

    def test_a_trial_cancelled_while_it_queued_is_released_once(self) -> None:
        guard, clock, _opened = _guard(max_concurrent_calls=1)
        released: list[bool] = []
        original = guard.abandoned

        def counting(*, trial: bool = False) -> None:
            released.append(trial)
            original(trial=trial)

        guard.abandoned = counting  # type: ignore[method-assign]

        class _Hangs:
            async def call_tool(self, name: str, arguments: dict[str, Any], **_: Any) -> Any:
                await asyncio.sleep(30)

        toolkit = MCPLangChainToolkit(guard=guard)
        toolkit.session = _Hangs()  # type: ignore[assignment]
        tool = _tool(toolkit)

        async def main() -> None:
            holder = asyncio.ensure_future(tool.ainvoke({}))
            await asyncio.sleep(0.01)
            for _ in range(3):
                guard.failed("x")
            clock.now += 61
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(tool.ainvoke({}), timeout=0.05)
            holder.cancel()
            with pytest.raises(asyncio.CancelledError):
                await holder

        asyncio.run(main())
        assert released == [True], "the queued trial is released exactly once"
        assert guard.admit("next") == (None, True), "and the next caller becomes the trial"


class TestAHungServerIsCounted:
    def test_ten_calls_cut_by_their_caller_rest_the_server(self) -> None:
        """The reviewer's probe: ten calls to a server that never answers."""
        guard, _clock, opened = _guard(max_concurrent_calls=4)
        sent: list[str] = []

        class _Hung:
            async def call_tool(self, name: str, arguments: dict[str, Any], **_: Any) -> Any:
                sent.append(name)
                await asyncio.sleep(30)

        toolkit = MCPLangChainToolkit(guard=guard)
        toolkit.session = _Hung()  # type: ignore[assignment]
        tool = _tool(toolkit)
        answers: list[str] = []

        async def one() -> None:
            try:
                answers.append(await asyncio.wait_for(tool.ainvoke({}), timeout=0.05))
            except TimeoutError:
                answers.append("cut")

        async def main() -> None:
            for _ in range(10):
                await one()

        asyncio.run(main())
        assert len(opened) == 1
        assert len(sent) == 3
        assert answers[:3] == ["cut"] * 3
        assert all(error_parts(a)[0] == SERVER_RESTING for a in answers[3:])  # type: ignore[index]

    def test_a_call_past_its_deadline_is_a_timeout_the_breaker_counts(self) -> None:
        guard, _clock, opened = _guard(failures_to_open=1)
        guard.call_timeout_seconds = 0.01
        seen: dict[str, Any] = {}

        class _TimesOut:
            async def call_tool(self, name: str, arguments: dict[str, Any], **kw: Any) -> Any:
                seen.update(kw)
                raise McpError(ErrorData(code=408, message="Timed out"))

        toolkit = MCPLangChainToolkit(guard=guard)
        toolkit.session = _TimesOut()  # type: ignore[assignment]
        asyncio.run(_tool(toolkit).ainvoke({}))
        assert seen["read_timeout_seconds"].total_seconds() == pytest.approx(30.01)
        assert len(opened) == 1


class TestTheCallDeadline:
    def test_it_is_derived_from_the_longest_tool_budget_and_capa_still_fits(self) -> None:
        settings = Settings()
        settings.static.capa.timeout_seconds = 900
        guard = guard_from_settings("analysis", settings)
        assert guard.call_timeout("capa") == 930.0

    def test_a_longer_budget_the_server_declares_wins(self) -> None:
        settings = Settings()
        guard = guard_from_settings("analysis", settings)
        guard.declare({"slow": {"timeout_s": 2000}, "quick": {"timeout_s": 15}})
        assert guard.call_timeout("slow") == 2030.0
        assert guard.call_timeout("quick") == settings.static.capa.timeout_seconds + 30.0

    def test_an_explicit_setting_is_used_as_written(self) -> None:
        settings = Settings()
        settings.mcp.breaker.call_timeout_seconds = 45
        assert guard_from_settings("x", settings).call_timeout("t") == 75.0
