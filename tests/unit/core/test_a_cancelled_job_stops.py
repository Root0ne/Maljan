"""A cancelled job stops: between nodes, before every model call, and in flight.

The benchmark cancelled a job and the worker issued the judge's model call two
seconds later, started the report stage eleven minutes after that, held open
16–19 connections to a model server that stayed "Stopping…", ignored SIGTERM
for three minutes and ended only on SIGKILL. The fake slow model here stands
in for that server: a call that would answer in an hour, and that notices
when it is abandoned.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any, TypedDict

import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import AIMessage, HumanMessage

from maljan.agents.base_agent import BaseAnalyst, _run_coro_blocking, run_on_agent_loop
from maljan.core.cancellation import (
    Cancellation,
    JobCancelled,
    bound,
    current,
    stops_when_cancelled,
)
from maljan.core.exceptions import AgentLoopCancelled

# How long any of these may take to stop once told. The slow model would
# otherwise hold a call for an hour.
PROMPTLY = 5.0


class _SlowModel:
    """A model server that takes an hour to answer and notices when it is abandoned."""

    def __init__(self) -> None:
        self.started = threading.Event()
        self.abandoned = threading.Event()

    async def ainvoke(self, messages: Any, *args: Any, **kwargs: Any) -> AIMessage:
        self.started.set()
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.abandoned.set()
            raise
        return AIMessage(content="never")  # pragma: no cover

    def invoke(self, messages: Any, *args: Any, **kwargs: Any) -> AIMessage:  # pragma: no cover
        raise AssertionError("a cancellable call is made through ainvoke")


def _cancel_when_started(job: Cancellation, model: _SlowModel, reason: str) -> threading.Thread:
    def _later() -> None:
        model.started.wait(PROMPTLY)
        job.cancel(reason)

    thread = threading.Thread(target=_later, daemon=True)
    thread.start()
    return thread


class TestTheFlag:
    def test_a_check_raises_and_records_where_it_first_stopped(self) -> None:
        job = Cancellation()
        job.check("before node judge")

        job.cancel("the operator cancelled the job")
        with pytest.raises(JobCancelled, match="the operator cancelled the job; stopped before"):
            job.check("before node judge")
        with pytest.raises(JobCancelled):
            job.check("before node report")

        assert job.stopped_at == "before node judge"

    def test_a_cancel_stops_every_call_in_flight_once(self) -> None:
        job = Cancellation()
        stopped: list[str] = []
        forget = job.track(lambda: stopped.append("a"))
        job.track(lambda: stopped.append("b"))
        forget()

        job.cancel("stop")
        job.cancel("stop again")

        assert stopped == ["b"]
        assert job.reason == "stop"

    def test_a_call_registered_after_the_cancel_is_stopped_at_once(self) -> None:
        job = Cancellation()
        job.cancel("stop")
        stopped: list[str] = []

        job.track(lambda: stopped.append("late"))

        assert stopped == ["late"]

    def test_it_is_not_an_exception_a_node_would_catch_as_its_own_failure(self) -> None:
        assert not issubclass(JobCancelled, Exception)


class TestNoModelIsAskedOnceCancelled:
    def test_a_sync_call_is_refused_before_anything_is_sent(self) -> None:
        model = FakeListChatModel(responses=["first", "second"])
        job = Cancellation()
        with bound(job):
            assert model.invoke("x").content == "first"
            job.cancel("the operator cancelled the job")
            with pytest.raises(JobCancelled, match="before a model call"):
                model.invoke("x")
        assert model.i == 1, "the second answer was never taken"

    def test_an_async_call_is_refused_too(self) -> None:
        model = FakeListChatModel(responses=["first"])
        job = Cancellation()
        job.cancel("the operator cancelled the job")

        async def _ask() -> Any:
            with bound(job):
                return await model.ainvoke("x")

        with pytest.raises(JobCancelled):
            asyncio.run(_ask())

    def test_outside_a_job_nothing_is_checked(self) -> None:
        assert current() is None
        assert FakeListChatModel(responses=["ok"]).invoke("x").content == "ok"


class TestACallInFlightIsStopped:
    def test_a_blocking_call_on_the_agent_loop_ends_with_the_job(self) -> None:
        model = _SlowModel()
        job = Cancellation()
        _cancel_when_started(job, model, "the operator cancelled the job")

        started = time.monotonic()
        with bound(job), pytest.raises(JobCancelled, match="in flight"):
            _run_coro_blocking(model.ainvoke([]), 3600, label="judge:verdict")

        assert time.monotonic() - started < PROMPTLY
        assert model.abandoned.wait(PROMPTLY), "the request itself was cancelled"
        assert job.stopped_at == "while judge:verdict was in flight"

    def test_an_awaited_call_on_the_agent_loop_ends_with_the_job(self) -> None:
        model = _SlowModel()
        job = Cancellation()
        _cancel_when_started(job, model, "the operator cancelled the job")

        async def _ask() -> Any:
            with bound(job):
                return await run_on_agent_loop(model.ainvoke([]), 3600, label="mediation")

        with pytest.raises(JobCancelled):
            asyncio.run(asyncio.wait_for(_ask(), PROMPTLY))
        assert model.abandoned.wait(PROMPTLY)

    def test_a_cancelled_caller_is_cancelled_and_so_is_its_call(self) -> None:
        """Not turned into ``AgentLoopCancelled``, which a node reads as a failure."""
        model = _SlowModel()
        seen: list[type[BaseException]] = []

        async def _caller() -> None:
            try:
                await run_on_agent_loop(model.ainvoke([]), 3600, label="mediation")
            except BaseException as exc:
                seen.append(type(exc))
                raise

        async def _main() -> None:
            task = asyncio.create_task(_caller())
            await asyncio.to_thread(model.started.wait, PROMPTLY)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(_main())

        assert seen == [asyncio.CancelledError]
        assert AgentLoopCancelled not in seen
        assert model.abandoned.wait(PROMPTLY)

    def test_an_analyst_s_own_call_is_cancelled_not_waited_on(self) -> None:
        class _Analyst(BaseAnalyst):
            def analyze(self, data: str) -> str:  # pragma: no cover - unused
                return ""

            def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
                return ""

        model = _SlowModel()
        analyst = _Analyst(llm=model, name="static")  # type: ignore[arg-type]
        job = Cancellation()
        _cancel_when_started(job, model, "the worker is shutting down")

        started = time.monotonic()
        with bound(job), pytest.raises(JobCancelled):
            analyst._invoke_llm_with_timeout([HumanMessage(content="answer")], 3600)

        assert time.monotonic() - started < PROMPTLY
        assert model.abandoned.wait(PROMPTLY)


class _State(TypedDict, total=False):
    ran: list[str]


class TestTheGraphStopsBetweenNodes:
    def test_no_node_starts_after_the_cancel(self) -> None:
        from langgraph.graph import END, START, StateGraph

        job = Cancellation()
        ran: list[str] = []

        def _mediation(state: _State) -> dict[str, Any]:
            ran.append("mediation")
            # The heartbeat reading the cancel flag while this node runs.
            job.cancel("the operator cancelled the job")
            return {}

        def _judge(state: _State) -> dict[str, Any]:  # pragma: no cover - must not run
            ran.append("judge")
            return {}

        graph = StateGraph(_State)
        graph.add_node("negotiation", stops_when_cancelled("negotiation", _mediation))
        graph.add_node("judge", stops_when_cancelled("judge", _judge))
        graph.add_edge(START, "negotiation")
        graph.add_edge("negotiation", "judge")
        graph.add_edge("judge", END)
        app = graph.compile()

        async def _run() -> Any:
            with bound(job):
                return await app.ainvoke({"ran": []})

        with pytest.raises(JobCancelled):
            asyncio.run(_run())

        assert ran == ["mediation"]
        assert job.stopped_at == "before node judge"

    def test_the_builder_wraps_every_node(self) -> None:
        import inspect

        from maljan.pipeline import builder

        source = inspect.getsource(builder)
        assert source.count("_node(") >= 8
        assert "instrument_node(name, stops_when_cancelled(name, fn))" in source


class TestTheWorker:
    def test_a_job_task_cancelled_by_shutdown_stops_its_pipeline(self) -> None:
        from app.worker.analysis_worker import PIPELINE_STOP_GRACE, await_the_pipeline

        model = _SlowModel()
        job = Cancellation()

        async def _pipeline() -> Any:
            with bound(job):
                return await run_on_agent_loop(model.ainvoke([]), 3600, label="judge:verdict")

        async def _main() -> float:
            pipeline = asyncio.create_task(_pipeline())
            waiting = asyncio.create_task(await_the_pipeline(pipeline, job))
            await asyncio.to_thread(model.started.wait, PROMPTLY)
            began = time.monotonic()
            waiting.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiting
            assert pipeline.done()
            return time.monotonic() - began

        took = asyncio.run(_main())

        assert took < PIPELINE_STOP_GRACE
        assert job.is_cancelled and job.reason == "the worker is shutting down"
        assert model.abandoned.wait(PROMPTLY)

    def test_a_pipeline_that_finishes_is_its_result(self) -> None:
        from app.worker.analysis_worker import await_the_pipeline

        async def _pipeline() -> dict[str, Any]:
            return {"verdict": "Malware"}

        async def _main() -> Any:
            return await await_the_pipeline(asyncio.create_task(_pipeline()), Cancellation())

        assert asyncio.run(_main()) == {"verdict": "Malware"}

    def test_a_pipeline_stopped_by_the_flag_raises_it(self) -> None:
        from app.worker.analysis_worker import await_the_pipeline

        job = Cancellation()
        job.cancel("the operator cancelled the job")

        async def _pipeline() -> Any:
            job.check("before node judge")

        async def _main() -> Any:
            return await await_the_pipeline(asyncio.create_task(_pipeline()), job)

        with pytest.raises(JobCancelled):
            asyncio.run(_main())
