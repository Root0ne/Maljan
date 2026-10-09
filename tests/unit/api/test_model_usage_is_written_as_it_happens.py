"""What every model call spent is committed to the job's record as soon as it is published.

The run summary holds a run's token usage, and it is built at the end of the
run; a worker killed before then (``SIGKILL``, the memory recycler, a host that
froze) took what the run spent with it. Each call the token ledger records now
goes on the job's event feed as a ``model_usage`` event, and the worker commits
it to ``job_events`` when the publish runs rather than with its next batch, so
no ``finally`` has to run for it. The publish is scheduled from the call's
thread, so what is guaranteed is "committed once the loop runs the publish",
not "before the next call". The event is a record, not progress: it is kept
off the live socket and the 1,000-entry replay stream.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from tests.integration._session_probe import SessionFactory

from app.worker import analysis_worker as worker_module
from maljan.core.token_ledger import TokenLedger, call_record
from maljan.pipeline.events import MODEL_USAGE


class TestTheLedgerSaysEachCall:
    def test_a_reported_call_carries_its_figures(self) -> None:
        heard: list[dict[str, Any]] = []
        ledger = TokenLedger()
        ledger.on_call = heard.append
        ledger.add(
            {"input_tokens": 900, "output_tokens": 120, "cached_input_tokens": 800, "cost": 0.01},
            agent="static",
            model="m1",
            call="tool loop turn",
        )
        assert heard == [
            {
                "agent": "static",
                "model": "m1",
                "call": "tool loop turn",
                "reported": True,
                "input_tokens": 900,
                "output_tokens": 120,
                "cached_input_tokens": 800,
                "cost": 0.01,
            }
        ]

    def test_an_unreported_call_carries_no_figure(self) -> None:
        assert call_record(None, agent="judge", model="m2", call="verdict") == {
            "agent": "judge",
            "model": "m2",
            "call": "verdict",
            "reported": False,
        }

    def test_a_listener_that_raises_costs_the_ledger_nothing(self) -> None:
        def _boom(row: dict[str, Any]) -> None:
            raise RuntimeError("listener")

        ledger = TokenLedger()
        ledger.on_call = _boom
        ledger.add({"input_tokens": 1, "output_tokens": 1}, agent="static")
        assert ledger.snapshot()["llm_calls"] == 1

    def test_a_job_s_container_puts_each_call_on_its_feed(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        sent: list[tuple[str, dict[str, Any]]] = []
        container = ServiceContainer(
            config=Settings(_env_file=None),
            mock=True,
            event_sink=lambda kind, data: sent.append((kind, data)),
        )
        container.get_token_ledger().add(
            {"input_tokens": 10, "output_tokens": 2}, agent="static", model="m1"
        )
        assert (
            MODEL_USAGE,
            call_record({"input_tokens": 10, "output_tokens": 2}, agent="static", model="m1"),
        ) in sent


def _redis() -> MagicMock:
    redis = MagicMock()
    redis.publish = AsyncMock()
    redis.exists = AsyncMock(return_value=1)
    redis.incr = AsyncMock(side_effect=[1, 2])
    redis.expire = AsyncMock()
    redis.xadd = AsyncMock()
    return redis


def _committed_events(factory: SessionFactory) -> list[Any]:
    from app.models.job_event import JobEvent

    return [
        obj
        for session in factory.sessions
        if session.commits
        for obj in session.added
        if isinstance(obj, JobEvent)
    ]


class TestTheWorkerWritesItAtOnce:
    @pytest.mark.asyncio
    async def test_a_usage_event_is_committed_before_the_run_ends(self) -> None:
        job_id = str(uuid.uuid4())
        factory = SessionFactory(lambda statement: MagicMock())
        redis = _redis()
        worker_module._start_event_feed(job_id, factory)
        try:
            await worker_module._publish_event(
                redis, job_id, "agent_message", {"agent": "static", "text": "a line"}
            )
            row = call_record({"input_tokens": 50, "output_tokens": 5}, agent="static", model="m")
            await worker_module._publish_event(redis, job_id, MODEL_USAGE, row)
            # The run is killed here: no ``_stop_event_feed``, no ``finally``.
            committed = _committed_events(factory)
            assert [event.type for event in committed] == ["agent_message", MODEL_USAGE]
            assert committed[-1].payload["input_tokens"] == 50
            assert committed[-1].payload["agent"] == "static"
            # Kept off the socket and the replay stream: only the line went there.
            assert redis.publish.await_count == 1
            assert redis.xadd.await_count == 1
            assert MODEL_USAGE not in str(redis.publish.await_args)
        finally:
            worker_module._EVENT_BUFFERS.pop(job_id, None)
            worker_module._LAST_SEQ.pop(job_id, None)

    @pytest.mark.asyncio
    async def test_other_events_still_wait_for_their_batch(self) -> None:
        job_id = str(uuid.uuid4())
        factory = SessionFactory(lambda statement: MagicMock())
        redis = _redis()
        worker_module._start_event_feed(job_id, factory)
        try:
            await worker_module._publish_event(
                redis, job_id, "agent_message", {"agent": "static", "text": "a line"}
            )
            assert _committed_events(factory) == []
        finally:
            worker_module._EVENT_BUFFERS.pop(job_id, None)
            worker_module._LAST_SEQ.pop(job_id, None)
