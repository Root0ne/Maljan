"""What a node may say about an exception on the live feed.

An ``agent_message`` goes to every connected browser, into the Redis stream
and into the ``job_events`` table for the whole retention window. An
exception's *message* is the part that names things a reader of that feed has
no business seeing: an ``OSError`` names the host path of the sample, an
``httpx`` transport error names the request URL, and a base URL configured
with userinfo carries the credential into the text.

So a published failure says what kind of failure it was, and the remedy when
the failure carries one, and never what it said. The verbatim text stays on
the ledger and the log, behind the report's ownership check.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.core.exceptions import AnalystError
from maljan.pipeline import events as ev
from maljan.pipeline.nodes import (
    make_negotiation_node,
    make_revision_node,
    make_stage_agent_node,
)
from tests.stages import ANALYSIS_STAGE, paper_profile

# One string carrying both of the things a message must not put on the wire.
SECRET = "sk-" + "L" * 32
HOST_PATH = "/home/operator/maljan/data/samples/ab12/evil.exe"
LOUD = f"POST https://user:{SECRET}@llm.internal/v1 failed reading {HOST_PATH}"


class _Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, data))

    def said(self) -> str:
        """Every string in every event, as one blob to search."""
        import json

        return json.dumps(self.events, default=str)


def _container(sink: Any, agents: list[str] | None = None) -> Any:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = sink
    container.agent_registry.list_agents.return_value = agents or ["network"]
    container.analyst_keys.return_value = agents or ["network"]
    container.agent_role.side_effect = lambda n: n
    container.active_profile.return_value = paper_profile(agents or ["network"])
    container.load_data_for_agent.side_effect = lambda n, *, file_hash, **_: container.load_chunked(
        file_hash, n
    )
    return container


def _assert_nothing_leaked(recorder: _Recorder) -> None:
    said = recorder.said()
    assert SECRET not in said, said
    assert "/home/operator" not in said, said
    assert "llm.internal" not in said, said


class TestTheHelper:
    def test_a_message_never_travels(self) -> None:
        assert ev.describe_exception(ValueError(LOUD)) == "ValueError"

    def test_the_class_is_what_is_said(self) -> None:
        assert ev.describe_exception(TimeoutError()) == "TimeoutError"

    def test_a_class_outside_the_builtins_is_qualified(self) -> None:
        """Two ``CancelledError`` classes print the same word; only one is an
        ``Exception``, which is exactly why one of them slipped through."""
        import asyncio as _asyncio
        import concurrent.futures as _futures

        assert ev.describe_exception(_asyncio.CancelledError()) != ev.describe_exception(
            _futures.CancelledError()
        )
        assert "asyncio" in ev.describe_exception(_asyncio.CancelledError())

    def test_a_remediation_the_failure_carries_is_said(self) -> None:
        from maljan.tools.roots import PathOutsideRoots

        said = ev.describe_exception(PathOutsideRoots())

        assert "PathOutsideRoots" in said
        assert PathOutsideRoots.remediation in said

    def test_a_remediation_is_scrubbed_like_anything_else(self) -> None:
        class _Remediated(Exception):
            remediation = f"open {HOST_PATH} and try again"

        said = ev.describe_exception(_Remediated("boom"))

        assert "/home/operator" not in said
        assert "evil.exe" in said

    def test_an_exception_group_names_what_is_inside_it(self) -> None:
        group = ExceptionGroup("several", [ValueError(LOUD), TimeoutError()])

        said = ev.describe_exception(group)

        assert "ValueError" in said and "TimeoutError" in said
        assert SECRET not in said


class TestTheAnalystNode:
    def test_a_failed_analyst_says_the_type_alone(self) -> None:
        recorder = _Recorder()
        container = _container(recorder)
        container.get_agent.side_effect = AnalystError(LOUD)

        make_stage_agent_node(ANALYSIS_STAGE, "network", container)({"file_hash": "a" * 64})

        _assert_nothing_leaked(recorder)
        (message,) = [d for t, d in recorder.events if t == ev.AGENT_MESSAGE]
        assert message["status"] == "failed"
        assert "AnalystError" in message["text"]

    def test_a_crashed_analyst_says_the_type_alone(self) -> None:
        recorder = _Recorder()
        container = _container(recorder)
        container.get_agent.side_effect = RuntimeError(LOUD)

        update = make_stage_agent_node(ANALYSIS_STAGE, "network", container)(
            {"file_hash": "a" * 64}
        )

        _assert_nothing_leaked(recorder)
        assert "RuntimeError" in update["reports"]["network"]
        assert SECRET not in update["reports"]["network"]


class TestTheMediator:
    def test_a_failed_mediation_says_the_type_alone(self) -> None:
        recorder = _Recorder()
        container = _container(recorder)
        judge = MagicMock()
        judge.mediate = AsyncMock(side_effect=RuntimeError(LOUD))
        container.get_judge_agent.return_value = judge

        update = asyncio.run(
            make_negotiation_node(container)(
                {"iteration_count": 1, "reports": {"network": "f"}, "isr_reports": {}}
            )
        )

        _assert_nothing_leaked(recorder)
        finding = update["discussion_history"][0].finding
        assert "RuntimeError" in finding
        assert SECRET not in finding


class TestTheRevision:
    def test_a_failed_revision_says_the_type_alone(self) -> None:
        recorder = _Recorder()
        container = _container(recorder, agents=["network"])
        agent = MagicMock()
        agent.safe_revise_isr.side_effect = OSError(LOUD)
        container.get_agent.return_value = agent

        asyncio.run(
            make_revision_node(container)(
                {"iteration_count": 1, "reports": {"network": "f"}, "isr_reports": {}}
            )
        )

        _assert_nothing_leaked(recorder)
        (message,) = [d for t, d in recorder.events if t == ev.AGENT_MESSAGE]
        assert message["status"] == "failed"
        assert "OSError" in message["text"]


class TestTheJudge:
    def test_a_failed_verdict_says_the_type_alone(self) -> None:
        from maljan.pipeline.nodes import make_judge_node
        from maljan.schemas.evidence import EvidenceCounter
        from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import _Container, _state

        recorder = _Recorder()
        container = _Container(EvidenceCounter())
        container.event_sink = recorder
        container.get_judge_agent(role="judge").give_verdict = AsyncMock(
            side_effect=RuntimeError(LOUD)
        )

        update = asyncio.run(make_judge_node(container)(_state([])))

        _assert_nothing_leaked(recorder)
        assert update["degraded_mode"] is True
        (message,) = [d for t, d in recorder.events if t == ev.AGENT_MESSAGE]
        assert "RuntimeError" in message["text"]


@pytest.mark.parametrize("exc", [ValueError(LOUD), OSError(LOUD), TimeoutError(LOUD)])
def test_no_shape_of_message_survives_the_helper(exc: BaseException) -> None:
    said = ev.describe_exception(exc)

    assert SECRET not in said
    assert "/home/operator" not in said
    assert "llm.internal" not in said
