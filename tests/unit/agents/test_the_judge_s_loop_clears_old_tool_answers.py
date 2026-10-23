"""The judge's tool loop clears its oldest tool answers to ledger references, as an analyst's does.

A mediation that gathers answers until the server refuses the request as over
its window used to end there and write its reasoning from what it had. Now one
batch of the oldest answers is cleared, ``read_evidence`` is offered from the
request that carries the first clear, and the turn is sent again. A loop that
fits sends what it always sent.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

from maljan.agents import tool_answer_clearing as tac
from maljan.agents.judge_agent import JudgeAgent
from maljan.pipeline.events import TOOL_ANSWERS_CLEARED

from .test_old_tool_answers_are_cleared import (
    TASK,
    _Container,
    _lookup,
    _size,
    _Thinker,
    _window,
)


@contextlib.contextmanager
def _settings(steps: int | None = None) -> Iterator[None]:
    with (
        patch("maljan.agents.base_agent.get_settings") as base,
        patch("maljan.agents.judge_agent.get_settings") as judge,
    ):
        for patched in (base, judge):
            cfg = patched.return_value
            cfg.react_agent_timeout = None
            cfg.react_agent_timeout_overrides = {}
            cfg.react_agent_max_steps = steps
            cfg.react_agent_max_steps_overrides = {}
            cfg.react_agent_tool_call_budget = 100
            cfg.llm.provider = "openai"
            cfg.llm.agents = {}
            cfg.llm.openai.context_size = 0
            cfg.reporting.evidence_budget_bytes = 0
        yield


def _run(
    refuse_over: int = 0, calls: int = 12, steps: int | None = None, window: int = 0
) -> tuple[_Thinker, _Container, str]:
    model = _Thinker(seen=[], refused=[], calls=calls, reasoning=200, refuse_over=refuse_over)
    judge = JudgeAgent(llm=model)
    judge.logger = logging.getLogger("test.judge.clearing")
    container = _Container(_window(1_000_000))
    judge._container = container
    judge.tools = [_lookup(6_000)]
    with (
        _settings(steps),
        patch.object(JudgeAgent, "_own_window_tokens", lambda self: window or None),
    ):
        answer = asyncio.run(judge.execute_tool_loop([("system", "You judge."), ("human", TASK)]))
    return model, container, answer


def _cleared(container: _Container) -> list[dict[str, Any]]:
    return [e[1] for e in container.events if e[0] == TOOL_ANSWERS_CLEARED]


def test_a_refused_mediation_request_is_cleared_and_sent_again() -> None:
    limit = 50_000
    model, container, answer = _run(refuse_over=limit)

    assert answer.strip().startswith("CLAIM:")
    assert model.refused, "the stub refused at least one request"
    assert all(_size(sent) <= limit for sent, _tools in model.seen)
    cleared = _cleared(container)
    assert cleared and all(e["why"] == tac.CLEARED_FOR_REFUSAL for e in cleared)


def test_read_evidence_is_offered_from_the_first_clear_and_never_before() -> None:
    model, _container, _answer = _run(refuse_over=50_000)

    offered = [tools for _sent, tools in model.seen]
    first = next(i for i, tools in enumerate(offered) if tac.READ_EVIDENCE_TOOL in tools)
    assert first > 0
    assert all(tools == ["lookup"] for tools in offered[:first])
    assert all(tac.READ_EVIDENCE_TOOL in tools for tools in offered[first:])


def test_a_loop_that_fits_sends_what_it_always_sent() -> None:
    model, container, _answer = _run(refuse_over=0)

    assert not model.refused
    assert not _cleared(container)
    assert all(tools == ["lookup"] for _sent, tools in model.seen)
    # Every request carries the answers whole, none a reference.
    last, _tools = model.seen[-1]
    answers = [m for m in last if m.type == "tool"]
    assert answers and all("[cleared" not in str(m.content) for m in answers)
    assert all("a" * 6_000 in str(m.content) for m in answers)


def test_a_resent_turn_stays_inside_the_loop_s_step_cap() -> None:
    cap = 6
    model, _container, _answer = _run(refuse_over=9_000, calls=120, steps=cap)

    assert model.refused, "the stub refused, so the turn was sent again"
    # Every answered turn is one model step, a tool round a second one.
    assert len(model.seen) <= cap


def test_a_prompt_past_the_judge_s_own_window_is_cleared_before_it_is_sent() -> None:
    model, container, _answer = _run(calls=10, window=8_000)

    cleared = _cleared(container)
    assert cleared and all(e["why"] == tac.CLEARED_FOR_WINDOW for e in cleared)
    assert not model.refused
    offered = [tools for _sent, tools in model.seen]
    assert any(tac.READ_EVIDENCE_TOOL in tools for tools in offered)
