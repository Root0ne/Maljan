"""The report node answers the questions a job was asked, and asks nothing of a job asked none.

Driven through the node, the way a run reaches it: the questions on the state
reach the reporter's model after the narrative round, the answers checked by
code are on the stored report and in the served markdown, and a job with no
question makes no call and stores no answers. A stopped run keeps each
question, not determinable, with why.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import AIMessage

from maljan.pipeline.stopped_run import QUESTIONS_STOPPED, partial_report
from maljan.pipeline.validation import ValidationTally
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers import MarkdownRenderer
from tests.stages import paper_profile
from tests.unit.pipeline.test_what_is_served_is_the_final_report import _state

QUESTION = "What is the C2 address?"


class _Reporter:
    """A narrative agent that writes no narrative and answers the question round."""

    llm = None

    def __init__(self, answer: dict[str, Any]) -> None:
        self.answer = answer
        self.asked: list[str] = []
        self.validation_tally = ValidationTally()
        self.degradations: list[str] = []

    def round_timeout(self, configured: Any, prompt_chars: int = 0) -> Any:
        return None

    def prompt_chars(self, *args: Any, **kwargs: Any) -> int:
        return 0

    async def generate(self, *args: Any, **kwargs: Any) -> Any:
        return None

    async def ask(self, turns: list[Any], *, call: str, what: str) -> Any:
        self.asked.append(call)
        return AIMessage(content=json.dumps(self.answer))


def _container(reporter: Any) -> Any:
    fake = MagicMock()
    fake.agent_registry.list_agents.return_value = ["static"]
    fake.analyst_keys.return_value = ["static"]
    fake.agent_role.side_effect = lambda n: n
    fake.is_mock = False
    fake.config.reporting.enabled = True
    fake.config.llm.parallel_analysts = False
    fake.config.negotiation.max_iterations = 3
    fake.active_profile.return_value = paper_profile(["static"], parallel=False)
    fake.get_narrative_agent.return_value = reporter
    fake.get_report_composer.return_value = None
    fake.get_static_provider.return_value.capabilities.provides_evidence = False
    return fake


async def _run(container: Any, state: dict[str, Any]) -> dict[str, Any]:
    from maljan.pipeline.nodes import make_report_node

    stage = next(step for step in container.active_profile().stages if step.kind == "report")
    node = make_report_node(container, stage=stage, announces=False)
    return await node(state)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_a_question_is_answered_checked_stored_and_printed() -> None:
    reporter = _Reporter(
        {"answers": [{"question": 1, "outcome": "out_of_scope", "answer": "No sample says."}]}
    )
    state = _state()
    state["analyst_questions"] = [QUESTION]

    result = await _run(_container(reporter), state)

    assert reporter.asked == ["questions"]
    stored = MalwareReport.model_validate(result["malware_report"])
    (answer,) = stored.question_answers
    assert (answer.question, answer.outcome, answer.answer) == (
        QUESTION,
        "out_of_scope",
        "No sample says.",
    )
    served = MarkdownRenderer().render(stored)
    assert f"### Q1. {QUESTION}" in served
    assert "**Outcome:** out of scope" in served


@pytest.mark.asyncio
async def test_a_job_asked_nothing_makes_no_call_and_stores_no_answers() -> None:
    reporter = _Reporter({"answers": []})

    result = await _run(_container(reporter), _state())

    assert reporter.asked == []
    assert "question_answers" not in result["malware_report"]


@pytest.mark.asyncio
async def test_with_no_report_model_each_question_is_not_determinable() -> None:
    state = _state()
    state["analyst_questions"] = [QUESTION]

    result = await _run(_container(None), state)

    (answer,) = MalwareReport.model_validate(result["malware_report"]).question_answers
    assert answer.outcome == "not_determinable"
    assert answer.checks == ["no report model ran in this run"]


def test_a_stopped_run_keeps_each_question_not_determinable() -> None:
    state = _state()
    state["analyst_questions"] = [QUESTION]
    state["malware_report"] = {"executive_summary": "", "degradation_reasons": []}

    report = partial_report(state, MagicMock(), note="stopped")

    assert report is not None
    (answer,) = report["question_answers"]
    assert answer["outcome"] == "not_determinable"
    assert answer["checks"] == [QUESTIONS_STOPPED]


def test_a_stopped_run_asked_nothing_carries_no_answers() -> None:
    state = _state()
    state["malware_report"] = {"executive_summary": "", "degradation_reasons": []}

    report = partial_report(state, MagicMock(), note="stopped")

    assert report is not None
    assert "question_answers" not in report


def test_a_run_stopped_before_its_first_step_still_prints_each_question() -> None:
    from types import SimpleNamespace

    from maljan.pipeline.stopped_run import stopped_state

    # Stopped while the sandbox submission ran: no graph step completed, so
    # the state is empty and the questions are known only to the app.
    app = SimpleNamespace(
        built_report=None,
        latest_state={},
        questions=[QUESTION],
        container=SimpleNamespace(report_in_progress=None),
    )

    state = stopped_state(app)
    report = partial_report(state, app.container, note="stopped")

    assert state["analyst_questions"] == [QUESTION]
    assert report is not None
    (answer,) = report["question_answers"]
    assert (answer["question"], answer["outcome"]) == (QUESTION, "not_determinable")
    assert answer["checks"] == [QUESTIONS_STOPPED]
