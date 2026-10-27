"""The replay runs every check the platform runs on an answer, or names why it cannot.

The analysts' and the judge's checks are composed once, by functions the
producer and the replay both call (``validation.analyst_answer_checks``,
``validation.settle_validation_marks``, ``judge_agent.verdict_bundle_checks``):
the names the producers call are those functions, and each is called by the
producer and by the replay, which a recorder in its place sees. The
narrative's, the composer's and the tool recorder's checks are still listed by
the replay (``scripts.replay.rules``): a check a producer calls that the
replay neither runs nor names fails here, and so does a check the replay lists
that the producer no longer calls. The oracle test holds the replay's whole
report to the real judge and report nodes.
"""

from __future__ import annotations

import inspect
import logging
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any

import pytest
from scripts.replay import rules
from scripts.replay.rules import replay_run
from scripts.replay.stored import read_run

from maljan.agents import base_agent, evidence_recorder, judge_agent
from maljan.agents.base_agent import BaseAnalyst
from maljan.pipeline import validation
from maljan.reporting import section_agreement
from maljan.reporting.composer import ReportComposer
from maljan.reporting.narrative_agent import NarrativeAgent
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.unit.scripts._replay_tiny import FIXTURE

# A call of a check-shaped function: ``validate_*``, or a name ending in what
# every check's name ends in.
CHECK_CALL = re.compile(
    r"\b((?:validate_[a-z0-9_]+)"
    r"|(?:[a-z][a-z0-9_]*(?:_violations?|_citations|_contents|_contradictions)))\("
)

SITES: dict[str, tuple[Sequence[Callable[..., Any]], Sequence[str], Mapping[str, str]]] = {
    "narrative": (
        (NarrativeAgent.generate, NarrativeAgent._kept_with_ungrounded_recorded),
        rules.NARRATIVE_CHECKS,
        {},
    ),
    "composer": (
        (ReportComposer.compose, ReportComposer._invoke),
        rules.COMPOSER_CHECKS,
        rules.COMPOSER_NOT_REPLAYED,
    ),
    "tool": ((evidence_recorder._record_tool,), rules.TOOL_CHECKS, {}),
    "agreement": (
        (section_agreement._ask, section_agreement._rewrite_violations),
        (),
        rules.AGREEMENT_NOT_REPLAYED,
    ),
}

# The compositions the producers and the replay share, by the module each
# producer calls it from.
SHARED: tuple[tuple[Any, str, Any], ...] = (
    (base_agent, "analyst_answer_checks", validation.analyst_answer_checks),
    (base_agent, "whole_answer_questions", validation.whole_answer_questions),
    (base_agent, "settle_validation_marks", validation.settle_validation_marks),
    (base_agent, "analyst_ledger_ids", validation.analyst_ledger_ids),
    (base_agent, "run_image_bases", validation.run_image_bases),
    (base_agent, "AnswerCheckInputs", validation.AnswerCheckInputs),
)


def _source(methods: Sequence[Callable[..., Any]]) -> str:
    return "\n".join(inspect.getsource(method) for method in methods)


@pytest.mark.parametrize("site", sorted(SITES))
def test_every_check_a_producer_calls_is_replayed_or_named(site: str) -> None:
    methods, checks, not_replayed = SITES[site]
    called = set(CHECK_CALL.findall(_source(methods)))
    unknown = sorted(called - set(checks) - set(not_replayed))
    assert unknown == [], f"the {site} producer calls checks the replay does not know: {unknown}"


@pytest.mark.parametrize("site", sorted(SITES))
def test_every_check_the_replay_lists_is_one_the_producer_calls(site: str) -> None:
    methods, checks, not_replayed = SITES[site]
    source = _source(methods)
    stale = sorted(name for name in [*checks, *not_replayed] if f"{name}(" not in source)
    assert stale == [], f"the replay lists checks the {site} producer no longer calls: {stale}"


def test_the_replay_calls_every_check_it_lists() -> None:
    source = inspect.getsource(rules)
    listed = {*rules.NARRATIVE_CHECKS, *rules.COMPOSER_CHECKS, *rules.TOOL_CHECKS}
    uncalled = sorted(name for name in listed if f"{name}(" not in source)
    assert uncalled == []
    assert "_bundle_from_response(" in source


@pytest.mark.parametrize(("module", "name", "shared"), SHARED, ids=[n for _m, n, _s in SHARED])
def test_the_analyst_calls_the_shared_composition(module: Any, name: str, shared: Any) -> None:
    assert getattr(module, name) is shared
    assert f"{name}(" in inspect.getsource(BaseAnalyst._validate_isr) + inspect.getsource(
        BaseAnalyst
    )


def test_the_judge_calls_the_shared_composition() -> None:
    source = inspect.getsource(judge_agent.JudgeAgent.give_verdict)
    assert "verdict_bundle_checks(" in source and "VerdictCheckInputs(" in source
    assert "verdict_checks(bundle, inputs)" in source


class _Analyst(BaseAnalyst):
    def __init__(self) -> None:
        self.name = "static"
        self.logger = logging.getLogger("test.shared")
        self.validation_not_run = []

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def test_the_producer_and_the_replay_both_call_it(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, list[Any]] = {"analyst": [], "replay": [], "judge": []}

    def _recorder(who: str, real: Callable[..., Any]) -> Callable[..., Any]:
        def _record(*args: Any, **kwargs: Any) -> Any:
            calls[who].append(args[1] if len(args) > 1 else None)
            return real(*args, **kwargs)

        return _record

    real = validation.analyst_answer_checks
    monkeypatch.setattr(base_agent, "analyst_answer_checks", _recorder("analyst", real))
    monkeypatch.setattr(validation, "analyst_answer_checks", _recorder("replay", real))
    monkeypatch.setattr(
        judge_agent, "verdict_bundle_checks", _recorder("judge", judge_agent.verdict_bundle_checks)
    )
    agent = _Analyst()
    agent._evidence_entries = []
    agent.pack_ledger_ids = ["ev_0001"]
    agent.sample_format = ("pe", "windows")
    claim = ClaimEvidence(
        claim="It injects into a remote process.",
        evidence_ref="[ev_0001]",
        confidence=0.6,
        technique_id="T1055",
    )
    monkeypatch.setattr(BaseAnalyst, "_seconds_the_last_loop_left", lambda *_a, **_k: 0.0)
    agent._validate_isr(AgentISR(agent_id="static", domain="static", claims=[claim]), "evidence")
    (inputs,) = calls["analyst"][:1]
    assert isinstance(inputs, validation.AnswerCheckInputs)
    assert list(inputs.ledger_ids) == ["ev_0001"]
    assert dict(inputs.sample) == {"file_type": "pe", "platform": "windows"}

    replay_run(read_run(FIXTURE))
    assert calls["replay"] and all(
        isinstance(i, validation.AnswerCheckInputs) for i in calls["replay"]
    )
    assert calls["judge"], "the replay asks the judge's round through the shared composition"
