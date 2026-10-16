"""The replay runs every check the platform runs on an answer, or names why it cannot.

Each producer composes its checks in its own code: the analyst's validation
turn, the judge's verdict round, the narrative round, the composer's sections
and the tool-call recorder. The replay keeps the same lists
(``scripts.replay.rules``). A check a producer calls that the replay neither
runs nor names as not replayable fails here, and so does a check the replay
lists that the producer no longer calls: a replay that missed the first would
under-count, and one that kept the second would count codes no run raises.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any

import pytest
from scripts.replay import rules

from maljan.agents import evidence_recorder
from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.judge_agent import JudgeAgent
from maljan.reporting.composer import ReportComposer
from maljan.reporting.narrative_agent import NarrativeAgent

# A call of a check-shaped function: ``validate_*``, or a name ending in what
# every check's name ends in.
CHECK_CALL = re.compile(
    r"\b((?:validate_[a-z0-9_]+)"
    r"|(?:[a-z][a-z0-9_]*(?:_violations?|_citations|_contents|_contradictions)))\("
)

# The checks the judge's own parse runs (``JudgeAgent._bundle_from_response``),
# which the replay calls whole rather than one by one.
JUDGE_PARSE_CHECKS = frozenset({"lift_misplaced_extensions", "duplicate_label_violations"})

SITES: dict[str, tuple[Sequence[Callable[..., Any]], Sequence[str], Mapping[str, str]]] = {
    "analysts": ((BaseAnalyst._validate_isr,), rules.ANALYST_CHECKS, rules.ANALYST_NOT_REPLAYED),
    "judge": (
        (JudgeAgent.give_verdict, JudgeAgent._bundle_from_response),
        rules.JUDGE_CHECKS,
        rules.JUDGE_NOT_REPLAYED,
    ),
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
}


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
    listed = {
        *rules.ANALYST_CHECKS,
        *rules.JUDGE_CHECKS,
        *rules.NARRATIVE_CHECKS,
        *rules.COMPOSER_CHECKS,
        *rules.TOOL_CHECKS,
    } - JUDGE_PARSE_CHECKS
    uncalled = sorted(name for name in listed if f"{name}(" not in source)
    assert uncalled == []
    assert "_bundle_from_response(" in source
