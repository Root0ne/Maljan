"""What a run summary says of a pass an evidence-only static provider did not make (T-556).

``operator_choice.static_pass_summary`` is pure: the report node lays its keys
over the run summary the report carries and over the state's, so both say the
run is degraded, why, and which tool it went without.
"""

from __future__ import annotations

from maljan.core.paths import OUTSIDE_PROJECT
from maljan.pipeline.operator_choice import (
    lost_tools,
    provider_pass_reason,
    static_pass_summary,
    with_reasons,
)

WHY = "no rule was loaded from data/capa-rules, which is missing or holds none"
REASON = provider_pass_reason("capa_yara", "capa", WHY, "put the rules in place")


def test_no_reason_is_no_change() -> None:
    assert static_pass_summary({"degraded_mode": False}, []) == {}
    assert static_pass_summary(None, ["", "  "]) == {}


def test_the_run_is_degraded_with_the_reason_after_its_own() -> None:
    summary = {"degraded_mode": False, "degradation_reasons": ["triage.floss_failed"]}

    laid = static_pass_summary(summary, [REASON])

    assert laid["degraded_mode"] is True
    assert laid["degradation_reasons"] == ["triage.floss_failed", REASON]
    assert laid["lost_tools"] == [{"tool": "capa", "reason": WHY}]
    assert summary == {"degraded_mode": False, "degradation_reasons": ["triage.floss_failed"]}


def test_a_reason_or_a_tool_already_there_is_not_said_twice() -> None:
    summary = {
        "degradation_reasons": [REASON],
        "lost_tools": [{"tool": "capa", "reason": "said by the judge"}],
    }

    laid = static_pass_summary(summary, [REASON])

    assert laid["degradation_reasons"] == [REASON]
    assert laid["lost_tools"] == [{"tool": "capa", "reason": "said by the judge"}]


def test_no_summary_is_a_summary_of_these_alone() -> None:
    laid = static_pass_summary(None, [REASON])
    assert laid["degradation_reasons"] == [REASON]
    assert [row["tool"] for row in laid["lost_tools"]] == ["capa"]


def test_a_host_path_in_the_reason_is_masked_when_written() -> None:
    reason = provider_pass_reason("capa_yara", "capa", "no rule in /srv/hk8/capa-rules", "fix")
    (row,) = static_pass_summary({}, [reason])["lost_tools"]
    assert row == {"tool": "capa", "reason": f"no rule in {OUTSIDE_PROJECT}"}


def test_the_reason_names_its_tool_for_the_banner() -> None:
    assert lost_tools([REASON]) == ["capa"]


def test_with_reasons_keeps_the_held_first_and_adds_each_once() -> None:
    assert with_reasons(["a", "b"], ["b", "c", "c"]) == ["a", "b", "c"]
    assert with_reasons(None, ["x"]) == ["x"]
