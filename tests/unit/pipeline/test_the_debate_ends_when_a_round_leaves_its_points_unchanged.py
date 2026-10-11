"""A revision round that leaves the contested points as they were ends the debate.

The router reads each mediation's blocking lines as contested points
(``debate_facts.point_key``: the analysts its field names, the ledger ids, hex
values and decimal numbers it writes, claim numbers aside, and its words when
it writes none of those). When the round before a mediation revised analysts
and that mediation's points are the last mediation's points, none resolved and
none new, another round would argue the same points: the debate goes to the
judge with its own end reason, ``contested_points_unchanged``, and no
consensus is claimed. Points that changed, or a round that revised nobody,
follow the rules they always did.

Every value is synthetic.
"""

from __future__ import annotations

import time
from typing import Any

from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.pipeline.debate_facts import point_key, same_points
from maljan.pipeline.routing import (
    NO_CONSENSUS,
    NOT_REVISED,
    POINTS_UNCHANGED,
    debate_route,
    points_unchanged,
)
from maljan.pipeline.state import AgentArgument

COUNTS = (
    "[analysts: TRIAGE ANALYST, STATIC] TRIAGE claim 6 says 101 strings and STATIC claim 4 "
    "says 81 from routine 0xae78 [ev_0019] [ev_0021]. [blocking: restate the counts]"
)
COUNTS_REWORDED = (
    "[analysts: static, triage] The decoder count (101) and the emulated count (81) for "
    "0xAE78 still disagree in STATIC claim 9 and TRIAGE claim 2 ([ev_0021], [ev_0019]). "
    "[blocking: the two counts are not one routine's]"
)
EXPORTS = "[analysts: network] NETWORK claim 3 names 5 exports; [ev_0004] states 4. [blocking: x]"
WORDING = "[analysts: dynamic] DYNAMIC calls the parent unknown. [blocking: wording]"


def _mediator(lines: list[str], status: str = "complete") -> AgentArgument:
    return AgentArgument(
        agent_name="Mediator",
        finding="x",
        confidence_score=0.6,
        contradictions=list(lines),
        status=status,
    )


def _state(before: list[str], after: list[str], made: int = 3, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "iteration_count": 2,
        "is_consensus": False,
        "consensus_applicable": True,
        "sycophancy_detected": False,
        "confidence_history": [0.6, 0.6],
        "discussion_history": [_mediator(before), _mediator(after)],
        "isr_reports": {},
        "revision_rounds": [
            {"round": 1, "stage": "debate", "made": made, "identical": False, "revised": []}
        ],
    }
    base.update(over)
    return base


class TestAPointIsWhatItIsAbout:
    def test_a_reworded_line_about_the_same_counts_is_the_same_point(self) -> None:
        assert point_key(COUNTS) == point_key(COUNTS_REWORDED)

    def test_claim_numbers_are_left_out(self) -> None:
        assert point_key(COUNTS).numbers == (81, 101)

    def test_the_mark_and_its_reason_are_left_out(self) -> None:
        a = point_key(EXPORTS)
        b = point_key(EXPORTS.replace("[blocking: x]", "[blocking: ev_0099 says 7]"))
        assert a == b

    def test_another_analyst_holding_it_is_another_point(self) -> None:
        moved = COUNTS.replace("TRIAGE ANALYST, STATIC", "ALL_TOOLS_STATIC_R2")
        assert point_key(COUNTS) != point_key(moved)

    def test_a_changed_number_is_another_point(self) -> None:
        assert point_key(EXPORTS) != point_key(EXPORTS.replace("states 4", "states 6"))

    def test_a_line_that_cites_and_counts_nothing_is_read_by_its_words(self) -> None:
        key = point_key(WORDING)
        assert key.words == ("dynamic", "calls", "the", "parent", "unknown")
        assert point_key(WORDING) != point_key(WORDING.replace("unknown", "the sandbox"))

    def test_the_same_points_in_another_order_are_the_same(self) -> None:
        assert same_points([COUNTS, EXPORTS], [EXPORTS, COUNTS_REWORDED])

    def test_a_resolved_point_or_a_new_one_is_a_change(self) -> None:
        assert not same_points([COUNTS, EXPORTS], [COUNTS])
        assert not same_points([COUNTS], [COUNTS, EXPORTS])

    def test_no_point_on_either_side_is_not_the_same_points(self) -> None:
        assert not same_points([], [])
        assert not same_points([COUNTS], [])

    def test_a_hostile_line_is_read_in_linear_time(self) -> None:
        timings = []
        for n in (2000, 20000):
            line = "[analysts: a] " + " ".join(f"{i} 0x{i:x} ev_{i:04d}" for i in range(n))
            start = time.perf_counter()
            point_key(line)
            timings.append(time.perf_counter() - start)
        assert timings[1] < timings[0] * 10 * 4 + 0.5


class TestTheRouter:
    def test_unchanged_points_after_a_round_that_revised_end_the_debate(self) -> None:
        state = _state([COUNTS, EXPORTS], [EXPORTS, COUNTS_REWORDED])

        assert points_unchanged(state)
        assert debate_route(state, max_rounds=5) == ("judge", POINTS_UNCHANGED)

    def test_no_consensus_is_claimed(self) -> None:
        state = _state([COUNTS], [COUNTS_REWORDED])

        route, reason = debate_route(state, max_rounds=5)

        assert (route, reason) == ("judge", POINTS_UNCHANGED)
        assert reason != "consensus"

    def test_points_that_changed_go_on_to_another_round(self) -> None:
        state = _state([COUNTS, EXPORTS], [COUNTS])

        assert debate_route(state, max_rounds=5) == ("revision", NO_CONSENSUS)

    def test_a_round_that_revised_nobody_ends_as_not_revised(self) -> None:
        state = _state([COUNTS], [COUNTS], made=0)

        assert debate_route(state, max_rounds=5) == ("judge", NOT_REVISED)

    def test_a_failed_mediation_is_not_read_as_unchanged_points(self) -> None:
        state = _state([COUNTS], [COUNTS])
        state["discussion_history"] = [_mediator([COUNTS]), _mediator([COUNTS], status="timeout")]

        assert not points_unchanged(state)

    def test_the_first_mediation_has_nothing_to_compare(self) -> None:
        state = _state([COUNTS], [COUNTS])
        state["discussion_history"] = [_mediator([COUNTS])]

        assert not points_unchanged(state)

    def test_at_the_limit_the_reason_is_the_rule_that_ended_it(self) -> None:
        state = _state([COUNTS], [COUNTS_REWORDED], iteration_count=5)
        state["revision_rounds"][0]["round"] = 4

        assert debate_route(state, max_rounds=5) == ("judge", POINTS_UNCHANGED)


class TestTheRunSummarySaysIt:
    def test_the_termination_reason_is_its_own(self) -> None:
        state = _state([COUNTS], [COUNTS_REWORDED])

        negotiation = (
            RunSummaryBuilder(start_time=0.0)
            .set_negotiation(state, max_iterations=5)
            .build()
            .negotiation
        )

        assert negotiation.termination_reason == POINTS_UNCHANGED
        assert negotiation.converged_early is True
