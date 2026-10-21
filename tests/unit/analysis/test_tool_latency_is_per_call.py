"""A slow run says whether the model was slow or a tool was.

The loop's own elapsed time cannot tell the two apart, and analyst latency used
to be that one number. Every ledger entry carries the clock of its own round
trip, so the summary carries three figures per agent — how many calls, how long
they took together, and the single slowest with the tool that answered it — and
the loop's log line names that slowest call.
"""

from __future__ import annotations

from typing import Any

from maljan.agents.base_agent import slowest_call
from maljan.analysis.run_summary import RunSummaryBuilder, tool_latency_lines


def _entry(agent: str, tool: str, ms: int, entry_id: str = "ev_0001") -> dict[str, Any]:
    return {"id": entry_id, "agent": agent, "tool": tool, "duration_ms": ms}


def _latency(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    return RunSummaryBuilder(start_time=0.0).set_tool_latency(entries)._tool_latency


class TestWhatTheSummaryCarries:
    def test_each_agent_gets_its_count_its_total_and_its_slowest_call(self) -> None:
        latency = _latency(
            [
                _entry("static", "decompile", 4_000, "ev_0001"),
                _entry("static", "list_imports", 250, "ev_0002"),
                _entry("network", "read_pcap", 900, "ev_0003"),
            ]
        )

        assert latency == {
            "static": {
                "calls": 2,
                "total_ms": 4_250,
                "slowest": {"tool": "decompile", "ms": 4_000, "id": "ev_0001"},
                "over_10s": 0,
                "p50_ms": 250,
                "p95_ms": 4_000,
            },
            "network": {
                "calls": 1,
                "total_ms": 900,
                "slowest": {"tool": "read_pcap", "ms": 900, "id": "ev_0003"},
                "over_10s": 0,
                "p50_ms": 900,
                "p95_ms": 900,
            },
        }

    def test_an_untimed_call_is_counted_and_measures_nothing(self) -> None:
        """A zero duration is an absent measurement, not a fast call."""
        latency = _latency([_entry("static", "peek", 0), _entry("static", "decompile", 30)])

        assert latency["static"]["calls"] == 2
        assert latency["static"]["total_ms"] == 30
        assert latency["static"]["slowest"]["tool"] == "decompile"

    def test_a_ledger_with_no_timed_call_leaves_the_field_absent(self) -> None:
        assert _latency([_entry("static", "peek", 0)])["static"]["slowest"] is None

    def test_a_run_with_no_ledger_carries_nothing(self) -> None:
        assert _latency([]) is None

    def test_a_row_with_no_agent_or_no_tool_is_not_a_measurement(self) -> None:
        assert _latency([_entry("", "decompile", 10), _entry("static", "", 10)]) is None

    def test_it_reaches_the_dict_a_consumer_reads(self) -> None:
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_sample("abc", None)
            .set_verdict("Malware", 3)
            .set_tool_latency([_entry("static", "decompile", 4_000)])
            .build()
        )

        assert summary.to_dict()["tool_latency"]["static"]["slowest"]["tool"] == "decompile"


class TestTheSpreadOfAnAgentsCalls:
    def test_percentiles_are_nearest_rank_over_a_known_list(self) -> None:
        ms = [5, 1, 9, 3, 7, 2, 8, 4, 6, 10, 20, 15, 12, 11, 13, 14, 16, 17, 18, 19]
        latency = _latency([_entry("static", f"t{v}", v * 1_000) for v in ms])["static"]

        # n=20: rank ceil(0.50*20)=10 -> 10 s, rank ceil(0.95*20)=19 -> 19 s.
        assert latency["p50_ms"] == 10_000
        assert latency["p95_ms"] == 19_000
        assert latency["over_10s"] == 10
        assert latency["slowest"]["ms"] == 20_000

    def test_equal_durations_and_a_single_call_select_correctly(self) -> None:
        same = _latency([_entry("a", "t", 77) for _ in range(50)])["a"]
        assert (same["p50_ms"], same["p95_ms"]) == (77, 77)
        one = _latency([_entry("a", "t", 12_000)])["a"]
        assert (one["p50_ms"], one["p95_ms"], one["over_10s"]) == (12_000, 12_000, 1)

    def test_selection_agrees_with_a_sort_on_many_lists(self) -> None:
        import random

        from maljan.analysis.run_summary import nearest_rank

        rng = random.Random(7)
        for _ in range(200):
            values = [rng.randint(1, 30) for _ in range(rng.randint(1, 60))]
            ordered = sorted(values)
            for percent in (50, 95):
                rank = max(1, -(-percent * len(values) // 100))
                assert nearest_rank(list(values), percent) == ordered[rank - 1]

    def test_the_line_shows_the_spread_only_when_the_row_has_it(self) -> None:
        new = tool_latency_lines(
            _latency([_entry("static", "decompile", 4_000), _entry("static", "peek", 12_000)])
        )
        assert new == [
            "**Tool calls**: static 2 calls in 16.0s, slowest `peek` 12.0s, "
            "p50 4.0s, p95 12.0s, 1 over 10s  "
        ]

    def test_a_stored_row_without_the_fields_reads_as_it_always_did(self) -> None:
        stored = {
            "static": {
                "calls": 1,
                "total_ms": 4_000,
                "slowest": {"tool": "decompile", "ms": 4_000, "id": "ev_0001"},
            }
        }
        assert tool_latency_lines(stored) == [
            "**Tool calls**: static 1 calls in 4.0s, slowest `decompile` 4.0s  "
        ]


class TestTheLineAReaderSees:
    def test_it_names_the_agent_its_calls_and_the_slowest_tool(self) -> None:
        lines = tool_latency_lines(_latency([_entry("static", "decompile", 4_000)]))

        assert lines == [
            "**Tool calls**: static 1 calls in 4.0s, slowest `decompile` 4.0s, "
            "p50 4.0s, p95 4.0s, 0 over 10s  "
        ]

    def test_an_agent_whose_calls_were_never_timed_draws_no_row(self) -> None:
        assert tool_latency_lines(_latency([_entry("static", "peek", 0)])) == []

    def test_nothing_is_drawn_for_a_run_that_made_no_call(self) -> None:
        assert tool_latency_lines(None) == []


def test_the_pipeline_hands_the_summary_the_ledger_it_measures() -> None:
    """The figures are only as real as the list they are computed from.

    Everything above works on a list handed in by hand; what makes the field
    appear on a real run is that the report node passes the run's own evidence
    ledger, which is the list the per-call clock is written onto.
    """
    import inspect
    import re

    from maljan.pipeline import nodes

    source = inspect.getsource(nodes)
    assert re.search(r"set_tool_latency\(\s*state\.get\(\"evidence_ledger\"\)", source)


class _Entry:
    def __init__(self, tool: str, duration_ms: int) -> None:
        self.tool = tool
        self.duration_ms = duration_ms


class TestTheClauseOnTheLoopSLogLine:
    def test_it_names_the_slowest_call_and_what_it_cost(self) -> None:
        clause = slowest_call([_Entry("list_imports", 250), _Entry("decompile", 4_000)])

        assert clause == ", slowest decompile 4.0s"

    def test_a_loop_whose_calls_were_never_timed_says_nothing_extra(self) -> None:
        assert slowest_call([_Entry("peek", 0)]) == ""

    def test_a_loop_that_called_nothing_says_nothing_extra(self) -> None:
        assert slowest_call([]) == ""
