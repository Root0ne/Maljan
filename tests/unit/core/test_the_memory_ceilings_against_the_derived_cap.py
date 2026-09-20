"""The two byte ceilings were argued against a 6,000-character answer.

That number is gone: a tool answer is measured against what the served context
window has left. The ceilings did not move — they bound the worker's memory and
a database column, not the model's context, and answering a bigger window by
holding a proportionally bigger corpus is how a machine that also runs the
model runs out of memory. What moved is the arithmetic in their comments, and
that arithmetic is pinned here so it cannot drift away from the constants it
was read off.

The one property it rests on: an answer takes a share of what is *free*, and
what is free is measured again before the next answer, so the answers of one
conversation sum to strictly less than the room it began with — at most
``(window - reply reserve) * chars_per_token`` characters.
"""

from __future__ import annotations

from maljan.core.config import Settings
from maljan.llm import context_window as cw


def _whole_loop_chars(window_tokens: int, reply_tokens: int = 8192) -> int:
    """Everything one loop's tool answers can come to, at this window."""
    reserve = cw.reply_reserve_tokens(window_tokens, reply_tokens)
    return (window_tokens - reserve) * cw.CHARS_PER_TOKEN


def _spent_by(window_tokens: int, answers: int, reply_tokens: int = 8192, floor: int = 0) -> int:
    """What ``answers`` successive answers take, one measured after the last."""
    held = 0
    for _ in range(answers):
        held += cw.derive_tool_output_chars(
            window_tokens=window_tokens,
            reply_tokens=reply_tokens,
            held_chars=held,
            floor=floor,
        )
    return held


class TestALoopCannotOutspendItsOwnWindow:
    def test_the_answers_never_sum_past_the_room_they_started_with(self) -> None:
        for window in (8192, 32768, 131072, 1_000_000):
            assert _spent_by(window, 60) < _whole_loop_chars(window), window

    def test_the_floor_is_where_that_stops_holding(self) -> None:
        """Pinned because it is the one overspend the derivation allows."""
        assert _spent_by(8192, 60, floor=cw.MIN_TOOL_OUTPUT_CHARS) > _whole_loop_chars(8192)

    def test_what_the_floor_costs_the_largest_configured_loop(self) -> None:
        """Twenty tool rounds is what the static analyst's forty steps buy.

        The table in ``MIN_TOOL_OUTPUT_CHARS``'s own comment, as assertions:
        on the windows a probe or the table answers for, the floor spends a
        few hundred tokens of the reply's room at worst; on the fallback,
        where nothing reported a window, it overruns.
        """
        for window, over_window in ((131072, False), (32768, False), (8192, True)):
            held = _spent_by(window, 20, floor=cw.MIN_TOOL_OUTPUT_CHARS)
            held_tokens = held // cw.CHARS_PER_TOKEN
            assert (held_tokens > window) is over_window, window
            if not over_window:
                # Past the free room only into the reply reserve, never far.
                assert held_tokens - _whole_loop_chars(window) // cw.CHARS_PER_TOKEN < 1000


class TestThePerAgentLedgerBudget:
    """``reporting.evidence_budget_bytes`` — half a megabyte, per agent."""

    def test_it_holds_a_whole_loop_on_every_window_this_platform_runs(self) -> None:
        budget = Settings(_env_file=None).reporting.evidence_budget_bytes
        for window in (8192, 32768, 131072):
            assert _whole_loop_chars(window) <= budget, window

    def test_the_window_it_stops_covering_is_the_one_the_comment_names(self) -> None:
        budget = Settings(_env_file=None).reporting.evidence_budget_bytes
        covered = budget // cw.CHARS_PER_TOKEN + cw.DEFAULT_REPLY_TOKENS
        assert 180_000 < covered < 186_000, covered

    def test_a_very_large_window_outgrows_it(self) -> None:
        """Stated rather than fixed: past this the call is kept and the output is not."""
        budget = Settings(_env_file=None).reporting.evidence_budget_bytes
        assert _whole_loop_chars(1_000_000) > budget


class TestTheRunWideGroundingCorpus:
    """``reporting.evidence_corpus_bytes`` — sixteen megabytes, per run."""

    def test_a_six_agent_team_fits_on_the_windows_this_platform_runs(self) -> None:
        ceiling = Settings(_env_file=None).reporting.evidence_corpus_bytes
        for window in (8192, 32768, 131072):
            assert _whole_loop_chars(window) * 6 <= ceiling, window

    def test_the_loops_a_million_token_window_fits_are_the_number_stated(self) -> None:
        ceiling = Settings(_env_file=None).reporting.evidence_corpus_bytes
        loops = ceiling / _whole_loop_chars(1_000_000)
        assert 5.0 < loops < 6.0, loops

    def test_the_ceiling_was_not_scaled_with_the_window(self) -> None:
        """It bounds the worker's memory, and the worker's memory did not grow."""
        assert Settings(_env_file=None).reporting.evidence_corpus_bytes == 16777216


class TestTheShortenersOwnCeiling:
    def test_what_arrives_is_bounded_by_the_parse_and_not_by_the_cap(self) -> None:
        """The cap sizes what is kept; this bounds what the tool sent."""
        assert cw.derive_tool_output_chars(window_tokens=1_000_000) < (
            __import__("maljan.agents.output_shortening", fromlist=["x"]).MAX_SHORTENABLE_CHARS
        )
