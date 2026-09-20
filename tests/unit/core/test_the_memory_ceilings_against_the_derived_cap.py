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


def _shipped_windows() -> list[int]:
    """Every distinct window the vendored table can hand out, and the small ones.

    Read from the file rather than listed, so a row added to it is a row this
    is measured against: ``8192`` and ``16384`` are shipped rows, and a claim
    about "the fallback only" was false because of exactly those two.
    """
    import json

    from maljan.core.paths import resolve_data

    raw = json.loads(resolve_data(cw.TABLE_PATH).read_text(encoding="utf-8"))
    return sorted(set(raw["windows"].values()) | {cw.FALLBACK_WINDOW_TOKENS, 4096, 32768})


class TestALoopCannotOutspendItsOwnWindow:
    """The property both ceiling arguments rest on, measured rather than assumed."""

    def test_the_answers_never_sum_past_the_room_they_started_with(self) -> None:
        for window in _shipped_windows():
            assert _spent_by(window, 60) <= _whole_loop_chars(window), window

    def test_the_floor_no_longer_breaks_it_on_any_shipped_window(self) -> None:
        """The floor applies while the room affords it, and never past it."""
        for window in _shipped_windows():
            spent = _spent_by(window, 60, floor=cw.MIN_TOOL_OUTPUT_CHARS)
            assert spent <= _whole_loop_chars(window), window

    def test_the_largest_configured_loop_stays_inside_every_shipped_window(self) -> None:
        """Twenty tool rounds is what the static analyst's forty steps buy."""
        for window in _shipped_windows():
            held = _spent_by(window, 20, floor=cw.MIN_TOOL_OUTPUT_CHARS)
            assert held // cw.CHARS_PER_TOKEN < window, window

    def test_a_loop_that_starts_with_a_chunk_in_it_stays_inside_too(self) -> None:
        """A static loop opens with a 20k-token chunk already in the conversation."""
        for window, preloaded in ((32768, 24000), (32768, 4000), (16384, 4000), (8192, 2000)):
            held = preloaded * cw.CHARS_PER_TOKEN
            for _ in range(20):
                held += cw.derive_tool_output_chars(
                    window_tokens=window, reply_tokens=8192, held_chars=held
                )
            assert held // cw.CHARS_PER_TOKEN <= _whole_loop_chars(window) // cw.CHARS_PER_TOKEN

    def test_a_turn_that_calls_eight_tools_spends_one_turns_room(self) -> None:
        """Each answer is measured after the last, not all against the same figure."""
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        budget.note_conversation("static", 0)
        caps = [budget.chars_for_one_answer() for _ in range(8)]
        assert caps == sorted(caps, reverse=True), caps
        assert sum(caps) < _whole_loop_chars(32768)


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
