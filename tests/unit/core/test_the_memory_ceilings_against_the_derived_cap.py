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
        with cw.answering_for("static"):
            budget.note_conversation("static", 0)
            caps = [budget.chars_for_one_answer() for _ in range(8)]
        assert caps == sorted(caps, reverse=True), caps
        assert sum(caps) < _whole_loop_chars(32768)

    def test_a_wide_fan_out_cannot_spend_the_room_twice(self) -> None:
        """The sum saturates: no fan-out takes more than one turn's room."""
        for fan_out in (8, 16, 32, 128):
            budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
            with cw.answering_for("static"):
                budget.note_conversation("static", 0)
                spent = sum(budget.chars_for_one_answer() for _ in range(fan_out))
            assert spent < _whole_loop_chars(32768), fan_out

    def test_a_second_analyst_cannot_clear_the_first_ones_spending(self) -> None:
        """One process-wide slot gave back the whole free room at a fan-out of sixteen."""
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        budget.note_conversation("static", 0)
        budget.note_conversation("network", 0)
        spent = 0
        for _ in range(16):
            with cw.answering_for("static"):
                spent += budget.chars_for_one_answer()
            # The other analyst refreshes between every one of A's calls.
            budget.note_conversation("network", 0)
        assert spent < _whole_loop_chars(32768)


# A standing run-state block, charged once because it is replaced on every
# model turn rather than appended to the conversation.
_RUN_STATE_BLOCK = 200


def _loop(window: int, rounds: int, preload: int = 0) -> int:
    """One agent's conversation after ``rounds``, in tokens, notices included.

    Drives the real budget the way the guardrail and the tool wrapper do:
    an answer is capped and charged, the first cap of zero is met with the
    sentence, and every call after that is refused with the short notice.
    Both notices are charged, and both are withheld when they would not fit.
    """
    sentence = len(cw.no_room_sentence(120_000))
    ended = len(cw.TOOL_PHASE_ENDED_NOTICE)
    budget = cw.ContextBudget(cw.WindowFact(window, cw.PROBED, "props"), reply_tokens=8192)
    held = preload * cw.CHARS_PER_TOKEN + _RUN_STATE_BLOCK
    with cw.answering_for("static"):
        budget.note_conversation("static", held)
        for _ in range(rounds):
            if budget.out_of_room("static"):
                if budget.room_for(ended, "static"):
                    budget.charge(ended)
                    held += ended
                continue
            cap = budget.chars_for_one_answer()
            if cap == 0:
                # ``note_no_room`` charges the standing run-state line itself,
                # once and only when it fits, so the caller adds it to its own
                # tally rather than charging it a second time.
                budget.note_no_room()
                if budget.says_no_room("static"):
                    held += len(cw.NO_ROOM_RUN_STATE)
                if budget.room_for(sentence, "static"):
                    budget.charge(sentence)
                    held += sentence
            else:
                held += cap
    assert held == budget.held_chars("static"), (held, budget.held_chars("static"))
    return held // cw.CHARS_PER_TOKEN


class TestTheReplyReserveIsNeverSpentOnSayingTheRoomRanOut:
    """Answers *and* refusals stay inside the tool budget, not just the window.

    Two rounds of this: first the refusal sentence was uncharged, which put a
    4,096-token window past itself; then it was charged but measured against
    the whole window, so on the shipped 8,192 rows the refusals took half the
    reply reserve and on 4,096 three quarters — leaving the forced synthesis,
    which is this design's own answer to a full conversation, 257 tokens to
    write in. Both notices are now measured against the window less the
    reserve, which is the same budget a cap comes out of.
    """

    ROUNDS = (20, 40, 60)

    def test_the_tool_budget_is_never_exceeded_on_any_shipped_window(self) -> None:
        for window in _shipped_windows():
            budget = _whole_loop_chars(window) // cw.CHARS_PER_TOKEN
            for rounds in self.ROUNDS:
                assert _loop(window, rounds) <= budget, (window, rounds)

    def test_the_whole_reply_reserve_survives_the_longest_loop(self) -> None:
        for window in _shipped_windows():
            reserve = cw.reply_reserve_tokens(window, 8192)
            assert window - _loop(window, 60) >= reserve, window

    def test_a_loop_that_starts_with_a_chunk_in_it_keeps_its_reserve_too(self) -> None:
        for window, preload in ((32768, 24000), (32768, 4000), (16384, 4000), (8192, 2000)):
            reserve = cw.reply_reserve_tokens(window, 8192)
            for rounds in self.ROUNDS:
                assert window - _loop(window, rounds, preload) >= reserve, (window, preload)

    def test_a_preload_past_the_budget_is_handed_nothing_at_all(self) -> None:
        """The operator put more prompt in than the window holds; nothing is added."""
        held = [_loop(4096, rounds, 4000) for rounds in self.ROUNDS]
        assert len(set(held)) == 1, held

    def test_a_wide_fan_out_stays_inside_the_tool_budget_on_a_tiny_window(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(4096, cw.PROBED, "props"), reply_tokens=8192)
        with cw.answering_for("static"):
            budget.note_conversation("static", 0)
            spent = sum(budget.chars_for_one_answer() for _ in range(128))
        assert spent <= budget.tool_budget_chars()

    def test_both_notices_are_withheld_once_they_would_reach_the_reserve(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(8192, cw.PROBED, "props"), reply_tokens=8192)
        with cw.answering_for("static"):
            budget.note_conversation("static", budget.tool_budget_chars())
            assert budget.room_for(len(cw.TOOL_PHASE_ENDED_NOTICE)) is False
            assert budget.room_for(len(cw.no_room_sentence(1))) is False

    def test_the_budget_a_notice_is_measured_against_is_not_the_window(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(8192, cw.PROBED, "props"), reply_tokens=8192)
        assert budget.tool_budget_chars() == (8192 - budget.reply_tokens) * cw.CHARS_PER_TOKEN
        assert budget.tool_budget_chars() < 8192 * cw.CHARS_PER_TOKEN

    def test_nothing_the_real_guardrail_returns_outruns_the_tool_budget(self) -> None:
        """The whole claim, through the guardrail itself rather than a stand-in.

        Plain text, so the shortener declines and the character cut runs — the
        branch whose marker used to be appended after the cut and charged to
        nobody. Twenty characters a call, self-correcting between model turns
        and not inside one, where a wide fan-out leaked every answer's own.
        """
        import logging

        from maljan.agents.mcp_client import MCPLangChainToolkit

        logging.disable(logging.WARNING)
        try:
            text = "a decompiled function, in C. " * 200_000
            for window in (4096, 8192, 32768, 131072):
                budget = cw.ContextBudget(
                    cw.WindowFact(window, cw.PROBED, "props"), reply_tokens=8192
                )
                toolkit = MCPLangChainToolkit(max_output_chars=0, context_budget=budget)
                held = 0
                with cw.answering_for("static"):
                    budget.note_conversation("static", 0)
                    for _ in range(60):
                        if budget.out_of_room("static"):
                            continue
                        held += len(toolkit._apply_output_guardrail(text))
                assert held <= budget.tool_budget_chars(), (window, held)
                assert budget.held_chars("static") <= budget.tool_budget_chars(), window
        finally:
            logging.disable(logging.NOTSET)

    def test_a_wide_fan_out_through_the_real_guardrail_stays_inside_too(self) -> None:
        """The one place the marker used to compound rather than stay constant."""
        import logging

        from maljan.agents.mcp_client import MCPLangChainToolkit

        logging.disable(logging.WARNING)
        try:
            text = "a decompiled function, in C. " * 200_000
            for window, fan_out in ((32768, 32), (32768, 128), (4096, 128)):
                budget = cw.ContextBudget(
                    cw.WindowFact(window, cw.PROBED, "props"), reply_tokens=8192
                )
                toolkit = MCPLangChainToolkit(max_output_chars=0, context_budget=budget)
                with cw.answering_for("static"):
                    budget.note_conversation("static", 0)
                    spent = sum(len(toolkit._apply_output_guardrail(text)) for _ in range(fan_out))
                assert spent <= budget.tool_budget_chars(), (window, fan_out, spent)
        finally:
            logging.disable(logging.NOTSET)

    def test_the_marker_comes_out_of_the_limit_rather_than_after_it(self) -> None:
        from maljan.agents import ghidra_http_client, mcp_client

        for module in (mcp_client, ghidra_http_client):
            assert module.truncation_target(4000) == 4000 - len(module.TRUNCATION_MARKER)
            assert module.truncation_target(5) == 0, "a limit under the marker keeps nothing"

    def test_an_unknown_window_never_withholds_a_refusal(self) -> None:
        """Nothing was measured, so nothing may be refused on its strength."""
        budget = cw.ContextBudget(cw.unknown_window())
        assert budget.room_for(10_000_000) is True


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
