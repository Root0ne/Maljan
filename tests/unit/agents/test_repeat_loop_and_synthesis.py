"""A loop that only repeats itself is ended, and the salvage keeps its evidence.

Two live runs. A static analyst spent 16 of its 19 steps calling ``pe_info``
with identical arguments and being told each time that the answer sits in
ev_0002; another spent 11 on one ``strings`` regex. Being told where the answer
is does not stop a model that has decided to ask again, so the third served
repeat ends the loop and hands what was gathered to forced synthesis.

The salvage then has to keep what it is asked to synthesise. A fixed
16,000-character budget cut 21 of 41 messages on one of those runs and dropped
a tool result while keeping the call that referenced it, and the analyst wrote
"no malicious strings were visible in ev_0007 (referenced but not displayed)".
"""

from __future__ import annotations

from typing import Any

from maljan.agents.base_agent import (
    _SYNTHESIS_MIN_CHARS,
    _trim_for_synthesis,
    ledger_ids_in,
    synthesis_budget_chars,
)
from maljan.agents.evidence_recorder import RepeatGuard, served_repeat_notice
from maljan.core.config import Settings


def _ai(content: str = "", tool: str = "") -> Any:
    """An assistant turn, with or without a tool call, as langgraph builds it."""
    from langchain_core.messages import AIMessage

    if not tool:
        return AIMessage(content=content)
    return AIMessage(
        content=content,
        tool_calls=[{"name": tool, "args": {"path": "/tmp/s.bin"}, "id": f"call_{tool}"}],
    )


def _result(text: str, tool: str) -> Any:
    from langchain_core.messages import ToolMessage

    return ToolMessage(content=text, tool_call_id=f"call_{tool}")


def _system(text: str) -> Any:
    from langchain_core.messages import SystemMessage

    return SystemMessage(content=text)


def _human(text: str) -> Any:
    from langchain_core.messages import HumanMessage

    return HumanMessage(content=text)


class TestTheGuardEndsTheLoop:
    def _served(self, guard: RepeatGuard, tool: str = "pe_info") -> str | None:
        """One call that has been made before, as the wrapper asks it."""
        args = {"path": "/tmp/sample.bin"}
        guard.note(tool, args, "ev_0002")
        return guard.repeat_of(tool, args)

    def test_a_served_repeat_is_counted_across_the_whole_loop(self) -> None:
        guard = RepeatGuard()

        self._served(guard, "pe_info")
        self._served(guard, "strings")

        assert guard.served_repeats == 2

    def test_the_second_notice_says_the_loop_is_about_to_end(self) -> None:
        guard = RepeatGuard()
        self._served(guard, "pe_info")
        self._served(guard, "strings")

        notice = served_repeat_notice(
            "strings", "ev_0002", ("pattern",), last_warning=guard.warning_of_the_end()
        )

        assert "One more repeated call ends this analysis" in notice

    def test_the_first_notice_does_not(self) -> None:
        guard = RepeatGuard()
        self._served(guard, "pe_info")

        notice = served_repeat_notice(
            "pe_info", "ev_0002", (), last_warning=guard.warning_of_the_end()
        )

        assert "ends this analysis" not in notice
        assert "A third will not be run" in notice

    def test_the_third_ends_the_loop(self) -> None:
        guard = RepeatGuard()

        self._served(guard, "pe_info")
        assert guard.ending_the_loop() is False
        self._served(guard, "strings")
        assert guard.ending_the_loop() is False
        self._served(guard, "hashes")

        assert guard.ending_the_loop() is True

    def test_a_loop_that_asks_different_things_is_left_alone(self) -> None:
        guard = RepeatGuard()
        for index in range(5):
            guard.note("strings", {"pattern": f"marker{index}"}, f"ev_000{index}")

        assert guard.served_repeats == 0
        assert guard.ending_the_loop() is False

    def test_the_analyst_loop_ends_and_synthesises_on_it(self) -> None:
        """The wiring: the stream is broken and the salvage is the same one a
        spent step budget takes."""
        import inspect

        from maljan.agents import base_agent

        source = inspect.getsource(base_agent.BaseAnalyst.execute_tool_loop)

        assert "if repeats.ending_the_loop():" in source
        assert "ended_on_repeats = repeats.ending_the_loop()" in source
        assert "hit_step_cap or ended_on_repeats" in source


class TestTheSynthesisBudget:
    def test_an_unknown_context_holds_the_floor(self) -> None:
        settings = Settings(_env_file=None, llm={"openai": {"context_size": 0}})

        assert synthesis_budget_chars(settings, "static") == _SYNTHESIS_MIN_CHARS

    def test_a_known_context_gives_two_fifths_of_it_in_characters(self) -> None:
        settings = Settings(_env_file=None, llm={"openai": {"context_size": 131072}})

        assert synthesis_budget_chars(settings, "static") == int(131072 * 4 * 0.4)

    def test_a_small_context_does_not_drop_below_the_floor(self) -> None:
        settings = Settings(_env_file=None, llm={"openai": {"context_size": 4096}})

        assert synthesis_budget_chars(settings, "static") == _SYNTHESIS_MIN_CHARS

    def test_an_ollama_agent_reads_its_own_window(self) -> None:
        settings = Settings(
            _env_file=None,
            llm={"provider": "ollama", "ollama": {"num_ctx": 65536}},
        )

        assert synthesis_budget_chars(settings, "static") == int(65536 * 4 * 0.4)

    def test_settings_that_cannot_be_read_hold_the_floor(self) -> None:
        assert synthesis_budget_chars(object(), "static") == _SYNTHESIS_MIN_CHARS


class TestWhatTrimmingDrops:
    def _conversation(self) -> list[Any]:
        return [
            _system("system prompt"),
            _human("the sample profile"),
            _ai(tool="pe_info"),
            _result("[ev_0001] " + "a" * 400, "pe_info"),
            _ai("I will look at strings next, they may show a C2 host."),
            _ai(tool="strings"),
            _result("[ev_0002] " + "b" * 400, "strings"),
            _ai(tool="hashes"),
            _result("[ev_0003] " + "c" * 400, "hashes"),
        ]

    def test_a_conversation_that_fits_is_untouched(self) -> None:
        msgs = self._conversation()

        assert _trim_for_synthesis(msgs, 100_000) is msgs

    def test_assistant_prose_goes_before_any_tool_call(self) -> None:
        msgs = self._conversation()

        # One prose turn over the budget: the prose goes and every pair stays.
        kept = _trim_for_synthesis(msgs, 1_560)

        assert not any("I will look at strings" in str(m.content) for m in kept)
        assert len([m for m in kept if type(m).__name__ == "ToolMessage"]) == 3

    def test_a_result_never_outlives_its_call(self) -> None:
        msgs = self._conversation()

        kept = _trim_for_synthesis(msgs, 1_100)

        calls = sum(1 for m in kept if getattr(m, "tool_calls", None))
        results = sum(1 for m in kept if type(m).__name__ == "ToolMessage")
        assert calls == results, "every kept call kept its result and the other way round"

    def test_the_oldest_pair_goes_first(self) -> None:
        msgs = self._conversation()

        kept = _trim_for_synthesis(msgs, 1_100)
        text = " ".join(str(m.content) for m in kept)

        assert "ev_0003" in text, "the most recent evidence is what the model chose last"
        assert "ev_0001" not in text

    def test_the_framing_is_never_dropped(self) -> None:
        msgs = self._conversation()

        kept = _trim_for_synthesis(msgs, 10)

        assert [str(m.content) for m in kept[:2]] == ["system prompt", "the sample profile"]


class TestWhatTheModelIsToldItCanCite:
    def test_the_ids_are_the_ones_still_in_the_window(self) -> None:
        kept = [
            _system("system prompt"),
            _result("[ev_0002] strings output", "strings"),
            _result("[ev_0003] hashes output", "hashes"),
        ]

        assert ledger_ids_in(kept) == ["ev_0002", "ev_0003"]

    def test_an_id_that_was_trimmed_away_is_not_offered(self) -> None:
        msgs = [
            _system("system prompt"),
            _human("the sample profile"),
            _ai(tool="pe_info"),
            _result("[ev_0001] " + "a" * 800, "pe_info"),
            _ai(tool="strings"),
            _result("[ev_0002] " + "b" * 100, "strings"),
        ]

        kept = _trim_for_synthesis(msgs, 600)

        assert ledger_ids_in(kept) == ["ev_0002"]

    def test_a_window_with_no_ids_says_so_without_naming_any(self) -> None:
        assert ledger_ids_in([_system("system prompt")]) == []

    def test_the_directive_carries_the_list(self) -> None:
        import inspect

        from maljan.agents import base_agent

        source = inspect.getsource(base_agent.BaseAnalyst._force_final_synthesis)

        assert "visible = ledger_ids_in(trimmed)" in source
        assert "Cite only these ids." in source
