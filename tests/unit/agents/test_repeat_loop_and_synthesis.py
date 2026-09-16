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
from maljan.agents.evidence_recorder import RepeatGuard
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
    """Driven through the wrapper the loop actually builds, not the guard alone.

    Every earlier test asked the guard directly and used three distinct tools,
    which is why a counter that could only ever reach one per call passed them.
    A model that likes an answer asks for that answer again, and the run this
    came from called one tool sixteen times.
    """

    def _tool(self, calls: list[str], name: str = "pe_info") -> Any:
        from langchain_core.tools import StructuredTool
        from pydantic import BaseModel

        class _Args(BaseModel):
            path: str = ""

        def _run(**kwargs: Any) -> str:
            calls.append(name)
            return "PE32 executable, 3 sections"

        return StructuredTool.from_function(
            func=_run, name=name, description=name, args_schema=_Args, infer_schema=False
        )

    def _wrapped(self, guard: RepeatGuard, calls: list[str], *names: str) -> list[Any]:
        from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
        from maljan.schemas.evidence import EvidenceCounter

        recorder = EvidenceRecorder("static", counter=EvidenceCounter())
        return record_tools(
            [self._tool(calls, name) for name in (names or ("pe_info",))], recorder, guard
        )

    def test_one_tool_asked_for_sixteen_times_ends_the_loop(self) -> None:
        guard = RepeatGuard()
        calls: list[str] = []
        tool = self._wrapped(guard, calls)[0]

        answers = [tool.invoke({"path": "/tmp/s.bin"}) for _ in range(16)]

        assert guard.ending_the_loop() is True
        assert len(calls) == 2, "the tool itself ran twice; the rest were refused"
        assert "[ev_0001]" in answers[0]

    def test_the_loop_ends_on_the_third_repeated_call(self) -> None:
        guard = RepeatGuard()
        tool = self._wrapped(guard, [])[0]
        args = {"path": "/tmp/s.bin"}

        tool.invoke(args)
        assert guard.served_repeats == 0
        tool.invoke(args)
        assert (guard.served_repeats, guard.ending_the_loop()) == (1, False)
        tool.invoke(args)
        assert (guard.served_repeats, guard.ending_the_loop()) == (2, False)
        tool.invoke(args)

        assert (guard.served_repeats, guard.ending_the_loop()) == (3, True)

    def test_three_tools_asked_twice_each_end_it_too(self) -> None:
        """The count is the loop's, not one call's."""
        guard = RepeatGuard()
        tools = self._wrapped(guard, [], "pe_info", "strings", "hashes")

        for tool in tools:
            tool.invoke({"path": "/tmp/s.bin"})
        for tool in tools:
            tool.invoke({"path": "/tmp/s.bin"})

        assert guard.ending_the_loop() is True

    def test_a_loop_that_asks_different_things_is_left_alone(self) -> None:
        guard = RepeatGuard()
        tool = self._wrapped(guard, [])[0]

        for index in range(6):
            tool.invoke({"path": f"/tmp/sample{index}.bin"})

        assert guard.served_repeats == 0
        assert guard.ending_the_loop() is False

    def test_the_call_before_the_last_warns_however_it_is_answered(self) -> None:
        guard = RepeatGuard()
        tool = self._wrapped(guard, [])[0]
        args = {"path": "/tmp/s.bin"}

        first = tool.invoke(args)
        served = tool.invoke(args)
        refused = tool.invoke(args)

        assert "ends this analysis" not in first
        assert "A third will not be run" in served
        assert "ends this analysis" not in served, "one repeat is not the last one"
        assert "ends this analysis" in refused

    def test_a_replayed_conversation_starts_the_count_again(self) -> None:
        """A connection error re-sends the conversation from the first message.

        The model then re-makes the calls it already made, and counting those
        ended an analyst for a dropped socket — the retry exists to stop
        exactly that.
        """
        guard = RepeatGuard()
        tool = self._wrapped(guard, [])[0]
        args = {"path": "/tmp/s.bin"}
        tool.invoke(args)
        tool.invoke(args)
        assert guard.served_repeats == 1

        guard.reset()

        tool.invoke(args)
        assert guard.served_repeats == 0, "the replayed call is the first one again"
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


class TestTheLoopStopsMidStream:
    """The end-to-end shape: a stream that grows, a tool that repeats, a break.

    Every stub written for the streaming change yielded one snapshot holding
    the finished message list, which is ``ainvoke``'s answer wearing a
    generator. Nothing exercised a state that grows step by step, and that is
    how a counter which could never reach its own threshold shipped green.
    """

    def _agent(self, llm: Any) -> Any:
        from maljan.agents.base_agent import BaseAnalyst

        class _ToolAgent(BaseAnalyst):
            def analyze(self, data: str) -> str:  # pragma: no cover - not exercised
                return ""

            def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
                return ""

        from unittest.mock import MagicMock

        return _ToolAgent(llm=llm, name="static", tools=[MagicMock()])

    def _executor(self, agent_tools: list[Any]) -> Any:
        """An executor that calls one wrapped tool again on every step.

        It answers the way ``stream_mode="values"`` does: each snapshot is the
        whole conversation so far, one step longer than the last.
        """
        from langchain_core.messages import AIMessage, ToolMessage

        class _Executor:
            def __init__(self) -> None:
                self.steps = 0

            async def astream(self, inputs: Any, config: Any, stream_mode: str = "values") -> Any:
                messages = list(inputs["messages"])
                for step in range(8):
                    self.steps += 1
                    answer = agent_tools[0].invoke({"path": "/tmp/s.bin"})
                    messages = [
                        *messages,
                        AIMessage(
                            content="",
                            tool_calls=[{"name": "pe_info", "args": {}, "id": f"call_{step}"}],
                        ),
                        ToolMessage(content=answer, tool_call_id=f"call_{step}"),
                    ]
                    yield {"messages": messages}

        return _Executor()

    def test_a_repeating_stream_is_broken_and_what_it_gathered_is_synthesised(self) -> None:
        from unittest.mock import MagicMock, patch

        from langchain_core.tools import StructuredTool
        from pydantic import BaseModel

        class _Args(BaseModel):
            path: str = ""

        ran: list[str] = []

        def _run(**kwargs: Any) -> str:
            ran.append("pe_info")
            return "PE32 executable, 3 sections"

        tool = StructuredTool.from_function(
            func=_run, name="pe_info", description="pe", args_schema=_Args, infer_schema=False
        )

        llm = MagicMock()
        llm.invoke.return_value = MagicMock(
            content=(
                "CLAIM: the binary is a PE32 executable\n"
                "EVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: NONE"
            )
        )
        agent = self._agent(llm)
        agent.tools = [tool]

        executor = None

        def _build(model: Any, tools: list[Any]) -> Any:
            nonlocal executor
            executor = self._executor(tools)
            return executor

        with patch("maljan.agents.base_agent.get_settings") as settings:
            cfg = settings.return_value
            cfg.react_agent_timeout = 180
            cfg.react_agent_timeout_overrides = {}
            cfg.react_agent_max_steps = 40
            cfg.react_agent_max_steps_overrides = {}
            cfg.react_agent_tool_call_budget = 20
            cfg.llm.provider = "openai"
            cfg.llm.agents = {}
            cfg.llm.openai.context_size = 0
            with patch("langgraph.prebuilt.create_react_agent", _build):
                answer = agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert executor is not None
        assert executor.steps == 4, "the fourth repeated call ends the loop"
        assert len(ran) == 2, "the tool itself ran twice; the rest were refused"
        assert "PE32" in answer, "the salvage answered from what was gathered"
        llm.invoke.assert_called_once()

    def test_the_last_snapshot_is_what_the_caller_gets(self) -> None:
        """Values mode grows the state, and the loop reads the last one."""
        from unittest.mock import MagicMock, patch

        from langchain_core.messages import AIMessage

        class _Executor:
            async def astream(self, inputs: Any, config: Any, stream_mode: str = "values") -> Any:
                yield {"messages": [AIMessage(content="thinking")]}
                yield {"messages": [AIMessage(content="thinking"), AIMessage(content="done")]}

        agent = self._agent(MagicMock())
        agent.tools = [MagicMock()]
        with patch("maljan.agents.base_agent.get_settings") as settings:
            cfg = settings.return_value
            cfg.react_agent_timeout = 180
            cfg.react_agent_timeout_overrides = {}
            cfg.react_agent_max_steps = 40
            cfg.react_agent_max_steps_overrides = {}
            cfg.react_agent_tool_call_budget = 20
            with patch("langgraph.prebuilt.create_react_agent", return_value=_Executor()):
                answer = agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert answer == "done"
