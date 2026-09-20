"""The tool-output cap comes from the served window, not from a constant.

``core.preprocessing.max_tool_output_chars`` is zero by default and zero means
"work it out". What it is worked out from — the window, what the conversation
holds, the room kept back for a reply — is tested in
``tests/unit/llm/test_context_window.py``. What is tested here is that the
number reaches every place an answer is cut, that an operator who sets one
still gets exactly theirs, and that the run says which applied.
"""

from __future__ import annotations

import json
import time
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from maljan.analysis.run_summary import RunSummaryBuilder, cap_in_force_sentence
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.llm import context_window as cw


def _langchain_tool(func: Any, name: str) -> Any:
    """One plain LangChain tool over ``func``, the way an analyst's tools arrive."""
    from langchain_core.tools import StructuredTool

    return StructuredTool.from_function(func=func, name=name)


def _answer(rows: int) -> str:
    return json.dumps(
        {
            "read_path": "/staging/sample",
            "strings": [{"offset": 100 + i, "text": f"row number {i}"} for i in range(rows)],
        }
    )


class TestTheDefaultIsToDerive:
    def test_the_setting_ships_at_zero(self) -> None:
        assert Settings(_env_file=None).preprocessing.max_tool_output_chars == 0

    def test_zero_means_the_window_decides(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        assert cw.output_limit(0, budget) == 9216

    def test_a_positive_setting_is_the_operators_own_cap(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(1_000_000, cw.PROBED, "props"), reply_tokens=8192)
        assert cw.output_limit(6000, budget) == 6000

    def test_a_toolkit_outside_a_job_gets_the_documented_constant(self) -> None:
        assert cw.output_limit(0, None) == cw.UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS


class TestBothToolPathsCutAtTheDerivedNumber:
    """One arithmetic, two guardrails, and the answer plus its notice fit."""

    ROOMY = cw.ContextBudget(cw.WindowFact(1_000_000, cw.PROBED, "props"), reply_tokens=8192)
    TIGHT = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)

    @staticmethod
    def _toolkit(budget: Any, configured: int = 0) -> Any:
        from maljan.agents.mcp_client import MCPLangChainToolkit

        return MCPLangChainToolkit(max_output_chars=configured, context_budget=budget)

    @staticmethod
    def _ghidra(budget: Any, configured: int = 0) -> Any:
        from maljan.agents.ghidra_http_client import GhidraHTTPClient

        client = GhidraHTTPClient.__new__(GhidraHTTPClient)
        client._max_output_chars = configured
        client._output_guardrail = None
        client._truncation_ledger = None
        client._context_budget = budget
        return client

    def test_a_wide_window_keeps_an_answer_a_narrow_one_would_cut(self) -> None:
        answer = _answer(400)
        assert len(answer) > self.TIGHT.chars_for_one_answer()
        assert len(answer) < self.ROOMY.chars_for_one_answer()

        assert self._toolkit(self.ROOMY)._apply_output_guardrail(answer) == answer
        assert self._toolkit(self.TIGHT)._apply_output_guardrail(answer) != answer

    def test_the_ghidra_path_reads_the_same_number(self) -> None:
        answer = _answer(400)
        assert self._ghidra(self.ROOMY)._apply_output_guardrail(answer) == answer
        assert self._ghidra(self.TIGHT)._apply_output_guardrail(answer) != answer

    def test_a_fuller_conversation_gets_a_smaller_answer(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        toolkit = self._toolkit(budget)
        answer = _answer(400)

        roomy = len(toolkit._apply_output_guardrail(answer))
        budget.note_conversation("static", 50_000)
        crowded = len(toolkit._apply_output_guardrail(answer))

        assert crowded < roomy

    def test_the_cap_in_force_is_what_the_ledger_records(self) -> None:
        class _Ledger:
            def __init__(self) -> None:
                self.rows: list[dict[str, Any]] = []

            def record_tool_output(self, **row: Any) -> None:
                self.rows.append(row)

        ledger = _Ledger()
        toolkit = self._toolkit(self.TIGHT)
        toolkit._truncation_ledger = ledger

        expected = self.TIGHT.cap_without_recording()
        toolkit._apply_output_guardrail(_answer(400))

        assert ledger.rows[-1]["limit"] == expected


class TestAConversationWithNoRoomLeft:
    """The one outcome that is not an answer, on both tool paths."""

    @staticmethod
    def _full_budget() -> Any:
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        budget.note_conversation("static", (32768 - 8192) * cw.CHARS_PER_TOKEN)
        return budget

    def test_the_model_is_told_rather_than_handed_a_fragment(self) -> None:
        from maljan.agents.mcp_client import MCPLangChainToolkit

        budget = self._full_budget()
        toolkit = MCPLangChainToolkit(max_output_chars=0, context_budget=budget)
        answer = _answer(400)

        said = toolkit._apply_output_guardrail(answer)

        assert said == cw.no_room_sentence(len(answer))
        assert "no room left" in said
        assert not said.startswith("{"), "no fragment of the answer was handed over"

    def test_the_ghidra_path_says_the_same_thing(self) -> None:
        from maljan.agents.ghidra_http_client import GhidraHTTPClient

        client = GhidraHTTPClient.__new__(GhidraHTTPClient)
        client._max_output_chars = 0
        client._output_guardrail = None
        client._truncation_ledger = None
        client._context_budget = self._full_budget()
        answer = _answer(400)

        assert client._apply_output_guardrail(answer) == cw.no_room_sentence(len(answer))

    def test_the_run_counts_it_and_the_report_shows_it(self) -> None:
        from maljan.agents.mcp_client import MCPLangChainToolkit
        from maljan.core.truncation_ledger import TruncationLedger

        ledger = TruncationLedger()
        toolkit = MCPLangChainToolkit(max_output_chars=0, context_budget=self._full_budget())
        toolkit._truncation_ledger = ledger

        toolkit._apply_output_guardrail(_answer(400))

        snapshot = ledger.snapshot()
        assert snapshot["tool_output_no_room"] == 1
        summary = RunSummaryBuilder(time.monotonic()).set_truncation(snapshot).build()
        assert summary.truncation is not None
        assert summary.truncation.any_bound_hit is True
        assert "no room left for the answer | 1" in summary.to_markdown()

    def test_the_sentence_is_charged_like_any_answer(self) -> None:
        from maljan.agents.mcp_client import MCPLangChainToolkit

        budget = self._full_budget()
        before = budget.held_chars("static")
        toolkit = MCPLangChainToolkit(max_output_chars=0, context_budget=budget)
        answer = _answer(400)

        with cw.answering_for("static"):
            said = toolkit._apply_output_guardrail(answer)

        assert budget.held_chars("static") == before + len(said)
        assert budget.out_of_room("static") is True

    def test_the_tool_phase_ends_rather_than_repeating_the_sentence(self) -> None:
        """A call made after the room ran out does not run, and costs one line."""
        from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools

        budget = self._full_budget()
        budget.note_no_room("static")
        ran: list[str] = []

        def strings(path: str) -> str:
            """List printable runs."""
            ran.append(path)
            return _answer(400)

        recorder = EvidenceRecorder("static")
        wrapped = record_tools(
            [_langchain_tool(strings, "strings")], recorder, context_budget=budget
        )[0]

        said = wrapped.invoke({"path": "/samples/evil.exe"})

        assert ran == [], "the tool was run after the room had gone"
        assert said == cw.TOOL_PHASE_ENDED_NOTICE
        assert recorder.entries == [], "a refused call is not citable evidence"

    def test_a_refusal_that_would_not_fit_is_not_handed_over(self) -> None:
        from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools

        budget = cw.ContextBudget(cw.WindowFact(4096, cw.PROBED, "props"), reply_tokens=8192)
        budget.note_conversation("static", 4096 * cw.CHARS_PER_TOKEN)
        budget.note_no_room("static")

        def strings(path: str) -> str:
            """List printable runs."""
            return "x"

        wrapped = record_tools(
            [_langchain_tool(strings, "strings")],
            EvidenceRecorder("static"),
            context_budget=budget,
        )[0]

        assert wrapped.invoke({"path": "/samples/evil.exe"}) == ""

    def test_the_run_state_block_carries_the_fact_every_turn(self) -> None:
        budget = self._full_budget()
        budget.note_no_room("static")
        analyst = TestALoopReportsWhatItHolds._analyst(budget)
        analyst.run_state_block = "stage: reversing"

        assert cw.NO_ROOM_RUN_STATE in analyst._run_state_body(3, 60.0)

    def test_an_operator_cap_never_produces_it(self) -> None:
        """A number the operator set is theirs, and it is never zero."""
        from maljan.agents.mcp_client import MCPLangChainToolkit

        toolkit = MCPLangChainToolkit(max_output_chars=6000, context_budget=self._full_budget())
        assert toolkit._apply_output_guardrail(_answer(400)) != cw.no_room_sentence(0)


class TestALoopReportsWhatItHolds:
    """The run-state refresher is where the conversation is measured."""

    @staticmethod
    def _analyst(budget: Any) -> Any:
        from maljan.agents.base_agent import BaseAnalyst

        class _Container:
            def get_context_budget(self) -> Any:
                return budget

        class _Analyst(BaseAnalyst):
            def __init__(self) -> None:
                self.name = "static"
                self._container = _Container()
                self.run_state_block = ""
                import logging

                self.logger = logging.getLogger("test")

            def analyze(self, data: str) -> str:  # pragma: no cover - never called
                return ""

            def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
                return ""

        return _Analyst()

    def test_the_refresher_tells_the_budget_what_the_turn_weighs(self) -> None:
        from maljan.agents.base_agent import LoopBudget

        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        analyst = self._analyst(budget)
        refresh = analyst._run_state_refresher(10, 60.0, time.monotonic(), LoopBudget(10, 60.0))

        refresh({"messages": [SystemMessage(content="s" * 4000), HumanMessage(content="h" * 500)]})

        assert budget.held_chars() == 4500

    def test_a_tool_request_is_not_free(self) -> None:
        """The payload of a tool call is outside ``content`` and still counts."""
        from maljan.agents.base_agent import LoopBudget

        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        analyst = self._analyst(budget)
        refresh = analyst._run_state_refresher(10, 60.0, time.monotonic(), LoopBudget(10, 60.0))

        refresh(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[{"name": "decompile", "args": {"b": "x" * 900}, "id": "1"}],
                    )
                ]
            }
        )

        assert budget.held_chars() > 900

    def test_a_finished_loop_stops_deciding_for_the_next_one(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        analyst = self._analyst(budget)
        budget.note_conversation("static", 60_000)

        analyst._forget_conversation()

        assert budget.held_chars() == 0


class TestTheContainerLearnsItOnce:
    def test_a_mock_container_never_puts_a_probe_on_the_network(self) -> None:
        container = ServiceContainer(Settings(_env_file=None), mock=True)
        budget = container.get_context_budget()
        assert budget.window.source in (cw.DECLARED, cw.TABLE, cw.FALLBACK)
        assert container.get_context_budget() is budget

    def test_the_registry_hands_every_toolkit_the_jobs_budget(self) -> None:
        container = ServiceContainer(Settings(_env_file=None), mock=True)
        registry = container.get_server_registry()
        assert registry._context_budget is container.get_context_budget()
        assert registry._attach({})["context_budget"] is container.get_context_budget()

    def test_a_zero_cap_reaches_the_attach_rather_than_being_dropped(self) -> None:
        """A ``setdefault`` guarded on a positive number hid the derive request."""
        container = ServiceContainer(Settings(_env_file=None), mock=True)
        assert container.get_server_registry()._attach({})["max_output_chars"] == 0

    def test_an_operator_cap_leaves_no_window_on_the_record(self) -> None:
        cfg = Settings(_env_file=None, preprocessing={"max_tool_output_chars": 6000})
        container = ServiceContainer(cfg, mock=True)
        container.get_context_budget()
        assert container.context_budget_snapshot() == {}

    def test_a_derived_cap_puts_the_window_on_the_record(self) -> None:
        container = ServiceContainer(Settings(_env_file=None), mock=True)
        container.get_context_budget()
        snapshot = container.context_budget_snapshot()
        assert snapshot["tokens"] > 0
        assert snapshot["source"] in (cw.DECLARED, cw.TABLE, cw.FALLBACK)
        assert snapshot["chars_per_token"] == cw.CHARS_PER_TOKEN


class TestTheRunSaysWhatWasInForce:
    @staticmethod
    def _summary(snapshot: dict[str, Any]) -> Any:
        return RunSummaryBuilder(time.monotonic()).set_truncation(snapshot).build()

    def test_the_window_and_the_caps_reach_the_run_summary(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "llama.cpp /props"))
        budget.chars_for_one_answer()
        from maljan.core.truncation_ledger import TruncationLedger

        ledger = TruncationLedger()
        ledger.record_tool_output(chars_in=10, chars_kept=10, over_limit=False, limit=9216)
        ledger.note_context_window(budget.snapshot())

        summary = self._summary(ledger.snapshot()).to_dict()["truncation"]

        assert summary["tool_output_limit_largest"] == 9216
        assert summary["context_window"]["tokens"] == 32768
        assert summary["context_window"]["source"] == cw.PROBED
        assert summary["context_window"]["chars_per_token"] == cw.CHARS_PER_TOKEN

    def test_the_sentence_names_the_window_and_where_it_came_from(self) -> None:
        from maljan.core.truncation_ledger import TruncationLedger

        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "llama.cpp /props reported it"))
        ledger = TruncationLedger()
        ledger.record_tool_output(chars_in=10, chars_kept=10, over_limit=False, limit=9216)
        ledger.record_tool_output(chars_in=10, chars_kept=10, over_limit=False, limit=2000)
        ledger.note_context_window(budget.snapshot())

        said = cap_in_force_sentence(self._summary(ledger.snapshot()).truncation)

        assert "32,768 tokens" in said
        assert cw.PROBED in said
        assert "llama.cpp /props reported it" in said
        assert "between 2,000 and 9,216 characters" in said
        assert "3 characters per token" in said

    def test_an_unknown_window_says_so_and_derives_nothing(self) -> None:
        from maljan.core.truncation_ledger import TruncationLedger

        budget = cw.ContextBudget(cw.unknown_window())
        ledger = TruncationLedger()
        ledger.record_tool_output(
            chars_in=10,
            chars_kept=10,
            over_limit=False,
            limit=cw.UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS,
        )
        ledger.note_context_window(budget.snapshot())

        said = cap_in_force_sentence(self._summary(ledger.snapshot()).truncation)

        assert "unknown" in said
        assert "6,000 characters" in said
        assert "context_size" in said
        assert "characters per token" not in said, "nothing is derived from nothing"

    def test_a_refused_figure_is_named_rather_than_read_as_a_silence(self) -> None:
        """The operator whose proxy reports bytes has a concrete thing to fix."""
        from maljan.core.truncation_ledger import TruncationLedger

        refused = cw.unknown_window(
            "the server description reported 1,000,000,000,000,000 tokens, which is past the "
            "10,000,000 this platform will believe; the figure was refused"
        )
        ledger = TruncationLedger()
        ledger.record_tool_output(
            chars_in=10,
            chars_kept=10,
            over_limit=False,
            limit=cw.UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS,
        )
        ledger.note_context_window(cw.ContextBudget(refused).snapshot())

        said = cap_in_force_sentence(self._summary(ledger.snapshot()).truncation)

        assert "refused" in said
        assert "1,000,000,000,000,000" in said
        assert "unknown" in said

    def test_a_window_nothing_reported_says_only_that(self) -> None:
        from maljan.core.truncation_ledger import TruncationLedger

        ledger = TruncationLedger()
        ledger.record_tool_output(
            chars_in=10,
            chars_kept=10,
            over_limit=False,
            limit=cw.UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS,
        )
        ledger.note_context_window(cw.ContextBudget(cw.unknown_window()).snapshot())

        said = cap_in_force_sentence(self._summary(ledger.snapshot()).truncation)

        assert "unknown" in said
        assert "refused" not in said

    def test_a_run_with_an_operator_cap_says_that_instead(self) -> None:
        from maljan.core.truncation_ledger import TruncationLedger

        ledger = TruncationLedger()
        ledger.record_tool_output(chars_in=10, chars_kept=10, over_limit=False, limit=6000)

        said = cap_in_force_sentence(self._summary(ledger.snapshot()).truncation)

        assert "6,000 characters, the number this run was set" in said

    def test_a_run_that_called_no_tool_says_nothing_about_a_cap(self) -> None:
        from maljan.core.truncation_ledger import TruncationLedger

        ledger = TruncationLedger()
        ledger.record_react_loop(hit_step_cap=False)

        assert cap_in_force_sentence(self._summary(ledger.snapshot()).truncation) == ""
