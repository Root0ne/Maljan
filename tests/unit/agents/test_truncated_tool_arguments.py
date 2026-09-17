"""A tool call the model ran out of room to finish is closed off, once.

A local model that hits its generation limit mid-call emits arguments that
stop in the middle. langchain marks the call invalid and langgraph ignores it
entirely, so nothing runs, nothing answers it, and the loop ends on a turn it
paid a step for. The repair is the smallest defensible one — append the
brackets that are missing, never remove or change a character, and never close
a value the model was still writing — and the ledger says the call was made on
repaired arguments and keeps what the model actually wrote.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool

from maljan.agents.evidence_recorder import (
    ArgumentRepairs,
    EvidenceRecorder,
    record_tools,
    repair_arguments,
    repair_invalid_tool_calls,
)


class TestWhatCanBeClosedOff:
    @pytest.mark.parametrize(
        ("written", "read_as"),
        [
            # An array left open inside an object.
            ('{"path": "/s.bin", "names": ["a", "b"', {"path": "/s.bin", "names": ["a", "b"]}),
            # The object alone, every value complete.
            ('{"path": "/s.bin", "start": 0', {"path": "/s.bin", "start": 0}),
            # A nested object, both levels left open.
            ('{"opts": {"depth": 2', {"opts": {"depth": 2}}),
        ],
    )
    def test_the_missing_closers_are_appended(self, written: str, read_as: dict) -> None:
        assert repair_arguments(written) == read_as

    @pytest.mark.parametrize(
        "written",
        [
            # A value cut in the middle. Closing the quote would hand the tool
            # a path that exists nowhere, or a different search.
            '{"path": "/tmp/dropper.ex',
            '{"path": "/s.bin", "pattern": "http|www',
            '{"pattern": "say \\"hi',
            # A key with nothing after it: appending cannot say what it was.
            '{"path": ',
            # A trailing comma: nothing appended makes this JSON.
            '{"path": "/s.bin",',
            # Nothing was left open, so the fault is something else.
            '{"path" "/s.bin"}',
            # Not an object at the end of it.
            '["a", "b"',
            "",
        ],
    )
    def test_anything_else_is_left_to_the_refusal_path(self, written: str) -> None:
        assert repair_arguments(written) is None

    def test_nothing_is_removed_or_substituted(self) -> None:
        """The repaired text is the written text with a tail, never a rewrite."""
        written = '{"pattern": "a[b]c"'
        assert repair_arguments(written) == {"pattern": "a[b]c"}


class TestTheTurnTheRepairChanges:
    def _turn(self, args: str) -> AIMessage:
        return AIMessage(
            content="Let me look.",
            id="turn-1",
            invalid_tool_calls=[
                {"name": "strings", "args": args, "id": "call_9", "error": "unterminated"}
            ],
        )

    def test_a_repairable_call_moves_across_and_the_turn_keeps_its_id(self) -> None:
        repairs = ArgumentRepairs()

        repaired = repair_invalid_tool_calls(self._turn('{"path": "/s.bin", "start": 0'), repairs)

        assert repaired is not None
        assert repaired.id == "turn-1" and repaired.content == "Let me look."
        assert repaired.invalid_tool_calls == []
        assert [call["args"] for call in repaired.tool_calls] == [{"path": "/s.bin", "start": 0}]
        assert repaired.tool_calls[0]["id"] == "call_9"

    def test_an_unrepairable_call_is_left_exactly_where_it_was(self) -> None:
        assert repair_invalid_tool_calls(self._turn('{"path": '), ArgumentRepairs()) is None

    def test_a_call_cut_inside_a_value_is_left_where_it_was(self) -> None:
        """Closing the quote would invent the rest of a path or a pattern."""
        assert (
            repair_invalid_tool_calls(self._turn('{"path": "/tmp/dropp'), ArgumentRepairs()) is None
        )

    def test_a_turn_with_nothing_wrong_is_not_touched(self) -> None:
        turn = AIMessage(content="", id="t", tool_calls=[{"name": "s", "args": {}, "id": "c"}])

        assert repair_invalid_tool_calls(turn, ArgumentRepairs()) is None


class TestTheLedgerSaysTheCallWasRepaired:
    def _tool(self) -> StructuredTool:
        def strings(path: str, pattern: str = "", start: int = 0) -> dict[str, Any]:
            """Read the strings."""
            return {"path": path, "pattern": pattern, "start": start}

        return StructuredTool.from_function(func=strings, name="strings", description="strings")

    def test_the_entry_is_marked_and_keeps_what_the_model_wrote(self) -> None:
        repairs = ArgumentRepairs()
        written = '{"path": "/s.bin", "start": 0'
        repair_invalid_tool_calls(
            AIMessage(
                content="",
                id="t",
                invalid_tool_calls=[
                    {"name": "strings", "args": written, "id": "c", "error": "unterminated"}
                ],
            ),
            repairs,
        )
        recorder = EvidenceRecorder("static")
        tool = record_tools([self._tool()], recorder, None, repairs)[0]

        # langchain fills the schema's defaults before the tool runs, so what
        # arrives is a superset of what the repair wrote.
        answer = tool.invoke({"path": "/s.bin", "start": 0, "pattern": ""})

        entry = recorder.entries[0]
        assert entry.args_repaired is True
        assert entry.args_raw == written
        # The model is told too: it is the one that can say the brackets were
        # not what it meant.
        assert "were closed off" in answer

    def test_an_ordinary_call_is_not_marked(self) -> None:
        recorder = EvidenceRecorder("static")
        tool = record_tools([self._tool()], recorder, None, ArgumentRepairs())[0]

        answer = tool.invoke({"path": "/s.bin", "pattern": "ht"})

        assert recorder.entries[0].args_repaired is False
        assert recorder.entries[0].args_raw is None
        assert "were closed off" not in answer


class _Scripted(BaseChatModel):
    script: list[Any]

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any):
        answer = self.script.pop(0) if self.script else AIMessage(content="")
        return ChatResult(generations=[ChatGeneration(message=answer)])

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        """Bound the way a real provider binds, so the repair can be appended.

        The repair rides on the runnable ``bind_tools`` returns rather than on
        a graph node, so a stand-in that answers with itself never sees it —
        and a test that never sees it would be testing nothing.
        """
        from langchain_core.utils.function_calling import convert_to_openai_tool

        return self.bind(tools=[convert_to_openai_tool(tool) for tool in tools])


class TestTheRepairedCallActuallyRuns:
    def test_the_loop_calls_the_tool_and_reads_its_answer(self) -> None:
        """End to end: without the repair the loop ends here having done nothing."""
        from maljan.agents.composition import ResolvedAgent
        from maljan.agents.configurable_analyst import ConfigurableAnalyst

        def peek(path: str) -> dict[str, Any]:
            """Look at the sample."""
            return {"opened": path}

        tool = StructuredTool.from_function(func=peek, name="peek", description="peek")
        model = _Scripted(
            script=[
                AIMessage(
                    content="",
                    id="turn-1",
                    invalid_tool_calls=[
                        {
                            "name": "peek",
                            "args": '{"path": "/samples/s.bin"',
                            "id": "call_1",
                            "error": "unterminated",
                        }
                    ],
                ),
                AIMessage(
                    content=(
                        "CLAIM: the file opened\nEVIDENCE: ev_0001\n"
                        "CONFIDENCE: 0.5\nTECHNIQUE: T1106\n"
                    )
                ),
            ]
        )
        resolved = ResolvedAgent(
            key="static",
            role="generic",
            prompt="You look.",
            tools=[tool],
            static_provider_id="none",
            llm=None,
        )
        analyst = ConfigurableAnalyst("static", resolved, model)

        isr = analyst.safe_analyze_isr("Have a look.")

        entries = analyst.drain_evidence_entries()
        assert [entry.tool for entry in entries] == ["peek"]
        assert entries[0].args == {"path": "/samples/s.bin"}
        assert entries[0].args_repaired is True
        assert entries[0].args_raw == '{"path": "/samples/s.bin"'
        assert [claim.claim for claim in isr.claims] == ["the file opened"]
