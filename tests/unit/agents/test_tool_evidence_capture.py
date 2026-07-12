"""Tests for ReAct tool-loop evidence capture (report-reshaping Phase 1).

The loop must pair each tool call with its ToolMessage by ``tool_call_id`` (not
positional order), cap the volume, and never let a capture failure break the
analysis.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from maljan.agents.base_agent import BaseAnalyst
from maljan.schemas.tool_evidence import MAX_OUTPUTS_PER_AGENT


class _StubAnalyst(BaseAnalyst):
    """Minimal concrete analyst so we can exercise the capture helper."""

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(  # pragma: no cover - unused
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        return ""


def _agent() -> _StubAnalyst:
    return _StubAnalyst(llm=None, name="static")  # type: ignore[arg-type]


class TestCaptureToolEvidence:
    def test_pairs_call_with_output_by_id(self) -> None:
        msgs: list[Any] = [
            HumanMessage(content="analyze"),
            AIMessage(
                content="",
                tool_calls=[
                    {"id": "c1", "name": "decompile_function", "args": {"name": "FUN_00401310"}},
                ],
            ),
            ToolMessage(content="void FUN_00401310() { ... }", tool_call_id="c1"),
        ]
        ev = _agent()._capture_tool_evidence(msgs)
        assert len(ev) == 1
        assert ev[0].tool_name == "decompile_function"
        assert ev[0].symbol == "FUN_00401310"
        assert ev[0].agent_id == "static"
        assert "FUN_00401310" in ev[0].output

    def test_pairs_out_of_order_ids(self) -> None:
        # Two calls issued together, outputs returned in a different order.
        msgs: list[Any] = [
            AIMessage(
                content="",
                tool_calls=[
                    {"id": "a", "name": "list_imports", "args": {}},
                    {"id": "b", "name": "detect_crypto_constants", "args": {}},
                ],
            ),
            ToolMessage(content="crypto: AES sbox", tool_call_id="b"),
            ToolMessage(content="imports: WS2_32", tool_call_id="a"),
        ]
        ev = _agent()._capture_tool_evidence(msgs)
        by_name = {e.tool_name: e.output for e in ev}
        assert by_name["detect_crypto_constants"] == "crypto: AES sbox"
        assert by_name["list_imports"] == "imports: WS2_32"

    def test_output_trimmed(self) -> None:
        big = "A" * 20000
        msgs: list[Any] = [
            AIMessage(
                content="", tool_calls=[{"id": "c1", "name": "decompile_function", "args": {}}]
            ),
            ToolMessage(content=big, tool_call_id="c1"),
        ]
        ev = _agent()._capture_tool_evidence(msgs)
        assert len(ev[0].output) < len(big)
        assert ev[0].output.endswith("…")

    def test_capped_at_max(self) -> None:
        msgs: list[Any] = []
        for i in range(MAX_OUTPUTS_PER_AGENT + 10):
            msgs.append(
                AIMessage(
                    content="", tool_calls=[{"id": f"c{i}", "name": "list_strings", "args": {}}]
                )
            )
            msgs.append(ToolMessage(content=f"out{i}", tool_call_id=f"c{i}"))
        ev = _agent()._capture_tool_evidence(msgs)
        assert len(ev) == MAX_OUTPUTS_PER_AGENT

    def test_no_tool_messages_yields_empty(self) -> None:
        msgs: list[Any] = [HumanMessage(content="hi"), AIMessage(content="done")]
        assert _agent()._capture_tool_evidence(msgs) == []

    def test_get_last_tool_evidence_default_empty(self) -> None:
        assert _agent().get_last_tool_evidence() == []

    def test_orphan_tool_message_uses_message_name(self) -> None:
        # A ToolMessage whose call id we never saw still captures, labeled by its
        # own ``name`` attribute rather than dropped.
        msgs: list[Any] = [ToolMessage(content="x", tool_call_id="zzz", name="list_segments")]
        ev = _agent()._capture_tool_evidence(msgs)
        assert len(ev) == 1
        assert ev[0].tool_name == "list_segments"
