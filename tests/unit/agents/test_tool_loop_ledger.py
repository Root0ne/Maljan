"""The tool loop writes each call down and shows the model the id it wrote.

Exercised through the recorder's wrapper rather than a real ReAct loop: the
wrapper is the seam the loop runs every tool through, so what it records and
what it hands back is exactly what the loop produces.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.schemas.evidence import EvidenceCounter


class _StubAnalyst(BaseAnalyst):
    """Minimal concrete analyst, so the publish path can be exercised."""

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


def _tool(func: Any, name: str, metadata: dict | None = None) -> StructuredTool:
    return StructuredTool.from_function(func=func, name=name, metadata=metadata)


class TestRecordedCalls:
    def test_a_call_becomes_an_entry_with_timing(self) -> None:
        def identify_file(path: str) -> dict[str, str]:
            """Identify a file."""
            return {"file_type": "PE"}

        recorder = EvidenceRecorder("static")
        wrapped = record_tools([_tool(identify_file, "identify_file")], recorder)[0]
        wrapped.invoke({"path": "/samples/evil.exe"})

        assert len(recorder.entries) == 1
        entry = recorder.entries[0]
        assert entry.id == "ev_0001"
        assert entry.agent == "static"
        assert entry.tool == "identify_file"
        assert entry.args == {"path": "/samples/evil.exe"}
        assert entry.ok is True
        assert entry.structured == {"file_type": "PE"}
        assert entry.duration_ms >= 0
        assert entry.seq == 1

    def test_the_result_the_model_sees_carries_the_entry_id(self) -> None:
        def strings(path: str) -> dict[str, list[str]]:
            """List strings."""
            return {"strings": ["hello"]}

        recorder = EvidenceRecorder("static")
        wrapped = record_tools([_tool(strings, "strings")], recorder)[0]
        result = wrapped.invoke({"path": "/samples/evil.exe"})
        assert result.startswith("[ev_0001]\n")
        assert "hello" in result

    def test_a_raising_tool_is_recorded_as_a_failure(self) -> None:
        def pe_info(path: str) -> dict[str, str]:
            """Parse a PE."""
            raise RuntimeError("pefile exploded")

        recorder = EvidenceRecorder("static")
        wrapped = record_tools([_tool(pe_info, "pe_info")], recorder)[0]
        result = wrapped.invoke({"path": "/samples/evil.exe"})

        entry = recorder.entries[0]
        assert entry.ok is False
        assert "pefile exploded" in (entry.error or "")
        # The model is told which entry failed, so it can cite the attempt.
        assert result.startswith("[ev_0001]")
        assert "pefile exploded" in result

    def test_the_server_a_tool_came_from_is_recorded(self) -> None:
        def decompile_function(name: str) -> str:
            """Decompile."""
            return "void f() {}"

        recorder = EvidenceRecorder("static")
        tool = _tool(decompile_function, "decompile_function", {"maljan_server": "ghidra"})
        record_tools([tool], recorder)[0].invoke({"name": "FUN_00401310"})
        assert recorder.entries[0].server == "ghidra"

    def test_an_in_process_tool_has_no_server(self) -> None:
        def hashes(path: str) -> dict[str, str]:
            """Hash a file."""
            return {"sha256": "0" * 64}

        recorder = EvidenceRecorder("static")
        record_tools([_tool(hashes, "hashes")], recorder)[0].invoke({"path": "/x"})
        assert recorder.entries[0].server is None

    def test_ids_are_shared_across_agents_in_one_job(self) -> None:
        def probe() -> str:
            """Probe."""
            return "ok"

        counter = EvidenceCounter()
        first = EvidenceRecorder("static", counter=counter)
        second = EvidenceRecorder("dynamic", counter=counter)
        record_tools([_tool(probe, "probe")], first)[0].invoke({})
        record_tools([_tool(probe, "probe")], second)[0].invoke({})
        assert first.entries[0].id == "ev_0001"
        assert second.entries[0].id == "ev_0002"


class TestPublishing:
    def test_the_agent_publishes_entries_and_the_legacy_view(self) -> None:
        def probe() -> str:
            """Probe."""
            return "ok"

        recorder = EvidenceRecorder("static")
        record_tools([_tool(probe, "probe")], recorder)[0].invoke({})

        agent = _agent()
        agent._finish_evidence(recorder)
        assert [e.id for e in agent.get_last_evidence_entries()] == ["ev_0001"]
        captured = agent.get_last_tool_evidence()
        assert captured[0].tool_name == "probe"
        assert captured[0].agent_id == "static"

    def test_the_budget_trim_is_counted_in_the_truncation_ledger(self) -> None:
        from maljan.core.truncation_ledger import TruncationLedger

        def bulk() -> str:
            """Return a lot."""
            return "A" * 500

        recorder = EvidenceRecorder("static")
        wrapped = record_tools([_tool(bulk, "bulk")], recorder)[0]
        for _ in range(4):
            wrapped.invoke({})

        agent = _agent()
        agent.truncation_ledger = TruncationLedger()

        import maljan.agents.base_agent as base_agent_module

        class _Reporting:
            evidence_budget_bytes = 600

        class _Settings:
            reporting = _Reporting()

        original = base_agent_module.get_settings
        base_agent_module.get_settings = lambda: _Settings()  # type: ignore[assignment]
        try:
            agent._finish_evidence(recorder)
        finally:
            base_agent_module.get_settings = original  # type: ignore[assignment]

        snapshot = agent.truncation_ledger.snapshot()
        assert snapshot["evidence_entries"] == 4
        assert snapshot["evidence_trimmed"] == 3
        assert agent.get_last_evidence_entries()[3].truncated is True

    def test_no_calls_publishes_nothing(self) -> None:
        agent = _agent()
        agent._finish_evidence(EvidenceRecorder("static"))
        assert agent.get_last_evidence_entries() == []
        assert agent.get_last_tool_evidence() == []
