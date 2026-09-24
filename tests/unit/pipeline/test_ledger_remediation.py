"""The ledger keeps a failed call's message and remedy, and the header lists them once.

A tool that returned an error is a failed entry like one that raised; the
flat shape an external server writes is still a failure; the report header
prints each distinct failure once, with its count and its remedy.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool

from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.pipeline.nodes import tool_failures
from maljan.schemas.evidence import LedgerEntry
from maljan.tools.errors import tool_error


class TestTheLedgerKeepsTheRemedy:
    def test_a_returned_structured_error_is_a_failed_entry_with_its_remedy(self) -> None:
        def document_info(path: str) -> dict[str, Any]:
            """Read a document."""
            return tool_error(
                "missing_dependency", "olefile is not installed", tool="document_info"
            )

        recorder = EvidenceRecorder("static")
        tool = StructuredTool.from_function(func=document_info, name="document_info")
        result = record_tools([tool], recorder)[0].invoke({"path": "/s"})
        entry = recorder.entries[0]
        assert entry.ok is False
        assert entry.error == "olefile is not installed"
        assert entry.remediation and "uv sync --extra tools" in entry.remediation
        # The model reads the tool's own answer, stamped, unchanged.
        assert result.startswith("[ev_0001]\n") and '"remediation"' in result

    def test_the_flat_shape_from_an_external_server_is_still_a_failure(self) -> None:
        def old_tool(path: str) -> dict[str, Any]:
            """Old shape."""
            return {"error": "boom"}

        recorder = EvidenceRecorder("static")
        record_tools([StructuredTool.from_function(func=old_tool, name="old")], recorder)[0].invoke(
            {"path": "/s"}
        )
        entry = recorder.entries[0]
        assert entry.ok is False and entry.error == "boom" and entry.remediation is None

    def test_an_answer_stays_an_answer(self) -> None:
        def fine(path: str) -> dict[str, Any]:
            """Fine."""
            return {"strings": ["a"], "error": ""}

        recorder = EvidenceRecorder("static")
        record_tools([StructuredTool.from_function(func=fine, name="fine")], recorder)[0].invoke(
            {"path": "/s"}
        )
        assert recorder.entries[0].ok is True and recorder.entries[0].remediation is None

    def test_a_stored_entry_without_the_field_still_loads(self) -> None:
        entry = LedgerEntry.model_validate(
            {"id": "ev_0001", "tool": "x", "ok": False, "error": "e"}
        )
        assert entry.remediation is None


class TestTheReportListsFailuresOnce:
    def _entries(self) -> list[LedgerEntry]:
        failed = {
            "tool": "document_info",
            "server": "analysis",
            "ok": False,
            "error": "olefile is not installed",
            "remediation": "uv sync --extra tools",
        }
        return [
            LedgerEntry(id="ev_0001", tool="hashes", ok=True),
            LedgerEntry(id="ev_0002", **failed),
            LedgerEntry(id="ev_0003", **failed),
            LedgerEntry(id="ev_0004", tool="capa", ok=False, error="not run: the pack's budget"),
            LedgerEntry(
                id="ev_0005", tool="strings", ok=False, error="boom", repeated_of="ev_0001"
            ),
        ]

    def test_failures_are_deduped_and_counted_and_not_run_is_left_out(self) -> None:
        rows = tool_failures(self._entries())
        assert rows == [
            {
                "tool": "document_info",
                "server": "analysis",
                "error": "olefile is not installed",
                "remediation": "uv sync --extra tools",
                "entry_id": "ev_0002",
                "count": 2,
            }
        ]

    def test_the_limitations_section_carries_them(self) -> None:
        from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            run_summary={
                "evidence": {"entries": 3, "failed": 2, "failures": tool_failures(self._entries())}
            },
        )
        header = MarkdownRenderer().render(report).split("## 13.", 1)[1]
        assert "**Tool failures:**" in header
        assert (
            "`document_info` (analysis) ×2: olefile is not installed — uv sync --extra tools"
            in (header)
        )
        assert header.count("document_info") == 1
