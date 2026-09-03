"""Regression for the dropped ``report_error`` channel.

``report_node`` returns ``{"report_error": ...}`` when the deterministic
report build raises, but ``report_error`` was missing from the
``AnalysisState`` TypedDict — an undeclared key is silently dropped by
``StateGraph(AnalysisState)`` between nodes, so the worker's failure check
(``apps/api/app/worker/analysis_worker.py``) always read ``None`` and a
pipeline that produced no report was persisted as a quietly successful run.
This builds the real graph (mirroring
``tests/unit/pipeline/test_analyst_parallelism.py``) with the report node's
internal build patched to raise, and asserts the message survives into the
graph's final state.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def fake_container() -> Any:
    """Minimal ServiceContainer stub with reporting enabled."""
    container = MagicMock()
    container.agent_registry.list_agents.return_value = ["static", "dynamic", "network"]
    container.is_mock = True
    container.config.reporting.enabled = True
    container.config.llm.parallel_analysts = True
    container.config.negotiation.max_iterations = 3
    return container


def _initial_state() -> dict[str, Any]:
    """A full ``AnalysisState`` literal, mirroring ``MaljanApp.arun``."""
    return {
        "file_hash": "deadbeef",
        "file_name": "sample.exe",
        "sample_path": None,
        "static_sample_path": None,
        "sandbox_report": None,
        "file_type": None,
        "platform": "windows",
        "reports": {},
        "revised_reports": {},
        "isr_reports": {},
        "tool_evidence": {},
        "discussion_history": [],
        "sycophancy_detected": False,
        "confidence_history": [],
        "iteration_count": 0,
        "is_consensus": False,
        "final_decision": None,
        "judge_report": None,
        "stix_output": None,
        "run_summary": None,
        "malware_report": None,
        "malware_report_markdown": None,
        "stix_bundle_extended": None,
        "report_error": None,
        "degraded_mode": False,
        "degradation_reasons": [],
        "function_hash_matches": [],
        "family_rag_candidates": [],
        "attck_case_candidates": [],
        "tool_artifact_matches": [],
    }


@pytest.mark.asyncio
async def test_report_error_reaches_final_state(fake_container: Any) -> None:
    """A ``report_node`` failure must survive as ``report_error`` in the final state."""
    from maljan.pipeline.builder import build_graph

    graph = build_graph(fake_container)

    with patch(
        "maljan.reporting.builder.MalwareReportBuilder.build_deterministic",
        side_effect=RuntimeError("boom"),
    ):
        result = await graph.ainvoke(_initial_state())

    assert result.get("report_error") == "RuntimeError: boom"
    # And the malware_report was never populated — the failure path, not a
    # partial success.
    assert result.get("malware_report") is None
