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

    container.analyst_keys.return_value = ["static", "dynamic", "network"]

    container.agent_role.side_effect = lambda n: n
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
        "validation_findings": {},
        "validation_retries": 0,
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


async def _report_only(container: Any, state: dict[str, Any]) -> dict[str, Any]:
    """Run the report node alone.

    The graph's mock judge returns an empty ``stix_output``, which would
    overwrite the bundle these tests are about; the node is the unit under test
    either way.
    """
    from maljan.pipeline.nodes import make_report_node

    container.is_mock = False
    container.get_narrative_agent.return_value = None
    container.get_report_composer.return_value = None
    container.get_static_provider.return_value.capabilities.provides_evidence = False
    return await make_report_node(container)(state)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_the_judges_assessment_reaches_the_report(fake_container: Any) -> None:
    """Severity, category and family are read off the bundle, not computed.

    The judge writes them into ``x_maljan_assessment`` on the STIX bundle it
    returns, and the report node has to carry them across because nothing
    downstream recomputes them any more. A break here does not raise — the
    report simply prints "not assessed" and an unattributed family, which is
    exactly the silence this catches.
    """
    state = _initial_state()
    state["stix_output"] = {
        "type": "bundle",
        "objects": [],
        "x_maljan_assessment": {
            "severity": {"rating": "High", "rationale": "it encrypts every file"},
            "malware_category": "ransomware",
            "family": {"name": "LockBit", "confidence": 0.66, "evidence_ids": ["ev_0003"]},
        },
    }

    report = (await _report_only(fake_container, state)).get("malware_report") or {}

    assert report.get("malware_category") == "ransomware"
    assert (report.get("severity") or {}).get("rating") == "High"
    assert (report.get("severity") or {}).get("business_impact") == "it encrypts every file"
    attribution = report.get("attribution") or {}
    assert attribution.get("family") == "LockBit"
    assert attribution.get("family_confidence") == 0.66
    assert attribution.get("family_grounded") is True


@pytest.mark.asyncio
async def test_a_family_the_judge_could_not_cite_is_kept_and_flagged(
    fake_container: Any,
) -> None:
    state = _initial_state()
    state["stix_output"] = {
        "type": "bundle",
        "objects": [],
        "x_maljan_assessment": {"family": {"name": "LockBit", "confidence": 0.4}},
    }

    report = (await _report_only(fake_container, state)).get("malware_report") or {}

    attribution = report.get("attribution") or {}
    assert attribution.get("family") == "LockBit"
    assert attribution.get("family_grounded") is False


@pytest.mark.asyncio
async def test_an_unassessed_run_says_so_rather_than_inventing_a_severity(
    fake_container: Any,
) -> None:
    report = (await _report_only(fake_container, _initial_state())).get("malware_report") or {}

    assert report.get("severity") is None
    assert report.get("malware_category") is None
