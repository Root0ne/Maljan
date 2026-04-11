"""Integration tests for the full pipeline using the new architecture."""

from maljan.app import MaljanApp
from maljan.core.config import Settings


def test_pipeline_mock_mode_end_to_end() -> None:
    """Full pipeline runs in mock mode and produces a verdict."""
    app = MaljanApp(mock=True)
    result = app.run("sample_1", file_name="test.exe")

    # All agent reports present in dynamic dict
    reports = result.get("reports", {})
    assert "static" in reports
    assert "dynamic" in reports
    assert "network" in reports

    # Negotiation occurred
    assert result["iteration_count"] >= 1

    # Revised reports exist after negotiation loop
    if result["iteration_count"] > 1:
        revised = result.get("revised_reports", {})
        assert len(revised) >= 1

    # Judge verdict
    assert result["final_decision"] == "Malware"
    assert len(result.get("discussion_history", [])) >= 1


def test_pipeline_graph_compiles() -> None:
    """Graph compiles without errors."""
    app = MaljanApp(mock=True)
    assert app.graph is not None


def test_pipeline_consensus_iterations() -> None:
    """Mock pipeline reaches consensus within reasonable iterations."""
    app = MaljanApp(mock=True)
    result = app.run("sample_1")

    assert result["iteration_count"] <= 3
    assert result["final_decision"] is not None


def test_pipeline_respects_max_iterations() -> None:
    """Pipeline respects custom max_iterations from config."""
    config = Settings()
    config.negotiation.max_iterations = 1
    app = MaljanApp(config=config, mock=True)
    result = app.run("sample_1")

    # Should hit judge after exactly 1 iteration (no revision since max=1)
    assert result["iteration_count"] == 1
    assert result["final_decision"] is not None
