"""Unit tests for the MaljanApp facade (run / arun)."""

from __future__ import annotations

import pytest

from maljan.app import MaljanApp


class TestRunMockMode:
    """Tests for MaljanApp.run() in mock mode."""

    def test_run_returns_expected_keys(self, mock_maljan_app: MaljanApp):
        """The result dict contains all expected final-state keys."""
        result = mock_maljan_app.run("abc123", file_name="evil.exe")

        assert "final_decision" in result
        assert "stix_output" in result
        assert "run_summary" in result
        assert "reports" in result
        assert "isr_reports" in result
        assert "discussion_history" in result
        assert "confidence_history" in result
        assert "iteration_count" in result

    def test_run_mock_verdict_is_malware(self, mock_maljan_app: MaljanApp):
        """Mock judge node returns the 'Malware' verdict."""
        result = mock_maljan_app.run("abc123")
        assert result["final_decision"] == "Malware"

    def test_run_populates_reports(self, mock_maljan_app: MaljanApp):
        """Mock analyst nodes populate the reports dict."""
        result = mock_maljan_app.run("abc123")
        reports = result["reports"]
        assert isinstance(reports, dict)
        assert len(reports) > 0
        for name, text in reports.items():
            assert isinstance(name, str)
            assert isinstance(text, str)

    def test_run_populates_isr_reports(self, mock_maljan_app: MaljanApp):
        """Mock analyst nodes populate the isr_reports dict."""
        result = mock_maljan_app.run("abc123")
        isr_reports = result["isr_reports"]
        assert isinstance(isr_reports, dict)
        assert len(isr_reports) > 0

    def test_run_negotiation_executed(self, mock_maljan_app: MaljanApp):
        """At least one negotiation round was executed."""
        result = mock_maljan_app.run("abc123")
        assert result["iteration_count"] >= 1
        assert len(result["discussion_history"]) >= 1
        assert len(result["confidence_history"]) >= 1

    def test_run_stix_output_is_dict(self, mock_maljan_app: MaljanApp):
        """Mock judge returns an empty STIX dict."""
        result = mock_maljan_app.run("abc123")
        assert isinstance(result["stix_output"], dict)


class TestArunAsync:
    """Tests for MaljanApp.arun() async path."""

    @pytest.mark.asyncio
    async def test_arun_returns_same_keys(self, mock_maljan_app: MaljanApp):
        """Async path produces the same result shape as sync path."""
        result = await mock_maljan_app.arun("def456", file_name="suspicious.bin")
        assert result["final_decision"] == "Malware"
        assert "reports" in result
        assert "isr_reports" in result

    @pytest.mark.asyncio
    async def test_arun_with_sample_path_mock(self, mock_maljan_app: MaljanApp):
        """Sample path is accepted but skipped in mock mode."""
        result = await mock_maljan_app.arun(
            "ghi789",
            file_name="sample.exe",
            sample_path="/nonexistent/path/sample.exe",
        )
        assert result["final_decision"] == "Malware"
        # Sandbox report should be None in mock mode
        assert result.get("sandbox_report") is None


class TestContainerReuse:
    """Tests verifying that the same MaljanApp instance can be reused."""

    def test_multiple_runs_on_same_instance(self, mock_maljan_app: MaljanApp):
        """Running twice on the same app does not raise and reuses graph."""
        result1 = mock_maljan_app.run("hash_a")
        result2 = mock_maljan_app.run("hash_b")

        assert result1["final_decision"] == "Malware"
        assert result2["final_decision"] == "Malware"
        assert result1["file_hash"] == "hash_a"
        assert result2["file_hash"] == "hash_b"

    def test_container_cached(self, mock_maljan_app: MaljanApp):
        """The ServiceContainer instance is reused across runs."""
        container_id = id(mock_maljan_app.container)
        mock_maljan_app.run("hash_c")
        assert id(mock_maljan_app.container) == container_id

    def test_graph_cached(self, mock_maljan_app: MaljanApp):
        """The compiled LangGraph is reused across runs."""
        graph_id = id(mock_maljan_app.graph)
        mock_maljan_app.run("hash_d")
        assert id(mock_maljan_app.graph) == graph_id


class TestInitialState:
    """Tests verifying AnalysisState initial values."""

    def test_initial_state_has_file_hash(self, mock_maljan_app: MaljanApp):
        """file_hash is propagated into the result state."""
        result = mock_maljan_app.run("custom_hash_123")
        assert result["file_hash"] == "custom_hash_123"

    def test_initial_state_has_file_name(self, mock_maljan_app: MaljanApp):
        """file_name is propagated into the result state."""
        result = mock_maljan_app.run("hash", file_name="ransomware.exe")
        assert result["file_name"] == "ransomware.exe"

    def test_initial_iteration_count_increases_during_pipeline(self):
        """Iteration count increases after the pipeline executes."""
        app = MaljanApp(mock=True)
        result = app.run("hash")
        assert result["iteration_count"] > 0


class TestUnsupportedSampleRejection:
    """OS-support scope (2026-06-02): Windows + Linux only — arun rejects a
    definitely-foreign sample up front, before the pipeline runs."""

    def test_arun_rejects_foreign_sample(self, tmp_path):
        from pathlib import Path

        from maljan.core.exceptions import UnsupportedSampleError

        macho = Path(tmp_path) / "evil.bin"
        macho.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 64)  # Mach-O magic
        app = MaljanApp(mock=True)
        with pytest.raises(UnsupportedSampleError):
            app.run("deadbeef", file_name="evil.bin", sample_path=str(macho))

    def test_arun_accepts_windows_sample(self, tmp_path):
        # A PE sample is not rejected by the guard (pipeline proceeds in mock mode).
        from pathlib import Path

        pe = Path(tmp_path) / "evil.exe"
        pe.write_bytes(b"MZ" + b"\x00" * 64)
        app = MaljanApp(mock=True)
        result = app.run("deadbeef", file_name="evil.exe", sample_path=str(pe))
        assert result["iteration_count"] > 0
