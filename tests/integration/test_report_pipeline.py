"""Integration tests for the comprehensive malware report (Faz 2).

Verifies that MaljanApp.run() with mock mode populates the new state fields
(``malware_report``, ``malware_report_markdown``, ``stix_bundle_extended``)
and that the dumped report round-trips through ``MalwareReport``.
"""

from __future__ import annotations

import pytest

from maljan.app import MaljanApp
from maljan.core.config import Settings
from maljan.reporting.models import MalwareReport
from maljan.schemas.stix_models import Bundle


@pytest.fixture
def mock_settings() -> Settings:
    s = Settings()
    s.llm.provider = "ollama"
    s.negotiation.max_iterations = 1
    s.reporting.enabled = True
    return s


class TestReportNodePopulatesState:
    def test_state_contains_malware_report(self, mock_settings: Settings) -> None:
        app = MaljanApp(config=mock_settings, mock=True)
        result = app.run("deadbeef" * 8, file_name="report-test.exe")

        assert result.get("malware_report") is not None, "malware_report missing"
        assert isinstance(result["malware_report"], dict)
        assert result.get("malware_report_markdown")
        # Extended STIX is optional but enabled by default.
        assert result.get("stix_bundle_extended") is not None

    def test_malware_report_round_trips_through_pydantic(self, mock_settings: Settings) -> None:
        app = MaljanApp(config=mock_settings, mock=True)
        result = app.run("deadbeef" * 8, file_name="report-test.exe")

        report = MalwareReport.model_validate(result["malware_report"])
        assert report.identity.hashes.sha256 == "deadbeef" * 8
        # Fallback narrative ensured the report is never empty.
        assert report.executive_summary

    def test_markdown_contains_required_headings(self, mock_settings: Settings) -> None:
        app = MaljanApp(config=mock_settings, mock=True)
        result = app.run("deadbeef" * 8, file_name="report-test.exe")
        markdown = result["malware_report_markdown"]
        assert "# Malware Analysis Report" in markdown
        assert "## Sample Identification" in markdown
        assert "## MITRE ATT&CK Matrix" in markdown

    def test_extended_bundle_round_trips(self, mock_settings: Settings) -> None:
        app = MaljanApp(config=mock_settings, mock=True)
        result = app.run("deadbeef" * 8, file_name="report-test.exe")
        bundle_dict = result["stix_bundle_extended"]
        rebuilt = Bundle.model_validate(bundle_dict)
        # Identity and Report SDOs are always added by the renderer.
        types = {obj.type for obj in rebuilt.objects}
        assert "identity" in types
        assert "report" in types


class TestReportNodeDisabled:
    def test_disabled_keeps_legacy_fields_only(self) -> None:
        s = Settings()
        s.llm.provider = "ollama"
        s.negotiation.max_iterations = 1
        s.reporting.enabled = False

        app = MaljanApp(config=s, mock=True)
        result = app.run("deadbeef" * 8, file_name="report-test.exe")

        # Legacy outputs still present.
        assert result.get("final_decision") == "Malware"
        # New fields stay None when the feature is off.
        assert not result.get("malware_report")
        assert not result.get("malware_report_markdown")
