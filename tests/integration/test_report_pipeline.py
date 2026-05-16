"""Integration tests for the comprehensive malware report (Faz 2 + Faz 3).

Verifies that MaljanApp.run() with mock mode populates the new state fields
(``malware_report``, ``malware_report_markdown``, ``stix_bundle_extended``)
and that the dumped report round-trips through ``MalwareReport``.

Faz 3 additions test that the NarrativeAgent, when present, is invoked and
its output reaches ``MalwareReport.executive_summary``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.app import MaljanApp
from maljan.core.config import Settings
from maljan.reporting.models import MalwareReport
from maljan.reporting.narrative_agent import NarrativeAgent, NarrativeOutput
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


class TestNarrativeFallbackInMock:
    """In mock mode, NarrativeAgent is None and the deterministic fallback runs."""

    def test_executive_summary_is_fallback_template(self, mock_settings: Settings) -> None:
        app = MaljanApp(config=mock_settings, mock=True)
        result = app.run("deadbeef" * 8, file_name="mock-test.exe")
        report = MalwareReport.model_validate(result["malware_report"])

        # Fallback narrative is unique enough to identify (mock/offline phrase).
        assert "auto-generated summary" in report.executive_summary.lower()
        # Always at least one recommendation, even on the fallback path.
        assert len(report.defensive_recommendations) >= 1


class TestNarrativeWithMockLLM:
    """Production-mode pipeline with a mocked NarrativeAgent injected.

    We monkeypatch ``container.get_narrative_agent`` so the integration test
    does not need a real LLM. The mock agent returns a canned
    ``NarrativeOutput``; we assert the fields flow through to the report.
    """

    @pytest.fixture
    def canned_narrative(self) -> NarrativeOutput:
        from maljan.reporting.models import DefensiveRecommendation

        return NarrativeOutput(
            executive_summary=(
                "FAKE LLM SUMMARY: sample exhibits persistence via Run keys "
                "(T1547.001), C2 over TLS, and limited anti-analysis. "
                "Recommend immediate containment of the affected host. "
                "Confidence anchored by corroborated dynamic + network layers."
            ),
            capabilities_narrative=[
                "Persistence via T1547.001 Run key under HKLM.",
                "Command and Control via TLS to public destination.",
                "Defense Evasion limited to standard packing.",
            ],
            defensive_recommendations=[
                DefensiveRecommendation(
                    category="firewall",
                    action="Block observed C2 IP.",
                    rationale="Sample beaconed there during sandbox detonation.",
                    priority="P0",
                ),
                DefensiveRecommendation(
                    category="registry_hardening",
                    action="Audit HKLM Software\\Run for unknown entries.",
                    rationale="Sample wrote a Run key.",
                    priority="P1",
                ),
                DefensiveRecommendation(
                    category="edr_hunting",
                    action="Hunt for child processes of test.exe.",
                    rationale="Process tree pivot observed.",
                    priority="P2",
                ),
            ],
        )

    def test_narrative_output_applied_to_report(
        self,
        mock_settings: Settings,
        canned_narrative: NarrativeOutput,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        agent = MagicMock(spec=NarrativeAgent)
        agent.generate = AsyncMock(return_value=canned_narrative)

        from maljan.core.container import ServiceContainer

        monkeypatch.setattr(ServiceContainer, "get_narrative_agent", lambda self: agent)

        # Still build with mock=True so the rest of the pipeline (judge LLM etc.)
        # stays mocked. ``get_narrative_agent`` is forced to return the
        # MagicMock so the report_node will dispatch into apply_narrative.
        app = MaljanApp(config=mock_settings, mock=True)
        result = app.run("deadbeef" * 8, file_name="narr-test.exe")

        report = MalwareReport.model_validate(result["malware_report"])
        assert "FAKE LLM SUMMARY" in report.executive_summary
        assert any("T1547.001" in p for p in report.capabilities_narrative)
        agent.generate.assert_awaited_once()

    def test_narrative_failure_falls_back_to_template(
        self,
        mock_settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        agent = MagicMock(spec=NarrativeAgent)
        agent.generate = AsyncMock(return_value=None)  # forced failure

        from maljan.core.container import ServiceContainer

        monkeypatch.setattr(ServiceContainer, "get_narrative_agent", lambda self: agent)

        app = MaljanApp(config=mock_settings, mock=True)
        result = app.run("deadbeef" * 8, file_name="fallback-test.exe")
        report = MalwareReport.model_validate(result["malware_report"])

        # Deterministic fallback should have run.
        assert "auto-generated summary" in report.executive_summary.lower()


class TestDetectionSignaturesInReport:
    """Faz 4: the report_node must attach YARA/Sigma/Suricata rules."""

    def test_at_least_yara_signature_is_present(self, mock_settings: Settings) -> None:
        app = MaljanApp(config=mock_settings, mock=True)
        result = app.run("deadbeef" * 8, file_name="detect-test.exe")
        report = MalwareReport.model_validate(result["malware_report"])

        # Mock pipeline has no sandbox data; only YARA is guaranteed.
        kinds = {rule.kind for rule in report.detection_signatures}
        assert "yara" in kinds

    def test_disabled_signatures_keep_list_empty(self) -> None:
        s = Settings()
        s.llm.provider = "ollama"
        s.negotiation.max_iterations = 1
        s.reporting.enabled = True
        s.reporting.auto_generate_detection_rules = False

        app = MaljanApp(config=s, mock=True)
        result = app.run("deadbeef" * 8, file_name="no-detect.exe")
        report = MalwareReport.model_validate(result["malware_report"])
        assert report.detection_signatures == []
