"""Tests for ``MarkdownRenderer``.

We feed the renderer three representative reports (minimal, full ransomware,
static-only) and assert on the section headings + structural rules. We do NOT
golden-snapshot the full markdown — that would force a rewrite every time we
nudge a phrase.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.markdown import MarkdownRenderer

REQUIRED_HEADINGS = [
    "# Malware Analysis Report",
    "## Sample Identification",
    "## Severity & Impact",
    "## Executive Summary",
    "## Capabilities Narrative",
    "## Static Analysis",
    "## Dynamic Behavior",
    "## Network IOCs",
    "## Persistence Mechanisms",
    "## MITRE ATT&CK Matrix",
    "## Capability Matrix (evidence)",
    "## Family Attribution",
    "## Detection Signatures",
    "## Defensive Recommendations",
    "## References",
    "## Run Summary",
]


def _build(**kwargs: Any) -> MalwareReport:
    return MalwareReportBuilder(
        file_hash=kwargs.pop("file_hash", "a" * 64),
        file_name=kwargs.pop("file_name", "fixture.bin"),
        sample_path=kwargs.pop("sample_path", None),
        sandbox_report=kwargs.pop("sandbox_report", {}),
        reports=kwargs.pop("reports", {}),
        isr_reports=kwargs.pop("isr_reports", {}),
        stix_output=kwargs.pop("stix_output", {"objects": []}),
        run_summary=kwargs.pop(
            "run_summary",
            {
                "elapsed_seconds": 12.3,
                "final_decision": kwargs.get("final_decision", "Malware"),
                "negotiation": {
                    "rounds_completed": 1,
                    "termination_reason": "consensus",
                    "final_confidence": 0.85,
                },
            },
        ),
        discussion_history=kwargs.pop("discussion_history", []),
        final_decision=kwargs.pop("final_decision", "Malware"),
        overall_confidence=kwargs.pop("overall_confidence", 0.85),
        cascade_summary=kwargs.pop("cascade_summary", None),
        malware_category=kwargs.pop("malware_category", None),
    ).build_deterministic()


class TestMinimalReport:
    def test_all_required_headings_present(self) -> None:
        report = _build()
        report = MalwareReportBuilder.apply_fallback_narrative(report)
        markdown = MarkdownRenderer().render(report)
        for heading in REQUIRED_HEADINGS:
            assert heading in markdown, f"missing heading: {heading}"

    def test_markdown_is_long_enough(self) -> None:
        report = _build()
        report = MalwareReportBuilder.apply_fallback_narrative(report)
        markdown = MarkdownRenderer().render(report)
        assert len(markdown.splitlines()) > 50

    def test_sha256_in_header(self) -> None:
        report = _build()
        markdown = MarkdownRenderer().render(report)
        assert "a" * 64 in markdown


class TestRansomwareReport:
    @pytest.fixture
    def report(self) -> MalwareReport:
        sandbox = {
            "target": {"file": {"sha256": "b" * 64, "name": "lockbit.exe"}},
            "behavior": {
                "processes": [
                    {
                        "name": "lockbit.exe",
                        "pid": 1234,
                        "ppid": 1,
                        "cmd": "lockbit.exe -encrypt",
                    }
                ],
                "calls": [
                    {
                        "api": "RegSetValueExA",
                        "arguments": [
                            {
                                "FullName": (
                                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                                ),
                                "ValueName": "lockbit",
                                "Buffer": "C:\\Users\\Public\\lockbit.exe",
                            }
                        ],
                    }
                ],
                "apistats": {"lockbit.exe": {"CryptEncrypt": 42}},
            },
            "network": {
                "dns": [{"request": "evil-c2.duckdns.org", "answers": []}],
                "tcp": [{"dst": "1.2.3.4", "dport": 443}],
            },
            "signatures": [
                {
                    "name": "InstallsAutoRun",
                    "severity": 8,
                    "marks": ["HKLM\\...\\Run\\lockbit"],
                }
            ],
        }
        report = _build(
            file_hash="b" * 64,
            sandbox_report=sandbox,
            malware_category="ransomware",
            overall_confidence=0.92,
        )
        return MalwareReportBuilder.apply_fallback_narrative(report)

    def test_network_iocs_rendered(self, report: MalwareReport) -> None:
        markdown = MarkdownRenderer().render(report)
        assert "evil-c2.duckdns.org" in markdown
        assert "1.2.3.4" in markdown

    def test_persistence_table_present(self, report: MalwareReport) -> None:
        markdown = MarkdownRenderer().render(report)
        assert "registry_run" in markdown
        assert "lockbit" in markdown.lower()

    def test_severity_badge_uppercase(self, report: MalwareReport) -> None:
        markdown = MarkdownRenderer().render(report)
        # severity badge is wrapped in square brackets and uppercased
        assert "[CRITICAL]" in markdown or "[HIGH]" in markdown


class TestSeverityBadge:
    def test_verdict_badge_uses_square_brackets(self) -> None:
        report = _build(final_decision="Suspicious")
        markdown = MarkdownRenderer().render(report)
        assert "[SUSPICIOUS]" in markdown
