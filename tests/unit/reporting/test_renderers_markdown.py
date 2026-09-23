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
from maljan.reporting.models import CapabilityCell, MalwareReport, TTPMapping
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.isr_models import UNVERIFIED_TECHNIQUE_MARKER
from tests.unit._ledger_helpers import ledger_from_sandbox, persistence_isr

# The headings every report carries, whatever the run gathered.
REQUIRED_HEADINGS = [
    "## 1. Key findings",
    "## 2. Sample overview",
    "## 3. Verdict and assessment",
    "## 6. Observed behaviour",
    "## 8. MITRE ATT&CK mapping",
    "## 9. Indicators of compromise",
    "## 12. Attribution and related activity",
    "## 13. Limitations and analysis notes",
    "## Appendix B. Run summary",
    "## Appendix C. References",
    "## Appendix D. Methodology",
]

# The headings that appear only when the run filled the block behind them. An
# empty heading reads as a gap in the sample rather than a run that never
# called the tool behind it.
# The sections a run fills only from evidence: printed with their one line
# when a run has none, and never with a model's voice.
EVIDENCE_DEPENDENT_HEADINGS = [
    "## 4. Execution flow · _Measured_",
    "## 5. Technical analysis",
    "## 7. Static properties · _Measured_",
    "## 10. Detection",
    "## 11. Recommendations · _Measured_",
]


def _build(**kwargs: Any) -> MalwareReport:
    # A sandbox fixture reaches the report through the tools a dynamic analyst
    # would have called on it, which is the only route there is now.
    _sandbox = kwargs.pop("sandbox_report", {})
    return MalwareReportBuilder(
        file_hash=kwargs.pop("file_hash", "a" * 64),
        file_name=kwargs.pop("file_name", "fixture.bin"),
        sample_path=kwargs.pop("sample_path", None),
        sandbox_report=_sandbox,
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
        judge_assessment=kwargs.pop("judge_assessment", None),
        malware_category=kwargs.pop("malware_category", None),
        evidence_ledger=kwargs.pop("evidence_ledger", None)
        or (ledger_from_sandbox(_sandbox) if _sandbox else []),
    ).build_deterministic()


class TestMinimalReport:
    def test_all_required_headings_present(self) -> None:
        report = _build()
        report = MalwareReportBuilder.apply_fallback_narrative(report)
        markdown = MarkdownRenderer().render(report)
        for heading in REQUIRED_HEADINGS:
            assert heading in markdown, f"missing heading: {heading}"

    def test_an_empty_section_is_printed_with_one_line_saying_so(self) -> None:
        report = MalwareReportBuilder.apply_fallback_narrative(_build())
        markdown = MarkdownRenderer().render(report)
        for heading in EVIDENCE_DEPENDENT_HEADINGS:
            assert heading in markdown, f"section not printed: {heading}"
        assert "_Written by the report model_" not in markdown

    def test_a_report_with_no_summary_says_so_and_lists_the_verdict_facts(self) -> None:
        report = MalwareReportBuilder.apply_fallback_narrative(_build(), "the round timed out")
        markdown = MarkdownRenderer().render(report)
        findings = markdown.split("## 1. Key findings", 1)[1].split("## 2.", 1)[0]
        assert "No summary was written: the round timed out." in findings
        assert "Verdict: Malware (moderate-to-high confidence, 0.85, stated by the judge)" in (
            findings
        )
        assert "Published network indicators: 0 _(Measured)_" in findings
        assert "_Pending narrative generation._" not in markdown

    def test_sha256_in_header(self) -> None:
        report = _build()
        markdown = MarkdownRenderer().render(report)
        assert "a" * 64 in markdown


class TestHonestySignals:
    """Degraded-run banner + family-grounding markers (report honesty)."""

    def test_defaults_are_clean(self) -> None:
        report = _build()
        assert report.degraded_mode is False
        assert report.degradation_reasons == []
        md = MarkdownRenderer().render(report)
        assert "[DEGRADED RUN]" not in md

    def test_degraded_banner_rendered(self) -> None:
        report = _build()
        report.degraded_mode = True
        report.degradation_reasons = ["all LLM analysts errored", "sandbox observed nothing"]
        md = MarkdownRenderer().render(report)
        assert "[DEGRADED RUN]" in md
        assert "all LLM analysts errored" in md

    def test_ungrounded_family_marker(self) -> None:
        report = _build()
        report.attribution.family = "evilcorp"
        report.attribution.family_confidence = 0.0
        report.attribution.family_grounded = False
        md = MarkdownRenderer().render(report)
        assert "evilcorp (very low confidence, 0.00) (no evidence cited)" in md

    def test_unknown_family_has_no_confidence_noise(self) -> None:
        report = _build(malware_category=None)
        report.attribution.family = None
        md = MarkdownRenderer().render(report)
        assert "**Family:** none attributed" in md
        assert "unknown (" not in md


class TestProfileLine:
    """Non-default analyst profiles surface a header line naming the ensemble."""

    def test_default_profile_is_byte_identical(self) -> None:
        report = _build()
        report = MalwareReportBuilder.apply_fallback_narrative(report)

        report_no_profile = _build(
            run_summary={
                "elapsed_seconds": 12.3,
                "final_decision": "Malware",
                "negotiation": {
                    "rounds_completed": 1,
                    "termination_reason": "consensus",
                    "final_confidence": 0.85,
                },
            }
        )
        report_no_profile = MalwareReportBuilder.apply_fallback_narrative(report_no_profile)
        # Pin the one field that legitimately varies between two builds
        # (wall-clock generation time) so this is a true byte-identical
        # comparison of the rendered content itself.
        report_no_profile.generated_at = report.generated_at

        with_default = MarkdownRenderer().render(report)
        without_profile = MarkdownRenderer().render(report_no_profile)

        assert with_default == without_profile
        assert "Profile:" not in with_default

    def test_absent_profile_has_no_line(self) -> None:
        report = _build()
        md = MarkdownRenderer().render(report)
        assert "Profile:" not in md

    def test_non_default_profile_line_rendered_once_in_order_with_custom_marked(self) -> None:
        report = _build(
            run_summary={
                "elapsed_seconds": 1.0,
                "final_decision": "Malware",
                "profile": {
                    "name": "lean",
                    "analysts": ["network", "strings"],
                    "custom": ["strings"],
                },
            }
        )
        md = MarkdownRenderer().render(report)
        assert md.count("Profile:") == 1
        assert "Profile: lean — analysts: network, strings (custom)" in md


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
                "tls": [{"ja3": "client-fp-1", "ja3s": "server-fp-1"}],
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
            isr_reports={
                "dynamic": persistence_isr(
                    [
                        [
                            "registry_run",
                            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            "C:\\Users\\Public\\lockbit.exe",
                        ]
                    ]
                )
            },
        )
        return MalwareReportBuilder.apply_fallback_narrative(report)

    def test_network_iocs_rendered_defanged(self, report: MalwareReport) -> None:
        markdown = MarkdownRenderer().render(report)
        assert "evil-c2[.]duckdns[.]org" in markdown
        assert "1[.]2[.]3[.]4" in markdown
        assert "evil-c2.duckdns.org" not in markdown

    def test_ja3_and_ja3s_fingerprints_rendered(self, report: MalwareReport) -> None:
        # The TLS rows have no typed home in ``NetworkIOCs`` any more; they
        # reach the report as the evidence section built from the sandbox
        # network call, which is where a reader can also see the call id.
        markdown = MarkdownRenderer().render(report)
        assert "client-fp-1" in markdown
        assert "server-fp-1" in markdown

    def test_persistence_table_present(self, report: MalwareReport) -> None:
        markdown = MarkdownRenderer().render(report)
        assert "registry_run" in markdown
        assert "lockbit" in markdown.lower()

    def test_an_unassessed_severity_says_so_rather_than_printing_a_rating(
        self, report: MalwareReport
    ) -> None:
        markdown = MarkdownRenderer().render(report)
        assert "not assessed" in markdown
        assert "[INFORMATIONAL]" not in markdown


class TestSeverityBadge:
    def test_the_severity_badge_uses_square_brackets(self) -> None:
        from maljan.schemas.judgement import JudgeAssessment, SeverityVerdict

        report = _build(
            final_decision="Suspicious",
            judge_assessment=JudgeAssessment(severity=SeverityVerdict(rating="Medium")),
        )
        markdown = MarkdownRenderer().render(report)
        assert "**Severity:** `[MEDIUM]`" in markdown
        assert "/10" not in markdown


# ---------------------------------------------------------------------------
# Wave 9 — per-section defensive isolation
# ---------------------------------------------------------------------------


class TestSectionFailureIsolation:
    """The /reports/{id}/markdown endpoint 500-ed on the 2026-05-29 Linux
    ELF audit because ``_section_dynamic_behavior`` called .get() on a
    non-dict entry in ``notable_apis``. After Wave 9, each section is
    wrapped so a single subtree failure cannot 500 the whole endpoint."""

    def test_malformed_notable_apis_does_not_500(self) -> None:
        from maljan.reporting.models import DynamicBehavior

        report = _build()
        # Pydantic normally rejects non-dict entries; bypass with
        # ``model_construct`` to simulate a partially-corrupted upstream
        # state (e.g., a state hop that lost a field). Renderer must still
        # produce output without raising.
        report.dynamic = DynamicBehavior.model_construct(
            notable_apis=[
                {"api": "CreateFile", "category": "fs", "process": "rat.exe", "count": 1},
                None,
                "bogus-string-not-a-dict",
                {"api": "VirtualAlloc"},
            ],
            process_tree=[],
            registry_mods=[],
            file_operations=[],
            sandbox_signatures=[],
        )
        markdown = MarkdownRenderer().render(report)
        assert "## 6. Observed behaviour" in markdown
        assert "CreateFile" in markdown

    def test_section_failure_isolated(self) -> None:
        """If a single section raises, the others must still render."""
        renderer = MarkdownRenderer()
        report = _build()

        def _boom(_report: MalwareReport) -> str:
            raise RuntimeError("synthetic section failure")

        # Monkey-patch one section to raise; the remaining sections + the
        # safe-section stub must still produce a valid markdown body.
        def _boom_with_context(_report: MalwareReport, _ctx: object) -> str:
            return _boom(_report)

        original = renderer._section_indicators  # type: ignore[attr-defined]
        renderer._section_indicators = _boom_with_context  # type: ignore[assignment]
        try:
            markdown = renderer.render(report)
        finally:
            renderer._section_indicators = original  # type: ignore[assignment]

        assert "## 2. Sample overview" in markdown
        assert "section 'indicators' rendering failed" in markdown


class TestAnUnverifiedTechniqueIdIsPrintedWithItsMarker:
    """An id the ATT&CK catalog does not have stays in the report, labelled.

    The analyst was told and kept its answer; deleting the row would delete the
    answer from the one surface a reader looks at. Both renderers print the
    reason beside it — HTML is generated from the markdown, so one source.
    """

    @staticmethod
    def _report_with_unverified() -> MalwareReport:
        report = _build()
        report.capability_matrix = [
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T7777",
                technique_name="Invented Technique",
                confidence=0.6,
                contributing_layers=["static"],
                technique_id_valid=False,
            )
        ]
        report.ttp_mappings = [
            TTPMapping(
                technique_id="T7777",
                technique_name="Invented Technique",
                tactic="TA0005",
                evidence_quotes=["the analyst said so"],
                confidence=0.6,
                contributing_layers=["static"],
                technique_id_valid=False,
            )
        ]
        return report

    def test_the_matrix_row_carries_the_marker(self) -> None:
        markdown = MarkdownRenderer().render(self._report_with_unverified())

        assert "T7777" in markdown
        assert UNVERIFIED_TECHNIQUE_MARKER in markdown

    def test_the_status_column_carries_it(self) -> None:
        markdown = MarkdownRenderer().render(self._report_with_unverified())

        (row,) = [
            line for line in markdown.splitlines() if line.startswith("| ") and "T7777" in line
        ]
        assert f"unverified id ({UNVERIFIED_TECHNIQUE_MARKER})" in row

    def test_the_html_export_carries_it(self) -> None:
        """HTML is generated from the markdown, so the ampersand in "ATT&CK"
        arrives escaped. The marker is one string in one place either way."""
        from maljan.reporting.renderers import HtmlRenderer

        html = HtmlRenderer().render(self._report_with_unverified())

        assert UNVERIFIED_TECHNIQUE_MARKER.replace("&", "&amp;") in html

    def test_a_catalogued_id_is_printed_without_one(self) -> None:
        report = _build()
        report.capability_matrix = [
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1055",
                technique_name="Process Injection",
                confidence=0.6,
                contributing_layers=["static"],
            )
        ]

        markdown = MarkdownRenderer().render(report)

        assert "T1055" in markdown
        assert UNVERIFIED_TECHNIQUE_MARKER not in markdown
