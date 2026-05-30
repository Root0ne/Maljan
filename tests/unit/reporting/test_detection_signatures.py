"""Unit tests for the template-based detection signature generator."""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.detection_signatures import (
    _escape_yara,
    _safe_rule_name,
    _suricata_content_escape,
    build_detection_rules,
)
from maljan.reporting.models import MalwareReport


def _build(**kwargs: Any) -> MalwareReport:
    return MalwareReportBuilder(
        file_hash=kwargs.pop("file_hash", "a" * 64),
        file_name=kwargs.pop("file_name", "fixture.exe"),
        sample_path=kwargs.pop("sample_path", None),
        sandbox_report=kwargs.pop("sandbox_report", {}),
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision=kwargs.pop("final_decision", "Malware"),
        overall_confidence=kwargs.pop("overall_confidence", 0.9),
        cascade_summary=None,
        malware_category=kwargs.pop("malware_category", "ransomware"),
    ).build_deterministic()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestEscapeHelpers:
    def test_escape_yara_double_quote(self) -> None:
        assert _escape_yara('he said "hi"') == 'he said \\"hi\\"'

    def test_escape_yara_backslash(self) -> None:
        assert _escape_yara("HKLM\\Run") == "HKLM\\\\Run"

    def test_escape_yara_drops_control_chars(self) -> None:
        assert _escape_yara("ab\x00\x01c") == "abc"

    def test_safe_rule_name_strips_punctuation(self) -> None:
        assert _safe_rule_name("evil.family-2.0") == "evil_family_2_0"

    def test_safe_rule_name_truncates(self) -> None:
        name = _safe_rule_name("x" * 200)
        assert len(name) <= 64

    def test_suricata_content_escape_safe_chars(self) -> None:
        assert _suricata_content_escape("evil.com") == "evil.com"

    def test_suricata_content_escape_unsafe_chars(self) -> None:
        out = _suricata_content_escape('"evil"')
        assert '"' not in out
        assert "|22|" in out  # double-quote as hex


# ---------------------------------------------------------------------------
# Empty / minimal report
# ---------------------------------------------------------------------------


class TestEmptyReport:
    def test_no_evidence_yields_only_yara(self) -> None:
        """An empty sandbox/static report still produces a YARA rule because
        the sha256 fingerprint is always available."""
        report = _build()
        # Wave 9 (2026-05-29): the YARA gate refuses generation for
        # ungrounded family attribution (mirrors the Sigma gate). The
        # builder fixture forces family_grounded=False; clear the family so
        # the gate doesn't fire and we exercise the legacy "sha256-only"
        # path.
        report.attribution.family = None
        rules = build_detection_rules(report)
        kinds = {r.kind for r in rules}
        assert kinds == {"yara"}

    def test_yara_rule_has_sha256_condition(self) -> None:
        report = _build(file_hash="b" * 64)
        report.attribution.family = None
        rules = build_detection_rules(report)
        yara_rule = next(r for r in rules if r.kind == "yara")
        assert "b" * 64 in yara_rule.body
        assert "hash.sha256" in yara_rule.body


# ---------------------------------------------------------------------------
# Ransomware fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def ransomware_report() -> MalwareReport:
    sandbox = {
        "target": {"file": {"sha256": "c" * 64, "name": "lockbit.exe"}},
        "behavior": {
            "processes": [
                {"name": "lockbit.exe", "pid": 1234, "ppid": 1, "cmd": "lockbit.exe -encrypt"}
            ],
            "calls": [
                {
                    "api": "RegSetValueExA",
                    "arguments": [
                        {
                            "FullName": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            "ValueName": "lockbit",
                            "Buffer": "C:\\Users\\Public\\lockbit.exe",
                        }
                    ],
                }
            ],
        },
        "network": {
            "dns": [{"request": "evil-c2.duckdns.org", "answers": []}],
            "tcp": [{"dst": "1.2.3.4", "dport": 443}],
            "http": [{"host": "evil-c2.duckdns.org", "uri": "/beacon", "method": "GET"}],
        },
        "signatures": [
            {
                "name": "InstallsAutoRun",
                "description": "Installs registry auto-run entry",
                "severity": 8,
            },
            # Wave 4: ground the "ransomware" family so the Sigma gate
            # doesn't refuse generation. The D11 guardrail (shipped Wave 3)
            # only allows the family through when a Triage CTI block,
            # sandbox signature, or analyst claim corroborates it.
            {
                "name": "RansomwareEncryptsFiles",
                "description": "Ransomware-style mass file encryption",
                "severity": 9,
            },
        ],
    }
    return _build(
        file_hash="c" * 64,
        sandbox_report=sandbox,
        malware_category="ransomware",
        overall_confidence=0.92,
    )


class TestRansomwareYara:
    def test_yara_rule_emitted(self, ransomware_report: MalwareReport) -> None:
        rules = build_detection_rules(ransomware_report)
        assert any(r.kind == "yara" for r in rules)

    def test_yara_rule_name_prefixed(self, ransomware_report: MalwareReport) -> None:
        rules = build_detection_rules(ransomware_report)
        rule = next(r for r in rules if r.kind == "yara")
        assert rule.name.startswith("Maljan_AutoGen_")

    def test_yara_body_includes_imports(self, ransomware_report: MalwareReport) -> None:
        rules = build_detection_rules(ransomware_report)
        rule = next(r for r in rules if r.kind == "yara")
        assert 'import "hash"' in rule.body


class TestRansomwareSigma:
    def test_sigma_emitted(self, ransomware_report: MalwareReport) -> None:
        rules = build_detection_rules(ransomware_report)
        assert any(r.kind == "sigma" for r in rules)

    def test_sigma_body_parses_as_yaml(self, ransomware_report: MalwareReport) -> None:
        rules = build_detection_rules(ransomware_report)
        rule = next(r for r in rules if r.kind == "sigma")
        parsed = yaml.safe_load(rule.body)
        assert isinstance(parsed, dict)
        for key in ("title", "id", "detection", "logsource"):
            assert key in parsed

    def test_sigma_compile_error_none(self, ransomware_report: MalwareReport) -> None:
        rules = build_detection_rules(ransomware_report)
        rule = next(r for r in rules if r.kind == "sigma")
        assert rule.compile_error is None

    def test_sigma_includes_registry_target(self, ransomware_report: MalwareReport) -> None:
        rules = build_detection_rules(ransomware_report)
        rule = next(r for r in rules if r.kind == "sigma")
        parsed = yaml.safe_load(rule.body)
        registry = parsed["detection"].get("selection_registry") or {}
        contains = registry.get("TargetObject|contains") or []
        joined = " ".join(contains)
        assert "CurrentVersion\\Run" in joined or "currentversion\\run" in joined.lower()


class TestRansomwareSuricata:
    def test_suricata_emitted(self, ransomware_report: MalwareReport) -> None:
        rules = build_detection_rules(ransomware_report)
        assert any(r.kind == "suricata" for r in rules)

    def test_suricata_body_passes_sanity_check(self, ransomware_report: MalwareReport) -> None:
        rules = build_detection_rules(ransomware_report)
        rule = next(r for r in rules if r.kind == "suricata")
        assert rule.compile_error is None

    def test_suricata_includes_domain_rule(self, ransomware_report: MalwareReport) -> None:
        rules = build_detection_rules(ransomware_report)
        rule = next(r for r in rules if r.kind == "suricata")
        assert "evil-c2.duckdns.org" in rule.body
        assert "alert dns" in rule.body

    def test_suricata_includes_ip_rule(self, ransomware_report: MalwareReport) -> None:
        rules = build_detection_rules(ransomware_report)
        rule = next(r for r in rules if r.kind == "suricata")
        # IP rule is emitted when at least one valid IP exists.
        assert "1.2.3.4" in rule.body

    def test_suricata_includes_http_rule(self, ransomware_report: MalwareReport) -> None:
        rules = build_detection_rules(ransomware_report)
        rule = next(r for r in rules if r.kind == "suricata")
        assert "http.host" in rule.body
        assert "/beacon" in rule.body


# ---------------------------------------------------------------------------
# Builder hook + escaping edge cases
# ---------------------------------------------------------------------------


class TestBuilderAttach:
    def test_attach_replaces_signatures(self, ransomware_report: MalwareReport) -> None:
        # Start with a stub signature so we can verify it's replaced.
        from maljan.reporting.models import DetectionRule

        ransomware_report.detection_signatures = [
            DetectionRule(kind="yara", name="stub", body="rule x {condition: false}")
        ]
        MalwareReportBuilder.attach_detection_signatures(ransomware_report)
        assert all(r.name != "stub" for r in ransomware_report.detection_signatures)


class TestEscapingEdgeCases:
    def test_domain_with_quotes_does_not_break_suricata(self) -> None:
        """Confirm that a malicious domain containing quotes is escaped."""
        sandbox = {
            "network": {
                "dns": [{"request": 'evil"injection.com', "answers": []}],
            }
        }
        report = _build(sandbox_report=sandbox)
        rules = build_detection_rules(report)
        suricata = next((r for r in rules if r.kind == "suricata"), None)
        assert suricata is not None
        # Raw double-quote must NOT appear in content. We check by scanning
        # the rule line by line for unescaped `content:"..."` quote breaks.
        for line in suricata.body.splitlines():
            if "content:" in line:
                assert 'content:"evil"injection' not in line


class TestNoNetworkNoSuricata:
    def test_skips_suricata_without_network(self) -> None:
        report = _build()  # default sandbox has no network section
        rules = build_detection_rules(report)
        assert all(r.kind != "suricata" for r in rules)


class TestNoDynamicNoSigma:
    def test_skips_sigma_without_dynamic(self) -> None:
        report = _build()
        rules = build_detection_rules(report)
        # Without registry / persistence / sandbox sigs Sigma is skipped.
        assert all(r.kind != "sigma" for r in rules)


# ---------------------------------------------------------------------------
# Wave 9 — YARA family-grounded gate (mirror of the Wave 4 Sigma gate)
# ---------------------------------------------------------------------------


class TestYaraFamilyGroundedGate:
    """The Wave 4 Sigma gate refuses generation when family_grounded=false.
    Wave 9 extends the same gate to YARA so the 2026-05-29 Linux ELF audit's
    ``Maljan_AutoGen_unknown`` stub cannot ship."""

    def test_yara_gated_when_family_ungrounded(self) -> None:
        report = _build()
        # Force the ungrounded-family condition the audit hit.
        report.attribution.family = "unknown"
        report.attribution.family_grounded = False
        rules = build_detection_rules(report)
        assert all(r.kind != "yara" for r in rules), (
            "YARA gate should refuse generation when family_grounded=false"
        )

    def test_yara_emitted_when_family_grounded(self) -> None:
        report = _build()
        report.attribution.family = "lockbit"
        report.attribution.family_grounded = True
        rules = build_detection_rules(report)
        assert any(r.kind == "yara" for r in rules)

    def test_yara_emitted_when_no_family_set(self) -> None:
        # Common case: deterministic-only pipeline with no attribution. The
        # gate must only fire on the explicit ungrounded-family path.
        report = _build()
        report.attribution.family = None
        report.attribution.family_grounded = True
        rules = build_detection_rules(report)
        assert any(r.kind == "yara" for r in rules)
