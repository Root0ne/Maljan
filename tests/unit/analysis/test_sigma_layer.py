"""tests/unit/analysis/test_sigma_layer.py — SigmaLayer birim testleri.

Kapsam:
  - from_rules_dir() graceful degradation (dizin yok)
  - scan_events() json / dict tabanli arama
  - scan_log_lines() metin tabanlı tarama (geriye donuk uyumluluk)
  - to_isr() AgentISR olusturma
  - techniques_covered() kume dondurme
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from maljan.analysis.sigma_layer import (
    SigmaLayer,
    SigmaMatch,
    _classify_log_source,
    _is_rule_compatible,
    build_events_from_sandbox,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_rules_dir(tmp_path: Path) -> Path:
    """Gecici bir sigma_rules dizini olusturur."""
    rules_dir = tmp_path / "sigma_rules"
    rules_dir.mkdir()
    return rules_dir


def _write_rule(rules_dir: Path, filename: str, content: str) -> Path:
    path = rules_dir / filename
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


VALID_RULE_CONTENT = """\
title: Test LSASS Access
id: 5a484c2f-e8d7-4632-9b2f-87002dbfbd28
status: stable
description: Test rule for LSASS credential dumping detection.
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess: '0x1010'
    condition: selection
tags:
    - attack.credential_access
    - attack.t1003.001
level: high
"""

POWERSHELL_RULE_CONTENT = """\
title: PowerShell Encoded Command
id: b2a84c2f-e8d7-4632-9b2f-87002dbfbd28
status: test
description: Detects encoded PowerShell commands.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'EncodedCommand'
    condition: selection
tags:
    - attack.execution
    - attack.t1059.001
level: medium
"""

NO_ATTACK_TAG_RULE = """\
title: Generic Detection
id: c3a84c2f-e8d7-4632-9b2f-87002dbfbd28
status: stable
description: A rule without ATT&CK tags.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'suspicious.exe'
    condition: selection
tags:
    - detection.generic
level: low
"""

# ---------------------------------------------------------------------------
# SigmaLayer factory & metadata tests
# ---------------------------------------------------------------------------


class TestSigmaLayerMetadata:
    def test_from_rules_dir_loads_valid_rules(self, tmp_rules_dir: Path) -> None:
        _write_rule(tmp_rules_dir, "rule1.yml", VALID_RULE_CONTENT)
        _write_rule(tmp_rules_dir, "rule2.yml", POWERSHELL_RULE_CONTENT)
        layer = SigmaLayer.from_rules_dir(tmp_rules_dir)
        assert layer.rule_count == 2

    def test_from_rules_dir_nonexistent_returns_empty(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "does_not_exist"
        layer = SigmaLayer.from_rules_dir(nonexistent)
        assert layer.rule_count == 0

    def test_techniques_covered_returns_set(self, tmp_rules_dir: Path) -> None:
        _write_rule(tmp_rules_dir, "rule1.yml", VALID_RULE_CONTENT)
        _write_rule(tmp_rules_dir, "rule2.yml", POWERSHELL_RULE_CONTENT)
        layer = SigmaLayer.from_rules_dir(tmp_rules_dir)
        covered = layer.techniques_covered()
        assert "T1003.001" in covered
        assert "T1059.001" in covered
        assert isinstance(covered, set)

    def test_confidence_and_technique_extraction(self, tmp_rules_dir: Path) -> None:
        _write_rule(tmp_rules_dir, "rule1.yml", VALID_RULE_CONTENT)
        layer = SigmaLayer.from_rules_dir(tmp_rules_dir)
        rule = layer._collection.rules[0]
        # Test private helpers
        assert layer._extract_technique_id(rule) == "T1003.001"
        assert layer._get_confidence(rule) == 0.88  # stable


# ---------------------------------------------------------------------------
# scan_events() tests (Structured)
# ---------------------------------------------------------------------------


class TestScanEvents:
    def test_scan_empty_events_returns_empty(self, tmp_rules_dir: Path) -> None:
        _write_rule(tmp_rules_dir, "rule.yml", VALID_RULE_CONTENT)
        layer = SigmaLayer.from_rules_dir(tmp_rules_dir)
        matches = layer.scan_events([])
        assert matches == []

    def test_scan_detects_lsass_match(self, tmp_rules_dir: Path) -> None:
        _write_rule(tmp_rules_dir, "rule.yml", VALID_RULE_CONTENT)
        layer = SigmaLayer.from_rules_dir(tmp_rules_dir)
        events = [
            {
                "EventID": "10",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1010",
            }
        ]
        matches = layer.scan_events(events, log_source="sysmon")
        assert len(matches) == 1
        match = matches[0]
        assert match.technique_id == "T1003.001"
        assert match.confidence == 0.88
        assert "TargetImage" in match.matched_fields

    def test_scan_no_match_returns_empty(self, tmp_rules_dir: Path) -> None:
        _write_rule(tmp_rules_dir, "rule.yml", VALID_RULE_CONTENT)
        layer = SigmaLayer.from_rules_dir(tmp_rules_dir)
        events = [{"TargetImage": "C:\\Windows\\explorer.exe", "GrantedAccess": "0x1000"}]
        matches = layer.scan_events(events)
        assert matches == []


# ---------------------------------------------------------------------------
# scan_log_lines() tests (Unstructured)
# ---------------------------------------------------------------------------


class TestScanLogLines:
    def test_scan_unstructured_lsass_match(self, tmp_rules_dir: Path) -> None:
        _write_rule(tmp_rules_dir, "rule.yml", VALID_RULE_CONTENT)
        layer = SigmaLayer.from_rules_dir(tmp_rules_dir)
        # Log satirindan heuristic olarak "TargetImage: C:\Windows\System32\lsass.exe" yakalanacak.
        log_lines = [
            "2024-01-01 TargetImage: C:\\Windows\\System32\\lsass.exe, GrantedAccess: 0x1010"
        ]
        matches = layer.scan_log_lines(log_lines, log_source="windows_security")
        assert len(matches) == 1
        assert matches[0].technique_id == "T1003.001"

    def test_scan_powershell_match(self, tmp_rules_dir: Path) -> None:
        _write_rule(tmp_rules_dir, "rule.yml", POWERSHELL_RULE_CONTENT)
        layer = SigmaLayer.from_rules_dir(tmp_rules_dir)
        log_lines = ["CommandLine: powershell.exe -EncodedCommand aGVsbG8="]
        matches = layer.scan_log_lines(log_lines, log_source="sysmon")
        assert len(matches) == 1
        assert matches[0].technique_id == "T1059.001"


# ---------------------------------------------------------------------------
# to_isr() tests
# ---------------------------------------------------------------------------


class TestToISR:
    def test_to_isr_with_matches(self, tmp_rules_dir: Path) -> None:
        _write_rule(tmp_rules_dir, "rule.yml", VALID_RULE_CONTENT)
        layer = SigmaLayer.from_rules_dir(tmp_rules_dir)
        events = [{"TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1010"}]
        matches = layer.scan_events(events)
        isr = layer.to_isr(matches)
        assert isr.domain == "sigma"
        assert isr.agent_id == "sigma_layer"
        assert len(isr.claims) == len(matches)
        assert isr.claims[0].technique_id == "T1003.001"


# ---------------------------------------------------------------------------
# SigmaMatch property tests
# ---------------------------------------------------------------------------


class TestSigmaMatchProperties:
    def test_properties(self) -> None:
        match = SigmaMatch(
            rule_id="test-001",
            rule_title="Test Rule",
            technique_id="T1055",
            confidence=0.85,
            log_source="sysmon",
            matched_fields={"CommandLine": "VirtualAllocEx"},
        )
        assert "Test Rule" in match.evidence_ref
        assert "T1055" in match.claim_text
        assert "sysmon" in match.claim_text

        with pytest.raises((AttributeError, TypeError)):
            match.technique_id = "T9999"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# _classify_log_source() tests
# ---------------------------------------------------------------------------


class TestClassifyLogSource:
    def test_sysmon(self) -> None:
        assert _classify_log_source("sysmon", "windows") == "sysmon"

    def test_zeek(self) -> None:
        assert _classify_log_source("zeek", "linux") == "zeek"

    def test_generic_fallback(self) -> None:
        assert _classify_log_source("unknown_source", "other") == "generic"


# ---------------------------------------------------------------------------
# Wave 4 platform filtering tests
# ---------------------------------------------------------------------------


class TestPlatformCompatibility:
    """Wave 4: rule-vs-sample platform compatibility resolver."""

    def test_none_sample_platform_is_legacy_pass_through(self) -> None:
        # Legacy callers (older tests) pass sample_platform=None → keep all.
        assert _is_rule_compatible("windows", None) is True
        assert _is_rule_compatible("azure", None) is True
        assert _is_rule_compatible(None, None) is True

    def test_generic_rule_always_compatible(self) -> None:
        for sp in (None, "windows", "linux", "unknown"):
            assert _is_rule_compatible(None, sp) is True
            assert _is_rule_compatible("", sp) is True

    def test_windows_rule_dropped_for_linux(self) -> None:
        # Foreign-OS rule dropped: a Windows PowerShell rule on a Linux sample.
        assert _is_rule_compatible("windows", "linux") is False

    def test_windows_rule_kept_for_windows(self) -> None:
        assert _is_rule_compatible("windows", "windows") is True

    def test_macos_rule_dropped_for_supported_sample(self) -> None:
        # A macOS (out-of-scope OS) rule is dropped for a Win/Linux sample.
        assert _is_rule_compatible("macos", "linux") is False
        assert _is_rule_compatible("macos", "windows") is False

    def test_cloud_rule_dropped_for_supported_sample(self) -> None:
        # Cloud/SaaS products are out of scope (Win/Linux only) — an azure/aws/gcp
        # rule is an unmapped product and dropped for every supported sample.
        assert _is_rule_compatible("aws", "windows") is False
        assert _is_rule_compatible("gcp", "linux") is False
        assert _is_rule_compatible("azure", "windows") is False

    def test_network_log_product_always_dropped(self) -> None:
        # T1095 DNS Z Flag (zeek product) — no network-log layer yet.
        assert _is_rule_compatible("zeek", "windows") is False
        assert _is_rule_compatible("suricata", "linux") is False

    def test_unknown_sample_drops_non_generic_rules(self) -> None:
        # Conservative default: platform inference failed → no risky rules.
        assert _is_rule_compatible("windows", "unknown") is False
        assert _is_rule_compatible("azure", "unknown") is False
        # Generic still fires.
        assert _is_rule_compatible(None, "unknown") is True
        assert _is_rule_compatible("", "unknown") is True


class TestScanWithPlatformFilter:
    """End-to-end: full scan loop should skip platform-incompatible rules."""

    def test_filters_windows_rule_for_linux(self, tmp_rules_dir: Path) -> None:
        # Foreign-OS rule dropped end-to-end: a Windows PowerShell rule must not
        # fire on a Linux sample.
        _write_rule(tmp_rules_dir, "ps.yml", POWERSHELL_RULE_CONTENT)
        layer = SigmaLayer.from_rules_dir(tmp_rules_dir)
        log_lines = ["CommandLine: powershell.exe -EncodedCommand aGVsbG8="]

        layer.reset_filter_stats()
        matches = layer.scan_log_lines(log_lines, sample_platform="linux")

        assert matches == []
        assert layer.last_filtered_count == 1

    def test_keeps_windows_rule_for_windows(self, tmp_rules_dir: Path) -> None:
        _write_rule(tmp_rules_dir, "ps.yml", POWERSHELL_RULE_CONTENT)
        layer = SigmaLayer.from_rules_dir(tmp_rules_dir)
        log_lines = ["CommandLine: powershell.exe -EncodedCommand aGVsbG8="]

        layer.reset_filter_stats()
        matches = layer.scan_log_lines(log_lines, sample_platform="windows")

        assert len(matches) == 1
        assert layer.last_filtered_count == 0
        # Rule platform metadata propagates into the match for the cascade.
        assert matches[0].rule_platforms == ("windows",)

    def test_legacy_path_no_filter(self, tmp_rules_dir: Path) -> None:
        # Backward compatibility: tests that don't pass sample_platform stay green.
        _write_rule(tmp_rules_dir, "ps.yml", POWERSHELL_RULE_CONTENT)
        layer = SigmaLayer.from_rules_dir(tmp_rules_dir)
        log_lines = ["CommandLine: powershell.exe -EncodedCommand aGVsbG8="]

        matches = layer.scan_log_lines(log_lines)
        assert len(matches) == 1


class TestBuildEventsFromSandbox:
    """2026-07 audit (Bulgu #2): Sigma scans structured events built from real
    sandbox telemetry (strict field matching), never analyst prose."""

    def test_no_sandbox_yields_no_events(self) -> None:
        assert build_events_from_sandbox(None) == []
        assert build_events_from_sandbox({}) == []
        assert build_events_from_sandbox({"behavior": {}}) == []

    def test_process_events_have_sysmon_fields(self) -> None:
        sandbox = {
            "behavior": {
                "processes": [
                    {"pid": 4, "ppid": 0, "process_name": "explorer.exe", "cmd": "explorer.exe"},
                    {
                        "pid": 42,
                        "ppid": 4,
                        "process_name": "evil.exe",
                        "command_line": "evil.exe -beacon",
                    },
                ]
            }
        }
        events = build_events_from_sandbox(sandbox)
        child = next(e for e in events if e.get("Image") == "evil.exe")
        assert child["CommandLine"] == "evil.exe -beacon"
        assert child["ParentImage"] == "explorer.exe"

    def test_registry_write_events(self) -> None:
        run_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x"
        sandbox = {
            "behavior": {
                "calls": [
                    {
                        "api": "RegSetValueExW",
                        "arguments": [
                            {"FullName": run_key},
                            {"Buffer": "C:\\evil.exe"},
                        ],
                    },
                    {"api": "RegQueryValueExW", "arguments": [{"FullName": "HKCU\\ignored"}]},
                ]
            }
        }
        events = build_events_from_sandbox(sandbox)
        reg = [e for e in events if "TargetObject" in e]
        assert len(reg) == 1  # the read-only query is not a write event
        assert reg[0]["TargetObject"].endswith("Run\\x")
        assert reg[0]["Details"] == "C:\\evil.exe"

    def test_namevalue_argument_form(self) -> None:
        sandbox = {
            "behavior": {
                "calls": [
                    {
                        "api": "RegCreateKeyExW",
                        "arguments": [{"name": "FullName", "value": "HKLM\\Software\\Evil"}],
                    }
                ]
            }
        }
        events = build_events_from_sandbox(sandbox)
        assert any(e.get("TargetObject") == "HKLM\\Software\\Evil" for e in events)
