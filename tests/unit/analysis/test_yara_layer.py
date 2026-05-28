"""Unit tests for YaraLayer (src/maljan/analysis/yara_layer.py).

Tests cover:
  - YaraTTPRule.from_dict() construction and validation
  - YaraLayer construction from rule list
  - scan() — positive and negative matching
  - scan() — case-insensitive matching
  - scan() — multiple patterns from same rule
  - scan() — empty text / empty rule set
  - to_isr() — correct AgentISR structure
  - from_default_rules() — loads and returns valid layer
  - techniques_covered() — correct set
  - rule_count property
"""

from __future__ import annotations

import pytest

from maljan.analysis.yara_layer import YaraLayer, YaraTTPRule

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_rules() -> list[YaraTTPRule]:
    return [
        YaraTTPRule(
            id="proc_injection",
            technique_id="T1055",
            confidence=0.88,
            description="Classic process injection indicators",
            patterns=("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"),
        ),
        YaraTTPRule(
            id="ransomware_crypto",
            technique_id="T1486",
            confidence=0.85,
            description="Data encrypted for impact",
            patterns=("CryptEncrypt", "BCryptEncrypt"),
        ),
        YaraTTPRule(
            id="keylogger",
            technique_id="T1056.001",
            confidence=0.88,
            description="Keylogging via SetWindowsHookEx",
            patterns=("SetWindowsHookEx", "WH_KEYBOARD_LL"),
        ),
    ]


@pytest.fixture()
def yara_layer(sample_rules: list[YaraTTPRule]) -> YaraLayer:
    return YaraLayer(rules=sample_rules)


# ---------------------------------------------------------------------------
# YaraTTPRule
# ---------------------------------------------------------------------------


class TestYaraTTPRule:
    def test_from_dict_basic(self) -> None:
        rule = YaraTTPRule.from_dict(
            {
                "id": "test_rule",
                "technique_id": "T1055",
                "confidence": 0.85,
                "description": "Test rule",
                "patterns": ["VirtualAllocEx", "WriteProcessMemory"],
            }
        )
        assert rule.id == "test_rule"
        assert rule.technique_id == "T1055"
        assert rule.confidence == pytest.approx(0.85)
        assert "VirtualAllocEx" in rule.patterns

    def test_from_dict_confidence_floor(self) -> None:
        """Confidence below 0.70 is raised to the floor."""
        rule = YaraTTPRule.from_dict(
            {
                "id": "low_conf",
                "technique_id": "T1055",
                "confidence": 0.30,
                "description": "Low confidence rule",
                "patterns": ["pattern"],
            }
        )
        assert rule.confidence >= 0.70

    def test_from_dict_missing_confidence_defaults(self) -> None:
        rule = YaraTTPRule.from_dict({"id": "r", "technique_id": "T1055", "patterns": ["x"]})
        assert rule.confidence >= 0.70


# ---------------------------------------------------------------------------
# YaraLayer — construction
# ---------------------------------------------------------------------------


class TestYaraLayerConstruction:
    def test_rule_count(self, yara_layer: YaraLayer, sample_rules: list[YaraTTPRule]) -> None:
        assert yara_layer.rule_count == len(sample_rules)

    def test_techniques_covered(self, yara_layer: YaraLayer) -> None:
        covered = yara_layer.techniques_covered()
        assert "T1055" in covered
        assert "T1486" in covered
        assert "T1056.001" in covered

    def test_empty_rules_layer(self) -> None:
        layer = YaraLayer(rules=[])
        assert layer.rule_count == 0
        assert layer.techniques_covered() == set()

    def test_repr(self, yara_layer: YaraLayer) -> None:
        r = repr(yara_layer)
        assert "YaraLayer" in r
        assert "rules=" in r


# ---------------------------------------------------------------------------
# YaraLayer.scan()
# ---------------------------------------------------------------------------


class TestYaraLayerScan:
    def test_scan_positive_match(self, yara_layer: YaraLayer) -> None:
        text = "API call: VirtualAllocEx @ 0x401234"
        matches = yara_layer.scan(text)
        technique_ids = {m.technique_id for m in matches}
        assert "T1055" in technique_ids

    def test_scan_case_insensitive(self, yara_layer: YaraLayer) -> None:
        text = "api call: virtualAllocEx at offset 0x100"
        matches = yara_layer.scan(text)
        technique_ids = {m.technique_id for m in matches}
        assert "T1055" in technique_ids

    def test_scan_multiple_patterns_same_rule(self, yara_layer: YaraLayer) -> None:
        text = "VirtualAllocEx and WriteProcessMemory and CreateRemoteThread"
        matches = yara_layer.scan(text)
        t1055_matches = [m for m in matches if m.technique_id == "T1055"]
        assert len(t1055_matches) == 1  # one match per rule
        assert len(t1055_matches[0].matched_patterns) == 3

    def test_scan_no_match(self, yara_layer: YaraLayer) -> None:
        text = "benign program that does nothing suspicious"
        matches = yara_layer.scan(text)
        assert matches == []

    def test_scan_empty_text(self, yara_layer: YaraLayer) -> None:
        assert yara_layer.scan("") == []

    def test_scan_empty_rules(self) -> None:
        layer = YaraLayer(rules=[])
        assert layer.scan("VirtualAllocEx WriteProcessMemory") == []

    def test_scan_multiple_techniques(self, yara_layer: YaraLayer) -> None:
        text = "VirtualAllocEx detected, also CryptEncrypt and SetWindowsHookEx"
        matches = yara_layer.scan(text)
        technique_ids = {m.technique_id for m in matches}
        assert "T1055" in technique_ids
        assert "T1486" in technique_ids
        assert "T1056.001" in technique_ids

    def test_scan_returns_confidence(self, yara_layer: YaraLayer) -> None:
        text = "VirtualAllocEx detected"
        matches = yara_layer.scan(text)
        proc_match = next(m for m in matches if m.technique_id == "T1055")
        assert proc_match.confidence == pytest.approx(0.88)

    def test_scan_evidence_ref_format(self, yara_layer: YaraLayer) -> None:
        text = "VirtualAllocEx present in binary"
        matches = yara_layer.scan(text)
        proc_match = next(m for m in matches if m.technique_id == "T1055")
        ref = proc_match.evidence_ref
        assert "proc_injection" in ref
        assert "VirtualAllocEx" in ref

    def test_scan_claim_text_format(self, yara_layer: YaraLayer) -> None:
        text = "VirtualAllocEx present"
        matches = yara_layer.scan(text)
        proc_match = next(m for m in matches if m.technique_id == "T1055")
        assert "YARA" in proc_match.claim_text
        assert "proc_injection" in proc_match.claim_text

    def test_yara_and_regex_produce_same_matches(self, sample_rules: list) -> None:
        """When yara-python is available, its output must match the regex fallback."""
        from unittest.mock import patch

        text = "VirtualAllocEx and powershell.exe"

        # YARA engine path
        yara_layer = YaraLayer(sample_rules)
        yara_matches = yara_layer.scan(text)

        # Regex fallback path (mock yara unavailable)
        with (
            patch("maljan.analysis.yara_layer._YARA_AVAILABLE", False),
            patch("maljan.analysis.yara_layer.yara", None),
        ):
            regex_layer = YaraLayer(sample_rules)
            regex_matches = regex_layer.scan(text)

        assert len(yara_matches) == len(regex_matches)
        for ym, rm in zip(yara_matches, regex_matches, strict=False):
            assert ym.rule_id == rm.rule_id
            assert ym.technique_id == rm.technique_id
            assert ym.confidence == rm.confidence


# ---------------------------------------------------------------------------
# YaraLayer.to_isr()
# ---------------------------------------------------------------------------


class TestYaraLayerToISR:
    def test_to_isr_domain(self, yara_layer: YaraLayer) -> None:
        text = "VirtualAllocEx detected"
        matches = yara_layer.scan(text)
        isr = yara_layer.to_isr(matches)
        assert isr.domain == "yara"

    def test_to_isr_agent_id(self, yara_layer: YaraLayer) -> None:
        text = "VirtualAllocEx detected"
        matches = yara_layer.scan(text)
        isr = yara_layer.to_isr(matches)
        assert isr.agent_id == "yara_layer"

    def test_to_isr_claims_count(self, yara_layer: YaraLayer) -> None:
        text = "VirtualAllocEx CryptEncrypt"
        matches = yara_layer.scan(text)
        isr = yara_layer.to_isr(matches)
        assert len(isr.claims) == len(matches)

    def test_to_isr_claim_technique_ids(self, yara_layer: YaraLayer) -> None:
        text = "VirtualAllocEx CryptEncrypt"
        matches = yara_layer.scan(text)
        isr = yara_layer.to_isr(matches)
        claim_tids = {c.technique_id for c in isr.claims}
        assert "T1055" in claim_tids
        assert "T1486" in claim_tids

    def test_to_isr_no_dissent(self, yara_layer: YaraLayer) -> None:
        text = "VirtualAllocEx"
        matches = yara_layer.scan(text)
        isr = yara_layer.to_isr(matches)
        assert isr.dissent_items == []

    def test_to_isr_revision_round_zero(self, yara_layer: YaraLayer) -> None:
        text = "VirtualAllocEx"
        matches = yara_layer.scan(text)
        isr = yara_layer.to_isr(matches)
        assert isr.revision_round == 0

    def test_to_isr_empty_matches(self, yara_layer: YaraLayer) -> None:
        isr = yara_layer.to_isr([])
        assert isr.claims == []
        assert isr.domain == "yara"


# ---------------------------------------------------------------------------
# YaraLayer.from_default_rules()
# ---------------------------------------------------------------------------


class TestYaraLayerFromDefaultRules:
    def test_loads_without_error(self) -> None:
        """from_default_rules() must not raise, even if file is missing."""
        layer = YaraLayer.from_default_rules()
        assert isinstance(layer, YaraLayer)

    def test_default_rules_cover_key_techniques(self) -> None:
        """Default rule set must cover critical ATT&CK techniques."""
        layer = YaraLayer.from_default_rules()
        if layer.rule_count == 0:
            pytest.skip("Default rules file not found — skipping technique coverage test.")
        covered = layer.techniques_covered()
        required = {"T1055", "T1486", "T1003", "T1059.001", "T1547.001"}
        missing = required - covered
        assert not missing, f"Default rules missing critical techniques: {missing}"

    def test_default_rules_min_count(self) -> None:
        """Default rule set should have at least 30 rules."""
        layer = YaraLayer.from_default_rules()
        if layer.rule_count == 0:
            pytest.skip("Default rules file not found — skipping count test.")
        assert layer.rule_count >= 30


# ---------------------------------------------------------------------------
# Wave 4 — Platform-aware filtering
# ---------------------------------------------------------------------------


class TestYaraPlatformFiltering:
    """Wave 4: scan() should drop rules whose platform doesn't match the sample."""

    @pytest.fixture()
    def mixed_rules(self) -> list[YaraTTPRule]:
        return [
            YaraTTPRule(
                id="powershell_only",
                technique_id="T1059.001",
                confidence=0.85,
                description="PowerShell — windows only",
                patterns=("powershell.exe",),
                platform=("windows",),
            ),
            YaraTTPRule(
                id="ransomware_anywhere",
                technique_id="T1486",
                confidence=0.85,
                description="Ransomware indicators — cross-platform",
                patterns=("ransom",),
                platform=("any",),
            ),
        ]

    def test_drops_windows_rule_for_android(self, mixed_rules: list[YaraTTPRule]) -> None:
        layer = YaraLayer(mixed_rules)
        text = "powershell.exe ransom"
        layer.reset_filter_stats()
        matches = layer.scan(text, sample_platform="android")
        triggered = {m.rule_id for m in matches}
        # Windows-only rule dropped; cross-platform rule survives.
        assert "powershell_only" not in triggered
        assert "ransomware_anywhere" in triggered
        assert layer.last_filtered_count == 1

    def test_keeps_windows_rule_for_windows(self, mixed_rules: list[YaraTTPRule]) -> None:
        layer = YaraLayer(mixed_rules)
        text = "powershell.exe ransom"
        layer.reset_filter_stats()
        matches = layer.scan(text, sample_platform="windows")
        triggered = {m.rule_id for m in matches}
        assert "powershell_only" in triggered
        assert "ransomware_anywhere" in triggered
        assert layer.last_filtered_count == 0

    def test_keeps_t1497_sandbox_evasion_on_apk(self) -> None:
        """The T1497 paradox: YARA sandbox_evasion is platform=any so it
        survives on Android even though MITRE Enterprise's T1497.platforms
        omits Android. This is the kingpin TP we must preserve."""
        layer = YaraLayer.from_default_rules()
        if layer.rule_count == 0:
            pytest.skip("Default rules file not found")
        # zararli.apk's Triage signature contained "sandbox" in the
        # signature name; that string is one of the sandbox_evasion rule's
        # patterns. With platform-aware filtering, the rule must still fire
        # on an android sample.
        matches = layer.scan("Listens for sandbox detection", sample_platform="android")
        triggered = {m.rule_id for m in matches}
        assert "sandbox_evasion" in triggered

    def test_legacy_no_platform_filter(self, mixed_rules: list[YaraTTPRule]) -> None:
        layer = YaraLayer(mixed_rules)
        text = "powershell.exe ransom"
        matches = layer.scan(text)  # no sample_platform → legacy path
        triggered = {m.rule_id for m in matches}
        assert "powershell_only" in triggered
        assert "ransomware_anywhere" in triggered

    def test_from_dict_default_platform_is_any(self) -> None:
        rule = YaraTTPRule.from_dict(
            {
                "id": "no_platform_specified",
                "technique_id": "T1055",
                "confidence": 0.85,
                "description": "Legacy rule with no platform field",
                "patterns": ["VirtualAllocEx"],
            }
        )
        assert rule.platform == ("any",)

    def test_from_dict_platform_list(self) -> None:
        rule = YaraTTPRule.from_dict(
            {
                "id": "windows_only",
                "technique_id": "T1059.001",
                "confidence": 0.85,
                "description": "PowerShell",
                "patterns": ["powershell.exe"],
                "platform": ["windows"],
            }
        )
        assert rule.platform == ("windows",)
