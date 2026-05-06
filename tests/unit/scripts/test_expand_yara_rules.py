"""tests/unit/scripts/test_expand_yara_rules.py — expand_yara_rules.py birim testleri.

Kapsam (6 test):
  - _tokenize() metin parcalama
  - _classify_token() API / tool / generic siniflandirma
  - _extract_patterns_from_text() pattern secimi
  - _parse_existing_rules() YAML parse
  - _generate_rules_for_technique() kural uretimi
  - expand() dry_run modu
"""

from __future__ import annotations

import json

# Script dizinini path'e ekle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))

from expand_yara_rules import (
    _classify_token,
    _extract_patterns_from_text,
    _generate_rules_for_technique,
    _parse_existing_rules,
    _tokenize,
    expand,
)

# ---------------------------------------------------------------------------
# _tokenize() tests
# ---------------------------------------------------------------------------


class TestTokenize:
    def test_filters_short_tokens(self) -> None:
        tokens = _tokenize("a bb cc the and")
        assert tokens == []

    def test_filters_stopwords(self) -> None:
        tokens = _tokenize("the system attacker windows process")
        # Tum stopwords'ler filtrelenmeli
        for t in tokens:
            assert t not in ("the", "system", "attacker", "windows", "process")

    def test_extracts_api_names(self) -> None:
        tokens = _tokenize("calls VirtualAllocEx and WriteProcessMemory")
        assert "VirtualAllocEx" in tokens
        assert "WriteProcessMemory" in tokens


# ---------------------------------------------------------------------------
# _classify_token() tests
# ---------------------------------------------------------------------------


class TestClassifyToken:
    def test_known_tool_gets_tool_confidence(self) -> None:
        token, conf = _classify_token("mimikatz")
        assert conf == 0.85

    def test_windows_api_gets_api_confidence(self) -> None:
        token, conf = _classify_token("VirtualAllocEx")
        assert conf == 0.88

    def test_generic_term_gets_generic_confidence(self) -> None:
        token, conf = _classify_token("injection")
        assert conf == 0.75


# ---------------------------------------------------------------------------
# _extract_patterns_from_text() tests
# ---------------------------------------------------------------------------


class TestExtractPatterns:
    def test_returns_list_of_tuples(self) -> None:
        text = "VirtualAllocEx WriteProcessMemory CreateRemoteThread"
        patterns = _extract_patterns_from_text(text)
        assert isinstance(patterns, list)
        for item in patterns:
            assert len(item) == 2  # (pattern, confidence)

    def test_max_count_respected(self) -> None:
        text = "a1 b1 c1 d1 e1 f1 g1 h1 i1 j1 k1 l1 VirtualAllocEx"
        patterns = _extract_patterns_from_text(text, max_count=5)
        assert len(patterns) <= 5

    def test_empty_text_returns_empty(self) -> None:
        patterns = _extract_patterns_from_text("")
        assert patterns == []


# ---------------------------------------------------------------------------
# _parse_existing_rules() tests
# ---------------------------------------------------------------------------


class TestParseExistingRules:
    def test_empty_file_returns_defaults(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "rules.yaml"
        yaml_file.write_text('version: "1.0"\nrules:\n', encoding="utf-8")
        header, covered, block = _parse_existing_rules(yaml_file)
        assert covered == []
        assert "version" in header

    def test_extracts_covered_technique_ids(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "rules.yaml"
        content = (
            'version: "1.0"\nrules:\n'
            "  - id: test\n"
            '    technique_id: "T1055"\n'
            "    confidence: 0.88\n"
            '    description: "test"\n'
            '    patterns: ["VirtualAllocEx"]\n'
        )
        yaml_file.write_text(content, encoding="utf-8")
        _, covered, _ = _parse_existing_rules(yaml_file)
        assert "T1055" in covered

    def test_nonexistent_file_returns_empty(self, tmp_path: Path) -> None:
        header, covered, block = _parse_existing_rules(tmp_path / "nonexistent.yaml")
        assert header == ""
        assert covered == []


# ---------------------------------------------------------------------------
# _generate_rules_for_technique() tests
# ---------------------------------------------------------------------------


class TestGenerateRulesForTechnique:
    def test_generates_rule_for_technique_with_sentences(self) -> None:
        meta = {
            "name": "Process Injection",
            "tactics": ["defense-evasion"],
            "platforms": ["windows"],
            "detection": "",
        }
        sentences = [
            "Uses VirtualAllocEx and WriteProcessMemory to inject code into process.",
            "Creates remote thread via CreateRemoteThread after allocation.",
        ]
        rules = _generate_rules_for_technique("T1055", meta, sentences)
        assert rules is not None
        assert len(rules) >= 1
        assert rules[0]["technique_id"] == "T1055"

    def test_returns_none_for_wrong_platform(self) -> None:
        meta = {
            "name": "Mac Only Technique",
            "tactics": ["execution"],
            "platforms": ["macos"],
            "detection": "",
        }
        result = _generate_rules_for_technique("T9999", meta, ["some text"])
        assert result is None


# ---------------------------------------------------------------------------
# expand() dry_run test
# ---------------------------------------------------------------------------


class TestExpand:
    def test_dry_run_does_not_modify_output(self, tmp_path: Path) -> None:
        # Sahte sentences dosyasi olustur
        sentences_path = tmp_path / "sentences.jsonl"
        lines = [
            json.dumps(
                {
                    "text": (
                        "Malware uses VirtualAllocEx and WriteProcessMemory to inject shellcode"
                    ),
                    "label": "T1055",
                    "layer": "relationship_description",
                    "source": "TestMalware",
                    "source_type": "malware",
                }
            ),
        ]
        sentences_path.write_text("\n".join(lines), encoding="utf-8")

        # Sahte output YAML
        output_path = tmp_path / "yara_ttp_rules.yaml"
        output_path.write_text('version: "1.0"\ndescription: "test"\nrules:\n', encoding="utf-8")

        original_mtime = output_path.stat().st_mtime

        expand(
            sentences_path=sentences_path,
            output_path=output_path,
            attck_cache_dir=tmp_path / "nonexistent_cache",
            dry_run=True,
        )

        # dry_run=True: dosya degistirilmemeli
        assert output_path.stat().st_mtime == original_mtime
