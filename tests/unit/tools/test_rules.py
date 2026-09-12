"""``maljan.tools.rules`` reports every rule that fired, on its own terms.

What the pipeline's layers add — the platform pre-filter, the confidence floor,
the ISR conversion — is exactly what these tests check is *absent*. A Windows
rule matching a Linux sample comes back, and the caller decides what that
means.

capa is mocked at the subprocess boundary. Running it for real needs vivisect,
a rules directory and minutes of disassembly; what is worth testing here is the
flattening of a ResultDocument into rows, and that is pure.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from maljan.tools import rules as tool

RULESET_YAML = """
rules:
  - id: injection_apis
    technique_id: T1055
    confidence: 0.9
    description: Classic Windows injection APIs
    platform: [windows]
    patterns:
      - WriteProcessMemory
      - CreateRemoteThread
  - id: persistence_run_key
    technique_id: T1547.001
    confidence: 0.8
    description: Run-key persistence
    platform: [windows]
    patterns:
      - "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
"""


@pytest.fixture
def ruleset(tmp_path: Path) -> str:
    path = tmp_path / "rules.yaml"
    path.write_text(RULESET_YAML, encoding="utf-8")
    tool.reset_rule_caches()
    yield str(path)
    tool.reset_rule_caches()


class TestYaraScan:
    def test_a_matching_rule_names_itself_and_where_it_matched(
        self, ruleset: str, tmp_path: Path
    ) -> None:
        target = tmp_path / "s.bin"
        target.write_bytes(b"\x00" * 32 + b"WriteProcessMemory" + b"\x00" * 32)

        result = tool.yara_scan(path=str(target), ruleset=ruleset)

        assert result["rule_count"] == 2
        assert result["filtered"] == 0, "a tool filters nothing; the layer does"
        assert [row["rule"] for row in result["matches"]] == ["injection_apis"]
        strings = result["matches"][0]["strings"]
        assert strings, "a match reports the strings that produced it"
        assert strings[0]["offset"] == 32
        assert bytes.fromhex(strings[0]["data_hex"]) == b"WriteProcessMemory"

    def test_the_rule_metadata_comes_through_unflattened(self, ruleset: str) -> None:
        result = tool.yara_scan(text="CreateRemoteThread", ruleset=ruleset)
        meta = result["matches"][0]["meta"]
        assert meta["technique_id"] == "T1055"
        assert "Classic Windows injection APIs" in meta["description"]

    def test_a_windows_rule_still_fires_on_text_with_no_platform_in_sight(
        self, ruleset: str
    ) -> None:
        """No platform pre-filter. The pipeline's YARA layer drops a
        Windows-only rule for a Linux sample; the tool reports the hit and
        leaves the judgement to the caller."""
        result = tool.yara_scan(text="WriteProcessMemory", ruleset=ruleset)
        assert [row["rule"] for row in result["matches"]] == ["injection_apis"]

    def test_nothing_matching_is_an_empty_list_and_a_rule_count(self, ruleset: str) -> None:
        result = tool.yara_scan(text="entirely unremarkable content", ruleset=ruleset)
        assert result["matches"] == []
        assert result["rule_count"] == 2

    def test_both_a_path_and_a_text_is_refused(self, ruleset: str) -> None:
        result = tool.yara_scan(path="/tmp/x", text="y", ruleset=ruleset)
        assert result == {"error": "give exactly one of path and text", "tool": "yara_scan"}

    def test_neither_a_path_nor_a_text_is_refused(self, ruleset: str) -> None:
        assert tool.yara_scan(ruleset=ruleset)["tool"] == "yara_scan"

    def test_a_missing_file_is_an_error_and_not_an_exception(self, ruleset: str) -> None:
        result = tool.yara_scan(path="/nonexistent/s.bin", ruleset=ruleset)
        assert "no such file" in result["error"]


SIGMA_RULE = """
title: Suspicious Rundll32 Script Execution
id: 11111111-2222-3333-4444-555555555555
status: test
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\rundll32.exe'
        CommandLine|contains: 'javascript:'
    condition: selection
tags:
    - attack.defense_evasion
    - attack.t1218.011
"""


@pytest.fixture
def sigma_dir(tmp_path: Path) -> str:
    directory = tmp_path / "sigma"
    directory.mkdir()
    (directory / "rundll32.yml").write_text(SIGMA_RULE, encoding="utf-8")
    tool.reset_rule_caches()
    yield str(directory)
    tool.reset_rule_caches()


class TestSigmaMatch:
    def test_a_matching_event_names_the_rule_its_level_and_the_matched_fields(
        self, sigma_dir: str
    ) -> None:
        events = [
            {
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "CommandLine": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"',
            }
        ]

        result = tool.sigma_match(events, ruleset=sigma_dir)

        assert result["rule_count"] == 1
        assert len(result["matches"]) == 1
        match = result["matches"][0]
        assert match["title"] == "Suspicious Rundll32 Script Execution"
        assert match["level"] == "high"
        assert match["logsource"] == {
            "product": "windows",
            "category": "process_creation",
            "service": "",
        }
        assert "attack.t1218.011" in match["tags"]
        assert "CommandLine" in match["matched_fields"]

    def test_a_non_matching_event_produces_nothing(self, sigma_dir: str) -> None:
        events = [{"Image": "C:\\Windows\\notepad.exe", "CommandLine": "notepad.exe a.txt"}]
        assert tool.sigma_match(events, ruleset=sigma_dir)["matches"] == []

    def test_a_rule_fires_at_most_once_across_a_batch(self, sigma_dir: str) -> None:
        event = {
            "Image": "C:\\Windows\\System32\\rundll32.exe",
            "CommandLine": "rundll32.exe javascript:x",
        }
        result = tool.sigma_match([event, event, event], ruleset=sigma_dir)
        assert len(result["matches"]) == 1

    def test_events_that_are_not_a_list_are_refused(self, sigma_dir: str) -> None:
        assert tool.sigma_match("not a list", ruleset=sigma_dir)["tool"] == "sigma_match"  # type: ignore[arg-type]


class TestSigmaMatchSandbox:
    def test_the_events_are_derived_from_the_report_and_counted(self, sigma_dir: str) -> None:
        report = {
            "behavior": {
                "processes": [
                    {
                        "pid": 1234,
                        "ppid": 1,
                        "process_name": "rundll32.exe",
                        "command_line": "rundll32.exe javascript:x",
                        "calls": [],
                    }
                ]
            }
        }

        result = tool.sigma_match_sandbox(report, ruleset=sigma_dir)

        assert result["event_count"] >= 1
        assert result["rule_count"] == 1

    def test_an_empty_report_yields_no_events_and_no_matches(self, sigma_dir: str) -> None:
        result = tool.sigma_match_sandbox({}, ruleset=sigma_dir)
        assert result["event_count"] == 0
        assert result["matches"] == []


CAPA_DOCUMENT: dict[str, Any] = {
    "meta": {
        "version": "9.4.0",
        "analysis": {"format": "pe", "arch": "i386", "os": "windows"},
        "sample": {"sha256": "a" * 64},
    },
    "rules": {
        "allocate RWX memory": {
            "meta": {
                "name": "allocate RWX memory",
                "namespace": "host-interaction/process/inject",
                "attack": [
                    {
                        "id": "T1055",
                        "tactic": "Defense Evasion",
                        "parts": ["Process Injection"],
                    }
                ],
                "mbc": [{"id": "C0007", "objective": "Memory", "parts": ["Allocate Memory"]}],
            },
            "matches": [["a"], ["b"]],
        },
        "get common file path": {
            "meta": {"name": "get common file path", "namespace": "host-interaction/file-system"},
            "matches": [["a"]],
        },
    },
}


class TestCapa:
    def test_a_result_document_flattens_to_one_row_per_rule(self, tmp_path, monkeypatch) -> None:
        """Mocked at the subprocess boundary: the spawn-and-kill loop is the
        provider's and is tested there; what is this tool's own is the shape it
        hands back."""
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 64)
        rules_dir = tmp_path / "capa-rules"
        rules_dir.mkdir()
        (rules_dir / "r.yml").write_text("rule:\n  meta:\n    name: r\n", encoding="utf-8")

        monkeypatch.setattr(
            "maljan.providers.static.capa_yara.run_capa_document",
            lambda **kwargs: CAPA_DOCUMENT,
        )

        result = tool.capa(str(sample), rules_dir=str(rules_dir))

        assert result["meta"] == {
            "capa_version": "9.4.0",
            "format": "pe",
            "arch": "i386",
            "os": "windows",
            "rule_count": 2,
            "sha256": "a" * 64,
        }
        by_rule = {row["rule"]: row for row in result["capabilities"]}
        rwx = by_rule["allocate RWX memory"]
        assert rwx["namespace"] == "host-interaction/process/inject"
        assert rwx["attck"] == ["Defense Evasion::Process Injection [T1055]"]
        assert rwx["mbc"] == ["Memory::Allocate Memory [C0007]"]
        assert rwx["match_count"] == 2
        assert by_rule["get common file path"]["attck"] == []

    def test_a_run_that_produced_nothing_says_so_rather_than_returning_empty(
        self, tmp_path, monkeypatch
    ) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")
        rules_dir = tmp_path / "capa-rules"
        rules_dir.mkdir()
        (rules_dir / "r.yml").write_text("rule:\n", encoding="utf-8")

        monkeypatch.setattr(
            "maljan.providers.static.capa_yara.run_capa_document", lambda **kwargs: None
        )

        result = tool.capa(str(sample), rules_dir=str(rules_dir))
        assert result["tool"] == "capa"
        assert "budget" in result["error"]

    def test_an_empty_rules_directory_is_named_before_anything_is_spawned(self, tmp_path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")
        empty = tmp_path / "no-rules"
        empty.mkdir()

        result = tool.capa(str(sample), rules_dir=str(empty))

        assert result["tool"] == "capa"
        assert "missing or empty" in result["error"]

    def test_a_missing_sample_is_an_error_and_not_an_exception(self) -> None:
        assert tool.capa("/nonexistent/s.exe")["tool"] == "capa"
