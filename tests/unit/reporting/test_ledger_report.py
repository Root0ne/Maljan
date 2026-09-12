"""Sections built from real tool output, one builder at a time.

The fixtures under ``tests/fixtures/ledger`` are the shapes the tools in
``maljan.tools`` and ``providers.sandbox_tools`` actually return, so a builder
that drifts from its tool fails here rather than in a report nobody re-reads.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from maljan.reporting.ledger_report import build_sections
from maljan.schemas.evidence import build_entry, format_entry_id
from maljan.schemas.isr_models import AgentISR, Artifact, Finding

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ledger"


def _entry(tool: str, payload: Any = None, *, seq: int = 1, agent: str = "static", **kwargs: Any):
    if payload is None:
        payload = json.loads((_FIXTURES / f"{tool}.json").read_text(encoding="utf-8"))
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent=agent,
        tool=tool,
        args=kwargs.pop("args", {}),
        server=kwargs.pop("server", None),
        output=payload if isinstance(payload, str) else json.dumps(payload),
        **kwargs,
    )


def _by_key(sections: list[Any]) -> dict[str, Any]:
    return {section.key: section for section in sections}


class TestIdentity:
    def test_identify_file_and_hashes_land_in_one_identity_block(self) -> None:
        sections = _by_key(build_sections([_entry("identify_file"), _entry("hashes", seq=2)]))
        identity = sections["identity"]
        assert identity.kind == "kv"
        rows = dict(identity.rows)
        assert rows["file type"] == "PE"
        assert rows["platform"] == "windows"
        assert rows["sha256"].startswith("275a0")
        assert identity.evidence_ids == ["ev_0001", "ev_0002"]

    def test_the_routing_minimum_fills_identity_when_no_tool_ran(self) -> None:
        sections = _by_key(build_sections([], {}, "elf", "linux"))
        assert dict(sections["identity"].rows) == {"file type": "elf", "platform": "linux"}
        assert sections["identity"].source == "routing"


class TestBinaryBuilders:
    def test_pe_info_yields_header_sections_imports_and_exports(self) -> None:
        sections = _by_key(build_sections([_entry("pe_info")]))
        assert dict(sections["pe_header"].rows)["machine"] == "332"
        assert sections["pe_sections"].columns[0] == "Name"
        assert [row[0] for row in sections["pe_sections"].rows] == [".text", ".rsrc"]
        assert ["KERNEL32.dll", "VirtualAllocEx", "process_injection"] in sections[
            "pe_imports"
        ].rows
        assert sections["pe_exports"].items == ["StartService"]
        assert sections["packer_signatures"].rows == [["UPX", ".text"]]

    def test_elf_info_yields_its_own_tables(self) -> None:
        sections = _by_key(build_sections([_entry("elf_info")]))
        assert dict(sections["elf_header"].rows)["interpreter"].endswith("ld-linux-x86-64.so.2")
        assert sections["elf_sections"].rows[0][0] == ".text"
        assert sections["elf_imports"].rows[0][1] == "execve"

    def test_apk_info_yields_permissions_and_components(self) -> None:
        sections = _by_key(build_sections([_entry("apk_info")]))
        assert "android.permission.READ_SMS" in sections["apk_permissions"].items
        assert ["service", "com.example.evil.Beacon"] in sections["apk_components"].rows

    def test_two_calls_of_the_same_tool_merge_and_cite_both(self) -> None:
        sections = _by_key(build_sections([_entry("pe_info"), _entry("pe_info", seq=2)]))
        assert len(sections["pe_sections"].rows) == 2
        assert sections["pe_sections"].evidence_ids == ["ev_0001", "ev_0002"]


class TestOtherToolBuilders:
    def test_iocs(self) -> None:
        sections = _by_key(build_sections([_entry("iocs_from_file")]))
        assert ["domain", "c2.evil.tld", "hard-coded"] in sections["iocs"].rows

    def test_strings(self) -> None:
        sections = _by_key(build_sections([_entry("strings")]))
        assert sections["strings"].rows[0][2].startswith("http://c2.evil.tld")

    def test_yara(self) -> None:
        sections = _by_key(build_sections([_entry("yara_scan")]))
        assert sections["yara_matches"].rows[0][0] == "Win32_Loader_Generic"

    def test_sigma(self) -> None:
        sections = _by_key(build_sections([_entry("sigma_match")]))
        row = sections["sigma_matches"].rows[0]
        assert row[0] == "Suspicious Run Key"
        assert row[1] == "high"
        assert "T1547.001" in row[2]

    def test_capa(self) -> None:
        sections = _by_key(build_sections([_entry("capa")]))
        assert sections["capa_capabilities"].rows[0][1] == "inject code"

    def test_pcap(self) -> None:
        sections = _by_key(build_sections([_entry("pcap_summary", agent="network")]))
        assert "beacon interval" in sections["pcap_summary"].text

    def test_sandbox_tables(self) -> None:
        entries = [
            _entry("sandbox_processes", seq=1, agent="dynamic"),
            _entry("sandbox_network", seq=2, agent="dynamic"),
            _entry("sandbox_signatures", seq=3, agent="dynamic"),
            _entry("sandbox_dropped_files", seq=4, agent="dynamic"),
        ]
        sections = _by_key(build_sections(entries))
        assert sections["sandbox_processes"].rows[0][3] == "evil.exe -install"
        endpoints = {row[1] for row in sections["sandbox_network"].rows}
        assert {"c2.evil.tld", "http://c2.evil.tld/gate.php", "185.220.101.5"} <= endpoints
        assert sections["sandbox_signatures"].rows[0][0] == "injection_runpe"
        assert sections["sandbox_dropped_files"].rows[0][0] == "svchost.exe"

    def test_a_named_sandbox_section_becomes_a_kv_block(self) -> None:
        sections = _by_key(build_sections([_entry("sandbox_report_section", agent="dynamic")]))
        assert dict(sections["sandbox_target"].rows)["category"] == "file"

    def test_functions_examined_records_what_was_looked_at(self) -> None:
        entries = [
            _entry("decompile_function", "void FUN_00401310() { }", args={"name": "FUN_00401310"}),
            _entry(
                "decompile_function",
                "void FUN_00401420() { }",
                seq=2,
                args={"name": "FUN_00401420"},
            ),
        ]
        sections = _by_key(build_sections(entries))
        assert sections["functions_examined"].kind == "list"
        assert len(sections["functions_examined"].items) == 2
        assert "FUN_00401310" in sections["functions_examined"].items[0]


class TestGenericFallbacks:
    def test_an_unknown_json_object_becomes_a_kv_block(self) -> None:
        sections = _by_key(build_sections([_entry("frobnicate", {"depth": 3, "mode": "deep"})]))
        assert dict(sections["tool_frobnicate"].rows) == {"depth": "3", "mode": "deep"}

    def test_an_unknown_json_array_of_objects_becomes_a_table(self) -> None:
        payload = [{"a": 1, "b": 2}, {"a": 3, "c": 4}]
        sections = _by_key(build_sections([_entry("listy", payload)]))
        section = sections["tool_listy"]
        assert section.columns == ["a", "b", "c"]
        assert section.rows == [["1", "2", ""], ["3", "", "4"]]

    def test_unknown_prose_becomes_a_capped_text_section(self) -> None:
        sections = _by_key(build_sections([_entry("notes", "x" * 9000)]))
        assert sections["tool_notes"].kind == "text"
        assert len(sections["tool_notes"].text) == 4000

    def test_a_failed_call_builds_no_section(self) -> None:
        entry = build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="static",
            tool="pe_info",
            args={},
            server=None,
            output="RuntimeError: boom",
            ok=False,
            error="RuntimeError: boom",
        )
        assert [s.key for s in build_sections([entry])] == ["identity"]

    def test_a_tool_that_answered_with_an_error_builds_no_section(self) -> None:
        entry = _entry("pe_info", {"error": "not a PE file (no MZ magic)", "tool": "pe_info"})
        assert [s.key for s in build_sections([entry])] == ["identity"]


class TestAgentContributions:
    def _isrs(self) -> dict[str, AgentISR]:
        return {
            "static": AgentISR(
                agent_id="static",
                domain="static",
                artifacts=[
                    Artifact(
                        kind="iocs",
                        label="C2",
                        columns=["Kind", "Value"],
                        rows=[["domain", "c2.evil.tld"]],
                        evidence_ids=["ev_0003"],
                        source="static",
                    ),
                    Artifact(
                        kind="hashes", label="imphash", value="f34d", evidence_ids=["ev_0002"]
                    ),
                ],
                findings=[
                    Finding(
                        title="Injects into a remote process",
                        technique_ids=["T1055"],
                        confidence=0.8,
                        evidence_ids=["ev_0001"],
                    )
                ],
            )
        }

    def test_artifacts_are_grouped_by_kind(self) -> None:
        sections = _by_key(build_sections([], self._isrs()))
        assert sections["artifact_iocs"].rows == [["domain", "c2.evil.tld"]]
        assert sections["artifact_iocs"].evidence_ids == ["ev_0003"]
        assert sections["artifact_hashes"].rows == [["imphash", "f34d"]]

    def test_findings_become_one_table(self) -> None:
        sections = _by_key(build_sections([], self._isrs()))
        findings = sections["findings"]
        assert findings.columns[0] == "Agent"
        assert findings.rows[0][1] == "Injects into a remote process"
        assert findings.rows[0][3] == "0.80"
        assert findings.evidence_ids == ["ev_0001"]


class TestGroundingContract:
    def test_every_section_names_the_evidence_or_the_source_it_came_from(self) -> None:
        entries = [
            _entry("identify_file"),
            _entry("pe_info", seq=2),
            _entry("sandbox_processes", seq=3, agent="dynamic"),
            _entry("frobnicate", {"depth": 3}, seq=4),
        ]
        for section in build_sections(entries, {}, "PE", "windows"):
            assert section.evidence_ids or section.source, section.key
