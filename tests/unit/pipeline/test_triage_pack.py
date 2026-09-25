"""The triage pack establishes the deterministic facts before any analyst starts.

What is pinned here is the contract the rest of the run reads: one ledger
entry per tool, in a fixed order with ids issued in that order, under
``agent="pipeline"``; the format tool chosen by the routed type; a tool that
fails becoming an ``ok=False`` entry and a degradation reason rather than a
failed job; the reputation step writing an entry that says why there was no
lookup; and the four facts a later stage's condition can read.

capa is faked throughout. It spawns a subprocess with a multi-minute budget
and what it finds in a synthetic header is not what any of this is about.
"""

from __future__ import annotations

import asyncio
import zipfile
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.core.config import Settings, TriageConfig
from maljan.core.container import ServiceContainer
from maljan.pipeline import triage_pack
from maljan.pipeline.conditions import StageContext, TriageFacts, evaluate
from maljan.pipeline.nodes import _reputation_lookup, make_triage_node, stage_context
from maljan.pipeline.triage_pack import (
    PIPELINE,
    CapaSettings,
    PackInputs,
    malicious_count,
    run_pack,
)
from maljan.schemas.evidence import EvidenceCounter
from maljan.tools import rules
from tests.unit.pipeline.test_stage_events import _state
from tests.unit.tools.test_binary import _elf, _elf_with_imports, _pe

CAPA = CapaSettings(rules_dir="data/capa-rules", signatures_dir="data/capa-signatures", timeout_s=5)

SANDBOX_REPORT: dict[str, Any] = {
    "target": {"file": {"md5": "x", "sha1": "y", "size": 10}},
    "behavior": {
        "processes": [
            {
                "pid": 4,
                "process_name": "rundll32.exe",
                "command_line": "rundll32.exe javascript:x",
                "calls": [],
            }
        ]
    },
    "network": {"dns": [{"request": "example.test"}]},
    "signatures": [{"name": "persistence_autorun", "description": "Installs itself"}],
    "dropped": [],
}


@pytest.fixture(autouse=True)
def _fake_capa(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        rules,
        "capa",
        lambda path, **_: {
            "capabilities": [{"rule": "contains PDB path", "attck": "", "mbc": ""}],
            "meta": {"backend": "fake"},
        },
    )


def _write(tmp_path: Path, name: str, blob: bytes) -> str:
    target = tmp_path / name
    target.write_bytes(blob)
    return str(target)


def _apk(tmp_path: Path) -> str:
    target = tmp_path / "app.apk"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
        archive.writestr("META-INF/CERT.RSA", b"\x30\x82 fake pkcs7")
    return str(target)


def _zip(tmp_path: Path) -> str:
    target = tmp_path / "bundle.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("readme.txt", b"hello there, this is a readme")
        archive.writestr("payload.bin", b"\x00" * 64)
    return str(target)


def _pdf(tmp_path: Path) -> str:
    blob = (
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /S /JavaScript /JS (app.alert(1)) >>\nendobj\n%%EOF\n"
    )
    return _write(tmp_path, "doc.pdf", blob)


def _inputs(path: str, file_type: str, **over: Any) -> PackInputs:
    values: dict[str, Any] = {
        "sample_path": path,
        "sha256": "a" * 64,
        "file_type": file_type,
        "strings_head": 50,
        "capa": CAPA,
    }
    values.update(over)
    return PackInputs(**values)


def _tools(result: Any) -> list[str]:
    return [entry.tool for entry in result.entries]


def _reputation_entry(result: Any) -> Any:
    """The pack's last reputation entry, whichever name it was recorded under."""
    return [
        entry
        for entry in result.entries
        if entry.tool in ("reputation", "get_file_report", "check_hash")
    ][-1]


def _pack(path: str, file_type: str, **over: Any) -> Any:
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    return run_pack(recorder, _inputs(path, file_type, **over))


class TestTheOrderAndTheIds:
    def test_a_pe_produces_the_pack_in_its_fixed_order(self, tmp_path: Path) -> None:
        result = _pack(_write(tmp_path, "s.exe", _pe()), "pe")
        assert _tools(result) == [
            "identify_file",
            "hashes",
            "signing_info",
            "pe_info",
            "strings",
            "iocs_from_file",
            "yara_scan",
            "capa",
            "api_capability",
            "sandbox_status",
            "floss",
        ]
        assert [entry.id for entry in result.entries] == [
            f"ev_{index:04d}" for index in range(1, len(result.entries) + 1)
        ]
        assert {entry.agent for entry in result.entries} == {PIPELINE}
        assert {entry.server for entry in result.entries} == {PIPELINE}
        assert {entry.stage for entry in result.entries} == {"triage_pack"}

    def test_the_same_sample_produces_the_same_ids_twice(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "s.exe", _pe())
        first = _pack(path, "pe")
        second = _pack(path, "pe")
        assert [(e.id, e.tool) for e in first.entries] == [(e.id, e.tool) for e in second.entries]

    def test_the_entries_are_the_tools_own_answers(self, tmp_path: Path) -> None:
        result = _pack(_write(tmp_path, "s.exe", _pe()), "pe")
        by_tool = {entry.tool: entry for entry in result.entries}
        assert by_tool["identify_file"].structured["file_type"] == "pe"
        assert len(by_tool["hashes"].structured["sha256"]) == 64
        assert by_tool["signing_info"].structured["authenticode"]["present"] is False
        assert by_tool["strings"].args == {
            "path": result.entries[0].args["path"],
            "min_len": 6,
            "limit": 50,
        }
        assert by_tool["pe_info"].structured["imports"][0]["function"] == "CreateFileA"

    def test_the_pack_asks_about_one_signing_scheme(self, tmp_path: Path) -> None:
        """The routed format decides which one, and the entry carries no other.

        A PE used to be recorded with "apk present=no" and "macho present=no"
        beside its Authenticode row — two absences about schemes the sample was
        never a candidate for, which the identity table then drew as findings.
        """
        signing = {
            entry.tool: entry for entry in _pack(_write(tmp_path, "s.exe", _pe()), "pe").entries
        }["signing_info"]

        assert signing.args["file_type"] == "pe"
        assert signing.structured["format"] == "pe"
        assert set(signing.structured) == {"format", "authenticode"}

    def test_a_format_with_no_signing_scheme_records_that_it_has_none(self, tmp_path: Path) -> None:
        signing = {
            entry.tool: entry for entry in _pack(_write(tmp_path, "s.bin", _elf()), "elf").entries
        }["signing_info"]

        assert signing.structured == {"format": "elf", "applicable": False}

    def test_the_import_set_reaches_api_capability(self, tmp_path: Path) -> None:
        result = _pack(_write(tmp_path, "s.exe", _pe()), "pe")
        (lookup,) = [entry for entry in result.entries if entry.tool == "api_capability"]
        assert lookup.args == {
            "api_names": ["CreateFileA", "HttpSendRequestA"],
            "platform": "windows",
        }
        assert [row["api"] for row in lookup.structured["capabilities"]] == [
            "CreateFileA",
            "HttpSendRequestA",
        ]


class TestTheFormatTools:
    def test_an_elf_gets_elf_info(self, tmp_path: Path) -> None:
        result = _pack(_write(tmp_path, "s.elf", _elf()), "elf")
        assert "elf_info" in _tools(result)
        assert "pe_info" not in _tools(result)

    def test_an_elf_s_symbols_are_asked_of_the_linux_vocabulary(self, tmp_path: Path) -> None:
        """The two blocks share names, so the routed format picks the block.

        The sample carries a real dynamic symbol table: a bare ELF header has
        no imports, the pack then records no catalogue lookup at all, and a
        test written over that list passes however the routing is wired.
        """
        sample = _elf_with_imports("socket", "connect", "send", "recv", "setuid")
        result = _pack(_write(tmp_path, "s.elf", sample), "elf")
        (lookup,) = [entry for entry in result.entries if entry.tool == "api_capability"]
        assert lookup.args["platform"] == "linux"
        assert lookup.args["api_names"] == ["socket", "connect", "send", "recv", "setuid"]
        assert lookup.structured["platform"] == "linux"
        rows = lookup.structured["capabilities"]
        assert [row["category"] for row in rows] == [
            "network",
            "network",
            "network",
            "network",
            "privilege",
        ]
        # The Windows rule these four names clear is not offered to an ELF.
        assert [hit for row in rows for hit in row["techniques"]] == []

    def test_a_pe_s_imports_are_asked_of_the_windows_vocabulary(self, tmp_path: Path) -> None:
        result = _pack(_write(tmp_path, "s.exe", _pe()), "pe")
        (lookup,) = [entry for entry in result.entries if entry.tool == "api_capability"]
        assert lookup.args["platform"] == "windows"
        assert lookup.structured["platform"] == "windows"
        categories = {row["category"] for row in lookup.structured["capabilities"]}
        assert categories == {"filesystem", "network"}

    def test_a_format_with_no_vocabulary_is_asked_nothing(self, tmp_path: Path) -> None:
        """A Mach-O's symbols are neither Win32 nor libc, and the catalogue
        answering about the wrong system is worse than not answering."""
        from maljan.pipeline import triage_pack as module

        assert "mach-o" not in module._BEHAVIOUR_PLATFORM_BY_FORMAT
        assert module._BEHAVIOUR_PLATFORM_BY_FORMAT == {"pe": "windows", "elf": "linux"}

    def test_an_apk_gets_apk_info_and_its_signature_is_seen(self, tmp_path: Path) -> None:
        result = _pack(_apk(tmp_path), "apk")
        assert "apk_info" in _tools(result)
        assert result.facts.has_signature is True

    def test_a_document_gets_document_info(self, tmp_path: Path) -> None:
        result = _pack(_pdf(tmp_path), "pdf")
        (doc,) = [entry for entry in result.entries if entry.tool == "document_info"]
        assert doc.structured["format"] == "pdf"
        assert doc.structured["markers"]["/OpenAction"] == 1

    def test_an_archive_gets_archive_list(self, tmp_path: Path) -> None:
        result = _pack(_zip(tmp_path), "zip")
        (listed,) = [entry for entry in result.entries if entry.tool == "archive_list"]
        assert {row["name"] for row in listed.structured["members"]} == {
            "readme.txt",
            "payload.bin",
        }

    def test_an_unrouted_sample_takes_the_type_identification_found(self, tmp_path: Path) -> None:
        result = _pack(_write(tmp_path, "blob", _pe()), "unknown")
        assert "pe_info" in _tools(result)

    def test_a_type_with_no_parser_gets_no_format_entry(self, tmp_path: Path) -> None:
        result = _pack(_write(tmp_path, "run.sh", b"#!/bin/sh\necho hello world there\n"), "sh")
        assert _tools(result)[3] == "strings"
        assert "api_capability" not in _tools(result)


class TestFailures:
    def test_a_tool_that_raises_is_an_entry_and_a_reason_and_the_pack_goes_on(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _boom(**_: Any) -> dict[str, Any]:
            raise RuntimeError("corpus on fire")

        monkeypatch.setattr(rules, "yara_scan", _boom)
        result = _pack(_write(tmp_path, "s.exe", _pe()), "pe")
        (failed,) = [entry for entry in result.entries if entry.tool == "yara_scan"]
        assert failed.ok is False
        assert failed.error == "RuntimeError: corpus on fire"
        assert failed.output == failed.error
        assert result.failed == ["yara_scan"]
        assert result.degradation_reasons == ["triage.yara_scan_failed"]
        assert "capa" in _tools(result)
        assert result.facts.yara_hits == 0

    def test_a_tool_that_answers_with_an_error_is_a_failed_entry_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            rules, "capa", lambda path, **_: {"error": "capa produced no result", "tool": "capa"}
        )
        result = _pack(_write(tmp_path, "s.exe", _pe()), "pe")
        (capa,) = [entry for entry in result.entries if entry.tool == "capa"]
        assert capa.ok is False
        assert capa.error == "capa produced no result"
        # The flat error the implementation wrote is kept as the message and
        # given the code and the remedy the sidecars give it.
        assert capa.structured["error"]["message"] == "capa produced no result"
        assert capa.structured["error"]["code"] == "tool_failed"
        assert capa.remediation == capa.structured["error"]["remediation"]
        assert capa.structured["tool"] == "capa"
        assert result.degradation_reasons == ["triage.capa_failed"]

    def test_the_counts_the_run_summary_reports(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(rules, "capa", lambda path, **_: {"error": "no", "tool": "capa"})
        state = _pack(_write(tmp_path, "s.exe", _pe()), "pe").to_state()
        assert state["entries"] == 11
        assert state["failed"] == 1
        assert state["duration_ms"] >= 0
        assert state["degradation_reasons"] == ["triage.capa_failed"]


class TestTheSandboxSteps:
    def test_a_report_adds_sigma_lolbin_the_summary_and_no_pcap_without_a_capture(
        self, tmp_path: Path
    ) -> None:
        result = _pack(_write(tmp_path, "s.exe", _pe()), "pe", sandbox_report=SANDBOX_REPORT)
        tools = _tools(result)
        assert tools[7:] == [
            "capa",
            "sigma_match_sandbox",
            "api_capability",
            "lolbin_lookup",
            "sandbox_processes",
            "sandbox_network",
            "sandbox_signatures",
            "sandbox_dropped_files",
            "sandbox_channels",
            "floss",
        ]
        (lolbin,) = [entry for entry in result.entries if entry.tool == "lolbin_lookup"]
        assert lolbin.args == {"command_lines": ["rundll32.exe javascript:x"]}
        assert lolbin.structured["hits"][0]["binary"] == "rundll32"
        assert "pcap_summary" not in tools

    def test_sigma_reads_the_report_s_events(self, tmp_path: Path) -> None:
        result = _pack(_write(tmp_path, "s.exe", _pe()), "pe", sandbox_report=SANDBOX_REPORT)
        (sigma,) = [entry for entry in result.entries if entry.tool == "sigma_match_sandbox"]
        assert sigma.structured["event_count"] == 1
        assert sigma.args == {"report": "<the job's sandbox report>"}

    def test_a_capture_beside_the_report_gets_a_summary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capture = tmp_path / "run.pcap"
        capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        monkeypatch.setattr(
            triage_pack.pcap,
            "pcap_summary",
            lambda path, **_: {"summary": "1 flow", "empty": False, "packet_limit": 5000},
        )
        report = {**SANDBOX_REPORT, "network": {"pcap_local_path": str(capture)}}
        result = _pack(_write(tmp_path, "s.exe", _pe()), "pe", sandbox_report=report)
        (summary,) = [entry for entry in result.entries if entry.tool == "pcap_summary"]
        # The name the network tools take back, never the host path.
        assert summary.args == {"pcap_path": "run.pcap"}
        assert summary.structured["summary"] == "1 flow"

    def test_no_report_means_none_of_them(self, tmp_path: Path) -> None:
        tools = _tools(_pack(_write(tmp_path, "s.exe", _pe()), "pe"))
        # One sentence saying no sandbox ran, and no view of a report there is not.
        assert [tool for tool in tools if tool.startswith("sandbox_")] == ["sandbox_status"]
        assert "sigma_match_sandbox" not in tools
        assert "lolbin_lookup" not in tools


class TestTheReputationStep:
    def _recorder(self) -> EvidenceRecorder:
        return EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")

    def test_with_no_reputation_server_enabled_the_entry_says_so(self, tmp_path: Path) -> None:
        settings = Settings(_env_file=None)
        settings.mcp.servers["threatintel"].enabled = False
        settings.mcp.servers["virustotal"].enabled = False
        container = ServiceContainer(settings, mock=True)
        container.sample_sha256 = "b" * 64
        result = run_pack(
            self._recorder(),
            _inputs(_write(tmp_path, "s.exe", _pe()), "pe"),
            reputation=_reputation_lookup(container, "b" * 64),
        )
        skipped = _reputation_entry(result)
        assert skipped.tool == "reputation"
        assert skipped.server == PIPELINE
        assert skipped.ok is False
        assert "no reputation server is enabled" in (skipped.error or "")
        assert skipped.args == {"sha256": "b" * 64}
        # A skip is not a failure: the run is exactly as thin as it was configured to be.
        assert result.failed == []
        assert result.facts.reputation_malicious is None

    def test_the_setting_off_is_a_skip_entry_as_well(self, tmp_path: Path) -> None:
        settings = Settings(_env_file=None, triage={"reputation": "off"})
        container = ServiceContainer(settings, mock=True)
        result = run_pack(
            self._recorder(),
            _inputs(_write(tmp_path, "s.exe", _pe()), "pe"),
            reputation=_reputation_lookup(container, "b" * 64),
        )
        assert "core.triage.reputation is off" in (_reputation_entry(result).error or "")
        assert result.failed == []

    def test_a_lookup_that_answered_is_read_for_its_count(self, tmp_path: Path) -> None:
        def lookup(recorder: EvidenceRecorder) -> Any:
            return recorder.record(
                tool="get_file_report",
                args={"hash": "a" * 64},
                server="virustotal",
                output='{"data": {"attributes": {"last_analysis_stats": {"malicious": 42}}}}',
            )

        result = run_pack(
            self._recorder(), _inputs(_write(tmp_path, "s.exe", _pe()), "pe"), reputation=lookup
        )
        assert _reputation_entry(result).server == "virustotal"
        assert result.facts.reputation_malicious == 42
        assert result.failed == []

    def test_a_lookup_that_failed_at_the_server_degrades_the_run(self, tmp_path: Path) -> None:
        def lookup(recorder: EvidenceRecorder) -> Any:
            return recorder.record(
                tool="check_hash",
                args={"file_hash": "a" * 64},
                server="threatintel",
                output="tool_returned_error",
                ok=False,
                error="tool_returned_error",
            )

        result = run_pack(
            self._recorder(), _inputs(_write(tmp_path, "s.exe", _pe()), "pe"), reputation=lookup
        )
        assert result.degradation_reasons == ["triage.check_hash_failed"]
        assert result.facts.reputation_malicious is None

    def test_a_lookup_that_raised_is_an_entry_under_the_pipeline(self, tmp_path: Path) -> None:
        def lookup(recorder: EvidenceRecorder) -> Any:
            raise TimeoutError("triage:get_file_report exceeded hard cap of 60s")

        result = run_pack(
            self._recorder(), _inputs(_write(tmp_path, "s.exe", _pe()), "pe"), reputation=lookup
        )
        last = _reputation_entry(result)
        assert last.tool == "reputation"
        assert last.ok is False
        assert "exceeded hard cap" in (last.error or "")
        assert result.degradation_reasons == ["triage.reputation_failed"]

    @pytest.mark.parametrize(
        ("output", "expected"),
        [
            ('{"data": {"attributes": {"last_analysis_stats": {"malicious": 7}}}}', 7),
            ('{"last_analysis_stats": {"malicious": 0, "undetected": 60}}', 0),
            ("Hash abc identified as Ransomware (LockBit) with 55/70 detections.", 55),
            ("Hash abc not found in VirusTotal database.", None),
            ("", None),
            ('{"tool_error": "exception"}', None),
        ],
    )
    def test_the_count_is_read_from_both_answer_shapes(self, output: str, expected) -> None:
        assert malicious_count(output) == expected


class TestTheFactsAConditionReads:
    def test_the_pack_s_facts_reach_the_stage_context(self) -> None:
        state = _state(
            triage_facts={
                "has_signature": True,
                "reputation_malicious": 12,
                "yara_hits": 3,
                "capa_hits": 5,
                "entries": 11,
                "failed": 0,
            }
        )
        ctx = stage_context(state)
        assert ctx.triage == TriageFacts(
            has_signature=True, reputation_malicious=12, yara_hits=3, capa_hits=5
        )
        assert evaluate("triage.has_signature and triage.reputation_malicious == 0", ctx) is False
        assert evaluate("triage.yara_hits > 0 or triage.capa_hits > 0", ctx) is True

    def test_a_run_without_the_pack_reads_as_nothing_established(self) -> None:
        ctx = stage_context(_state())
        assert ctx.triage == TriageFacts()
        assert evaluate("triage.reputation_malicious == None", ctx) is True

    def test_the_facts_are_read_off_the_tools_answers(self, tmp_path: Path) -> None:
        result = _pack(_apk(tmp_path), "apk")
        assert result.facts == TriageFacts(
            has_signature=True, reputation_malicious=None, yara_hits=0, capa_hits=1
        )

    def test_a_condition_names_only_the_four_fields(self) -> None:
        from maljan.pipeline.conditions import validate_condition

        (problem,) = validate_condition("triage.verdict")
        assert "triage has no field 'verdict'" in problem
        assert validate_condition("triage.yara_hits > 0") == []
        # The count is there to be compared to a number, and a save-time dry
        # run against ``None`` used to refuse exactly that.
        assert validate_condition("triage.reputation_malicious > 5") == []
        assert validate_condition("triage.reputation_malicious >= 1 and triage.yara_hits > 0") == []
        assert evaluate("triage.capa_hits >= 0", StageContext()) is True


def _container(settings: Settings | None = None) -> tuple[ServiceContainer, list]:
    container = ServiceContainer(settings or Settings(_env_file=None), mock=True)
    events: list[tuple[str, dict]] = []
    container.event_sink = lambda kind, payload: events.append((kind, payload))
    return container, events


def _triage_stage(container: ServiceContainer) -> Any:
    return container.active_profile().stage("triage_pack")


class TestTheNode:
    def test_without_a_sample_on_disk_the_stage_declines_and_says_so(self) -> None:
        container, events = _container()
        node = make_triage_node(container, stage=_triage_stage(container))
        update = asyncio.run(node(_state()))
        record = update["stage_results"]["triage_pack"]
        assert record["ran"] is False
        assert record["reason"] == "no sample on disk to read"
        assert record["kind"] == "triage"
        assert events == [
            (
                "stage_skipped",
                {"stage": "triage_pack", "kind": "triage", "reason": "no sample on disk to read"},
            )
        ]
        assert "evidence_ledger" not in update

    def test_the_setting_off_declines_with_that_reason(self, tmp_path: Path) -> None:
        container, _ = _container(Settings(_env_file=None, triage={"enabled": False}))
        node = make_triage_node(container, stage=_triage_stage(container))
        update = asyncio.run(node(_state(sample_path=_write(tmp_path, "s.exe", _pe()))))
        assert update["stage_results"]["triage_pack"]["reason"] == "core.triage.enabled is off"

    def test_a_stage_that_withholds_the_built_in_tools_declines(self, tmp_path: Path) -> None:
        container, _ = _container()
        stage = _triage_stage(container).model_copy(update={"builtin_tools": False})
        node = make_triage_node(container, stage=stage)
        update = asyncio.run(node(_state(sample_path=_write(tmp_path, "s.exe", _pe()))))
        assert update["stage_results"]["triage_pack"]["ran"] is False
        assert "withholds" in update["stage_results"]["triage_pack"]["reason"]

    def test_with_a_sample_the_pack_lands_on_the_ledger_and_the_facts_on_the_state(
        self, tmp_path: Path
    ) -> None:
        settings = Settings(_env_file=None)
        settings.mcp.servers["threatintel"].enabled = False
        container, events = _container(settings)
        container.sample_sha256 = "c" * 64
        node = make_triage_node(
            container, stage=_triage_stage(container), finishes=("triage_pack",)
        )
        path = _write(tmp_path, "s.exe", _pe())
        update = asyncio.run(node(_state(sample_path=path, file_type="pe", file_hash="c" * 64)))

        ledger = update["evidence_ledger"]
        assert [row["tool"] for row in ledger] == [
            "identify_file",
            "hashes",
            "signing_info",
            "pe_info",
            "strings",
            "iocs_from_file",
            "yara_scan",
            "capa",
            "api_capability",
            "sandbox_status",
            "reputation",
            "floss",
        ]
        assert [row["id"] for row in ledger][:2] == ["ev_0001", "ev_0002"]
        assert all(row["agent"] == PIPELINE and row["stage"] == "triage_pack" for row in ledger)
        assert ledger[-2]["ok"] is False
        # No build on a test host: the entry says so, and it is not a failure.
        assert ledger[-1]["ok"] is False
        assert ledger[-1]["error"].startswith("not run: floss is not installed")
        assert "tool_evidence" not in update

        facts = update["triage_facts"]
        assert facts["entries"] == 12
        assert facts["failed"] == 0
        assert facts["has_signature"] is False
        assert facts["capa_hits"] == 1
        assert facts["degradation_reasons"] == []

        record = update["stage_results"]["triage_pack"]
        assert record["ran"] is True
        assert record["failure"] is False
        assert record["reason"] == ""
        assert record["duration_ms"] >= 0
        assert [kind for kind, _ in events if kind.startswith("stage_")] == [
            "stage_started",
            "stage_finished",
        ]
        # The strings head is the setting, not a constant of the pack.
        assert ledger[4]["args"]["limit"] == TriageConfig().strings_head

    def test_the_counter_is_the_job_s_so_an_analyst_continues_the_sequence(
        self, tmp_path: Path
    ) -> None:
        container, _ = _container()
        node = make_triage_node(container, stage=_triage_stage(container))
        update = asyncio.run(node(_state(sample_path=_write(tmp_path, "s.exe", _pe()))))
        issued = container.get_evidence_counter().issued
        assert issued == len(update["evidence_ledger"])
        assert container.get_evidence_counter().next_id()[0] == f"ev_{issued + 1:04d}"

    def test_a_pack_that_raises_is_a_stage_that_ran_and_says_it_failed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import maljan.pipeline.nodes as nodes

        def _explode(*_: Any, **__: Any) -> Any:
            raise RuntimeError("the pack itself broke")

        monkeypatch.setattr(nodes, "run_pack", _explode)
        container, _ = _container()
        node = make_triage_node(container, stage=_triage_stage(container))
        update = asyncio.run(node(_state(sample_path=_write(tmp_path, "s.exe", _pe()))))
        record = update["stage_results"]["triage_pack"]
        assert record["ran"] is True
        assert record["failure"] is True
        assert record["reason"] == "triage pack failed: RuntimeError: the pack itself broke"
        assert update["triage_facts"]["degradation_reasons"] == ["triage.pack_failed"]
        assert update["triage_facts"]["entries"] == 0
        assert update["triage_facts"]["failed"] == 1


class TestTheReputationLookupHonoursTheTeam:
    def _run(self, settings: Settings, sha256: str = "b" * 64, tmp_path: Path | None = None):
        container = ServiceContainer(settings, mock=True)
        recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
        path = _write(tmp_path, "s.exe", _pe())
        return run_pack(
            recorder,
            _inputs(path, "pe", sha256=sha256),
            reputation=_reputation_lookup(container, sha256),
        )

    def test_a_team_that_withholds_every_server_gets_a_skip_that_says_so(
        self, tmp_path: Path
    ) -> None:
        settings = Settings(_env_file=None)
        settings.agents.profile = "measurement"
        result = self._run(settings, tmp_path=tmp_path)
        last = _reputation_entry(result)
        assert last.tool == "reputation" and last.server == PIPELINE and last.ok is False
        assert "withheld by the team's exclude_servers" in (last.error or "")
        assert result.failed == []

    def test_a_team_that_withholds_the_one_enabled_server_gets_the_same(
        self, tmp_path: Path
    ) -> None:
        settings = Settings(
            _env_file=None,
            agents={
                "profiles": {"quiet": {"analysts": ["static"], "exclude_servers": ["threatintel"]}},
                "profile": "quiet",
            },
        )
        settings.mcp.servers["virustotal"].enabled = False
        result = self._run(settings, tmp_path=tmp_path)
        assert "threatintel withheld by the team's exclude_servers" in (
            _reputation_entry(result).error or ""
        )

    def test_exclusions_that_cannot_be_read_withhold_every_server(self, tmp_path: Path) -> None:
        """Not knowing what the team withholds is read as withholding: the hash stays home."""
        container = ServiceContainer(Settings(_env_file=None), mock=True)

        def _broken() -> Any:
            raise RuntimeError("profile unreadable")

        container.active_profile = _broken  # type: ignore[method-assign]
        recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
        result = run_pack(
            recorder,
            _inputs(_write(tmp_path, "s.exe", _pe()), "pe"),
            reputation=_reputation_lookup(container, "b" * 64),
        )
        last = _reputation_entry(result)
        assert last.tool == "reputation" and last.server == PIPELINE and last.ok is False
        assert "withheld because the team's exclusions could not be read" in (last.error or "")
        assert result.failed == []

    def test_no_sha256_means_no_lookup_and_a_reason(self, tmp_path: Path) -> None:
        result = self._run(Settings(_env_file=None), sha256="", tmp_path=tmp_path)
        assert "no sha256 to look up" in (_reputation_entry(result).error or "")
        assert result.failed == []


class TestThePackBudget:
    def test_steps_after_the_budget_are_recorded_as_not_run(self, tmp_path: Path) -> None:
        result = _pack(_write(tmp_path, "s.exe", _pe()), "pe", budget_s=1e-9)
        tools = _tools(result)
        assert tools[0] == "identify_file"
        assert result.entries[0].ok is True
        later = result.entries[1:]
        assert later and all(entry.ok is False for entry in later)
        assert all("budget of 0 s was spent" in (entry.error or "") for entry in later)
        assert "hashes" in result.failed

    def test_the_lookup_is_not_made_once_the_budget_is_spent(self, tmp_path: Path) -> None:
        asked: list[str] = []

        def lookup(recorder: EvidenceRecorder) -> Any:
            asked.append("yes")
            return recorder.record(tool="check_hash", args={}, server="threatintel", output="x")

        recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
        result = run_pack(
            recorder,
            _inputs(_write(tmp_path, "s.exe", _pe()), "pe", budget_s=1e-9),
            reputation=lookup,
        )
        assert asked == []
        (entry,) = [e for e in result.entries if e.tool == "reputation"]
        assert entry.ok is False and entry.server == PIPELINE
        assert (entry.error or "").startswith("not run:")

    def test_no_budget_means_every_step_runs(self, tmp_path: Path) -> None:
        result = _pack(_write(tmp_path, "s.exe", _pe()), "pe", budget_s=0)
        # A test host has no FLOSS build, which the entry says; that is not a
        # step the budget stopped.
        assert all(entry.ok for entry in result.entries if entry.tool != "floss")
        (floss,) = [entry for entry in result.entries if entry.tool == "floss"]
        assert "budget" not in (floss.error or "")


class TestAReasonBesideNothingIsAFailure:
    def test_api_capability_with_no_catalogue_is_a_failed_entry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.tools import knowledge

        monkeypatch.setattr(
            knowledge,
            "api_capability",
            lambda names, **_: {
                "capabilities": [
                    {
                        "api": n,
                        "category": None,
                        "behaviours": [],
                        "techniques": [],
                        "catalog_flags": [],
                    }
                    for n in names
                ],
                "reason": "the API behaviour catalog is not readable at x",
            },
        )
        result = _pack(_write(tmp_path, "s.exe", _pe()), "pe")
        (lookup,) = [e for e in result.entries if e.tool == "api_capability"]
        assert lookup.ok is False
        assert "not readable" in (lookup.error or "")
        assert "triage.api_capability_failed" in result.degradation_reasons

    def test_a_function_match_store_that_answered_nothing_is_timed_and_failed(
        self, tmp_path: Path
    ) -> None:
        import time as _time

        def step():
            _time.sleep(0.02)
            return {"func_hashes": ["h"]}, {"matches": [], "reason": "the store is unavailable"}

        recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
        result = run_pack(
            recorder, _inputs(_write(tmp_path, "s.exe", _pe()), "pe"), function_matches=step
        )
        (entry,) = [e for e in result.entries if e.tool == "function_matches"]
        assert entry.ok is False
        assert entry.duration_ms >= 10
        assert entry.args == {"func_hashes": ["h"]}


class TestWhichPackFailuresDegradeTheRun:
    def test_only_the_identity_tools_and_the_pack_itself_do(self) -> None:
        from maljan.pipeline.triage_pack import degrades_run, is_pack_reason, reason_sentence

        assert degrades_run("triage.identify_file_failed")
        assert degrades_run("triage.hashes_failed")
        assert degrades_run("triage.pack_failed")
        for optional in (
            "capa",
            "yara_scan",
            "sigma_match_sandbox",
            "reputation",
            "function_matches",
        ):
            assert not degrades_run(f"triage.{optional}_failed"), optional
        assert is_pack_reason("triage.capa_failed") and not is_pack_reason("analyst failures: x")
        assert reason_sentence("triage.capa_failed") == "the triage pack could not run capa"
        assert reason_sentence("no sandbox report") == "no sandbox report"
        # A lookup that failed under either server's tool name is one sentence.
        for tool in ("reputation", "get_file_report", "check_hash"):
            assert reason_sentence(f"triage.{tool}_failed") == (
                "the triage pack's reputation lookup did not answer"
            )

    def test_the_run_is_degraded_only_by_what_degrades_it(self) -> None:
        from maljan.pipeline.triage_pack import run_is_degraded

        assert run_is_degraded(["triage.capa_failed", "triage.reputation_failed"]) is False
        assert run_is_degraded(["triage.hashes_failed"]) is True
        assert run_is_degraded(["triage.capa_failed", "analyst failures: static"]) is True
        assert run_is_degraded([]) is False


class TestADegradedAnswerIsAnAnswer:
    """A tool that answered less than it wanted to still answered.

    `apk_info` without androguard returns the zip-level facts — dex files,
    ABIs, certificate members — and used to return them beside an `error`
    key. The ledger read that as a failed call, the pack printed nothing, and
    an Android run had no container channel at all although the archive was
    perfectly readable. The facts are recorded, and what is missing from them
    is its own reason.
    """

    def test_the_entry_is_recorded_as_a_success(self) -> None:
        from maljan.pipeline.triage_pack import degradation_reason_for

        answer = {
            "manifest_present": True,
            "dex_count": 2,
            "degraded": "androguard is not installed; the manifest was not decoded",
            "remediation": "install the optional tool libraries",
        }
        assert degradation_reason_for("apk_info", answer) == "triage.apk_info_degraded"

    def test_an_answer_with_nothing_missing_contributes_no_reason(self) -> None:
        from maljan.pipeline.triage_pack import degradation_reason_for

        assert degradation_reason_for("apk_info", {"manifest_present": True}) is None

    @pytest.mark.parametrize("tool", ["apk_info", "document_info"])
    def test_the_sentence_says_it_answered_rather_than_that_it_could_not_run(
        self, tool: str
    ) -> None:
        """This sentence goes into the judge's prompt beside the facts the tool
        produced. Saying the pack could not run it, while the same prompt
        carries its dex count and its ABIs, is a deterministic statement that
        is false."""
        from maljan.pipeline.triage_pack import reason_sentence

        sentence = reason_sentence(f"triage.{tool}_degraded")
        assert tool in sentence
        assert "could not run" not in sentence
        assert "answered" in sentence

    @pytest.mark.parametrize("tool", ["apk_info", "document_info", "capa"])
    def test_a_failed_tool_still_reads_as_one_that_could_not_run(self, tool: str) -> None:
        from maljan.pipeline.triage_pack import reason_sentence

        assert reason_sentence(f"triage.{tool}_failed") == (f"the triage pack could not run {tool}")

    def test_the_degraded_reason_does_not_make_the_whole_run_degraded(self) -> None:
        """Same weight as an optional tool that failed: an absence the reader
        is told about, not a verdict about the run."""
        from maljan.pipeline.triage_pack import run_is_degraded

        assert run_is_degraded(["triage.apk_info_degraded"]) is False
