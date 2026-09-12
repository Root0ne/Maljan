"""The report is what the run gathered, and nothing else.

Identity comes from the identification tools when they ran and from the
routing minimum when they did not; the typed blocks are projections of the
same ledger; and a run that called nothing produces a report with an identity
and no body — which is the honest outcome, not a bug.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport
from maljan.schemas.evidence import EvidenceCounter
from maljan.schemas.isr_models import AgentISR, Artifact
from tests.unit._ledger_helpers import entry, ledger_from_sandbox

_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _build(
    ledger: list[Any] | None = None,
    *,
    isrs: dict[str, Any] | None = None,
    sample_path: str | None = None,
    file_type: str | None = None,
    platform: str | None = None,
    file_hash: str = "a" * 64,
) -> MalwareReport:
    return MalwareReportBuilder(
        file_hash=file_hash,
        file_name="fixture.bin",
        sample_path=sample_path,
        sandbox_report={},
        reports={},
        isr_reports=isrs or {},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.8,
        sample_platform=platform,
        sample_file_type=file_type,
        evidence_ledger=ledger or [],
    ).build_deterministic()


class TestIdentity:
    def test_identity_comes_from_the_tools_when_they_ran(self) -> None:
        counter = EvidenceCounter()
        ledger = [
            entry(
                "identify_file", {"file_type": "PE", "platform": "windows", "size": 2048}, counter
            ),
            entry("hashes", {"sha256": _SHA, "md5": "b" * 32, "imphash": "f34d"}, counter),
        ]
        report = _build(ledger, file_type="elf", platform="linux")
        assert report.identity.hashes.sha256 == _SHA
        assert report.identity.hashes.imphash == "f34d"
        # The tools' answer beats the routing guess it contradicts.
        assert report.identity.file_type == "PE"
        assert report.identity.platform == "windows"
        assert report.identity.file_size_bytes == 2048

    def test_identity_falls_back_to_the_routing_minimum(self, tmp_path) -> None:
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"MZ" + b"\x00" * 30)
        report = _build(sample_path=str(sample), file_type="pe", platform="windows")
        # No identification tool ran, so the builder hashed the file itself.
        assert len(report.identity.hashes.sha256) == 64
        assert report.identity.hashes.md5
        assert report.identity.hashes.sha1
        assert report.identity.file_size_bytes == 32
        assert report.identity.file_type == "pe"
        assert report.identity.magic_bytes.startswith("4d5a")

    def test_a_sample_the_builder_cannot_open_keeps_the_job_hash(self) -> None:
        report = _build(sample_path="/nonexistent/sample.bin", file_hash="c" * 64)
        assert report.identity.hashes.sha256 == "c" * 64


class TestTypedBlocks:
    def test_static_is_projected_from_the_format_tool(self) -> None:
        counter = EvidenceCounter()
        ledger = [
            entry(
                "pe_info",
                {
                    "machine": 332,
                    "sections": [
                        {"name": ".text", "virtual_address": 4096, "entropy": 6.4, "raw_size": 100}
                    ],
                    "imports": [
                        {
                            "dll": "KERNEL32.dll",
                            "function": "VirtualAllocEx",
                            "category": "process_injection",
                        }
                    ],
                    "exports": ["StartService"],
                    "packer_signatures": [{"name": "UPX"}],
                },
                counter,
            )
        ]
        report = _build(ledger)
        assert report.static is not None
        assert report.static.sections[0].name == ".text"
        assert report.static.sections[0].virtual_address == "0x1000"
        assert report.static.imports[0].function == "VirtualAllocEx"
        assert report.static.exports == ["StartService"]
        assert report.static.packer_hint == "UPX"
        assert report.static.api_capabilities == {"process_injection": 1}

    def test_dynamic_and_network_are_projected_from_the_sandbox_tools(self) -> None:
        ledger = ledger_from_sandbox(
            {
                "behavior": {"processes": [{"pid": 4, "ppid": 1, "name": "evil.exe"}]},
                "network": {
                    "dns": [{"request": "c2.evil.tld"}],
                    "tcp": [{"dst": "185.220.101.5", "dport": 443}],
                },
                "signatures": [{"name": "injection_runpe", "severity": 3}],
            }
        )
        report = _build(ledger)
        assert report.dynamic is not None
        assert report.dynamic.process_tree[0].name == "evil.exe"
        assert {s.name for s in report.dynamic.sandbox_signatures} == {"injection_runpe"}
        assert report.network is not None
        assert [d.fqdn for d in report.network.domains] == ["c2.evil.tld"]
        assert [i.address for i in report.network.ips] == ["185.220.101.5"]

    def test_the_host_tools_fill_the_registry_and_api_channels(self) -> None:
        counter = EvidenceCounter()
        ledger = [
            entry(
                "sandbox_registry_ops",
                {
                    "registry": [
                        {
                            "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            "operation": "modify",
                            "value": "C:\\evil.exe",
                        }
                    ]
                },
                counter,
                agent="dynamic",
            ),
            entry(
                "sandbox_api_calls",
                {"apis": [{"api": "VirtualAllocEx", "count": 4, "category": "process_injection"}]},
                counter,
                agent="dynamic",
            ),
            entry(
                "sandbox_services_and_tasks",
                {"services": ["EvilUpdater"], "tasks": ["schtasks /create /tn Evil"]},
                counter,
                agent="dynamic",
            ),
        ]
        report = _build(ledger)
        assert report.dynamic is not None
        assert [(m.hive, m.operation) for m in report.dynamic.registry_mods] == [("HKCU", "modify")]
        assert report.dynamic.notable_apis[0]["api"] == "VirtualAllocEx"
        # The persistence tab and the Sigma registry selection are fed by the
        # same calls, without an analyst having to restate them.
        assert {p.kind for p in report.persistence} == {
            "registry_run",
            "service",
            "scheduled_task",
        }

    def test_a_run_that_gathered_nothing_leaves_every_block_empty(self) -> None:
        report = _build([])
        assert report.static is None
        assert report.dynamic is None
        assert report.network is None
        assert report.persistence == []

    def test_persistence_comes_from_the_agents(self) -> None:
        isrs = {
            "dynamic": AgentISR(
                agent_id="dynamic",
                domain="dynamic",
                artifacts=[
                    Artifact(
                        kind="persistence",
                        label="Autorun",
                        columns=["Kind", "Target", "Payload"],
                        rows=[["registry_run", "HKCU\\...\\Run\\evil", "evil.exe"]],
                        evidence_ids=["ev_0004"],
                    )
                ],
            )
        }
        report = _build([], isrs=isrs)
        assert [p.kind for p in report.persistence] == ["registry_run"]
        assert report.persistence[0].evidence_ref == "ev_0004"


class TestConsolidatedIOCs:
    def test_iocs_come_from_the_tools_and_the_agents(self) -> None:
        counter = EvidenceCounter()
        ledger = [
            entry("hashes", {"sha256": _SHA, "md5": "b" * 32}, counter),
            entry(
                "iocs_from_file",
                {"iocs": [{"kind": "domain", "value": "c2.evil.tld", "notes": "hard-coded"}]},
                counter,
            ),
        ]
        report = _build(ledger)
        values = {row.value for row in report.consolidated_iocs}
        assert _SHA in values
        # Network indicators are defanged on the way into the table.
        assert "c2[.]evil[.]tld" in values


class TestEvidenceIndex:
    def test_the_index_names_every_call_without_repeating_its_output(self) -> None:
        counter = EvidenceCounter()
        ledger = [
            entry("identify_file", {"file_type": "PE"}, counter),
            entry(
                "strings", {"strings": [{"offset": 1, "enc": "ascii", "text": "hello"}]}, counter
            ),
        ]
        report = _build(ledger)
        assert [row.id for row in report.evidence_index] == ["ev_0001", "ev_0002"]
        assert [row.tool for row in report.evidence_index] == ["identify_file", "strings"]
        assert not hasattr(report.evidence_index[0], "output")

    def test_sections_are_attached(self) -> None:
        counter = EvidenceCounter()
        report = _build([entry("identify_file", {"file_type": "PE"}, counter)])
        assert {section.key for section in report.sections} >= {"identity"}
