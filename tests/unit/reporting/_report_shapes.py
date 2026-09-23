"""Three reports the layout is checked against, built the way a run builds them.

* :func:`rich_report` — the recorded tool answers under ``tests/fixtures/ledger``
  (a Windows PE run with a sandbox), passed through the real builder, with a
  judge's assessment and the report model's narrative and composer answers
  applied the way the report node applies them.
* :func:`stored_old_shape` — a report as the JSON column held it before the
  layout changed: a severity score, capability paragraphs, a conclusion, an IOC
  table with defanged values and no kinds, and none of the new fields.
* :func:`hostile_report` — the rich report with a pipe and a newline written
  into every value a sample, a tool, a model or the judge controls; called with
  another value it writes that one instead (a line that would open a heading,
  a code fence).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import (
    C2Channel,
    CapabilityCell,
    CliFlag,
    CommandRow,
    ConfigItem,
    FlowStep,
    MalwareReport,
    TechnicalAnalysis,
    TechnicalSubsection,
    TTPMapping,
)
from maljan.schemas.evidence import EvidenceCounter
from maljan.schemas.judgement import FamilyVerdict, JudgeAssessment, SeverityVerdict
from tests.unit._ledger_helpers import entry

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ledger"

# The tools a static analyst, the triage pack and a dynamic analyst would have
# called on a Windows PE, in the order a run calls them.
_RICH_TOOLS: tuple[tuple[str, str], ...] = (
    ("identify_file", "pipeline"),
    ("hashes", "pipeline"),
    ("pe_info", "pipeline"),
    ("strings", "static"),
    ("iocs_from_file", "static"),
    ("yara_scan", "pipeline"),
    ("capa", "pipeline"),
    ("sandbox_processes", "dynamic"),
    ("sandbox_network", "dynamic"),
    ("sandbox_signatures", "dynamic"),
    ("sandbox_dropped_files", "dynamic"),
    ("sandbox_registry_ops", "dynamic"),
    ("sandbox_api_calls", "dynamic"),
    ("sandbox_mutexes", "dynamic"),
    ("sandbox_services_and_tasks", "dynamic"),
    ("sigma_match", "dynamic"),
    ("pcap_summary", "network"),
)


def _payload(tool: str) -> Any:
    return json.loads((_FIXTURES / f"{tool}.json").read_text(encoding="utf-8"))


def rich_ledger() -> list[Any]:
    counter = EvidenceCounter()
    return [entry(tool, _payload(tool), counter, agent=agent) for tool, agent in _RICH_TOOLS]


def rich_report() -> MalwareReport:
    """The recorded Windows PE run, through the builder, with the models' answers."""
    ledger = rich_ledger()
    ids = {e.tool: e.id for e in ledger}
    report = MalwareReportBuilder(
        file_hash=None,
        file_name="invoice.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={
            "elapsed_seconds": 412.5,
            "final_decision": "Malware",
            "negotiation": {
                "rounds_completed": 2,
                "termination_reason": "consensus",
                "final_confidence": 0.86,
            },
            "evidence": {"entries": len(ledger), "ok": len(ledger), "failed": 0, "trimmed": 0},
            "stages": [
                {"key": "triage", "kind": "pipeline", "ran": True, "duration_ms": 4200},
                {"key": "analysts", "kind": "team", "ran": True, "duration_ms": 280000},
                {"key": "judge", "kind": "judge", "ran": True, "duration_ms": 61000},
            ],
            "corroboration": {
                "T1055": {"asserted_by": ["capa"], "claimed_by": ["static"]},
                "T1547.001": {"asserted_by": ["sigma"], "claimed_by": ["dynamic", "judge"]},
            },
            "validation": {
                "retries": 1,
                "by_code": {"narrative.ungrounded_capability": 1},
                "unresolved": [
                    {
                        "agent": "judge",
                        "code": "stix.unpublishable_endpoint",
                        "message": "a name that does not resolve outside the analysed network",
                    }
                ],
            },
        },
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.86,
        judge_assessment=JudgeAssessment(
            verdict="Malware",
            confidence=0.86,
            severity=SeverityVerdict(
                rating="High",
                rationale=(
                    "The sample persists through a Run key and injects into a suspended "
                    "process [ev_0010, ev_0012]."
                ),
            ),
            malware_category="loader",
            family=FamilyVerdict(
                name="ExampleLoader", confidence=0.72, evidence_ids=[ids["yara_scan"]]
            ),
        ),
        malware_category="loader",
        evidence_ledger=ledger,
    ).build_deterministic()

    report.capability_matrix = [
        CapabilityCell(
            tactic="TA0005",
            tactic_name="Defense Evasion",
            technique_id="T1055",
            technique_name="Process Injection",
            evidence=[f"Injects into a suspended process [{ids['sandbox_signatures']}]"],
            confidence=0.8,
            confidence_source="the static analyst",
            contributing_layers=["static", "capa"],
        ),
        CapabilityCell(
            tactic="TA0003",
            tactic_name="Persistence",
            technique_id="T1547.001",
            technique_name="Registry Run Keys / Startup Folder",
            evidence=[f"Writes the Run key for its copy [{ids['sandbox_registry_ops']}]"],
            confidence=0.92,
            confidence_source="the judge",
            contributing_layers=["dynamic", "judge"],
        ),
        CapabilityCell(
            tactic="TA0007",
            tactic_name="Discovery",
            technique_id="T1082",
            technique_name="System Information Discovery",
            evidence=["claimed on a finding"],
            confidence=0.4,
            contributing_layers=["static"],
            not_published="it was named on a finding rather than on a claim",
        ),
    ]
    report.ttp_mappings = [
        TTPMapping(
            technique_id="T1055",
            technique_name="Process Injection",
            tactic="TA0005",
            tactic_name="Defense Evasion",
            evidence_quotes=[f"Injects into a suspended process [{ids['sandbox_signatures']}]"],
            confidence=0.8,
            contributing_layers=["static", "capa"],
            is_corroborated=True,
        ),
        TTPMapping(
            technique_id="T1547.001",
            technique_name="Registry Run Keys / Startup Folder",
            tactic="TA0003",
            tactic_name="Persistence",
            evidence_quotes=[f"Writes the Run key for its copy [{ids['sandbox_registry_ops']}]"],
            confidence=0.92,
            contributing_layers=["dynamic", "judge"],
        ),
    ]

    MalwareReportBuilder.apply_narrative(
        report,
        {
            "executive_summary": (
                "The sample is a Windows loader that we assess with moderate-to-high "
                "confidence belongs to the ExampleLoader family. It persists through a "
                "Run key and posts to c2.evil.tld over HTTP [ev_0009, ev_0013]. Hosts that "
                "ran it should be isolated."
            ),
            "key_findings": [
                {
                    "text": "It injects code into a suspended child process.",
                    "evidence_ids": [ids["sandbox_signatures"]],
                },
                {
                    "text": "It writes a Run key that starts its dropped copy at logon.",
                    "evidence_ids": [ids["sandbox_registry_ops"]],
                },
                {
                    "text": "It posts to http://c2.evil.tld/gate.php, likely its C2.",
                    "evidence_ids": [ids["sandbox_network"]],
                },
            ],
            "defensive_recommendations": [
                {
                    "category": "firewall",
                    "action": "Block c2.evil.tld at the egress proxy.",
                    "rationale": "It is the only C2 the sandbox saw.",
                    "priority": "P0",
                    "technique_id": "T1071.001",
                    "detection": "Proxy POST requests to c2.evil.tld/gate.php.",
                },
                {
                    "category": "registry_hardening",
                    "action": "Remove the Run value and the dropped copy.",
                    "rationale": "The Run key restarts it at logon.",
                    "priority": "P1",
                    "technique_id": "T1547.001",
                    "detection": "Sysmon event 13 on the CurrentVersion\\Run key.",
                },
                {
                    "category": "edr_hunting",
                    "action": "Hunt for processes created suspended and written to.",
                    "rationale": "It injects into a suspended process.",
                    "priority": "P2",
                    "technique_id": "T1055",
                    "detection": None,
                },
            ],
        },
    )
    report.intro_background = (
        "Loaders of this kind are reported to arrive through phishing attachments; "
        "this run saw only the file itself."
    )
    report.technical_analysis = TechnicalAnalysis(
        execution_flow=[
            FlowStep(
                order=1,
                action="Starts as evil.exe with the -install argument",
                voice="observed",
                evidence_refs=[ids["sandbox_processes"]],
            ),
            FlowStep(
                order=2,
                action="Creates the mutex Global\\LockBitMutex and exits if it exists",
                voice="observed",
                evidence_refs=[ids["sandbox_mutexes"]],
            ),
            FlowStep(
                order=3,
                action="Resolves its injection APIs before writing into a suspended process",
                voice="assessed",
                evidence_refs=[ids["capa"]],
            ),
            FlowStep(order=4, action="Beacons to its C2 every minute", voice="observed"),
        ],
        packing_obfuscation=TechnicalSubsection(
            title="Packing & Obfuscation",
            body="No packer signature matched and the .text entropy is ordinary [ev_0003].",
            evidence_refs=[ids["pe_info"]],
        ),
        persistence_detail=TechnicalSubsection(
            title="Persistence",
            body="It writes HKLM Run with the path of its dropped copy.",
            evidence_refs=[ids["sandbox_registry_ops"]],
        ),
        command_and_control=TechnicalSubsection(
            title="Command and Control",
            body="It posts to http://c2.evil.tld/gate.php; we assess the body is encoded.",
            evidence_refs=[ids["sandbox_network"]],
        ),
        configuration=[
            ConfigItem(
                key="C2 URL",
                value="http://c2.evil.tld/gate.php",
                how_obtained="observed",
                evidence_refs=[ids["sandbox_network"]],
            ),
            ConfigItem(key="Beacon interval", value="60 s", how_obtained="inferred"),
        ],
        commands=[
            CommandRow(
                id="1",
                name="install",
                description="Copies itself and writes the Run key",
                evidence_refs=[ids["sandbox_registry_ops"]],
            )
        ],
        cli_flags=[CliFlag(flag="-install", description="Installs the sample")],
    )
    report.c2_channels = [
        C2Channel(
            name="HTTP gate",
            protocol="HTTP POST",
            encryption="unknown",
            beacon_format="form-encoded fields",
            endpoints=["http://c2.evil.tld/gate.php", "10.0.0.5"],
            evidence_refs=[ids["sandbox_network"]],
        )
    ]
    return report


def stored_old_shape() -> MalwareReport:
    """A report as the JSON column held it before this layout: the old keys, no new ones."""
    stored: dict[str, Any] = {
        "schema_version": "1.0",
        "generated_at": "2026-08-01T10:00:00Z",
        "verdict": "Malware",
        "overall_confidence": 0.8,
        "malware_category": "ransomware",
        "severity": {
            "overall_score": 7.5,
            "rating": "High",
            "business_impact": "Encrypts files on local drives.",
            "affected_platforms": ["Windows"],
            "likely_targets": [],
        },
        "identity": {
            "hashes": {"sha256": "c" * 64, "md5": "d" * 32},
            "file_name": "old.exe",
            "file_size_bytes": 1024,
            "file_type": "PE",
            "platform": "windows",
        },
        "attribution": {
            "family": "OldLocker",
            "family_confidence": 0.6,
            "family_grounded": True,
            "attck_case_candidates": [],
        },
        "executive_summary": "An older summary written before key findings existed.",
        "capabilities_narrative": [
            "First paragraph about encryption.",
            "Second paragraph about the ransom note.",
        ],
        "conclusion": {"sophistication_rating": "medium sophistication", "text": "It encrypts."},
        "intro_background": "Old background.",
        "consolidated_iocs": [
            {
                "type": "Domain",
                "description": "C2",
                "value": "old-c2[.]example[.]org",
                "is_network": True,
            },
            {"type": "URL", "description": "", "value": "hxxp[://]old-c2[.]example[.]org/x"},
        ],
        "network": {
            "domains": [{"fqdn": "old-c2.example.org", "source": "sandbox"}],
            "ips": [],
            "urls": [{"url": "http://old-c2.example.org/x", "source": "sandbox"}],
        },
        "c2_channels": [{"name": "HTTP", "protocol": "HTTP", "evidence_ref": "ev_0004"}],
        "technical_analysis": {
            "packing_obfuscation": {"title": "Packing", "body": "UPX-packed.", "evidence_refs": []},
        },
        "run_summary": {"final_decision": "Malware"},
    }
    return MalwareReport.model_validate(stored)


_HOSTILE = "a|b\nc"


def hostile_report(h: str = _HOSTILE) -> MalwareReport:
    """The rich report with ``h`` in every value a sample, a tool or a model writes."""
    report = rich_report()
    report.identity.file_name = f"in{h}voice.exe"
    report.identity.export_name = f"exp{h}.dll"
    report.identity.internal_name = f"int{h}"
    static = report.static
    assert static is not None
    for section in static.sections:
        section.name = f"{section.name}{h}"
    for row in static.imports:
        row.function = f"{row.function}{h}"
    for s in static.interesting_strings:
        s.value = f"{s.value}{h}"
        s.notes = f"note{h}"
    static.exports = [f"exp{h}"]
    static.pdb_path = f"C:\\build{h}.pdb"
    static.obfuscation_indicators = [f"xor{h}"]
    static.embedded_resources = [{"type": f"RT_RCDATA{h}", "id": 1, "size": 10}]
    report.unmapped_behaviours = [f"behaviour{h}"]
    for cell in report.capability_matrix:
        cell.technique_name = f"{cell.technique_name}{h}"
    assert report.severity is not None
    report.severity.affected_platforms = [f"Windows{h}"]
    report.severity.likely_targets = [f"finance{h}"]
    report.attribution.family_evidence_ids = [f"ev_0006{h}"]
    dynamic = report.dynamic
    assert dynamic is not None
    for node in dynamic.process_tree:
        node.name = f"{node.name}{h}"
        node.command_line = f"{node.command_line}{h}"
    for reg in dynamic.registry_mods:
        reg.key = f"{reg.key}{h}"
    for op in dynamic.file_operations:
        for key in ("path", "name"):
            if op.get(key):
                op[key] = f"{op[key]}{h}"
    for sig in dynamic.sandbox_signatures:
        sig.name = f"{sig.name}{h}"
        sig.description = f"{sig.description}{h}"
    network = report.network
    assert network is not None
    for d in network.domains:
        d.reason = f"reason{h}"
    for u in network.urls:
        u.user_agent = f"agent{h}"
    for mech in report.persistence:
        mech.target = f"{mech.target}{h}"
        mech.payload = f"{mech.payload}{h}"
    for cell in report.capability_matrix:
        cell.evidence = [f"{quote}{h}" for quote in cell.evidence]
    report.executive_summary = f"{report.executive_summary}{h}"
    for finding in report.key_findings:
        finding.text = f"{finding.text}{h}"
        finding.evidence_ids = [*finding.evidence_ids, f"ev_9{h}"]
    for rec in report.defensive_recommendations:
        rec.action = f"{rec.action}{h}"
        rec.rationale = f"{rec.rationale}{h}"
        rec.detection = f"{rec.detection or 'd'}{h}"
        rec.technique_id = f"{rec.technique_id}{h}"
    ta = report.technical_analysis
    assert ta is not None
    for step in ta.execution_flow:
        step.action = f"{step.action}{h}"
        step.evidence_refs = [*step.evidence_refs, f"ev_9{h}"]
    for item in ta.configuration:
        item.key = f"{item.key}{h}"
        item.value = f"{item.value}{h}"
    for cmd in ta.commands:
        cmd.name = f"{cmd.name}{h}"
        cmd.description = f"{cmd.description}{h}"
    for flag in ta.cli_flags:
        flag.description = f"{flag.description}{h}"
    for ch in report.c2_channels:
        ch.name = f"{ch.name}{h}"
        ch.protocol = f"{ch.protocol}{h}"
        ch.beacon_format = f"{ch.beacon_format}{h}"
        ch.endpoints = [f"{e}{h}" for e in ch.endpoints]
    assert report.severity is not None
    report.severity.business_impact = f"{report.severity.business_impact}{h}"
    report.attribution.family = f"Example{h}Loader"
    report.malware_category = f"load{h}er"
    for section in report.sections:
        section.title = f"{section.title}{h}"
        section.rows = [[f"{cell}{h}" for cell in row] for row in section.rows]
        section.items = [f"{item}{h}" for item in section.items]
    report.intro_background = f"{report.intro_background}{h}"
    return report
