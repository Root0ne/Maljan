"""A small synthetic job whose surfaces agree, for the surface-completeness checker's tests.

``clean_run()`` returns every surface the checker reads, consistent with one
another; each test breaks one thing. ``clean_spec()`` is the shipped web field
map without the kinds the console does not render today, so a clean run is
clean; the shipped map's own gaps have a test of their own.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from scripts.audit import surfaces

SHA256 = "a" * 64
DOMAIN = "bad.example"
IP = "192.0.2.1"
TECHNIQUE = ("T1059", "Command and Scripting Interpreter")
FINDING = "The sample talks to bad.example over HTTPS."
CELL = "hello world from the sample"
RULE = "maljan_rule_one"
PROCESS = {"pid": 4, "name": "sample.exe", "command_line": "sample.exe /run", "children": []}

# The kinds the shipped map names that no tab renders today.
UNRENDERED_TODAY = ("ioc", "ioc_publication", "judge_indicator")


def _malware_report() -> dict[str, Any]:
    return {
        "verdict": "Malware",
        "overall_confidence": 0.8,
        "severity": {"rating": "High"},
        "attribution": {"family": "Examplefam"},
        "identity": {"hashes": {"sha256": SHA256}, "file_name": "sample.bin"},
        "ttp_mappings": [{"technique_id": TECHNIQUE[0], "technique_name": TECHNIQUE[1]}],
        "capability_matrix": [
            {"technique_id": TECHNIQUE[0], "technique_name": TECHNIQUE[1], "not_published": ""},
            {
                "technique_id": "T1055",
                "technique_name": "Process Injection",
                "not_published": "the judge dropped it",
            },
        ],
        "consolidated_iocs": [
            {
                "kind": "hash",
                "type": "SHA-256",
                "value": SHA256,
                "published": "yes: the sample's own digest",
            },
            {
                "kind": "domain",
                "type": "Domain",
                "value": DOMAIN,
                "published": "yes: the judge kept it",
            },
            {"kind": "ip", "type": "IPv4", "value": IP, "published": "no: a sandbox peer"},
        ],
        "judge_indicators": [{"kind": "domain", "value": DOMAIN}],
        "network": {
            "domains": [{"fqdn": DOMAIN, "kept_by": ["judge"]}],
            "ips": [{"address": IP}],
            "urls": [],
        },
        "key_findings": [{"text": FINDING, "evidence_ids": ["ev_0001"]}],
        "sections": [
            {
                "key": "strings",
                "title": "Printable strings",
                "kind": "table",
                "columns": ["Text"],
                "rows": [[CELL]],
                "items": [],
                "text": "",
                "evidence_ids": ["ev_0001"],
            }
        ],
        "evidence_index": [{"id": "ev_0001"}, {"id": "ev_0002"}],
        "dynamic": {"process_tree": [dict(PROCESS)]},
        "detection_signatures": [
            {"kind": "yara", "name": RULE, "body": "rule x { condition: true }"}
        ],
        "run_summary": {"final_decision": "Malware"},
    }


def _stix() -> dict[str, Any]:
    return {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {
                "type": "report",
                "id": "report--1",
                "description": "Verdict: Malware. Severity High.",
            },
            {"type": "malware", "id": "malware--1", "name": "Examplefam"},
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": TECHNIQUE[1],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": TECHNIQUE[0]}
                ],
            },
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": f"[file:hashes.'SHA-256' = '{SHA256}']",
            },
            {
                "type": "indicator",
                "id": "indicator--2",
                "pattern": f"[domain-name:value = '{DOMAIN}']",
                "x_maljan_evidence_refs": ["ev_0002"],
            },
            {"type": "process", "id": "process--1", "pid": 4, "command_line": "sample.exe /run"},
        ],
    }


def _markdown() -> str:
    return "\n".join(
        [
            "# Examplefam analysis",
            "**Verdict:** Malware (high confidence, 0.80) · **Severity:** `[HIGH]` · "
            "**Family:** Examplefam",
            "## 1. Key findings",
            f"- {FINDING.replace('bad.example', 'bad[.]example')} [ev_0001]",
            "## 6. Observed behaviour",
            "pid=4 sample.exe (sample.exe /run)",
            "## 8. MITRE ATT&CK mapping",
            f"| {TECHNIQUE[0]} | {TECHNIQUE[1]} |",
            "## 9. Indicators of compromise",
            f"| SHA-256 | `{SHA256}` |",
            "| Domain | `bad[.]example` |",
            "| IPv4 | `192[.]0[.]2[.]1` |",
            "## 10. Detection",
            f"rule {RULE}",
            "### Printable strings · _Measured_",
            "| Text |",
            "|---|",
            f"| {CELL} |",
        ]
    )


def clean_run() -> dict[str, Any]:
    """Every surface of one job, all in agreement."""
    mr = _malware_report()
    stix = _stix()
    markdown = _markdown()
    row = {
        "id": "report-1",
        "job_id": "job-1",
        "verdict": "Malware",
        "overall_confidence": 0.8,
        "mitre_techniques": [{"technique_id": TECHNIQUE[0], "name": TECHNIQUE[1]}],
        "section_tabs": None,
        "run_summary": {
            "final_decision": "Malware",
            "evidence": {"entries": 2},
            "stix_object_count": len(stix["objects"]),
            "judge_stix_object_count": 2,
            "tokens": {"llm_calls": 1},
        },
        "malware_report": mr,
    }
    return {
        "job": {"id": "job-1", "status": "completed", "sample_sha256": SHA256},
        "report_row": row,
        "report_full": copy.deepcopy(mr),
        "run_summary": copy.deepcopy(row["run_summary"]),
        "markdown": markdown,
        "html": "<html><body>"
        + "".join(f"<p>{line}</p>" for line in markdown.replace("**", "").split("\n"))
        + "</body></html>",
        "stix": stix,
        "stix_judge": {
            "kept": True,
            "bundle": {
                "objects": [
                    {
                        "type": "attack-pattern",
                        "name": TECHNIQUE[1],
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": TECHNIQUE[0]}
                        ],
                    },
                    {
                        "type": "attack-pattern",
                        "name": "Process Injection",
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T1055"}
                        ],
                    },
                ]
            },
        },
        "mitre": {"techniques": [{"technique_id": TECHNIQUE[0], "name": TECHNIQUE[1]}]},
        "iocs_all": {
            "items": [
                {"kind": "hash", "value": f"sha256:{SHA256}", "published": True},
                {"kind": "domain", "value": DOMAIN, "published": True},
                {"kind": "ip", "value": IP, "published": False},
            ],
            "total": 3,
        },
        "evidence": {"total": 2, "items": [{"entry_id": "ev_0001"}, {"entry_id": "ev_0002"}]},
        "events": [
            {"type": "tool_call_finished", "payload": {}},
            {"type": "tool_call_finished", "payload": {}},
            {"type": "model_usage", "payload": {}},
            {
                "type": "completed",
                "payload": {"verdict": "Malware", "confidence": 0.8, "report_id": "report-1"},
            },
        ],
    }


def clean_spec() -> dict[str, Any]:
    spec = json.loads(surfaces.WEB_FIELDS.read_text(encoding="utf-8"))
    for kind in UNRENDERED_TODAY:
        spec["kinds"].pop(kind)
    return spec


def write_run(directory: Path, run: dict[str, Any]) -> Path:
    """The run as the benchmark runner stores it."""
    directory.mkdir(parents=True, exist_ok=True)
    for name, value in run.items():
        target = directory / surfaces.SURFACES[name]["file"]
        if isinstance(value, str):
            target.write_text(value, encoding="utf-8")
        else:
            target.write_text(json.dumps(value), encoding="utf-8")
    return directory


def defects(result: dict[str, Any], cls: str | None = None) -> list[tuple[str, str, str]]:
    """``(class, kind, surface)`` of each defect, optionally of one class."""
    return [
        (d["class"], d["kind"], d["surface"])
        for d in result["defects"]
        if cls is None or d["class"] == cls
    ]
