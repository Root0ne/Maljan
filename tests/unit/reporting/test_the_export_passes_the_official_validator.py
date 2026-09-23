"""Every export shape passes the OASIS STIX 2.1 validator.

The platform's own checks had opinions about dangling references and empty
patterns and none about what the standard requires, and twenty-two of forty
stored exports failed the standard's own validator. That validator is the
grader here: a rich Malware export, a sandbox export carrying observed-data,
and a Benign export are rendered through the real pipeline path — the judge's
answer post-processed, validated into a bundle, rendered — and each must come
out with no error. Warnings are allowed; an error is a bundle a consumer may
refuse.

The observed-data shape is the one this file was written for. It used the
deprecated ``objects`` dictionary with ``process`` entries that carried
``name`` (not a STIX 2.1 property) and no ids, and put the process count in
``number_observed``; the validator crashed on it.
"""

from __future__ import annotations

import json
from typing import Any

from stix2validator import ValidationOptions, validate_instance

from maljan.agents.judge_postprocess import postprocess_judge_bundle
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import (
    DynamicBehavior,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    ProcessNode,
)
from maljan.reporting.renderers.stix_renderer import (
    UNPUBLISHABLE_OBJECT_CODE,
    ExtendedSTIXRenderer,
)
from maljan.schemas.stix_models import Bundle

SHA256 = "36dabc40fa8983ce900a90b8156d2c754875fe1b5413a997843c4a0ef3908220"
C2 = "82.157.13.47"


def _report(verdict: str, judge: Bundle | None = None) -> MalwareReport:
    report = MalwareReportBuilder(
        file_hash=SHA256,
        file_name="sample.elf",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output=judge.model_dump(mode="json") if judge is not None else {"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision=verdict,
        overall_confidence=0.9,
        judge_assessment=None,
        malware_category="reverse_shell",
        evidence_ledger=[],
    ).build_deterministic()
    report.executive_summary = "A reverse shell that connects to a hard-coded address."
    return report


def _judge(answer: dict[str, Any]) -> Bundle:
    return Bundle.model_validate(postprocess_judge_bundle(json.loads(json.dumps(answer))))


def _errors(bundle: Bundle) -> list[str]:
    result = validate_instance(bundle.model_dump(mode="json"), ValidationOptions(version="2.1"))
    return [str(getattr(error, "message", error)) for error in result.errors]


def _rich() -> Bundle:
    report = _report("Malware")
    report.network = NetworkIOCs(
        ips=[NetworkIP(address=C2, source="sandbox", is_suspicious=True)],
        domains=[NetworkDomain(fqdn="gate.example.org", source="sandbox", is_suspicious=True)],
    )
    judge = _judge(
        {
            "type": "bundle",
            "objects": [
                {"type": "malware", "id": "malware--1", "name": "shell", "is_family": False},
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--1",
                    "name": "Application Layer Protocol",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1071"}
                    ],
                },
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "name": "C2 address",
                    "pattern": f"[ipv4-addr:value = '{C2}']",
                    "pattern_type": "stix",
                    "indicator_types": ["malicious-activity"],
                },
                {
                    "type": "relationship",
                    "id": "relationship--1",
                    "relationship_type": "uses",
                    "source_ref": "malware--1",
                    "target_ref": "attack-pattern--1",
                    "x_maljan_confidence": 0.9,
                    "x_maljan_evidence_basis": "static",
                    "x_maljan_contributing_agents": ["static"],
                },
                {
                    "type": "relationship",
                    "id": "relationship--2",
                    "relationship_type": "indicates",
                    "source_ref": "indicator--1",
                    "target_ref": "malware--1",
                },
            ],
        }
    )
    report.ttp_mappings = _report("Malware", judge).ttp_mappings
    return ExtendedSTIXRenderer().render(report, judge)


def _sandbox() -> Bundle:
    report = _report("Malware")
    report.dynamic = DynamicBehavior(
        process_tree=[
            ProcessNode(
                pid=100,
                name="sample.exe",
                command_line="sample.exe -install",
                children=[ProcessNode(pid=101, ppid=100, name="cmd.exe", command_line="cmd /c x")],
            )
        ]
    )
    return ExtendedSTIXRenderer().render(report, None)


def _benign() -> Bundle:
    judge = _judge(
        {
            "type": "bundle",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--1",
                    "name": "System Information Discovery",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1082"}
                    ],
                }
            ],
        }
    )
    return ExtendedSTIXRenderer().render(_report("Benign", judge), judge)


def test_a_rich_malware_export_is_valid() -> None:
    assert _errors(_rich()) == []


def test_a_sandbox_export_with_observed_data_is_valid() -> None:
    bundle = _sandbox()

    assert _errors(bundle) == []


def test_a_benign_export_is_valid() -> None:
    assert _errors(_benign()) == []


class TestTheObservedData:
    def test_it_references_process_objects_the_bundle_holds(self) -> None:
        dumped = _sandbox().model_dump(mode="json")
        by_id = {o["id"]: o for o in dumped["objects"]}
        (observed,) = [o for o in dumped["objects"] if o["type"] == "observed-data"]

        assert "objects" not in observed
        assert observed["object_refs"]
        assert all(ref in by_id for ref in observed["object_refs"])
        processes = [by_id[ref] for ref in observed["object_refs"] if ref.startswith("process--")]
        assert sorted(p["pid"] for p in processes) == [100, 101]
        assert all("name" not in p for p in processes)

    def test_it_says_one_observation(self) -> None:
        dumped = _sandbox().model_dump(mode="json")
        (observed,) = [o for o in dumped["objects"] if o["type"] == "observed-data"]

        assert observed["number_observed"] == 1

    def test_the_tree_and_the_image_names_are_kept(self) -> None:
        dumped = _sandbox().model_dump(mode="json")
        by_id = {o["id"]: o for o in dumped["objects"]}
        (parent,) = [o for o in dumped["objects"] if o["type"] == "process" and o["pid"] == 100]

        assert by_id[parent["image_ref"]]["name"] == "sample.exe"
        (child_ref,) = parent["child_refs"]
        assert by_id[child_ref]["pid"] == 101


def test_the_rich_and_benign_exports_carry_the_judges_technique() -> None:
    """The gate grades the shapes a real run publishes, attack-patterns included."""
    for bundle in (_rich(), _benign()):
        assert [o.type for o in bundle.objects].count("attack-pattern") == 1


def _judge_observables() -> Bundle:
    judge = _judge(
        {
            "type": "bundle",
            "objects": [
                {"type": "malware", "id": "malware--1", "name": "loader", "is_family": False},
                {
                    "type": "file",
                    "id": "file--1",
                    "name": "putty.exe",
                    "size": 1706136,
                    "hashes": {"SHA-256": "d" * 64},
                    "mime_type": "application/octet-stream",
                },
                {"type": "file", "id": "file--2", "hashes": {"MD5": "a" * 32}},
                {
                    "type": "process",
                    "id": "process--1",
                    "pid": 100,
                    "command_line": "putty.exe -ssh",
                    "image_ref": "file--1",
                },
            ],
        }
    )
    return ExtendedSTIXRenderer().render(_report("Malware", judge), judge)


def test_an_export_carrying_the_judges_file_and_process_objects_is_valid() -> None:
    bundle = _judge_observables()
    dumped = bundle.model_dump(mode="json")
    kinds = [o["type"] for o in dumped["objects"]]

    assert kinds.count("file") == 2 and kinds.count("process") == 1
    (named,) = [o for o in dumped["objects"] if o["type"] == "file" and o.get("name")]
    assert named["hashes"] == {"SHA-256": "d" * 64} and named["size"] == 1706136
    assert _errors(bundle) == []


class TestWhatTheStandardRequiresIsNeverPublishedAbsent:
    """A malware object without ``is_family`` or a file with neither ``hashes`` nor
    ``name`` is an object the standard refuses. Kept after the question, it is
    declined with a record — never published invalid, never filled in — and the
    platform mints its own sample object as it does when the judge wrote none."""

    def _render(self, *objects: dict) -> tuple[Bundle, list]:
        judge = _judge({"type": "bundle", "objects": list(objects)})
        renderer = ExtendedSTIXRenderer()
        return renderer.render(_report("Malware", judge), judge), renderer.declined

    def test_a_malware_object_without_is_family(self) -> None:
        bundle, declined = self._render({"type": "malware", "id": "malware--1", "name": "loader"})

        malware = [o for o in bundle.objects if o.type == "malware"]
        assert [m.is_family for m in malware] == [False]
        assert [m.name for m in malware] != ["loader"]
        assert [code for code, _why in declined] == [UNPUBLISHABLE_OBJECT_CODE]
        assert _errors(bundle) == []

    def test_a_file_with_nothing_to_identify_it(self) -> None:
        bundle, declined = self._render(
            {"type": "malware", "id": "malware--1", "name": "loader", "is_family": False},
            {"type": "file", "id": "file--1", "size": 10},
        )

        assert [o for o in bundle.objects if o.type == "file"] == []
        assert [code for code, _why in declined] == [UNPUBLISHABLE_OBJECT_CODE]
        assert _errors(bundle) == []
