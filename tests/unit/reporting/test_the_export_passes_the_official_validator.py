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

from langchain_core.messages import AIMessage
from stix2validator import ValidationOptions, validate_instance

from maljan.agents.judge_agent import JudgeAgent
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


# The ids of every ``indicates`` edge a judge fixture wrote, as published: the
# gate tells the judge's edges from any the platform mints by them.
_JUDGE_INDICATES: set[str] = set()


def _judge(answer: dict[str, Any]) -> Bundle:
    """The judge's answer read by the pipeline's own reader.

    ``JudgeAgent._bundle_from_response`` itself, so every pass the real path
    makes over an answer — the per-object pass, the post-processor, and anything
    added to that path later — runs here too, and a fixture never reaches the
    renderer with something the real path would not.
    """
    reader = JudgeAgent(llm=object())  # type: ignore[arg-type]
    bundle = reader._bundle_from_response(AIMessage(content=json.dumps(answer)), {}, None)
    assert bundle.x_maljan_fallback_verdict is None, "the fixture must read as a bundle"
    _JUDGE_INDICATES.update(
        str(o.id)
        for o in bundle.objects
        if o.type == "relationship" and o.relationship_type == "indicates"
    )
    return bundle


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


def _report_object_findings(bundle: Bundle) -> tuple[list[str], list[str]]:
    """The report object's ``report_types``, and every validator message about it."""
    dumped = bundle.model_dump(mode="json")
    (report_object,) = [o for o in dumped["objects"] if o["type"] == "report"]
    result = validate_instance(dumped, ValidationOptions(version="2.1"))
    about = [
        str(getattr(finding, "message", finding))
        for finding in [*result.errors, *result.warnings]
        if report_object["id"] in str(getattr(finding, "message", finding))
    ]
    return report_object["report_types"], about


class TestTheReportTypeFollowsTheVerdict:
    """A Benign export once went out typed ``malware``: "a characterization of one
    or more malware instances". Each verdict's type is in the vocabulary, and the
    validator has nothing to say about the report object of either."""

    def test_a_malware_export(self) -> None:
        types, about = _report_object_findings(_rich())

        assert (types, about) == (["malware"], [])

    def test_a_benign_export(self) -> None:
        types, about = _report_object_findings(_benign())

        assert (types, about) == (["threat-report"], [])


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


def _declined_malware_with_edges() -> tuple[Bundle, MalwareReport]:
    """The judge's malware kept without is_family, with a numbered technique and an indicator."""
    judge = _judge(
        {
            "type": "bundle",
            "objects": [
                {"type": "malware", "id": "malware--1", "name": "loader"},
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--1",
                    "name": "Inhibit System Recovery",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1490"}
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
                    "x_maljan_confidence": 0.95,
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
    report = _report("Malware", judge)
    return ExtendedSTIXRenderer().render(report, judge), report


def _malware_exports() -> list[tuple[str, Bundle]]:
    return [
        ("rich", _rich()),
        ("sandbox", _sandbox()),
        ("judge observables", _judge_observables()),
        ("declined malware", _declined_malware_with_edges()[0]),
        ("platform only", ExtendedSTIXRenderer().render(_report("Malware"), None)),
        ("judge indicator typed benign, related to nothing", _benign_typed_indicator()),
    ]


def _benign_typed_indicator() -> Bundle:
    """A judge indicator for a vendor updater file, typed ``benign``, related to nothing.

    The sandbox saw the file written, which is the second source the one
    publish rule asks of the judge's value; a file name is a value the export
    mints no row of its own for, so the object carried is the judge's.
    """
    judge = _judge(
        {
            "type": "bundle",
            "objects": [
                {"type": "malware", "id": "malware--1", "name": "shell", "is_family": False},
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "name": "vendor updater",
                    "pattern": "[file:name = 'vendor_update.exe']",
                    "pattern_type": "stix",
                    "indicator_types": ["benign"],
                },
            ],
        }
    )
    report = _report("Malware", judge)
    report.dynamic = DynamicBehavior(
        file_operations=[{"operation": "write", "path": "C:\\ProgramData\\vendor_update.exe"}]
    )
    return ExtendedSTIXRenderer().render(report, judge)


class TestEveryMalwareExportHangsTogether:
    """In a Malware export every technique is used by a malware object, every
    ``indicates`` edge is one somebody made, and the export publishes the
    techniques the report does. A declined judge malware object used to leave
    its technique unrelated and its indicator indicating nothing, while the
    report still published the technique at the judge's number."""

    def test_every_attack_pattern_is_used_by_a_malware_object(self) -> None:
        for name, bundle in _malware_exports():
            by_id = {o.id: o for o in bundle.objects}
            used = {
                o.target_ref
                for o in bundle.objects
                if o.type == "relationship"
                and o.relationship_type == "uses"
                and getattr(by_id.get(o.source_ref), "type", "") == "malware"
            }
            patterns = {o.id for o in bundle.objects if o.type == "attack-pattern"}
            assert patterns <= used, name

    def test_every_indicator_is_related_by_its_maker_or_listed_unrelated(self) -> None:
        """An indicator indicates the malware object only by an edge the judge
        wrote or by the sample's own hash edge; any other is related to nothing
        and listed in the report object's ``object_refs``. In STIX ``indicates``
        says the pattern detects the malware, which a verdict does not say."""
        for name, bundle in _malware_exports():
            by_id = {o.id: o for o in bundle.objects}
            sample_hash = {
                o.id
                for o in bundle.objects
                if o.type == "indicator" and SHA256 in str(getattr(o, "pattern", ""))
            }
            (report_object,) = [o for o in bundle.objects if o.type == "report"]
            listed = set(report_object.object_refs)
            indicating: set[str] = set()
            for o in bundle.objects:
                if o.type != "relationship" or o.relationship_type != "indicates":
                    continue
                assert getattr(by_id.get(o.target_ref), "type", "") == "malware", name
                assert o.id in _JUDGE_INDICATES or o.source_ref in sample_hash, (
                    f"{name}: an indicates edge nobody made from {o.source_ref}"
                )
                indicating.add(o.source_ref)
            for o in bundle.objects:
                if o.type == "indicator":
                    assert o.id in indicating or o.id in listed, (name, o.id)

    def test_a_benign_typed_judge_indicator_is_not_said_to_indicate_the_malware(self) -> None:
        bundle = _benign_typed_indicator()

        (indicator,) = [
            o for o in bundle.objects if o.type == "indicator" and "vendor_update.exe" in o.pattern
        ]
        assert indicator.indicator_types == ["benign"]
        assert not [
            o
            for o in bundle.objects
            if o.type == "relationship" and indicator.id in (o.source_ref, o.target_ref)
        ]
        (report_object,) = [o for o in bundle.objects if o.type == "report"]
        assert indicator.id in report_object.object_refs

    def test_the_export_and_the_report_publish_the_same_techniques_with_the_same_numbers(
        self,
    ) -> None:
        bundle, report = _declined_malware_with_edges()
        by_id = {o.id: o for o in bundle.objects}
        exported: dict[str, object] = {}
        for o in bundle.objects:
            if o.type == "relationship" and o.relationship_type == "uses":
                target = by_id[o.target_ref]
                tid = target.external_references[0]["external_id"]
                exported[tid] = getattr(o, "x_maljan_confidence", None)

        assert exported == {m.technique_id: m.confidence for m in report.ttp_mappings}
        assert exported == {"T1490": 0.95}

    def test_the_moved_edges_keep_the_judges_annotation(self) -> None:
        bundle, _report_ = _declined_malware_with_edges()

        (uses,) = [o for o in bundle.objects if getattr(o, "relationship_type", "") == "uses"]
        assert uses.x_maljan_evidence_basis == "static"
        assert uses.x_maljan_contributing_agents == ["static"]
