"""A sandbox process outside the sample's tree is exported as the sandbox's, never as the sample's.

A run's export carried every process of the sandbox's listing in one
observation, a desktop process the sandbox listed under sihost.exe
(explorer.exe) among them, with nothing telling it from the sample's own. The
process stays in the export, where it stands in the tree, and carries the
platform's ``x_maljan_sample_process_tree: false``, read by the one lineage
rule the commands table and the host values read
(``sandbox_report.sample_process_tree``); one the two lineage facts dispute
carries ``x_maljan_lineage_disputed`` with the fact that alone names it, as
the report's network rows say it. A process of the tree carries nothing new.
"""

from __future__ import annotations

from typing import Any

from stix2validator import ValidationOptions, validate_instance

from maljan.agents.judge_postprocess import PROPERTY_NOT_CARRIED_CODE, lift_misplaced_extensions
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import DynamicBehavior, MalwareReport, ProcessNode
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.stix_models import LINEAGE_DISPUTED_PROPERTY, SAMPLE_TREE_PROPERTY

SHA256 = "36dabc40fa8983ce900a90b8156d2c754875fe1b5413a997843c4a0ef3908220"


def _report(tree: list[ProcessNode], file_name: str = "sample.exe") -> MalwareReport:
    report = MalwareReportBuilder(
        file_hash=SHA256,
        file_name=file_name,
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.9,
        judge_assessment=None,
        malware_category="trojan",
        evidence_ledger=[],
    ).build_deterministic()
    report.dynamic = DynamicBehavior(process_tree=tree)
    return report


def _desktop_and_sample() -> list[ProcessNode]:
    return [
        ProcessNode(
            pid=90,
            name="sihost.exe",
            command_line="sihost.exe",
            children=[ProcessNode(pid=95, ppid=90, name="explorer.exe", command_line="explorer")],
        ),
        ProcessNode(
            pid=100,
            name="sample.exe",
            command_line="sample.exe -install",
            children=[
                ProcessNode(pid=101, ppid=100, name="cmd.exe", command_line="cmd /c x"),
                ProcessNode(pid=0, ppid=100, name="conhost.exe", command_line="conhost"),
            ],
        ),
    ]


def _exported(report: MalwareReport) -> dict[str, Any]:
    return ExtendedSTIXRenderer().render(report, None).model_dump(mode="json")


def _processes(dumped: dict[str, Any]) -> dict[str, dict[str, Any]]:
    by_id = {o["id"]: o for o in dumped["objects"]}
    return {
        by_id[o["image_ref"]]["name"]: o
        for o in dumped["objects"]
        if o["type"] == "process" and "image_ref" in o
    }


def test_a_process_outside_the_tree_is_kept_and_says_it_is_not_the_sample_s() -> None:
    dumped = _exported(_report(_desktop_and_sample()))
    processes = _processes(dumped)

    assert sorted(processes) == [
        "cmd.exe",
        "conhost.exe",
        "explorer.exe",
        "sample.exe",
        "sihost.exe",
    ]
    assert {name for name, p in processes.items() if SAMPLE_TREE_PROPERTY in p} == {
        "explorer.exe",
        "sihost.exe",
    }
    assert all(
        p[SAMPLE_TREE_PROPERTY] is False for p in processes.values() if SAMPLE_TREE_PROPERTY in p
    )


def test_the_tree_and_the_one_observation_are_unchanged() -> None:
    dumped = _exported(_report(_desktop_and_sample()))
    processes = _processes(dumped)
    (observed,) = [o for o in dumped["objects"] if o["type"] == "observed-data"]

    assert {p["id"] for p in processes.values()} <= set(observed["object_refs"])
    assert processes["sihost.exe"]["child_refs"] == [processes["explorer.exe"]["id"]]


def test_the_export_stays_valid() -> None:
    dumped = _exported(_report(_desktop_and_sample()))

    result = validate_instance(dumped, ValidationOptions(version="2.1"))

    assert [str(getattr(e, "message", e)) for e in result.errors] == []


def test_a_listing_with_every_process_in_the_tree_is_exported_as_before() -> None:
    tree = [_desktop_and_sample()[1]]

    dumped = _exported(_report(tree))

    assert not any(
        SAMPLE_TREE_PROPERTY in o or LINEAGE_DISPUTED_PROPERTY in o for o in dumped["objects"]
    )


def test_a_process_the_two_facts_dispute_says_which_fact_alone_names_it() -> None:
    # A run's listing: the sandbox marks every process, the desktop's
    # (sihost.exe, explorer.exe) among them, and the file names only the
    # sample's own. Where both facts name processes, one only the mark names
    # is disputed, not settled outside, as the report's network rows say it.
    tree = [
        ProcessNode(
            pid=93,
            name="sihost.exe",
            command_line="sihost.exe",
            marked=True,
            children=[
                ProcessNode(
                    pid=95, ppid=93, name="explorer.exe", command_line="explorer", marked=True
                )
            ],
        ),
        ProcessNode(
            pid=84,
            name="rundll32.exe",
            command_line=f"rundll32.exe C:\\Temp\\{SHA256}.dll,Start",
            marked=True,
        ),
    ]

    processes = _processes(_exported(_report(tree, file_name=f"{SHA256}.exe")))

    assert [
        (name, p.get(SAMPLE_TREE_PROPERTY), p.get(LINEAGE_DISPUTED_PROPERTY))
        for name, p in sorted(processes.items())
    ] == [
        ("explorer.exe", None, "marked"),
        ("rundll32.exe", None, None),
        ("sihost.exe", None, "marked"),
    ]


def test_a_judge_process_never_carries_the_platform_s_property() -> None:
    bundle: dict[str, Any] = {
        "type": "bundle",
        "objects": [
            {
                "type": "process",
                "id": "process--8a3b6d5e-0d0b-4b8e-9c1e-0a1b2c3d4e5f",
                "pid": 95,
                SAMPLE_TREE_PROPERTY: False,
                LINEAGE_DISPUTED_PROPERTY: "marked",
            }
        ],
    }

    found = lift_misplaced_extensions(bundle)

    assert SAMPLE_TREE_PROPERTY not in bundle["objects"][0]
    assert LINEAGE_DISPUTED_PROPERTY not in bundle["objects"][0]
    assert [v.code for v in found] == [PROPERTY_NOT_CARRIED_CODE]
