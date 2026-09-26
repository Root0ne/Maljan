"""An address a guest's desktop process reached is not published as the sample's.

A DLL sample ran as two ``rundll32`` processes. Minutes later the guest's
desktop started (``sihost``, ``explorer``, ``SearchHost``,
``StartMenuExperienceHost``), and ``StartMenuExperienceHost`` — whose parent is
no process of the sample, and which runs none of its files — reached one
address on 443. The mapping put that flow in the sample's process tree, on
Triage's ``orig`` mark alone, so the address went out as the sample's C2 in
STIX, ``/iocs``, the YARA draft and a Suricata rule, while the report's own
text tied it to that process and called it no indicator. Where Triage's mark
and the submitted file's own process tree disagree about a process, its
attribution is now not stated; the row names the process and both facts, and
it is published only when a model keeps it. The run's artefacts do not keep
Triage's marks, so every shape that could have produced the run is tested:
only the desktop process marked, the sample and the desktop process marked,
every listed process marked, and nothing marked. Every surface reads that one
answer.

The process table and the flows are the run's own rows.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from maljan.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
from maljan.reporting.detection_signatures import build_detection_rules
from maljan.reporting.ledger_projection import network_from_ledger
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.stix_renderer import (
    FLOW_OUTSIDE_THE_TREE,
    MARKED_ONLY_PROCESS,
    ExtendedSTIXRenderer,
    emulation_kwargs,
    publish_answer,
)
from maljan.schemas.evidence import build_entry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.sandbox_report import triage_overview_to_sandbox_report

SHA256 = "6091f2589fef42e0ab3d7975806cd8a0da012b519637c03b73f702f7586b21ef"
DESKTOP_ADDRESS = "20.67.186.184"
RUNDLL = f"rundll32.exe C:\\Users\\Admin\\AppData\\Local\\Temp\\{SHA256}.dll,#1"
START_MENU = (
    "C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy"
    "\\StartMenuExperienceHost.exe"
)


def _processes(marked: set[int]) -> list[dict[str, Any]]:
    rows = [
        (84, 56, "C:\\Windows\\system32\\rundll32.exe", RUNDLL),
        (87, 81, "C:\\Windows\\system32\\rundll32.exe", RUNDLL),
        (96, 6, "C:\\Windows\\system32\\svchost.exe", "svchost.exe -k GPSvcGroup"),
        (100, 28, "C:\\Windows\\system32\\sihost.exe", "sihost.exe"),
        (102, 100, "C:\\Windows\\explorer.exe", "explorer.exe /LOADSAVEDWINDOWS"),
        (
            104,
            8,
            "C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\SearchHost.exe",
            "SearchHost.exe -ServerName:CortanaUI.AppXstmwaab17q5s3y22tp6apqz7a45vwv65.mca",
        ),
        (105, 8, START_MENU, f'"{START_MENU}" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55.mca'),
    ]
    return [
        {
            "procid": procid,
            "procid_parent": parent,
            "image": image,
            "cmd": cmd,
            **({"orig": True} if procid in marked else {}),
        }
        for procid, parent, image, cmd in rows
    ]


FLOWS = [
    {"proto": "udp", "dst": "8.8.8.8:53", "procid": 36, "pid": 2040},
    {"proto": "tcp", "dst": "142.251.30.94:80", "procid": 47, "pid": 2720},
    {"proto": "tcp", "dst": "4.211.70.206:443", "procid": 90, "pid": 3916},
    {"proto": "tcp", "dst": f"{DESKTOP_ADDRESS}:443", "procid": 105, "pid": 4052},
]


def _sandbox(marked: set[int], flows: list[dict[str, Any]] | None = None) -> Any:
    overview = {"sample": {"id": "s", "target": f"{SHA256}.exe", "sha256": SHA256}}
    task = {"processes": _processes(marked), "network": {"flows": flows or FLOWS}}
    return triage_overview_to_sandbox_report(overview, task_reports={"behavioral1": task})


def _desktop_flow(marked: set[int]) -> dict[str, Any]:
    report = _sandbox(marked)
    return next(row for row in report.network.tcp if row["dst"] == DESKTOP_ADDRESS)


MARKED_SHAPES = [
    pytest.param({105}, id="only-the-desktop-process-marked"),
    pytest.param({84, 87, 105}, id="the-sample-and-the-desktop-process-marked"),
    pytest.param({84, 87, 96, 100, 102, 104, 105}, id="every-listed-process-marked"),
]


@pytest.mark.parametrize("marked", MARKED_SHAPES)
def test_a_marked_desktop_process_the_file_does_not_name_states_no_attribution(
    marked: set[int],
) -> None:
    flow = _desktop_flow(marked)
    assert "sample_process_tree" not in flow
    assert flow["lineage_disputed"] == "orig"
    assert flow["process"] == "StartMenuExperienceHost.exe"


def test_with_nothing_marked_the_desktop_process_is_outside_the_tree() -> None:
    flow = _desktop_flow(set())
    assert flow["sample_process_tree"] is False
    assert flow["process"] == "StartMenuExperienceHost.exe"


def _mentions() -> dict[str, AgentISR]:
    said = (
        f"One row carries the sample-process flag, {DESKTOP_ADDRESS}:443 from procid 105; "
        "it remains an unattributed sandbox-side row rather than an indicator."
    )
    return {
        name: AgentISR(
            agent_id=name,
            domain=name,
            claims=[ClaimEvidence(claim=said, evidence_ref="[ev_0001]", confidence=0.6)],
        )
        for name in ("static", "dynamic", "network")
    }


def _report(marked: set[int], flows: list[dict[str, Any]] | None = None) -> MalwareReport:
    sandbox = _sandbox(marked, flows)
    ledger = [
        build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="dynamic",
            tool="sandbox_network",
            args={},
            server=None,
            output=json.dumps({"tcp": sandbox.network.tcp, "udp": sandbox.network.udp}),
        )
    ]
    report = MalwareReportBuilder(
        file_hash=SHA256,
        file_name=f"{SHA256}.exe",
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
        malware_category="loader",
        sample_platform="windows",
        sample_file_type="pe",
        evidence_ledger=ledger,
    ).build_deterministic()
    report.network = network_from_ledger(
        ledger, _mentions(), sandbox_report={"network": sandbox.network.model_dump()}
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


MENTIONED = (
    "(a claim by the static analyst, a claim by the dynamic analyst, a claim by the "
    "network analyst mentions it and does not keep it)"
)


def _on_no_surface(report: MalwareReport) -> None:
    patterns = [
        str(getattr(o, "pattern", "")) for o in ExtendedSTIXRenderer().render(report).objects
    ]
    assert not any(DESKTOP_ADDRESS in p for p in patterns)
    for rule in build_detection_rules(report):
        assert DESKTOP_ADDRESS not in rule.body, rule.kind


def _answer(report: MalwareReport) -> str:
    return publish_answer(
        "ip", DESKTOP_ADDRESS, "sandbox", None, **emulation_kwargs(report, "ip", DESKTOP_ADDRESS)
    )


@pytest.mark.parametrize("marked", MARKED_SHAPES)
def test_a_disputed_row_is_on_no_surface_and_its_no_states_both_facts(marked: set[int]) -> None:
    report = _report(marked)
    (row,) = [ip for ip in report.network.ips if ip.address == DESKTOP_ADDRESS]
    assert row.sample_process_tree is None
    assert row.marked_only_processes == ["StartMenuExperienceHost.exe (procid 105)"]
    assert row.kept_by == []

    answer = _answer(report)
    assert answer.startswith(
        "no: the sandbox report attributes its flows to StartMenuExperienceHost.exe "
        f"(procid 105), {MARKED_ONLY_PROCESS}"
    )
    # Three analysts named it while saying it is no indicator: that keeps nothing.
    assert answer.endswith(MENTIONED)

    (table_row,) = [i for i in report.consolidated_iocs if i.value == DESKTOP_ADDRESS]
    assert table_row.published == answer
    assert MARKED_ONLY_PROCESS in table_row.context
    _on_no_surface(report)


def test_with_nothing_marked_the_no_names_the_process_outside_the_tree() -> None:
    report = _report(set())
    answer = _answer(report)
    assert answer.startswith(
        f"no: {FLOW_OUTSIDE_THE_TREE} (StartMenuExperienceHost.exe (procid 105))"
    )
    assert answer.endswith(MENTIONED)
    _on_no_surface(report)


def test_a_flow_both_facts_give_the_sample_reaches_every_surface() -> None:
    # The surfaces above are empty of it for the rule's answer, not for want of a path.
    flows = [{"proto": "tcp", "dst": f"{DESKTOP_ADDRESS}:443", "procid": 84, "pid": 1}]
    report = _report({84, 87, 105}, flows)
    (table_row,) = [i for i in report.consolidated_iocs if i.value == DESKTOP_ADDRESS]
    assert table_row.published == "yes"
    patterns = [
        str(getattr(o, "pattern", "")) for o in ExtendedSTIXRenderer().render(report).objects
    ]
    assert f"[ipv4-addr:value = '{DESKTOP_ADDRESS}']" in patterns


def test_a_flow_of_the_sample_s_own_process_is_still_published() -> None:
    flows = [{"proto": "tcp", "dst": f"{DESKTOP_ADDRESS}:443", "procid": 84, "pid": 1}]
    overview = {"sample": {"id": "s", "target": f"{SHA256}.exe", "sha256": SHA256}}
    task = {"processes": _processes({84, 87, 105}), "network": {"flows": flows}}
    report = triage_overview_to_sandbox_report(overview, task_reports={"behavioral1": task})
    assert report.network.tcp[0]["sample_process_tree"] is True
    assert "process" not in report.network.tcp[0]
