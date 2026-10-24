"""Each kind of surface defect is found and named by class, kind and surface.

Every case breaks one thing in the clean synthetic run: a finding left off a
surface, a value cut or renamed, a citation that names no ledger entry, a
section the console would draw blank, an object with no report item behind
it, a scalar two surfaces disagree on, a count that does not add up. Each is
reported, and nothing else is. An empty section is blank only when the call it
cites answered with a value that no child section of it holds.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from scripts.audit import surfaces

from tests.unit.scripts._surfaces_run import (
    CELL,
    DOMAIN,
    IP,
    SHA256,
    clean_run,
    clean_spec,
    defects,
    write_run,
)


def _mr(run: dict[str, Any]) -> dict[str, Any]:
    return run["report_row"]["malware_report"]


def _drop_mitre_row(run: dict[str, Any]) -> None:
    run["mitre"]["techniques"] = []


def _rename_stix_technique(run: dict[str, Any]) -> None:
    run["stix"]["objects"][2]["name"] = "Command Interpreter"


def _extra_stix_technique(run: dict[str, Any]) -> None:
    run["stix"]["objects"].append(
        {
            "type": "attack-pattern",
            "name": "System Information Discovery",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1082"}],
        }
    )
    run["report_row"]["run_summary"]["stix_object_count"] += 1
    run["run_summary"]["stix_object_count"] += 1


def _judge_technique_lost(run: dict[str, Any]) -> None:
    for cell in _mr(run)["capability_matrix"]:
        cell["not_published"] = ""
    _mr(run)["capability_matrix"] = _mr(run)["capability_matrix"][:1]
    run["report_full"]["capability_matrix"] = _mr(run)["capability_matrix"]


def _feed_loses_ioc(run: dict[str, Any]) -> None:
    run["iocs_all"]["items"] = run["iocs_all"]["items"][:2]


def _feed_gains_ioc(run: dict[str, Any]) -> None:
    run["iocs_all"]["items"].append(
        {"kind": "domain", "value": "other.example", "published": False}
    )


def _feed_flips_publication(run: dict[str, Any]) -> None:
    run["iocs_all"]["items"][2]["published"] = True


def _stix_loses_published_ioc(run: dict[str, Any]) -> None:
    del run["stix"]["objects"][4]
    run["report_row"]["run_summary"]["stix_object_count"] -= 1
    run["run_summary"]["stix_object_count"] -= 1


def _stix_publishes_withheld_ioc(run: dict[str, Any]) -> None:
    run["stix"]["objects"].append({"type": "indicator", "pattern": f"[ipv4-addr:value = '{IP}']"})
    run["report_row"]["run_summary"]["stix_object_count"] += 1
    run["run_summary"]["stix_object_count"] += 1


def _markdown_truncates_ioc(run: dict[str, Any]) -> None:
    run["markdown"] = run["markdown"].replace(f"`{SHA256}`", f"`{SHA256[:30]}…`")


def _key_finding_cites_nothing(run: dict[str, Any]) -> None:
    _mr(run)["key_findings"][0]["evidence_ids"] = ["ev_0099"]
    run["report_full"]["key_findings"][0]["evidence_ids"] = ["ev_0099"]


def _stix_cites_nothing(run: dict[str, Any]) -> None:
    run["stix"]["objects"][4]["x_maljan_evidence_refs"] = ["ev_0042"]


def _section_text_beside_rows(run: dict[str, Any]) -> None:
    for mr in (_mr(run), run["report_full"]):
        mr["sections"][0]["text"] = "9 more rows not shown here."
    run["markdown"] += "\n9 more rows not shown here."
    run["html"] += "<p>9 more rows not shown here.</p>"


def _section_on_detection(run: dict[str, Any]) -> None:
    for mr in (_mr(run), run["report_full"]):
        mr["sections"][0]["key"] = "custom_rules"
    run["report_row"]["section_tabs"] = {"custom_rules": "detection"}


def _row_wider_than_columns(run: dict[str, Any]) -> None:
    for mr in (_mr(run), run["report_full"]):
        mr["sections"][0]["rows"] = [[CELL, "a cell with no heading"]]


def _full_report_verdict(run: dict[str, Any]) -> None:
    run["report_full"]["verdict"] = "Suspicious"


def _stix_severity(run: dict[str, Any]) -> None:
    run["stix"]["objects"][0]["description"] = "Verdict: Malware. Severity Medium."


def _event_confidence(run: dict[str, Any]) -> None:
    run["events"][-1]["payload"]["confidence"] = 0.5


def _stix_family(run: dict[str, Any]) -> None:
    run["stix"]["objects"][1]["name"] = "Otherfam"


def _stix_count(run: dict[str, Any]) -> None:
    run["report_row"]["run_summary"]["stix_object_count"] = 99
    run["run_summary"]["stix_object_count"] = 99


def _job_hash(run: dict[str, Any]) -> None:
    run["job"]["sample_sha256"] = "b" * 64


def _process_without_object(run: dict[str, Any]) -> None:
    run["stix"]["objects"][5]["command_line"] = "sample.exe /other"


def _section_blank_while_its_call_answered(run: dict[str, Any]) -> None:
    for mr in (_mr(run), run["report_full"]):
        mr["sections"].append(
            {
                "key": "tool_lookup",
                "title": "Lookup",
                "kind": "table",
                "columns": ["name"],
                "rows": [],
                "items": [],
                "text": "",
                "evidence_ids": ["ev_0002"],
            }
        )
    run["evidence"]["items"][1]["output"] = '{"name": "answered"}'


def _ioc_no_tab_draws(run: dict[str, Any]) -> None:
    # A dropped file's path: in the report's IOC table, the feed and the
    # renderings, publication unstated, and in no field a tab draws.
    path = "C:\\Users\\Public\\drop.dat"
    for mr in (_mr(run), run["report_full"]):
        mr["consolidated_iocs"].append(
            {"kind": "path", "type": "File path", "value": path, "published": None}
        )
    run["iocs_all"]["items"].append({"kind": "path", "value": path, "published": False})
    run["markdown"] += f"\n| File path | `{path}` |"
    run["html"] += f"<p>{path}</p>"


CASES: dict[str, tuple[Callable[[dict[str, Any]], None], set[tuple[str, str, str]]]] = {
    "a technique missing from /mitre": (_drop_mitre_row, {("missing", "technique", "mitre")}),
    "a technique renamed in STIX": (_rename_stix_technique, {("altered", "technique", "stix")}),
    "a STIX technique with no report item": (
        _extra_stix_technique,
        {("orphan", "technique", "stix")},
    ),
    "a judge technique neither published nor declined": (
        _judge_technique_lost,
        {("orphan", "technique", "stix_judge")},
    ),
    "an IOC missing from the feed": (_feed_loses_ioc, {("missing", "ioc", "iocs_all")}),
    "a feed row with no report row": (_feed_gains_ioc, {("orphan", "ioc", "iocs_all")}),
    "a feed row published the report withholds": (
        _feed_flips_publication,
        {("altered", "ioc", "iocs_all")},
    ),
    "a published IOC missing from STIX": (_stix_loses_published_ioc, {("missing", "ioc", "stix")}),
    "STIX publishes a withheld IOC": (_stix_publishes_withheld_ioc, {("filter", "ioc", "stix")}),
    "an IOC cut short in the Markdown": (
        _markdown_truncates_ioc,
        {("truncated", "ioc", "markdown")},
    ),
    "a key finding citing no ledger entry": (
        _key_finding_cites_nothing,
        {
            ("unresolved_citation", "citation", "evidence"),
            ("unresolved_citation", "citation", "report_full.evidence_index"),
        },
    ),
    "a STIX object citing no ledger entry": (
        _stix_cites_nothing,
        {("unresolved_citation", "citation", "stix")},
    ),
    "a table's text the console does not draw": (
        _section_text_beside_rows,
        {("dropped", "section", "web")},
    ),
    "a section placed on a tab that does not draw it": (
        _section_on_detection,
        {("missing", "section", "web")},
    ),
    "cells past a table's columns": (
        _row_wider_than_columns,
        {("dropped", "section", "markdown"), ("dropped", "section", "html")},
    ),
    "a verdict two surfaces disagree on": (
        _full_report_verdict,
        {("differs", "verdict", "report_full")},
    ),
    "a severity two surfaces disagree on": (_stix_severity, {("differs", "severity", "stix")}),
    "a confidence two surfaces disagree on": (
        _event_confidence,
        {("differs", "confidence", "events")},
    ),
    "a family two surfaces disagree on": (_stix_family, {("differs", "family", "stix")}),
    "a count that does not add up": (_stix_count, {("differs", "count", "stix")}),
    "a job that names another sample": (_job_hash, {("differs", "identity", "job")}),
    "a process with no STIX object": (
        _process_without_object,
        {("missing", "process", "stix"), ("orphan", "process", "stix")},
    ),
    "an empty section whose call answered": (
        _section_blank_while_its_call_answered,
        {("blank_section", "section", "web")},
    ),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_one_break_is_one_named_defect(name: str) -> None:
    run = clean_run()
    breaks, expected = CASES[name]
    breaks(run)

    result = surfaces.audit(run, clean_spec())

    assert set(defects(result)) == expected
    assert result["status"] == "defects"


def test_an_ioc_no_tab_draws_is_one_named_defect() -> None:
    # A console whose DETECTION tab no longer draws the IOC table.
    run = clean_run()
    _ioc_no_tab_draws(run)
    spec = clean_spec()
    spec["tabs"]["detection"]["fields"] = [
        item
        for item in spec["tabs"]["detection"]["fields"]
        if "consolidated_iocs" not in item["path"]
    ]
    spec["kinds"].pop("ioc")
    spec["kinds"].pop("ioc_publication")

    result = surfaces.audit(run, spec)

    assert set(defects(result)) == {("missing", "ioc", "web")}
    assert result["status"] == "defects"


def test_a_missing_finding_exits_one(tmp_path: Path) -> None:
    run = clean_run()
    _drop_mitre_row(run)
    directory = write_run(tmp_path / "run", run)

    assert surfaces.main(["--run", str(directory), "--out", str(tmp_path / "out.json")]) == 1


def test_defanged_network_values_read_as_the_values() -> None:
    run = clean_run()
    assert f"`{DOMAIN}`" not in run["markdown"]
    assert f"`{IP}`" not in run["markdown"]

    result = surfaces.audit(run, clean_spec())

    assert not [d for d in result["defects"] if d["kind"] in {"ioc", "network_fact"}]


def test_an_empty_section_is_not_blank_when_its_call_answered_nothing() -> None:
    run = clean_run()
    _section_blank_while_its_call_answered(run)
    run["evidence"]["items"][1]["structured"] = {"channels": [], "rows": []}

    assert defects(surfaces.audit(run, clean_spec())) == []


def test_an_empty_section_is_not_blank_when_a_child_section_holds_its_records() -> None:
    run = clean_run()
    _section_blank_while_its_call_answered(run)
    for mr in (_mr(run), run["report_full"]):
        mr["sections"].append(
            {
                "key": "tool_lookup_families",
                "title": "Lookup: families",
                "kind": "list",
                "columns": [],
                "rows": [],
                "items": ["Examplefam 0.9"],
                "text": "",
                "evidence_ids": ["ev_0002"],
            }
        )
    run["markdown"] += "\n### Lookup: families\n- Examplefam 0.9"
    run["html"] += "<h3>Lookup: families</h3><li>Examplefam 0.9</li>"

    assert defects(surfaces.audit(run, clean_spec())) == []
