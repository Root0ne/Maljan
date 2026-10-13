"""A rule tool swapped in for a shipped one is labelled as itself wherever its table is read.

The rule tables keep their keys (stored runs re-render byte for byte), and a
table is titled by the declared display name of the tool whose rows it holds.
Every label printed for the rows is read back from that title, so the shipped
tool's name is never printed over another tool's rows.
"""

from __future__ import annotations

from maljan.reporting.ledger_report import CAPABILITIES_TITLE, RULE_MATCHES_TITLE, titled_tool
from maljan.reporting.run_diff import RunRecord, _detection_items


def test_a_title_gives_back_its_tool_and_any_other_title_nothing() -> None:
    assert titled_tool("RuleBench capabilities", CAPABILITIES_TITLE) == "RuleBench"
    assert titled_tool("Sigma rule matches", RULE_MATCHES_TITLE) == "Sigma"
    assert titled_tool(" capabilities", CAPABILITIES_TITLE) == ""
    assert titled_tool("YARA matches", RULE_MATCHES_TITLE) == ""
    assert titled_tool(None, CAPABILITIES_TITLE) == ""


def _run(title: str) -> RunRecord:
    section = {
        "key": "capa_capabilities",
        "title": title,
        "kind": "table",
        "columns": ["Namespace", "Rule", "ATT&CK", "MBC"],
        "rows": [["anti-analysis", "check for debugger", "T1622", ""]],
        "evidence_ids": ["ev_0002"],
    }
    return RunRecord(report_id="r", job_id="j", malware_report={"sections": [section]})


def test_the_run_diff_labels_a_swapped_tools_rows_by_its_title() -> None:
    items, recorded, _ = _detection_items(_run("RuleBench capabilities"))
    assert recorded and [item.label for item in items] == ["rulebench: check for debugger"]


def test_the_shipped_tools_rows_keep_their_label() -> None:
    items, _, _ = _detection_items(_run("capa capabilities"))
    assert [item.label for item in items] == ["capa: check for debugger"]
    # A stored table titled otherwise keeps the engine it was built for.
    items, _, _ = _detection_items(_run("Capabilities"))
    assert [item.label for item in items] == ["capa: check for debugger"]
