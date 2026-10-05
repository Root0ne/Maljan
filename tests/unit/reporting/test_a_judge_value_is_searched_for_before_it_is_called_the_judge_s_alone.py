"""A judge value is said to be the judge's alone only after the run was searched for it.

A value the judge's indicator names and no row publishes was refused as
"seen only in the file's strings", a source that did not hold it, and then as
"named only by the judge's indicator" while a decoded-strings entry held it
whole. The judge's values now join the build's whole-value search of every
tool answer: an entry that holds one is named, "no tool answer in this run
holds it" is said only when the whole search found none, and a report stored
before the search says what was searched.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
from maljan.reporting.models import (
    EvidenceSection,
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
)
from maljan.schemas.evidence import build_entry

NAME = "only-judge.example.net"
SEEN = "no: seen only in the text of ev_0007 (floss), and no second source in this run records it"
NOTHING = (
    "no: named only by the judge's indicator; no tool answer in this run holds it, and no "
    "second source records it"
)


def _judge_bundle() -> dict[str, Any]:
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332211",
                "pattern": f"[domain-name:value = '{NAME}']",
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "valid_from": "2026-01-01T00:00:00Z",
            }
        ],
    }


def _built(ledger: list[Any]) -> MalwareReport:
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="fixture.bin",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output=_judge_bundle(),
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.8,
        sample_platform="windows",
        sample_file_type="PE",
        evidence_ledger=ledger,
    ).build_deterministic()


def _entry(entry_id: str, tool: str, payload: dict[str, Any]) -> Any:
    return build_entry(
        entry_id=entry_id,
        seq=int(entry_id.split("_")[1]),
        agent="pipeline",
        tool=tool,
        args={},
        server="pipeline",
        output=json.dumps(payload),
    )


def _answer(report: MalwareReport) -> str:
    (row,) = [r for r in build_consolidated_iocs(report) if r.value == NAME]
    return str(row.published)


def test_the_build_searches_every_answer_for_the_judge_s_values() -> None:
    report = _built([_entry("ev_0007", "floss", {"strings": [{"string": NAME}]})])

    assert report.tool_sightings is not None
    assert report.tool_sightings[NAME] == [("ev_0007", "floss")]


def test_a_value_a_tool_answer_holds_names_the_entry() -> None:
    report = _built([_entry("ev_0007", "floss", {"strings": [{"string": NAME}]})])

    assert _answer(report) == SEEN


def test_a_value_no_answer_holds_is_the_judge_s_alone() -> None:
    report = _built([_entry("ev_0003", "pe_info", {"imports": ["KERNEL32.dll"]})])

    assert _answer(report) == NOTHING


def test_a_value_only_a_query_for_it_holds_says_so() -> None:
    asked = build_entry(
        entry_id="ev_0004",
        seq=4,
        agent="network",
        tool="get_domain_report",
        args={"domain": NAME},
        server="threatintel",
        output=json.dumps({"domain": NAME, "detections": 0}),
    )

    answer = _answer(_built([asked]))

    assert answer.startswith("no: named only by the judge's indicator; ")
    assert "only the answer to a query for it holds it (ev_0004 get_domain_report)" in answer


def test_a_value_the_file_s_strings_hold_keeps_that_reason() -> None:
    report = _built([])
    report.static = StaticAnalysis(interesting_strings=[StringIOC(kind="domain", value=NAME)])

    assert _answer(report) == "no: seen only in the file's strings"


def _stored(*sections: EvidenceSection) -> MalwareReport:
    """A report stored before the build searched for the judge's values."""
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        judge_indicators=[JudgeIndicator(kind="domain", value=NAME)],
        sections=list(sections),
        tool_sightings={},
    )


def test_a_stored_report_names_the_kept_section_that_holds_it() -> None:
    kept = EvidenceSection(
        key="floss",
        title="Floss",
        kind="kv",
        rows=[["string", NAME]],
        evidence_ids=["ev_0007"],
        source="tool:floss",
    )

    answer = _answer(_stored(kept))

    assert answer == (
        "no: seen only in the text of ev_0007 (floss), as the tool sections this stored report "
        "keeps show it, and no second source in this run records it"
    )


def test_a_stored_report_says_only_its_kept_sections_were_searched() -> None:
    assert _answer(_stored()) == (
        "no: named only by the judge's indicator; no tool answer this report keeps holds it, "
        "and no second source records it"
    )
