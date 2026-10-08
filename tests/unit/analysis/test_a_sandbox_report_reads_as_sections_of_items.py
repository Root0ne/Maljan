"""The sandbox report as sections of items, each item with an id a claim can cite.

The index is one pack entry stating each section's count, or the ``no:`` that
says why the report does not carry it; ``sandbox_items`` answers items whole,
with their ids and the report fields they came from; and an item id a claim
writes is checked against the run's index and resolved to the process or the
flow it is, for the citation checks and the evidence roots.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.analysis import sandbox_sections as ss
from maljan.analysis.evidence_roots import run_roots
from maljan.pipeline import triage_pack
from maljan.pipeline.validation import (
    CITATION_NOT_EVIDENCE_CODE,
    UNGROUNDED_TECHNIQUE_CODE,
    citation_violations,
    flow_voice_violations,
    validate_isr,
)
from maljan.providers import sandbox_tools
from maljan.providers.cape_view import to_cape_shaped_dict
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.sandbox_report import triage_overview_to_sandbox_report

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox"


def _cape() -> dict[str, Any]:
    return json.loads((FIXTURES / "cape2_report.json").read_text())


def _triage() -> dict[str, Any]:
    overview = json.loads((FIXTURES / "triage_overview.json").read_text())
    task = json.loads((FIXTURES / "triage_report_behavioral1.json").read_text())
    return to_cape_shaped_dict(
        triage_overview_to_sandbox_report(overview, task_reports={"behavioral1": task})
    )


REPORT: dict[str, Any] = {
    "behavior": {
        "processes": [
            {"pid": 84, "ppid": 56, "process_name": "rundll32.exe", "command_line": "a b,#1"},
            {"pid": 90, "ppid": 84, "process_name": "cmd.exe", "command_line": "cmd /c x"},
            {"pid": 90, "ppid": 84, "process_name": "cmd.exe", "command_line": "cmd /c y"},
            {"process_name": "nameless.exe"},
            "not a row",
        ],
        "summary": {
            "keys": ["HKCU\\Software\\Run\\x"],
            "write_keys": ["HKCU\\Software\\Run\\x"],
            "mutexes": ["Global\\m1"],
            "executed_commands": [],
        },
    },
    "network": {
        "dns": [{"request": "gate.example.com", "type": "A"}],
        "hosts": ["192.0.2.10"],
        "tcp": [{"dst": "192.0.2.10", "dport": 443, "pid": 84}],
        "http": [{"host": "gate.example.com", "uri": "/live/", "method": "POST"}],
    },
    "signatures": [
        {"name": "persistence_autorun", "severity": 3},
        {"name": "Uses Task Scheduler", "severity": 6},
    ],
    "unavailable": ["registry"],
}


class TestTheIndex:
    def test_each_section_counts_its_items_or_says_why_it_is_not_carried(self) -> None:
        index = ss.section_index(REPORT)["sections"]

        assert list(index) == list(ss.SECTION_PREFIXES)
        assert index["processes"]["items"] == 5
        assert index["processes"]["ids"] == [
            "proc:84",
            "proc:90",
            "proc:90.2",
            "proc:p4",
            "proc:p5",
        ]
        assert index["network"] == {"items": 4, "prefix": "net"}
        assert index["mutexes"] == {"items": 1, "prefix": "mutex"}
        assert index["commands"] == {"items": 0, "prefix": "cmd"}
        # The report lists registry as unavailable, though it holds the lists.
        assert index["registry"] == {
            "no": "no: the report lists registry as unavailable from its sandbox"
        }
        assert index["dropped"] == {"no": "no: the report holds none of dropped, dropped_files"}
        assert index["events"] == {"no": "no: the report holds no behavior.generic"}

    def test_a_triage_report_names_the_sections_its_sandbox_does_not_record(self) -> None:
        index = ss.section_index(_triage())["sections"]

        for name in ("api_calls", "registry", "events", "apistats", "screenshots"):
            assert index[name]["no"].startswith("no: the report lists ")
        assert index["processes"]["ids"] == ["proc:1000", "proc:1001"]
        assert index["network"]["items"] > 0

    def test_a_cape_process_is_named_by_its_process_id(self) -> None:
        index = ss.section_index(_cape())["sections"]

        assert index["processes"]["ids"] == ["proc:4616"]
        assert index["api_calls"]["items"] == 5

    def test_the_pack_line_states_counts_id_forms_and_reasons(self) -> None:
        entry = LedgerEntry(
            id="ev_0040",
            tool=ss.SECTIONS_TOOL,
            agent="pipeline",
            structured=ss.section_index(REPORT),
        )
        line = triage_pack.render_pack([entry], 0)

        assert line.startswith("[ev_0040] sandbox sections: processes 5 (proc:84, proc:90, ")
        assert "network 4 (net:1 to net:4)" in line
        assert "mutexes 1 (mutex:1)" in line
        assert "commands 0" in line
        assert "registry no: the report lists registry as unavailable" in line
        assert line.endswith(triage_pack.SECTIONS_SERVED_BY)


class TestItems:
    def test_every_id_the_index_states_names_the_item_the_section_lists(self) -> None:
        for report in (REPORT, _cape(), _triage()):
            found = ss.Sections(report)
            index = ss.ItemIndex.from_answer(ss.section_index(report))
            assert index is not None
            listed = [item["id"] for name in ss.SECTION_PREFIXES for item in found.items(name)]
            assert listed == list(index.ids())
            for item_id in listed:
                assert index.known(item_id)
                item = found.item(item_id)
                assert item is not None and item["id"] == item_id

    def test_an_item_is_the_report_row_whole_with_where_it_came_from(self) -> None:
        found = ss.Sections(REPORT)

        assert found.item("proc:90.2") == {
            "id": "proc:90.2",
            "kind": "processes",
            "source": "behavior.processes[2]",
            "fields": REPORT["behavior"]["processes"][2],
            "parent": "proc:84",
        }
        assert found.item("net:2") == {
            "id": "net:2",
            "kind": "hosts",
            "source": "network.hosts[0]",
            "fields": {"value": "192.0.2.10"},
        }
        assert found.item("proc:p5")["fields"] == {"value": "not a row"}
        # A parent two processes share is not named.
        assert "parent" not in (found.item("proc:84") or {})
        assert found.item("net:5") is None
        assert found.item("proc:91") is None

    def test_the_network_items_are_the_network_view_s_rows_in_its_order(self) -> None:
        view = sandbox_tools.sandbox_network(_triage())
        found = ss.Sections(_triage())
        rows = [(kind, row) for kind in ss.NETWORK_KINDS for row in view.get(kind) or []]
        items = list(found.items("network"))

        assert [(i["kind"], i["fields"].get("dst")) for i in items] == [
            (kind, row.get("dst") if isinstance(row, dict) else None) for kind, row in rows
        ]

    def test_a_process_s_calls_are_items_of_the_calls_section_under_its_id(self) -> None:
        found = ss.Sections(_cape())

        (first,) = [i for i in found.items("api_calls")][:1]
        assert first["process"] == "proc:4616"
        assert "calls" not in found.item("proc:4616")["fields"]

    def test_item_ids_are_read_out_of_text_whole(self) -> None:
        text = "see proc:84. then net:3, [reg:12] and proc:84.2; tcp:443 http://x call:7x"
        assert ss.item_ids_in(text) == ["proc:84", "net:3", "reg:12", "proc:84.2"]


class TestQuery:
    def test_the_filters_combine(self) -> None:
        found = ss.Sections(REPORT)

        by_pid, _ = found.query("processes", pid="90")
        assert [i["id"] for i in by_pid] == ["proc:90", "proc:90.2"]
        text, _ = found.query("processes", pid="90", contains="/C Y")
        assert [i["id"] for i in text] == ["proc:90.2"]
        flows, _ = found.query("network", pid="84")
        assert [i["id"] for i in flows] == ["net:4"]
        named, _ = found.query("signatures", signature="uses task scheduler")
        by_id, _ = found.query("signatures", signature="sig:2")
        assert named == by_id and [i["id"] for i in named] == ["sig:2"]

    def test_asked_ids_are_found_by_position_and_the_rest_are_named(self) -> None:
        class _NoWalk(list):  # a section read whole would iterate it
            def __iter__(self):  # type: ignore[no-untyped-def]
                raise AssertionError("the section was walked")

        report = {"behavior": {"summary": {"mutexes": _NoWalk(f"m{i}" for i in range(50_000))}}}
        found = ss.Sections(report)

        items, missing = found.query("mutexes", ids=["mutex:49999", "mutex:0", "net:1", "x"])
        assert [i["fields"]["value"] for i in items] == ["m49998"]
        assert missing == ["mutex:0", "net:1", "x"]

    def test_a_deeply_nested_row_is_searched_without_recursion(self) -> None:
        nested: Any = "needle"
        for _ in range(50_000):
            nested = [nested]
        found = ss.Sections({"behavior": {"generic": [{"deep": nested}]}})

        items, _ = found.query("events", contains="NEEDLE")
        assert [i["id"] for i in items] == ["event:1"]

    def test_hostile_pids_are_no_pid(self) -> None:
        report = {
            "behavior": {
                "processes": [
                    {"pid": True},
                    {"pid": -4},
                    {"pid": "9" * 40},
                    {"pid": " 0012 "},
                ]
            }
        }
        ids = ss.section_index(report)["sections"]["processes"]["ids"]
        assert ids == ["proc:p1", "proc:p2", "proc:p3", "proc:12"]


class _Sizer:
    def __init__(self) -> None:
        self.narrowing: tuple[str, ...] = ()

    def _apply_output_guardrail(self, text: str, narrowing: tuple[str, ...]) -> str:
        self.narrowing = tuple(narrowing)
        return text


class TestTheTool:
    def test_it_answers_the_items_and_how_many_matched(self) -> None:
        answer = sandbox_tools.sandbox_items(REPORT, "processes", pid="90")
        assert answer["section"] == "processes"
        assert answer["matched"] == 2
        assert [i["id"] for i in answer["items"]] == ["proc:90", "proc:90.2"]

    def test_what_it_cannot_answer_it_says(self) -> None:
        assert sandbox_tools.sandbox_items(None, "processes") == {
            "error": "no sandbox report for this job",
            "tool": "sandbox",
        }
        stand_in = {"synthetic": True, "behavior": {"processes": []}}
        assert "No sandbox ran" in sandbox_tools.sandbox_items(stand_in, "processes")["error"]
        assert sandbox_tools.sandbox_items(REPORT, "nope")["sections"] == list(ss.SECTION_PREFIXES)
        assert sandbox_tools.sandbox_items(REPORT, "registry") == {
            "section": "registry",
            "no": "no: the report lists registry as unavailable from its sandbox",
        }
        assert sandbox_tools.sandbox_items(REPORT, "processes", pid="x1")["error"] == (
            sandbox_tools.ITEMS_BAD_PID
        )
        assert sandbox_tools.sandbox_items(REPORT, "network", signature="sig:1")["error"] == (
            sandbox_tools.ITEMS_SIGNATURE_SECTION
        )
        asked = sandbox_tools.sandbox_items(REPORT, "network", ids="net:1, net:9")
        assert [i["id"] for i in asked["items"]] == ["net:1"]
        assert asked["not_in_section"] == ["net:9"]

    def test_it_is_in_the_sandbox_set_sized_by_the_guardrail(self) -> None:
        class _Container:
            sandbox_report = REPORT

        tools = sandbox_tools.sandbox_tools(_Container())
        (tool,) = [t for t in tools if t.name == ss.ITEMS_TOOL]
        assert set(tool.args_schema.model_fields) == {
            "section",
            "pid",
            "contains",
            "signature",
            "ids",
        }
        sizer = _Sizer()
        sized = sandbox_tools.items_tool(REPORT, sizer)
        answer = json.loads(sized.invoke({"section": "mutexes"}))
        assert answer["matched"] == 1
        assert sizer.narrowing == ("pid", "contains", "signature", "ids")


def _index_entry(report: dict[str, Any], eid: str = "ev_0040") -> LedgerEntry:
    return LedgerEntry(
        id=eid, tool=ss.SECTIONS_TOOL, agent="pipeline", structured=ss.section_index(report)
    )


class TestCitations:
    def test_a_held_item_is_a_citation_and_an_unheld_one_is_asked_once(self) -> None:
        index = ss.ItemIndex.from_answer(ss.section_index(REPORT))
        assert index is not None
        citable = ["ev_0001", *index.ids()]
        prose = {"body": "Runs rundll32 [proc:84], then [proc:99] and [proc:99] [net:3]."}

        (asked,) = citation_violations(prose, citable)
        assert asked.code == CITATION_NOT_EVIDENCE_CODE
        assert asked.message.startswith("[proc:99] is not an item of this run's sandbox report.")
        assert citation_violations({"body": "x [proc:84]"}, citable) == []

    def test_without_an_index_an_item_shaped_bracket_is_asked_as_before(self) -> None:
        (asked,) = citation_violations({"body": "x [proc:84]"}, ["ev_0001"])
        assert "is cited, and it is not an evidence id" in asked.message

    def test_an_analyst_claim_citing_a_held_item_is_grounded(self) -> None:
        index = ss.ItemIndex.from_answer(ss.section_index(REPORT))
        assert index is not None
        ids = ["ev_0001", *index.ids()]

        def _claim(ref: str) -> AgentISR:
            return AgentISR(
                agent_id="dynamic",
                domain="dynamic",
                claims=[
                    ClaimEvidence(
                        claim="Writes an autorun key",
                        evidence_ref=ref,
                        confidence=0.8,
                        technique_id="T1547.001",
                    )
                ],
            )

        held = validate_isr(_claim("process proc:84"), ledger_ids=ids)
        assert not [v for v in held if v.code == UNGROUNDED_TECHNIQUE_CODE]
        (unheld,) = [
            v
            for v in validate_isr(_claim("process proc:99"), ledger_ids=ids)
            if v.code == UNGROUNDED_TECHNIQUE_CODE
        ]
        assert "[proc:99] is not an item of this run's sandbox report." in unheld.message

    def test_an_observed_step_may_cite_items(self) -> None:
        step = {
            "steps": [
                {
                    "order": 1,
                    "action": "Starts cmd.",
                    "voice": "observed",
                    "evidence_refs": ["proc:90"],
                }
            ]
        }
        assert flow_voice_violations(step, ["proc:90"]) == []
        (asked,) = flow_voice_violations(step, ["ev_0012"])
        assert "cites no sandbox entry" in asked.message


class TestRoots:
    def test_a_process_item_s_root_is_that_process_and_a_flow_item_s_its_flow(self) -> None:
        network = sandbox_tools.sandbox_network(REPORT)
        ledger = [
            _index_entry(REPORT),
            LedgerEntry(id="ev_0041", tool="sandbox_network", agent="pipeline", structured=network),
        ]
        roots = run_roots(ledger)

        assert roots.of_statement("rundll32 runs as proc:84", []) == (["sandbox process 84"], [])
        assert roots.of_statement("connects (net:4)", []) == (
            ["network flow tcp to 192.0.2.10:443"],
            [],
        )
        assert roots.of_statement("resolves net:1", []) == (["DNS query gate.example.com"], [])
        found, why = roots.of_statement("posts net:3 and proc:99", [])
        assert found == []
        assert why == [
            "net:3: no: a sandbox network item names no process, flow or query to place",
            "proc:99: no: proc:99 is not an item of this run's sandbox report",
        ]

    def test_a_sandbox_items_answer_places_its_items(self) -> None:
        answer = sandbox_tools.sandbox_items(REPORT, "network", ids=["net:4"])
        ledger = [
            _index_entry(REPORT),
            LedgerEntry(id="ev_0050", tool=ss.ITEMS_TOOL, agent="network", structured=answer),
        ]
        roots = run_roots(ledger)

        assert roots.of_statement("the flow [ev_0050]", ["ev_0050"]) == (
            ["network flow tcp to 192.0.2.10:443"],
            [],
        )
        assert roots.of_statement("net:4", [])[0] == ["network flow tcp to 192.0.2.10:443"]

    def test_a_run_with_no_index_reads_no_item_ids(self) -> None:
        roots = run_roots([LedgerEntry(id="ev_0001", tool="hashes", agent="pipeline")])
        assert roots.of_statement("as proc:84 shows", []) == (
            [],
            ["no: the statement cites no ledger entry"],
        )


@pytest.mark.parametrize("report", [REPORT, {"behavior": {}}, {}])
def test_the_index_never_raises_on_what_a_report_holds(report: dict[str, Any]) -> None:
    index = ss.section_index(report)
    assert set(index["sections"]) == set(ss.SECTION_PREFIXES)
