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
from maljan.analysis.evidence_roots import NO_CITATION, run_roots
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
from maljan.reporting.evidence_bundles import sandbox_item_observation
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.sandbox_report import reader_of, triage_overview_to_sandbox_report

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox"
IDENTITY = SampleIdentity(hashes=FileHashes(sha256="a" * 64))


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
        assert _process_ids(REPORT) == [
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
            "no": "no: the report lists `registry` as unavailable from its sandbox"
        }
        assert index["dropped"] == {"no": "no: the report holds none of `dropped`, `dropped_files`"}
        assert index["events"] == {"no": "no: the report holds no `behavior.generic`"}

    def test_a_triage_report_names_the_sections_its_sandbox_does_not_record(self) -> None:
        index = ss.section_index(_triage())["sections"]

        for name in ("api_calls", "registry", "events", "apistats", "screenshots"):
            assert index[name]["no"].startswith("no: the report lists ")
        assert _process_ids(_triage()) == ["proc:1000", "proc:1001"]
        assert index["network"]["items"] > 0

    def test_a_cape_process_is_named_by_its_process_id(self) -> None:
        index = ss.section_index(_cape())["sections"]

        assert _process_ids(_cape()) == ["proc:4616"]
        assert index["api_calls"]["items"] == 5

    def test_the_pack_line_states_counts_id_forms_and_reasons(self) -> None:
        entry = LedgerEntry(
            id="ev_0040",
            tool=ss.SECTIONS_TOOL,
            agent="pipeline",
            structured=ss.section_index(REPORT),
        )
        line = triage_pack.render_pack([entry], 0)

        assert line.startswith("[ev_0040] sandbox sections: `processes` 5 (proc:84, proc:90, ")
        assert "`network` 4 (net:1 to net:4)" in line
        assert "`mutexes` 1 (mutex:1)" in line
        assert "`commands` 0" in line
        assert "`registry` no: the report lists `registry` as unavailable" in line
        assert line.endswith(triage_pack.SECTIONS_SERVED_BY)


class TestItems:
    def test_every_id_the_index_states_names_the_item_the_section_lists(self) -> None:
        for report in (REPORT, _cape(), _triage()):
            found = ss.Sections(report)
            index = ss.ItemIndex.from_answer(ss.section_index(report))
            assert index is not None
            listed = [item["id"] for name in ss.SECTION_PREFIXES for item in found.items(name)]
            assert sorted(listed) == sorted(index.ids())
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

        by_pid = found.query("processes", pid="90").items
        assert [i["id"] for i in by_pid] == ["proc:90", "proc:90.2"]
        text = found.query("processes", pid="90", contains="/C Y").items
        assert [i["id"] for i in text] == ["proc:90.2"]
        flows = found.query("network", pid="84").items
        assert [i["id"] for i in flows] == ["net:4"]
        named = found.query("signatures", signature="uses task scheduler").items
        by_id = found.query("signatures", signature="sig:2").items
        assert named == by_id and [i["id"] for i in named] == ["sig:2"]

    def test_asked_ids_are_found_by_position_and_the_rest_are_named(self) -> None:
        class _NoWalk(list):  # a section read whole would iterate it
            def __iter__(self):  # type: ignore[no-untyped-def]
                raise AssertionError("the section was walked")

        report = {"behavior": {"summary": {"mutexes": _NoWalk(f"m{i}" for i in range(50_000))}}}
        found = ss.Sections(report)

        kept = found.query("mutexes", ids=["mutex:49999", "mutex:0", "net:1", "x"])
        assert [i["fields"]["value"] for i in kept.items] == ["m49998"]
        assert kept.missing == ["mutex:0", "net:1", "x"]
        assert kept.not_read == 0

    def test_a_deeply_nested_row_is_searched_without_recursion(self) -> None:
        nested: Any = "needle"
        for _ in range(50_000):
            nested = [nested]
        found = ss.Sections({"behavior": {"generic": [{"deep": nested}]}})

        kept = found.query("events", contains="NEEDLE")
        assert [i["id"] for i in kept.items] == ["event:1"]

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
        ids = _process_ids(report)
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
            "no": "no: the report lists `registry` as unavailable from its sandbox",
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


def _process_ids(report: dict[str, Any], normalised_by: Any = None) -> list[str]:
    return list(ss.Sections(report, normalised_by).sections["processes"].ids)


def _citations(report: dict[str, Any], normalised_by: Any = None) -> ss.ItemCitations:
    index = ss.ItemIndex.from_answer(ss.section_index(report, normalised_by))
    assert index is not None
    return ss.ItemCitations(index, ss.Sections(report, normalised_by))


def _index_entry(report: dict[str, Any], eid: str = "ev_0040") -> LedgerEntry:
    return LedgerEntry(
        id=eid, tool=ss.SECTIONS_TOOL, agent="pipeline", structured=ss.section_index(report)
    )


class TestCitations:
    def test_a_held_item_is_a_citation_and_an_unheld_one_is_asked_once(self) -> None:
        items = _citations(REPORT)
        prose = {"body": "Runs rundll32 [proc:84], then [proc:99] and [proc:99] [net:3]."}

        (asked,) = citation_violations(prose, ["ev_0001"], items=items)
        assert asked.code == CITATION_NOT_EVIDENCE_CODE
        assert asked.message.startswith("[proc:99] is not an item of this run's sandbox report.")
        assert citation_violations({"body": "x [proc:84]"}, ["ev_0001"], items=items) == []

    def test_an_item_whose_text_is_not_read_is_no_citation(self) -> None:
        index = ss.ItemIndex.from_answer(ss.section_index(REPORT))
        (asked,) = citation_violations({"body": "x [proc:84]"}, ["ev_0001"], items=index)
        assert "whose text this check cannot read" in asked.message
        unread = ss.ItemCitations(index, None) if index is not None else None
        (asked,) = citation_violations({"body": "x [proc:84]"}, ["ev_0001"], items=unread)
        assert "whose text this check cannot read" in asked.message

    def test_without_an_index_an_item_shaped_bracket_is_asked_as_before(self) -> None:
        (asked,) = citation_violations({"body": "x [proc:84]"}, ["ev_0001"])
        assert "is cited, and it is not an evidence id" in asked.message

    def test_an_analyst_claim_citing_a_held_item_is_grounded(self) -> None:
        index = ss.ItemIndex.from_answer(ss.section_index(REPORT))
        assert index is not None
        ids = ["ev_0001"]

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

        held = validate_isr(_claim("process proc:84"), ledger_ids=ids, items=index)
        assert not [v for v in held if v.code == UNGROUNDED_TECHNIQUE_CODE]
        (unheld,) = [
            v
            for v in validate_isr(_claim("process proc:99"), ledger_ids=ids, items=index)
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
        index = ss.ItemIndex.from_answer(ss.section_index(REPORT))
        observed = sandbox_item_observation(MalwareReport(identity=IDENTITY), index)
        assert flow_voice_violations(step, ["ev_0012"], observed_item=observed) == []
        (asked,) = flow_voice_violations(step, ["ev_0012"])
        assert "cites no sandbox entry" in asked.message
        # A network item is an observation only where the sample's tree made a flow.
        step["steps"][0]["evidence_refs"] = ["net:4"]
        assert flow_voice_violations(step, ["ev_0012"], observed_item=observed)
        reached = MalwareReport(
            identity=IDENTITY,
            network=NetworkIOCs(
                ips=[NetworkIP(address="192.0.2.10", source="sandbox", sample_process_tree=True)]
            ),
        )
        observed = sandbox_item_observation(reached, index)
        assert flow_voice_violations(step, ["ev_0012"], observed_item=observed) == []


class TestRoots:
    def test_a_process_item_s_root_is_that_process_and_a_flow_item_s_its_flow(self) -> None:
        network = sandbox_tools.sandbox_network(REPORT)
        ledger = [
            _index_entry(REPORT),
            LedgerEntry(id="ev_0041", tool="sandbox_network", agent="pipeline", structured=network),
        ]
        roots = run_roots(ledger)

        assert roots.of_statement("rundll32 runs [proc:84]", []) == (["sandbox process 84"], [])
        assert roots.of_statement("connects", ["net:4"]) == (
            ["network flow tcp to 192.0.2.10:443"],
            [],
        )
        assert roots.of_statement("resolves [net:1]", []) == (["DNS query gate.example.com"], [])
        found, why = roots.of_statement("posts [net:3, proc:99]", [])
        assert found == []
        assert why == [
            "net:3: no: a sandbox `network` item names no process, flow or query to place",
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
        assert roots.of_statement("[net:4]", [])[0] == ["network flow tcp to 192.0.2.10:443"]

    def test_a_run_with_no_index_reads_no_item_ids(self) -> None:
        roots = run_roots([LedgerEntry(id="ev_0001", tool="hashes", agent="pipeline")])
        assert roots.of_statement("as [proc:84] shows", []) == (
            [],
            ["no: the statement cites no ledger entry"],
        )


@pytest.mark.parametrize("report", [REPORT, {"behavior": {}}, {}])
def test_the_index_never_raises_on_what_a_report_holds(report: dict[str, Any]) -> None:
    index = ss.section_index(report)
    assert set(index["sections"]) == set(ss.SECTION_PREFIXES)


class TestBounds:
    """Each path is linear in the report and bounded by the section's own size.

    Timed at one size and ten times it: the larger may take at most ten times
    the smaller, with a margin for the clock, and the memory a query holds is
    measured, not guessed.
    """

    @staticmethod
    def _report(n: int) -> dict[str, Any]:
        return {
            "behavior": {
                "processes": [
                    {"pid": i, "ppid": i - 1, "process_name": "p.exe", "command_line": f"p {i}"}
                    for i in range(n)
                ],
                "summary": {"keys": [f"HKCU\\k{i}" for i in range(n)]},
            },
            "network": {"tcp": [{"dst": "192.0.2.1", "dport": i, "pid": i} for i in range(n)]},
        }

    @staticmethod
    def _seconds(call: Any) -> float:
        import time

        best = float("inf")
        for _ in range(3):
            started = time.perf_counter()
            call()
            best = min(best, time.perf_counter() - started)
        return best

    def test_reading_and_querying_grow_linearly(self) -> None:
        small, large = self._report(10_000), self._report(100_000)

        def _work(report: dict[str, Any]) -> Any:
            def run() -> None:
                found = ss.Sections(report)
                ss.section_index(report)
                found.query("registry", contains="k99")
                found.query("network", pid="77")
                found.query("processes", contains="p 5")

            return run

        assert self._seconds(_work(large)) <= 10 * self._seconds(_work(small)) * 1.5 + 0.05

    def test_a_million_asked_ids_are_read_only_to_the_section_s_size(self) -> None:
        import tracemalloc

        found = ss.Sections(self._report(1_000))
        asked = [f"net:{i}" for i in range(1_000_000)]
        tracemalloc.start()
        try:
            kept = found.query("network", ids=asked)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert len(kept.items) == 999
        assert kept.missing == ["net:0"]
        assert kept.not_read == 1_000_000 - 1_000
        # The items kept and one set of the ids read, never the million.
        assert peak < 8 * 1024 * 1024

    def test_a_pid_is_looked_up_in_an_index_built_once(self) -> None:
        found = ss.Sections(self._report(100_000))
        found.query("network", pid="5")
        index = found._pid_index["network"]
        assert found.query("network", pid="5").items[0]["id"] == "net:6"
        assert found._pid_index["network"] is index

    def test_a_ten_megabyte_command_line_is_searched_once(self) -> None:
        import tracemalloc

        line = "a" * (10 * 1024 * 1024) + "needle"
        report = {"behavior": {"processes": [{"pid": 1, "command_line": line}]}}
        found = ss.Sections(report)
        tracemalloc.start()
        try:
            kept = found.query("processes", contains="NEEDLE")
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert [i["id"] for i in kept.items] == ["proc:1"]
        # One lower-cased copy of the line at most.
        assert peak < 2.5 * len(line)

    def test_the_tool_reads_the_report_once_for_the_job(self, monkeypatch: Any) -> None:
        built: list[int] = []
        original = ss.Sections.__init__

        def _counting(self: Any, report: Any, normalised_by: Any = None) -> None:
            built.append(1)
            original(self, report, normalised_by)

        monkeypatch.setattr(ss.Sections, "__init__", _counting)
        tool = sandbox_tools.items_tool(self._report(100))
        for section in ("processes", "network", "registry"):
            tool.invoke({"section": section})
        assert built == [1]


class TestWhatTheReaderCanFill:
    """A list the provider's reader never fills is not carried; one it left empty counts 0."""

    def test_a_triage_report_states_the_lists_its_reader_never_fills(self) -> None:
        index = ss.section_index(_triage(), ("triage", "triage"))["sections"]

        for name in ("files", "mutexes", "commands", "services", "channels"):
            assert index[name] == {
                "no": f"no: the triage report as normalised here carries no `{name}`"
            }
        # The report's own statement comes first.
        assert index["registry"]["no"].startswith("no: the report lists `registry`")
        assert index["dropped"]["items"] >= 0 and "no" not in index["dropped"]
        answer = sandbox_tools.sandbox_items(
            _triage(), "mutexes", normalised_by=("triage", "triage")
        )
        assert answer == {
            "section": "mutexes",
            "no": "no: the triage report as normalised here carries no `mutexes`",
        }

    def test_a_reader_that_can_fill_a_list_and_filled_none_says_zero(self) -> None:
        report = {**_cape(), "dropped": []}
        index = ss.section_index(report, ("cape2", "cape2"))["sections"]
        assert index["dropped"] == {"items": 0, "prefix": "drop"}
        assert index["mutexes"] == {"items": 0, "prefix": "mutex"}

    def test_an_unknown_reader_reads_the_dict_as_it_stands(self) -> None:
        assert ss.section_index(_triage(), ("x", "nope")) == ss.section_index(_triage())

    def test_the_tool_holds_the_reader_the_job_names(self) -> None:
        class _Container:
            sandbox_report = _triage()
            sandbox_normalised = ("triage", "triage")

        (tool,) = [t for t in sandbox_tools.sandbox_tools(_Container()) if t.name == ss.ITEMS_TOOL]
        assert tool.invoke({"section": "files"})["no"].startswith("no: the triage report")


def _rich_cape() -> dict[str, Any]:
    from maljan.schemas.sandbox_report import _SUMMARY_KEYS

    one = [{"x": 1}]
    return {
        "behavior": {
            "processes": [{"pid": 1, "calls": [{"api": "A"}]}],
            "apistats": {"1": {"A": 1}},
            "generic": one,
            "summary": {key: ["v"] for key in (*_SUMMARY_KEYS, "keys")},
        },
        "network": {
            kind: one for kind in ("dns", "http", "tcp", "udp", "hosts", "domains", "tls", "icmp")
        },
        "signatures": [{"name": "s"}],
        "dropped": one,
        "screenshots": one,
        "file_writes": ["f"],
        "channels": {"linux.systemd": one},
    }


class TestTheReadersDeclareWhatTheyFill:
    """Each reader's declaration is what its code fills: all on a full input, no more on any."""

    def test_the_cape_reader(self) -> None:
        from maljan.schemas.sandbox_report import (
            CAPE_NORMALISER_FILLS,
            cape_report_to_sandbox_report,
            report_fills,
        )

        report = cape_report_to_sandbox_report(_rich_cape(), provider="cape2")
        assert report_fills(report) == CAPE_NORMALISER_FILLS

    def test_the_triage_reader(self) -> None:
        from maljan.schemas.sandbox_report import (
            TRIAGE_NORMALISER_FILLS,
            report_fills,
            triage_overview_to_sandbox_report,
        )

        overview = json.loads((FIXTURES / "triage_overview.json").read_text())
        task = json.loads((FIXTURES / "triage_report_behavioral1.json").read_text())
        report = triage_overview_to_sandbox_report(overview, task_reports={"b": task})
        assert report_fills(report) == TRIAGE_NORMALISER_FILLS
        # Every other block a CAPE report has, given to it too, fills nothing more.
        crowded = {**_rich_cape(), **overview}
        crowded_task = {**_rich_cape(), **task}
        more = triage_overview_to_sandbox_report(crowded, task_reports={"b": crowded_task})
        assert report_fills(more) <= TRIAGE_NORMALISER_FILLS

    def test_the_rest_mapping(self) -> None:
        from maljan.core.config import RestMappingConfig
        from maljan.providers.sandbox.rest_mapping import (
            REST_MAPPING_FILLS,
            apply_mapping,
            compile_mapping,
        )
        from maljan.schemas.sandbox_report import report_fills

        mapping = RestMappingConfig(
            processes="$.p[*]",
            calls="$.c[*]",
            signatures="$.s[*]",
            dns="$.dns[*]",
            http="$.http[*]",
            tcp="$.tcp[*]",
            udp="$.udp[*]",
            hosts="$.hosts[*]",
            domains="$.domains[*]",
            dropped_files="$.d[*]",
            registry="$.r[*]",
            channels={"linux.systemd": "$.sd[*]"},
        )
        payload = {
            "p": [{"pid": 1, "name": "a", "command_line": "a"}],
            "c": [{"pid": 1, "api": "A"}],
            "s": [{"name": "s", "description": "d", "severity": 1, "ttps": []}],
            "dns": [{"request": "a.example"}],
            "http": [{"uri": "/x", "host": "a.example"}],
            "tcp": [{"dst": "192.0.2.1", "dport": 1}],
            "udp": [{"dst": "192.0.2.1", "dport": 1}],
            "hosts": ["192.0.2.1"],
            "domains": ["a.example"],
            "d": [{"name": "f", "sha256": "a" * 64, "size": 1}],
            "r": ["HKCU\\x"],
            "sd": [{"unit": "u"}],
            **_rich_cape(),
        }
        report = apply_mapping(compile_mapping(mapping), payload, provider="rest", task_id="t")
        assert report_fills(report.report) == REST_MAPPING_FILLS

    def test_every_section_reads_fields_of_the_one_vocabulary(self) -> None:
        from maljan.schemas.sandbox_report import CAPE_RAW_BLOCKS, REPORT_LIST_FIELDS

        named = {field for fields in ss.SECTION_FIELDS.values() for field in fields}
        assert set(ss.SECTION_FIELDS) == set(ss.SECTION_PREFIXES)
        # The process tree gives parent links, not a section.
        assert named == set(REPORT_LIST_FIELDS) | set(CAPE_RAW_BLOCKS) - {ss.RAW_PROCESSTREE}


class TestReviewRoundOne:
    """Each finding of the first review, held by a test of its own."""

    def test_an_item_citation_faces_the_value_checks_an_entry_citation_faces(self) -> None:
        from maljan.pipeline.validation import (
            EntryTexts,
            identifier_citation_violations,
            stated_value_violations,
            wrong_entry_citations,
        )

        items = _citations(REPORT)
        entries = EntryTexts(
            texts={"ev_0041": "dns gate.example.com", "ev_0042": "http evil.example.org"},
            tools={},
            items=items,
        )
        made_up = {
            "identifiers": [
                {"kind": "mutex", "value": "Global\\Fabricated", "evidence_refs": ["mutex:1"]}
            ]
        }
        assert identifier_citation_violations(made_up, ["ev_0041"], items) == []
        (unheld,) = stated_value_violations(made_up, entries)
        assert "mutex:1 (sandbox report)" in unheld.message
        held = {
            "identifiers": [{"kind": "mutex", "value": "Global\\m1", "evidence_refs": ["mutex:1"]}]
        }
        assert stated_value_violations(held, entries) == []
        (wrong,) = wrong_entry_citations(
            {"body": "The sample contacts evil.example.org [net:1]."}, entries, prose=["body"]
        )
        assert "net:1 (sandbox report)" in wrong.message and "ev_0042" in wrong.message

    def test_an_item_id_is_never_read_out_of_a_host_and_port(self) -> None:
        text = "C2 at c2.example.net:443, ns.foo.net:53, a@net:2, x/net:3, y-net:4, proc:84, sig:1"
        assert ss.item_ids_in(text) == ["proc:84", "sig:1"]
        ledger = [_index_entry(REPORT)]
        roots = run_roots(ledger)
        assert roots.of_statement("beacons to cdn.example.net:4", []) == ([], [NO_CITATION])
        # A statement's own words are not read for an item; a bracket or a citing field is.
        assert roots.of_statement("runs as proc:84", []) == ([], [NO_CITATION])
        index = ss.ItemIndex.from_answer(ss.section_index(REPORT))
        isr = AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="C2 over HTTPS",
                    evidence_ref="string cdn.example.net:4 in .rdata",
                    confidence=0.8,
                    technique_id="T1071.001",
                )
            ],
        )
        codes = [v.code for v in validate_isr(isr, ledger_ids=["ev_0001"], items=index)]
        assert UNGROUNDED_TECHNIQUE_CODE in codes

    def test_a_rendered_report_s_pid_zero_is_no_pid_and_no_process_is_its_own_parent(self) -> None:
        from maljan.schemas.sandbox_report import SandboxProcess, SandboxReport

        report = to_cape_shaped_dict(
            SandboxReport(
                provider="rest",
                source_format="generic",
                processes=[
                    SandboxProcess(name="nopid"),
                    SandboxProcess(pid=7, ppid=7, name="self"),
                    SandboxProcess(pid=8, ppid=0, name="root"),
                    SandboxProcess(pid=9, ppid=8, name="child"),
                ],
            )
        )
        found = ss.Sections(report, ("rest", "generic"))
        assert [(i["id"], i.get("parent")) for i in found.items("processes")] == [
            ("proc:p1", None),
            ("proc:7", None),
            ("proc:8", None),
            ("proc:9", "proc:8"),
        ]

    def test_the_uploaded_triage_overview_fills_only_the_signatures(self) -> None:
        from maljan.core.config import Settings
        from maljan.providers.sandbox.upload import UploadSandboxProvider
        from maljan.schemas.sandbox_report import TRIAGE_OVERVIEW_FILLS, report_fills

        cfg = Settings(_env_file=None)
        cfg.sandbox.provider = "upload"
        blob = (FIXTURES / "triage_overview.json").read_bytes()
        run = UploadSandboxProvider.from_settings(cfg).attach_report(blob, filename="r.json")
        assert report_fills(run.report) == TRIAGE_OVERVIEW_FILLS
        index = ss.section_index(to_cape_shaped_dict(run.report), reader_of(run.report))["sections"]
        assert index["signatures"]["items"] > 0
        assert index["processes"] == {
            "no": "no: the upload report, read from the Triage overview alone, carries no "
            "`processes`"
        }

    def test_rest_calls_are_read_under_their_process_and_filtered_by_pid(self) -> None:
        from maljan.schemas.sandbox_report import SandboxProcess, SandboxReport

        report = to_cape_shaped_dict(
            SandboxReport(
                provider="rest",
                source_format="generic",
                processes=[
                    SandboxProcess(pid=84, name="a", calls=[{"api": "NtWriteFile"}]),
                    SandboxProcess(pid=90, ppid=84, name="b", calls=[{"api": "connect"}]),
                ],
            )
        )
        found = ss.Sections(report, ("rest", "generic"))
        kept = found.query("api_calls", pid="84").items
        assert [(i["id"], i["process"]) for i in kept] == [("call:1", "proc:84")]

    def test_a_pid_on_rows_that_name_no_process_says_so(self) -> None:
        answer = sandbox_tools.sandbox_items(REPORT, "signatures", pid=84)
        assert answer == {
            "section": "signatures",
            "no": "no: the `signatures` rows name no process",
        }
        dropped = {"dropped": [{"name": "a", "pids": [5, 6]}, {"name": "b", "pids": [7]}]}
        kept = sandbox_tools.sandbox_items(dropped, "dropped", pid="6")
        assert [i["id"] for i in kept["items"]] == ["drop:1"]

    def test_the_index_is_recorded_after_the_pack_s_budget_is_spent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents.evidence_recorder import EvidenceRecorder
        from maljan.pipeline.triage_pack import PIPELINE, CapaSettings, PackInputs, _Pack
        from maljan.schemas.evidence import EvidenceCounter

        inputs = PackInputs(
            sample_path=str(tmp_path / "s"),
            sha256="a" * 64,
            file_type="pe",
            strings_head=10,
            capa=CapaSettings(rules_dir="", signatures_dir="", timeout_s=1),
            sandbox_report=REPORT,
            budget_s=1.0,
        )
        recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
        pack = _Pack(recorder, inputs, reputation=None, function_matches=None)
        pack.steps_run = 1
        pack.started -= 100
        pack._sandbox_sections()
        (entry,) = [e for e in pack.recorder.entries if e.tool == ss.SECTIONS_TOOL]
        assert entry.ok is True

    def test_pid_takes_a_number_or_digits_and_ids_a_list_or_one_text(self) -> None:
        tool = sandbox_tools.items_tool(REPORT)
        assert tool.invoke({"section": "processes", "pid": 84})["matched"] == 1
        assert tool.invoke({"section": "processes", "pid": "84"})["matched"] == 1
        assert tool.invoke({"section": "network", "ids": "net:1, net:2"})["matched"] == 2
        assert tool.invoke({"section": "network", "ids": ["net:1"]})["matched"] == 1

    def test_ids_asked_of_an_empty_section_are_missing(self) -> None:
        kept = ss.Sections({"network": {"dns": []}}).query("network", ids=["net:1", "net:2"])
        assert (kept.missing, kept.missing_more, kept.not_read) == (["net:1"], 1, 0)

    def test_a_pid_past_the_id_pattern_gets_a_positional_id(self) -> None:
        ids = _process_ids({"behavior": {"processes": [{"pid": 10**25}]}})
        assert ids == ["proc:p1"]

    def test_an_observed_step_is_told_of_the_items_when_no_answer_recorded_anything(self) -> None:
        index = ss.ItemIndex.from_answer(ss.section_index(REPORT))
        observed = sandbox_item_observation(MalwareReport(identity=IDENTITY), index)
        step = {
            "steps": [
                {"order": 1, "action": "x", "voice": "observed", "evidence_refs": ["ev_0099"]}
            ]
        }
        (asked,) = flow_voice_violations(step, [], observed_item=observed)
        assert "the sandbox report's items are cited by their ids" in asked.message

    def test_a_network_row_s_own_attribution_decides_its_item(self) -> None:
        report = {
            "network": {
                "tcp": [
                    {"dst": "192.0.2.1", "dport": 1, "sample_process_tree": True},
                    {"dst": "192.0.2.2", "dport": 2, "sample_process_tree": False},
                    {"dst": "192.0.2.3", "dport": 3},
                ]
            }
        }
        observed = sandbox_item_observation(MalwareReport(identity=IDENTITY), _citations(report))
        assert observed is not None
        assert [observed(f"net:{n}") for n in (1, 2, 3)] == [True, False, False]

    def test_the_network_order_is_the_network_view_s(self) -> None:
        assert ss.NETWORK_KINDS == sandbox_tools.NETWORK_VIEW_KINDS

    def test_the_raw_cape_blocks_are_sections_and_the_tree_gives_parents(self) -> None:
        raw = {
            "behavior": {
                "processes": [{"process_id": 10}, {"process_id": 11}],
                "processtree": [{"pid": 10, "children": [{"pid": 11, "children": []}]}],
                "summary": {"resolved_apis": ["kernel32.dll.GetProcAddress"]},
            },
            "CAPE": {"payloads": [{"sha256": "b" * 64}], "configs": [{"Family": {"k": "v"}}]},
            "suricata": {"alerts": [{"signature": "s"}]},
            "procdump": [{"pid": 10}],
        }
        index = ss.section_index(raw, ("cape2", "cape2"))["sections"]
        assert index["cape"]["items"] == 2
        assert index["resolved_apis"]["items"] == 1
        assert index["alerts"]["items"] == 1
        assert index["procdumps"]["items"] == 1
        found = ss.Sections(raw, ("cape2", "cape2"))
        assert found.item("proc:11")["parent"] == "proc:10"
        assert [i["id"] for i in found.query("procdumps", pid="10").items] == ["dump:1"]
        rendered = ss.section_index(raw, ("upload", "cuckoo"))["sections"]
        assert rendered["cape"] == {
            "no": "no: the upload report as normalised here carries no `cape`"
        }

    def test_the_raw_blocks_are_declared_where_the_report_is_its_own_dict(self) -> None:
        from maljan.schemas.sandbox_report import (
            CAPE_RAW_BLOCKS,
            cape_report_to_sandbox_report,
            normaliser_reading,
        )

        raw = {**_rich_cape(), "CAPE": {"payloads": [{}]}, "suricata": {"alerts": [{}]}}
        raw["procdump"] = [{}]
        for fmt, held in (("cape2", True), ("mock", True), ("cuckoo", False)):
            shown = to_cape_shaped_dict(
                cape_report_to_sandbox_report(raw, provider="x", source_format=fmt)
            )
            reading = normaliser_reading(fmt, "x")
            assert reading is not None
            assert (set(CAPE_RAW_BLOCKS) <= reading.fills) is held
            assert ("CAPE" in shown and "suricata" in shown and "procdump" in shown) is held


class TestReviewRoundTwo:
    """Each finding of the second review, held by a test of its own."""

    def test_a_fetched_run_whose_task_reports_all_failed_is_read_from_its_overview(
        self,
    ) -> None:
        import httpx
        from pydantic import SecretStr

        from maljan.core.config import Settings
        from maljan.providers.sandbox.triage import TriageSandboxProvider

        overview = json.loads((FIXTURES / "triage_overview.json").read_text())

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("overview.json"):
                return httpx.Response(200, json=overview)
            return httpx.Response(404, json={"error": "NOT_FOUND"})

        cfg = Settings(_env_file=None)
        cfg.sandbox.provider = "triage"
        cfg.sandbox.triage.api_token = SecretStr("not-a-real-token")
        provider = TriageSandboxProvider.from_settings(cfg)
        provider._http = httpx.Client(
            base_url=cfg.sandbox.triage.base_url, transport=httpx.MockTransport(handler)
        )
        run = provider.fetch("260904-abcdefgh1")
        assert run.report.read_from == "overview"
        index = ss.section_index(to_cape_shaped_dict(run.report), reader_of(run.report))["sections"]
        for name in ("processes", "network", "dropped"):
            assert index[name] == {
                "no": f"no: the triage report, read from the Triage overview alone, carries "
                f"no `{name}`"
            }
        # With no behavioural task listed at all, the same.
        bare = {**overview, "tasks": {}}
        report = triage_overview_to_sandbox_report(bare, provider="triage", task_reports={})
        assert reader_of(report) == ("triage", "triage", "overview")
        # A run whose task report was read states its counts.
        assert reader_of(_triage_report())[2] == "tasks"

    def test_the_index_is_a_few_runs_for_a_hundred_thousand_processes(self) -> None:
        report = {
            "behavior": {
                "processes": [{"pid": 1000 + i} for i in range(100_000)]
                + [{"pid": 1000}, {"pid": 1000}, {"name": "x"}]
            }
        }
        index = ss.section_index(report)
        assert len(json.dumps(index)) < 4096
        known = ss.ItemIndex.from_answer(index)
        assert known is not None
        assert all(known.known(f"proc:{1000 + i}") for i in range(100_000))
        assert known.known("proc:1000.3") and not known.known("proc:1000.4")
        assert known.known("proc:p100003") and not known.known("proc:p1")
        assert not known.known("proc:999") and not known.known(f"proc:{101_000}")

    def test_the_index_is_not_blanked_by_the_byte_budget(self) -> None:
        from maljan.pipeline.triage_pack import budgeted_entries
        from maljan.schemas.evidence import apply_budget

        entries = [
            LedgerEntry(id="ev_0001", tool="strings", agent="pipeline", output="x" * 100),
            _index_entry(REPORT),
        ]
        entries[1].output = json.dumps(entries[1].structured)
        apply_budget(budgeted_entries(entries), 10)
        assert entries[0].truncated and not entries[1].truncated
        assert entries[1].structured is not None

    def test_the_report_node_reads_cited_items_through_their_rows(self) -> None:
        from maljan.pipeline.nodes import sandbox_item_citations, with_item_texts
        from maljan.pipeline.validation import EntryTexts, stated_value_violations

        class _Container:
            sandbox_normalised = None

        ledger = [_index_entry(REPORT, "ev_0001")]
        state = {"evidence_ledger": ledger, "sandbox_report": REPORT}
        items = sandbox_item_citations(state, _Container())
        assert items is not None and items.known("mutex:1")
        entries = with_item_texts(EntryTexts.from_ledger(ledger), items)
        assert entries.items is items
        row = {
            "identifiers": [{"kind": "m", "value": "Global\\Other", "evidence_refs": ["mutex:1"]}]
        }
        assert stated_value_violations(row, entries)
        assert with_item_texts(None, items) is None
        assert with_item_texts(entries, None) is entries
        assert (
            sandbox_item_citations({"evidence_ledger": [], "sandbox_report": REPORT}, None) is None
        )

    def test_an_item_s_text_is_its_row_not_the_platform_s_words(self) -> None:
        items = _citations(REPORT)
        text = items.text("mutex:1") or ""
        assert "global" in text
        for platform_word in ("mutex:1", "behavior.summary.mutexes", '"kind"', '"source"'):
            assert platform_word not in text
        assert '"parent": "proc:84"' in (items.text("proc:90") or "")

    def test_no_item_is_read_out_of_a_url_query_or_a_windows_path(self) -> None:
        for text in (
            "http://h/?a=net:4",
            "http://h/#net:4",
            "https://h/path?x=1&sig:2",
            "C:\\Users\\x\\file:3",
            "%net:4",
            "=net:4",
        ):
            assert ss.item_ids_in(text) == [], text
        assert ss.item_ids_in("(net:4) [net:5] 'net:6', net:7;") == [
            "net:4",
            "net:5",
            "net:6",
            "net:7",
        ]

    def test_a_cape_report_with_no_raw_dict_is_read_as_rendered(self) -> None:
        from maljan.schemas.sandbox_report import SandboxProcess, SandboxReport

        model = SandboxReport(
            provider="cape2",
            source_format="cape2",
            processes=[SandboxProcess(pid=0, name="a"), SandboxProcess(pid=5, ppid=0, name="b")],
        )
        assert reader_of(model) == ("cape2", "cape2", "model")
        found = ss.Sections(to_cape_shaped_dict(model), reader_of(model))
        assert [(i["id"], i.get("parent")) for i in found.items("processes")] == [
            ("proc:p1", None),
            ("proc:5", None),
        ]


def _triage_report() -> Any:
    overview = json.loads((FIXTURES / "triage_overview.json").read_text())
    task = json.loads((FIXTURES / "triage_report_behavioral1.json").read_text())
    return triage_overview_to_sandbox_report(overview, provider="triage", task_reports={"b": task})
