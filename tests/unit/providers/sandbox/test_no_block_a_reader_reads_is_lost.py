"""No block a reader is given is lost: Triage's task reports, a mapped report's unnamed blocks.

A Triage task report's blocks with no place of their own reach the document as
``task.<block>`` channels and its flows and requests keep their other fields;
a report read through the JSONPath mapping keeps every top-level block no path
names as a ``report.<block>`` channel, whole, for the analyst to read. The
mapping's places are read whole, and a reader of its own declares the renames
it keeps its source's arrangement with.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from maljan.analysis import sandbox_sections as ss
from maljan.core.config import RestMappingConfig
from maljan.providers.sandbox.readers import ReportReader, required_reader
from maljan.providers.sandbox.rest_mapping import MAX_ROWS_PER_CHANNEL, unnamed_blocks
from maljan.providers.sandbox_tools import sandbox_channels, sandbox_network
from maljan.schemas.sandbox_document import sandbox_document
from maljan.schemas.sandbox_report import TASK_KEY, TASK_ROWS_KEY, SandboxReport

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "sandbox"


def _triage_document() -> dict[str, Any]:
    overview = json.loads((FIXTURES / "triage_overview.json").read_text())
    task = json.loads((FIXTURES / "triage_report_behavioral1.json").read_text())
    task = copy.deepcopy(task)
    task["signatures"] = [
        {
            "name": "task_only_signature",
            "score": 7,
            "indicators": [{"ioc": "C:\\Users\\user\\x.dll", "procid": 1000}],
        }
    ]
    task["extracted"] = [{"config": {"family": "f", "c2": ["192.0.2.9:443"]}}]
    task["network"]["listening"] = [{"port": 8080}]
    report = required_reader("triage").read(
        overview, provider="triage", task_id="s1", task_reports={"behavioral1": task}
    )
    return sandbox_document(report)


class TestATriageTaskReportKeepsItsBlocks:
    def test_the_task_s_own_blocks_are_channels_naming_the_task(self) -> None:
        document = _triage_document()
        # Held once, by reference: one row per task holding the block.
        (kept,) = document["channels"]["task.signatures"]
        assert kept[TASK_KEY] == "behavioral1" and isinstance(kept[TASK_ROWS_KEY], list)
        # Read as the block's items, each naming its task.
        assert sandbox_channels(document, "task.signatures")["rows"] == [
            {
                TASK_KEY: "behavioral1",
                "name": "task_only_signature",
                "score": 7,
                "indicators": [{"ioc": "C:\\Users\\user\\x.dll", "procid": 1000}],
            }
        ]
        assert sandbox_channels(document, "task.network.listening")["rows"] == [
            {TASK_KEY: "behavioral1", "port": 8080}
        ]
        (task,) = sandbox_channels(document, "task.task")["rows"]
        assert task[TASK_KEY] == "behavioral1" and task["kind"] == "behavioral"

    def test_what_the_task_extracted_joins_the_extracted_section(self) -> None:
        document = _triage_document()
        assert {"config": {"family": "f", "c2": ["192.0.2.9:443"]}} in document["extracted"]
        index = ss.section_index(document, ("triage", "triage", "tasks"))["sections"]
        assert index["extracted"]["items"] == 1
        assert index["channels"]["items"] >= 3

    def test_a_flow_and_a_request_keep_their_other_fields(self) -> None:
        view = sandbox_network(_triage_document())
        (tcp,) = view["tcp"]
        assert tcp["dst"] == "45.33.32.23" and tcp["dport"] == 443
        assert tcp["extra"]["domain"] == "update-relay-c9f2.net"
        assert tcp["extra"]["tls_ja3"] == "e7d705a3286e19ea42f587b344ee6865"
        (http,) = view["http"]
        assert http["extra"]["request"]["url"] == "https://update-relay-c9f2.net/gate.php"
        assert http["extra"]["flow"] == 1
        (dns,) = view["dns"]
        assert dns["request"] == "update-relay-c9f2.net" and dns["extra"] == {"flow": 2}


def _mapped(payload: dict[str, Any], mapping: RestMappingConfig) -> dict[str, Any]:
    report = required_reader("generic").read(payload, provider="upload", mapping=mapping)
    return sandbox_document(report)


class TestAMappedReportKeepsItsUnnamedBlocks:
    PAYLOAD: dict[str, Any] = {
        "run": {"procs": [{"pid": 4, "name": "a.exe", "command_line": "a.exe"}]},
        "joe": {"behavior": {"files": ["C:\\x"]}, "score": 70},
        "iocs": ["192.0.2.7", {"domain": "relay.example"}],
        "version": "2.1",
        "empty": [],
    }

    def test_every_block_no_path_names_is_a_channel_kept_whole(self) -> None:
        document = _mapped(self.PAYLOAD, RestMappingConfig(processes="$.run.procs[*]"))
        names = sandbox_channels(document)["channels"]
        assert names == ["report.iocs", "report.joe", "report.version"]
        assert sandbox_channels(document, "report.joe")["rows"] == [self.PAYLOAD["joe"]]
        # Each block as the report holds it: a list's items as they are, any
        # other value one row; nothing is wrapped or copied.
        assert document["channels"]["report.iocs"] is self.PAYLOAD["iocs"]
        assert sandbox_channels(document, "report.iocs")["rows"] == [
            "192.0.2.7",
            {"domain": "relay.example"},
        ]
        assert sandbox_channels(document, "report.version")["rows"] == ["2.1"]
        # The block a path reads is read through its channel, not kept twice.
        assert document["behavior"]["processes"][0]["process_name"] == "a.exe"
        index = ss.section_index(document, ("upload", "generic"))["sections"]
        assert index["channels"]["items"] == 4

    def test_an_empty_mapping_offers_the_whole_report(self) -> None:
        document = _mapped(self.PAYLOAD, RestMappingConfig(target_sha256=""))
        assert sandbox_channels(document)["channels"] == [
            "report.iocs",
            "report.joe",
            "report.run",
            "report.version",
        ]

    def test_a_path_that_may_start_anywhere_names_every_block(self) -> None:
        assert unnamed_blocks(RestMappingConfig(signatures="$..detections[*]"), self.PAYLOAD) == {}

    def test_bracketed_paths_name_their_block(self) -> None:
        mapping = RestMappingConfig(target_sha256="$['joe'].sha", dns='$["iocs"][*]')
        assert set(unnamed_blocks(mapping, self.PAYLOAD)) == {"report.run", "report.version"}

    def test_an_operator_s_channel_of_the_same_name_wins(self) -> None:
        mapping = RestMappingConfig(
            processes="$.run.procs[*]", channels={"report.joe": "$.run.procs[*]"}
        )
        document = _mapped(self.PAYLOAD, mapping)
        assert sandbox_channels(document, "report.joe")["rows"][0]["pid"] == 4


class TestTheMappedPlacesAreReadWhole:
    def test_a_place_keeps_every_row_past_the_channel_cap(self) -> None:
        many = MAX_ROWS_PER_CHANNEL + 7
        payload = {"apis": [f"kernel32.dll.F{i}" for i in range(many)]}
        document = _mapped(payload, RestMappingConfig(places={"resolved_apis": "$.apis[*]"}))
        assert len(document["behavior"]["summary"]["resolved_apis"]) == many

    def test_a_named_value_with_no_text_is_no_row(self) -> None:
        payload = {"apis": [{"value": "a.F"}, {"other": 1}, "", None, "b.G"]}
        document = _mapped(payload, RestMappingConfig(places={"resolved_apis": "$.apis[*]"}))
        assert document["behavior"]["summary"]["resolved_apis"] == ["a.F", "b.G"]


class _RenamingReader(ReportReader):
    id = "renaming_box"
    keeps_source_arrangement = True
    renames = {"payloads_found": "extracted"}

    def read(
        self,
        payload: dict[str, Any],
        *,
        provider: str,
        task_id: str = "",
        fmt: Any = None,
        **c: Any,
    ) -> SandboxReport:
        report = SandboxReport(provider=provider, source_format=self.id)
        return self.keep_source(report, payload)


def test_a_reader_declares_the_renames_it_keeps_its_source_with() -> None:
    source = {"info": {"id": 1}, "payloads_found": [{"sha256": "c" * 64}], "behavior": {}}
    document = sandbox_document(_RenamingReader().read(source, provider="x"))
    assert list(document) == ["info", "extracted", "behavior"]
    assert document["extracted"] is source["payloads_found"]


class TestAKeptTaskBlockIsPagedPerItem:
    """Each item of a kept block is its own row, reached by page and cited by id."""

    @staticmethod
    def _document(count: int) -> dict[str, Any]:
        task = {"signatures": [{"name": f"sig{i}", "score": i % 10} for i in range(count)]}
        report = required_reader("triage").read(
            {}, provider="triage", task_reports={"behavioral1": task}
        )
        return sandbox_document(report)

    def test_three_hundred_signatures_page_and_one_is_cited(self) -> None:
        document = self._document(300)
        first = sandbox_channels(document, "task.signatures", offset=0, limit=10)
        assert first["total"] == 300 and first["next_offset"] == 10
        assert [row["name"] for row in first["rows"]] == [f"sig{i}" for i in range(10)]
        page = sandbox_channels(document, "task.signatures", offset=290, limit=50)
        assert [row["name"] for row in page["rows"]] == [f"sig{i}" for i in range(290, 300)]
        assert all(row[TASK_KEY] == "behavioral1" for row in page["rows"])

        index = ss.section_index(document, ("triage", "triage", "tasks"))["sections"]
        channel_items = index["channels"]["items"]
        assert channel_items >= 300
        sections = ss.Sections(document, ("triage", "triage", "tasks"))
        named = [item for item in sections.items("channels") if item["kind"] == "task.signatures"]
        assert len(named) == 300
        cited = sections.item(named[249]["id"])
        assert cited is not None
        assert cited["fields"] == {TASK_KEY: "behavioral1", "name": "sig249", "score": 9}

    def test_a_page_builds_only_its_own_rows(self) -> None:
        from maljan.schemas.sandbox_document import GroupedRows

        document = self._document(100_000)
        held = document["channels"]["task.signatures"]
        # The document holds one row per task, the block by reference.
        assert len(held) == 1
        view = GroupedRows(held)
        assert len(view) == 100_000
        assert view[99_999]["name"] == "sig99999"
        assert len(view[50:53]) == 3
