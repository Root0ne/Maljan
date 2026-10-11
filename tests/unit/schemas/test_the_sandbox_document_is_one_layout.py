"""The neutral sandbox report's document: one declared layout, cut and laid out again unchanged.

``schemas.sandbox_document`` declares where each part of the form sits, and a
source that already uses the document's arrangement is cut into its parts and
laid out again as the very same document, key for key and in order. Both are
linear in the source's size.
"""

from __future__ import annotations

import json
import time
from typing import Any

from maljan.schemas.sandbox_document import (
    CONTAINERS,
    OPEN_PLACES,
    PLACES,
    decompose,
    place,
    place_path,
    renamed,
    sandbox_document,
)
from maljan.schemas.sandbox_report import (
    CAPE_RENAMES,
    REPORT_LIST_FIELDS,
    SandboxReport,
    cape_report_to_sandbox_report,
)


def _same(a: Any, b: Any) -> bool:
    return json.dumps(a) == json.dumps(b)


class TestTheLayout:
    def test_every_part_has_its_own_place(self) -> None:
        assert len(set(PLACES.values())) == len(PLACES)

    def test_every_list_field_of_the_form_has_a_place(self) -> None:
        derived = {"processes.calls"}
        assert set(REPORT_LIST_FIELDS) - derived <= set(PLACES)

    def test_the_open_places_are_parts(self) -> None:
        assert set(OPEN_PLACES) <= set(PLACES)

    def test_a_part_s_container_is_a_declared_dict(self) -> None:
        for path in PLACES.values():
            assert path[:-1] in CONTAINERS

    def test_a_part_is_read_by_its_name(self) -> None:
        document = {"behavior": {"summary": {"keys": ["k"]}}, "ids": {"alerts": [1]}}
        assert place(document, "registry") == ["k"]
        assert place(document, "ids_alerts") == [1]
        assert place(document, "signatures", []) == []
        assert place({"behavior": ["not", "a", "dict"]}, "processes") is None
        assert place(None, "target", {}) == {}
        assert place_path("ids_alerts") == "ids.alerts"


class TestCutAndLaidOutAgain:
    def _round_trip(self, source: dict[str, Any]) -> dict[str, Any]:
        report = cape_report_to_sandbox_report(source, provider="x")
        return sandbox_document(report)

    def test_a_source_is_its_own_document(self) -> None:
        source = {
            "info": {"id": 3},
            "behavior": {
                "anomaly": [],
                "processes": [{"pid": 1, "first_seen": 1.5}],
                "summary": {"read_keys": ["r"], "keys": ["k"], "resolved_apis": ["a"]},
                "enhanced": [{"event": "x"}],
            },
            "network": {"dead_hosts": [["192.0.2.1", 80]], "dns": [], "pcap_sha256": "p"},
            "signatures": [{"name": "s", "families": ["f"], "confidence": 80}],
            "statistics": {"processing": []},
        }
        assert _same(self._round_trip(source), source)

    def test_the_renamed_blocks_keep_their_place(self) -> None:
        source = {"a": 1, "CAPE": {"payloads": []}, "b": 2, "procdump": [], "suricata": {}}
        document = self._round_trip(source)
        assert list(document) == ["a", "extracted", "b", "procdumps", "ids"]
        assert _same(document, renamed(source, CAPE_RENAMES))

    def test_a_document_word_a_source_already_uses_is_left_alone(self) -> None:
        source = {"CAPE": [1], "extracted": [2]}
        assert renamed(source, CAPE_RENAMES) == {"CAPE": [1], "extracted": [2]}
        assert _same(self._round_trip(source), source)

    def test_a_section_that_is_not_a_dict_is_kept_as_it_is(self) -> None:
        source = {"behavior": ["odd"], "network": None, "target": "t"}
        assert _same(self._round_trip(source), source)

    def test_no_value_is_copied(self) -> None:
        processes = [{"pid": 1}]
        source = {"behavior": {"processes": processes, "x": {"y": 1}}}
        published, extras, arrangement = decompose(source)
        assert published["processes"] is processes
        assert extras["behavior"]["x"] is source["behavior"]["x"]
        assert arrangement == {"": ["behavior"], "behavior": ["processes", "x"]}

    def test_an_empty_source_is_laid_out_from_the_form(self) -> None:
        document = self._round_trip({})
        assert set(document) >= {"target", "behavior", "signatures", "network", "unavailable"}

    def test_a_report_with_no_source_is_laid_out_in_the_platform_s_order(self) -> None:
        document = sandbox_document(SandboxReport(provider="p", source_format="generic"))
        assert list(document) == [
            "target",
            "behavior",
            "signatures",
            "network",
            "dropped",
            "screenshots",
            "cti",
            "ttp_tags",
            "unavailable",
            "file_writes",
        ]


class TestLinearTime:
    @staticmethod
    def _source(n: int) -> dict[str, Any]:
        return {
            **{f"block{i}": i for i in range(n)},
            "behavior": {
                "processes": [{"pid": i} for i in range(n)],
                **{f"extra{i}": i for i in range(n)},
                "summary": {f"list{i}": [i] for i in range(n)},
            },
            "network": {f"kind{i}": [] for i in range(n)},
        }

    @staticmethod
    def _seconds(source: dict[str, Any]) -> float:
        best = float("inf")
        for _ in range(3):
            started = time.perf_counter()
            sandbox_document(cape_report_to_sandbox_report(source, provider="x"))
            best = min(best, time.perf_counter() - started)
        return best

    def test_ten_times_the_keys_costs_at_most_ten_times_the_time(self) -> None:
        small, large = self._source(5_000), self._source(50_000)
        assert self._seconds(large) <= 10 * self._seconds(small) * 1.5 + 0.05
