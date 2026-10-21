"""ATT&CK's own mitigations, detection data and a Navigator layer, per published technique.

All of it is read from the cached ATT&CK bundles and the report's stored
published list: no model call, nothing from a draft, revoked and deprecated
objects skipped.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.v1.reports import get_attack_navigator_layer
from app.services.report_service import ReportService
from maljan.memory import attck_defense, attck_loader
from maljan.reporting.builder import attck_defense_rows
from maljan.reporting.models import TTPMapping
from maljan.reporting.navigator_layer import build_layer, support_score
from maljan.reporting.renderers.markdown import MarkdownRenderer
from tests.unit.reporting._report_shapes import rich_report


def _ref(external_id: str) -> list[dict[str, str]]:
    return [{"source_name": "mitre-attack", "external_id": external_id}]


def _rel(source: str, kind: str, target: str, **extra: object) -> dict:
    return {
        "type": "relationship",
        "id": f"relationship--{source}-{target}",
        "relationship_type": kind,
        "source_ref": source,
        "target_ref": target,
        **extra,
    }


def _object(kind: str, stix_id: str, external_id: str = "", **fields: object) -> dict:
    obj: dict = {"type": kind, "id": stix_id, **fields}
    if external_id:
        obj["external_references"] = _ref(external_id)
    return obj


BUNDLE = {
    "objects": [
        {"type": "x-mitre-collection", "x_mitre_version": "20.0"},
        _object("attack-pattern", "ap-1", "T1055"),
        _object("attack-pattern", "ap-2", "T1003"),
        _object("attack-pattern", "ap-old", "T1999", revoked=True),
        _object("course-of-action", "m-1", "M1040", name="Behavior Prevention"),
        _object("course-of-action", "m-dep", "M1000", name="Gone", x_mitre_deprecated=True),
        _object("course-of-action", "m-2", "M1047", name="Audit"),
        _object(
            "x-mitre-detection-strategy",
            "ds-1",
            "DET0001",
            name="Injection strategy",
            x_mitre_analytic_refs=["an-1", "an-2"],
        ),
        _object(
            "x-mitre-analytic",
            "an-1",
            x_mitre_log_source_references=[{"x_mitre_data_component_ref": "dc-1"}],
        ),
        _object(
            "x-mitre-analytic",
            "an-2",
            x_mitre_log_source_references=[
                {"x_mitre_data_component_ref": "dc-1"},
                {"x_mitre_data_component_ref": "dc-gone"},
            ],
        ),
        _object("x-mitre-data-component", "dc-1", "DC0035", name="Process Access"),
        _object("x-mitre-data-component", "dc-gone", "DC0001", name="Gone", revoked=True),
        _object("x-mitre-data-component", "dc-2", "DC0032", name="Process Creation"),
        _rel(
            "m-1",
            "mitigates",
            "ap-1",
            description="Use <code>EDR</code> rules (Citation: Vendor 2020) to block [it](https://x.example/a).",
        ),
        _rel("m-dep", "mitigates", "ap-1"),
        _rel("m-2", "mitigates", "ap-2", description="Audit it."),
        _rel("m-2", "mitigates", "ap-old"),
        _rel("m-2", "mitigates", "ap-2", description="a retired duplicate", revoked=True),
        _rel("ds-1", "detects", "ap-1"),
        _rel("dc-2", "detects", "ap-2"),
        _rel("ap-1", "uses", "ap-2"),
    ]
}


class TestTheIndex:
    def test_mitigations_carry_the_relationships_own_cleaned_sentence(self) -> None:
        index = attck_defense.index_bundle(BUNDLE)

        assert [(m.attck_id, m.text) for m in index["T1055"].mitigations] == [
            ("M1040", "Use EDR rules to block it.")
        ]
        assert [(m.attck_id, m.text) for m in index["T1003"].mitigations] == [
            ("M1047", "Audit it.")
        ]

    def test_a_strategy_reaches_its_data_components_through_its_analytics_once(self) -> None:
        defense = attck_defense.index_bundle(BUNDLE)["T1055"]

        assert [s.attck_id for s in defense.detection_strategies] == ["DET0001"]
        assert [c.attck_id for c in defense.data_components] == ["DC0035"]

    def test_a_data_component_joined_directly_is_read_too(self) -> None:
        defense = attck_defense.index_bundle(BUNDLE)["T1003"]

        assert [c.attck_id for c in defense.data_components] == ["DC0032"]

    def test_revoked_and_deprecated_objects_and_relationships_are_skipped(self) -> None:
        index = attck_defense.index_bundle(BUNDLE)

        assert "T1999" not in index
        assert all(m.attck_id != "M1000" for m in index["T1055"].mitigations)
        assert len(index["T1003"].mitigations) == 1


class TestTheCachedBundle:
    @pytest.fixture
    def cached(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
        file = tmp_path / "enterprise-attack.json"
        file.write_text(json.dumps(BUNDLE), encoding="utf-8")
        monkeypatch.setattr(
            attck_loader,
            "ATTCK_CACHE_FILES",
            {
                "enterprise": file,
                "mobile": tmp_path / "mobile-attack.json",
                "ics": tmp_path / "ics-attack.json",
            },
        )
        monkeypatch.setattr(attck_loader, "domain_of", lambda tid: "enterprise")
        attck_defense.reset_caches()
        yield
        attck_defense.reset_caches()

    def test_only_the_asked_techniques_with_something_listed_are_answered(
        self, cached: None
    ) -> None:
        found = attck_defense.defense_for(["t1055", "T1000"])

        assert set(found) == {"T1055"}
        assert attck_defense.release_for(["T1055"]) == "20.0"
        assert attck_defense.cached_version("enterprise") == "20.0"

    def test_no_cached_bundle_answers_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            attck_loader,
            "ATTCK_CACHE_FILES",
            {d: tmp_path / f"{d}.json" for d in attck_loader.DOMAINS},
        )
        monkeypatch.setattr(attck_loader, "domain_of", lambda tid: "enterprise")
        attck_defense.reset_caches()

        assert attck_defense.defense_for(["T1055"]) == {}

    def test_the_rows_cite_the_techniques_own_evidence_ids(self, cached: None) -> None:
        mapping = TTPMapping(
            technique_id="T1055", technique_name="Process Injection", sources=["ev_0003", "ev_0007"]
        )

        (row,) = attck_defense_rows([mapping])

        assert row.evidence_ids == ["ev_0003", "ev_0007"]
        assert [m.attck_id for m in row.mitigations] == ["M1040"]

    def test_the_report_prints_both_sections_and_the_rest_is_unchanged(self, cached: None) -> None:
        report = rich_report()
        report.attck_defense = []
        before = MarkdownRenderer().render(report)
        assert "ATT&CK detection data" not in before
        assert "ATT&CK mitigations" not in before

        report.attck_defense = attck_defense_rows(
            [
                TTPMapping(
                    technique_id="T1055", technique_name="Process Injection", sources=["ev_0003"]
                )
            ]
        )
        report.attck_defense_version = attck_defense.release_for(["T1055"])
        after = MarkdownRenderer().render(report)

        assert "### 10.4 ATT&CK detection data" in after
        assert "DET0001 Injection strategy" in after
        assert "DC0035 Process Access" in after
        assert "M1040 Behavior Prevention" in after
        assert "Use EDR rules to block it." in after
        assert "x.example" not in after
        assert "(ATT&CK 20.0)" in after
        assert "ev_0003" in after.split("ATT&CK mitigations", 1)[1]
        kept = set(after.splitlines())
        assert all(line in kept for line in before.splitlines())


class TestTheNavigatorLayer:
    MR = {
        "ttp_mappings": [
            {
                "technique_id": "T1055",
                "support": "",
                "is_corroborated": True,
                "sources": ["ev_0001", "ev_0002"],
                "independent_sources": 2,
                "confidence": 0.9,
            },
            {
                "technique_id": "T1003",
                "support": "capability",
                "is_corroborated": False,
                "sources": ["ev_0003"],
            },
            {"technique_id": "T1204", "support": "unobserved", "sources": []},
            {
                "technique_id": "T1566",
                "support": "",
                "is_corroborated": False,
                "sources": ["ev_0004"],
            },
        ]
    }

    def test_score_follows_the_reports_own_support(self) -> None:
        scores = {m["technique_id"]: support_score(m) for m in self.MR["ttp_mappings"]}

        assert scores == {"T1055": 100, "T1003": 50, "T1204": 25, "T1566": 75}

    def test_the_layer_names_published_techniques_with_their_evidence_ids(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(attck_loader, "domain_of", lambda tid: "enterprise")

        layer = build_layer(self.MR, name="r")

        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["layer"] == "4.5"
        assert layer["versions"]["attack"].isdigit()
        by_id = {t["techniqueID"]: t for t in layer["techniques"]}
        assert set(by_id) == {"T1055", "T1003", "T1204", "T1566"}
        assert by_id["T1055"]["comment"] == "ev_0001, ev_0002"
        assert by_id["T1055"]["score"] == 100
        assert by_id["T1055"]["color"] != by_id["T1204"]["color"]
        assert by_id["T1204"]["comment"] == ""

    def test_a_technique_of_another_domain_is_named_not_dropped_silently(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            attck_loader, "domain_of", lambda tid: "mobile" if tid == "T1204" else "enterprise"
        )

        layer = build_layer(self.MR)

        assert "T1204" not in {t["techniqueID"] for t in layer["techniques"]}
        assert "T1204" in layer["description"]
        assert build_layer(self.MR, domain="mobile")["domain"] == "mobile-attack"

    def test_a_mapping_that_records_no_support_is_not_scored_as_behaviour(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(attck_loader, "domain_of", lambda tid: "enterprise")
        old = {"technique_id": "T1055", "support": "", "sources": [], "source_kinds": {}}

        assert support_score(old) is None
        (entry,) = build_layer({"ttp_mappings": [old]})["techniques"]
        assert "score" not in entry and "color" not in entry
        assert entry["metadata"] == [{"name": "support", "value": "not recorded"}]

    def test_the_layer_hides_nothing_and_opens_subtechniques_of_unpublished_parents(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(attck_loader, "domain_of", lambda tid: "enterprise")

        layer = build_layer(self.MR)

        assert "filters" not in layer
        assert layer["layout"]["expandedSubtechniques"] == "annotated"

    def test_no_published_technique_is_an_empty_layer(self) -> None:
        assert build_layer({})["techniques"] == []

    @pytest.mark.asyncio
    async def test_the_route_reads_the_stored_report_through_the_ownership_check(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(attck_loader, "domain_of", lambda tid: "enterprise")
        svc = ReportService(db=AsyncMock())
        svc.get_malware_report = AsyncMock(return_value=self.MR)  # type: ignore[method-assign]
        user = MagicMock(id=uuid.uuid4())
        report_id = uuid.uuid4()

        layer = await get_attack_navigator_layer(report_id, None, user, svc)

        svc.get_malware_report.assert_awaited_once_with(report_id, user)
        assert len(layer["techniques"]) == 4

        svc.get_malware_report = AsyncMock(return_value=None)  # type: ignore[method-assign]
        with pytest.raises(Exception) as missing:  # noqa: PT011 — HTTPException
            await get_attack_navigator_layer(report_id, None, user, svc)
        assert getattr(missing.value, "status_code", None) == 404
