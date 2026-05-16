"""Smoke tests for the extended STIX 2.1 SDOs (Identity / ObservedData / Note / Report)."""

from __future__ import annotations

from datetime import UTC, datetime

from maljan.schemas.stix_models import (
    Bundle,
    Identity,
    Malware,
    Note,
    ObservedData,
    Relationship,
    Report,
)


class TestExtendedSDOs:
    def test_identity_round_trip(self) -> None:
        ident = Identity(name="Maljan", identity_class="software")
        dumped = ident.model_dump(mode="json")
        rebuilt = Identity.model_validate(dumped)
        assert rebuilt.name == "Maljan"
        assert rebuilt.identity_class == "software"
        assert rebuilt.id.startswith("identity--")

    def test_observed_data_round_trip(self) -> None:
        observed = ObservedData(
            first_observed=datetime(2025, 1, 1, tzinfo=UTC),
            last_observed=datetime(2025, 1, 1, 0, 0, 5, tzinfo=UTC),
            number_observed=1,
            objects={"0": {"type": "process", "pid": 42, "name": "rat.exe"}},
        )
        dumped = observed.model_dump(mode="json")
        rebuilt = ObservedData.model_validate(dumped)
        assert rebuilt.number_observed == 1
        assert rebuilt.objects["0"]["pid"] == 42

    def test_note_round_trip(self) -> None:
        note = Note(abstract="exec summary", content="long-form text", object_refs=["x--y"])
        dumped = note.model_dump(mode="json")
        rebuilt = Note.model_validate(dumped)
        assert rebuilt.abstract == "exec summary"
        assert rebuilt.object_refs == ["x--y"]

    def test_report_round_trip(self) -> None:
        rpt = Report(
            name="test report",
            description="hello",
            object_refs=["malware--abc"],
        )
        dumped = rpt.model_dump(mode="json")
        rebuilt = Report.model_validate(dumped)
        assert rebuilt.name == "test report"
        assert rebuilt.report_types == ["malware"]
        assert rebuilt.object_refs == ["malware--abc"]


class TestBundleAcceptsExtendedSDOs:
    def test_bundle_contains_extended_sdos(self) -> None:
        ident = Identity(name="Maljan")
        malware = Malware(name="example")
        note = Note(content="summary text", object_refs=[malware.id])
        rpt = Report(name="r", object_refs=[ident.id, malware.id, note.id])
        bundle = Bundle(objects=[ident, malware, note, rpt])
        assert [obj.type for obj in bundle.objects] == [
            "identity",
            "malware",
            "note",
            "report",
        ]

    def test_minimal_judge_bundle_still_validates(self) -> None:
        """Legacy judge bundle (only Malware + Relationship) must keep working."""
        malware = Malware(name="example")
        relationship = Relationship(
            relationship_type="uses",
            source_ref=malware.id,
            target_ref="attack-pattern--placeholder",
        )
        bundle = Bundle(objects=[malware, relationship])
        dumped = bundle.model_dump(mode="json")
        rebuilt = Bundle.model_validate(dumped)
        types = [obj.type for obj in rebuilt.objects]
        assert types == ["malware", "relationship"]
