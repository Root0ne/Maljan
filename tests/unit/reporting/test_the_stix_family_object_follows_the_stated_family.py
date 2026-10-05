"""The exported bundle holds a malware object for the family the run states.

A judge that writes its malware object for the one sample ("a loader DLL",
``is_family: false``) states that object, and it is published as written. It
is not the family: a paid run attributed the sample to a family in the
verdict and the report, and its bundle carried only the sample object, so a
consumer reading the bundle found no family at all, where an earlier run
whose judge named its object for the family had carried it. The export now
adds the object for the family the run states, with ``is_family: true``,
whenever no malware object already stands for it, and relates the judge's
sample object to it as a variant. The judge's object is never edited.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.stix_models import Bundle, Malware

FAMILY = "Examplefamily"


def _report(family: str | None = FAMILY, verdict: str = "Malware") -> MalwareReport:
    report = MalwareReportBuilder(
        file_hash="c" * 64,
        file_name="loader.dll",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision=verdict,
        overall_confidence=0.8,
        judge_assessment=None,
        malware_category="loader",
        evidence_ledger=[],
    ).build_deterministic()
    report.attribution.family = family
    report.attribution.family_source = "judge" if family else None
    return report


def _malware(bundle: Bundle) -> list[Malware]:
    return [obj for obj in bundle.objects if isinstance(obj, Malware)]


def _relationships(bundle: Bundle) -> list[Any]:
    return [obj for obj in bundle.objects if getattr(obj, "type", "") == "relationship"]


def _sample_object(**over: Any) -> Malware:
    fields: dict[str, Any] = {
        "id": "malware--b2c3d4e5-f6a7-8901-bcde-f12345678901",
        "name": "loader.dll sample",
        "malware_types": ["downloader"],
        "is_family": False,
    }
    fields.update(over)
    return Malware(**fields)


def test_a_judge_sample_object_is_kept_and_the_family_is_added_beside_it() -> None:
    judge = _sample_object()
    bundle = ExtendedSTIXRenderer().render(_report(), base_bundle=Bundle(objects=[judge]))

    by_name = {m.name: m for m in _malware(bundle)}
    assert set(by_name) == {"loader.dll sample", FAMILY}
    # The judge's object as written.
    kept = by_name["loader.dll sample"]
    assert (kept.id, kept.is_family, kept.malware_types) == (judge.id, False, ["downloader"])
    # The family's object.
    assert by_name[FAMILY].is_family is True
    variants = [r for r in _relationships(bundle) if r.relationship_type == "variant-of"]
    assert [(r.source_ref, r.target_ref) for r in variants] == [(judge.id, by_name[FAMILY].id)]


def test_a_judge_family_object_is_the_family_and_nothing_is_added() -> None:
    judge = _sample_object(name=FAMILY, is_family=True)
    bundle = ExtendedSTIXRenderer().render(_report(), base_bundle=Bundle(objects=[judge]))

    assert [(m.name, m.is_family) for m in _malware(bundle)] == [(FAMILY, True)]
    assert not [r for r in _relationships(bundle) if r.relationship_type == "variant-of"]


def test_the_family_name_is_matched_whatever_its_case() -> None:
    judge = _sample_object(name=FAMILY.upper(), is_family=True)
    bundle = ExtendedSTIXRenderer().render(_report(), base_bundle=Bundle(objects=[judge]))

    assert len(_malware(bundle)) == 1


def test_an_object_named_for_the_family_the_judge_kept_as_a_sample_is_its_answer() -> None:
    """Asked about is_family false on an object named for the family, the judge's answer stands."""
    judge = _sample_object(name=FAMILY, is_family=False)
    bundle = ExtendedSTIXRenderer().render(_report(), base_bundle=Bundle(objects=[judge]))

    assert [(m.name, m.is_family) for m in _malware(bundle)] == [(FAMILY, False)]


def test_with_no_judge_object_the_platform_s_object_stands_for_the_family() -> None:
    bundle = ExtendedSTIXRenderer().render(_report(), base_bundle=None)

    assert [(m.name, m.is_family) for m in _malware(bundle)] == [(FAMILY, True)]


def test_with_no_family_stated_nothing_is_said_to_be_a_family() -> None:
    judge = _sample_object()
    bundle = ExtendedSTIXRenderer().render(
        _report(family=None), base_bundle=Bundle(objects=[judge])
    )
    assert [(m.name, m.is_family) for m in _malware(bundle)] == [("loader.dll sample", False)]

    fallback = ExtendedSTIXRenderer().render(_report(family=None), base_bundle=None)
    assert [m.is_family for m in _malware(fallback)] == [False]


def test_a_benign_verdict_carries_no_family_object() -> None:
    bundle = ExtendedSTIXRenderer().render(_report(verdict="Benign"), base_bundle=None)

    assert _malware(bundle) == []
