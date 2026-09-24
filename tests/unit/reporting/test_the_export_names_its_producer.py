"""The export states who produced it, in STIX's own words.

Every one of the forty stored exports carried an identity for this platform
typed ``identity_class: "software"`` and a report typed ``"malware-analysis"``;
neither word is in its vocabulary (``software`` is not an identity class and
``malware-analysis`` is an object type, not a report type), so the OASIS
validator warned on both in every run. And nothing in any of them named the
identity: no object carried ``created_by_ref``, so the one object saying who
produced the bundle was attached to nothing, under a new random id every run.
These are facts the platform states about itself; they are stated right now.
"""

from __future__ import annotations

import pytest

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.judgement import JudgeAssessment
from maljan.schemas.stix_models import Bundle, Identity, Indicator, Malware, Report


def _report(verdict: str = "Malware") -> MalwareReport:
    report = MalwareReportBuilder(
        file_hash="c" * 64,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision=verdict,
        overall_confidence=0.9,
        judge_assessment=None,
        malware_category="loader",
        evidence_ledger=[],
    ).build_deterministic()
    report.executive_summary = "A loader."
    return report


def _judge_bundle() -> Bundle:
    return Bundle(
        objects=[
            Malware(name="sample"),
            Indicator(
                name="C2",
                pattern="[ipv4-addr:value = '82.157.13.47']",
                indicator_types=["malicious-activity"],
            ),
        ],
        x_maljan_assessment=JudgeAssessment(verdict="Malware", confidence=0.9),
    )


def _identity(bundle: Bundle) -> Identity:
    (identity,) = [o for o in bundle.objects if isinstance(o, Identity)]
    return identity


class TestTheVocabularies:
    def test_the_platform_is_a_system(self) -> None:
        bundle = ExtendedSTIXRenderer().render(_report(), _judge_bundle())

        assert _identity(bundle).identity_class == "system"

    def test_the_report_is_about_malware(self) -> None:
        bundle = ExtendedSTIXRenderer().render(_report(), _judge_bundle())

        (report,) = [o for o in bundle.objects if isinstance(o, Report)]
        assert report.report_types == ["malware"]

    @pytest.mark.parametrize("verdict", ["Benign", "Suspicious"])
    def test_a_report_whose_verdict_is_not_malware_is_not_typed_malware(self, verdict: str) -> None:
        """A Benign export went out as a characterization of a malware instance."""
        bundle = ExtendedSTIXRenderer().render(_report(verdict), None)

        (report,) = [o for o in bundle.objects if isinstance(o, Report)]
        assert report.report_types == ["threat-report"]


class TestEveryObjectNamesItsProducer:
    def test_the_identity_has_one_id_across_exports(self) -> None:
        first = _identity(ExtendedSTIXRenderer().render(_report(), _judge_bundle()))
        second = _identity(ExtendedSTIXRenderer().render(_report("Benign"), None))

        assert first.id == second.id

    def test_every_other_object_names_the_identity(self) -> None:
        bundle = ExtendedSTIXRenderer().render(_report(), _judge_bundle())
        producer = _identity(bundle).id

        others = [o for o in bundle.objects if not isinstance(o, Identity)]
        assert others
        assert {o.type: o.created_by_ref for o in others} == {o.type: producer for o in others}

    def test_the_dump_carries_it(self) -> None:
        dumped = ExtendedSTIXRenderer().render(_report(), _judge_bundle()).model_dump(mode="json")
        producer = next(o["id"] for o in dumped["objects"] if o["type"] == "identity")

        assert all(
            o.get("created_by_ref") == producer
            for o in dumped["objects"]
            if o["type"] != "identity"
        )

    def test_the_judges_own_bundle_is_not_edited(self) -> None:
        base = _judge_bundle()
        ExtendedSTIXRenderer().render(_report(), base)

        assert all(getattr(o, "created_by_ref", None) is None for o in base.objects)

    def test_a_producer_the_bundle_does_not_hold_is_not_published(self) -> None:
        base = _judge_bundle()
        base.objects[0] = base.objects[0].model_copy(
            update={"created_by_ref": "identity--00000000-0000-4000-8000-000000000000"}
        )
        bundle = ExtendedSTIXRenderer().render(_report(), base)
        present = {o.id for o in bundle.objects}

        assert all(
            o.created_by_ref in present for o in bundle.objects if not isinstance(o, Identity)
        )
