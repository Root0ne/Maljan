"""Every reference in an exported bundle points at something that is there.

STIX 2.1 makes ``object_refs`` required on a note and on a report, and a
required list property may not be empty; a relationship's two refs must resolve
inside the bundle or the consumer has nothing to follow. A bundle that breaks
either is rejected whole rather than in part — a conformance-checking parser or
a TAXII server throws the analysis away, not the one object.

The first Benign verdict this pipeline published would have done it. With no
malware object to be about, the summary note was emitted with
``object_refs: []``. The note is about the object that stands for the sample
instead — the indicator carrying its hash, which the cap keeps in a band of its
own so it cannot be dropped from under the reference — and where a bundle holds
nothing the note could truthfully be about, there is no note and the summary
stays in the report.

No STIX library is a dependency of this project, so the rules that matter here
are written out. They are the ones a parser rejects on, not a style guide.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import (
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkURL,
    StaticAnalysis,
    StringIOC,
)
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.judgement import INDICATOR_TYPES, indicator_type_for
from maljan.schemas.stix_models import Bundle

# The properties a STIX object carries a reference in.
_REF_FIELDS = ("source_ref", "target_ref")
_REF_LIST_FIELDS = ("object_refs",)

# The types whose reference list is required and may not be empty.
_REFS_REQUIRED = ("note", "report")


def assert_conforms(bundle: Bundle) -> None:
    """Every reference resolves, no required list is empty, every type is a type."""
    ids = {str(obj.id) for obj in bundle.objects}
    for obj in bundle.objects:
        kind = str(getattr(obj, "type", ""))
        for field in _REF_FIELDS:
            ref = getattr(obj, field, None)
            if ref is not None:
                assert str(ref) in ids, (
                    f"{kind}.{field} points at {ref}, which is not in the bundle"
                )
        for field in _REF_LIST_FIELDS:
            refs = getattr(obj, field, None)
            if refs is None:
                continue
            for ref in refs:
                assert str(ref) in ids, f"{kind}.{field} names {ref}, which is not in the bundle"
            if kind in _REFS_REQUIRED:
                assert refs, f"{kind}.{field} is empty, which STIX does not allow"
        for declared in getattr(obj, "indicator_types", None) or []:
            assert str(declared) in INDICATOR_TYPES, (
                f"{declared!r} is not a value of the indicator-type vocabulary"
            )
        assert str(getattr(obj, "spec_version", "")) == "2.1"


def _isr() -> dict[str, AgentISR]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="it hides its own code",
                    evidence_ref="[ev_0001] packer signature",
                    confidence=0.8,
                    technique_id="T1027",
                )
            ],
        )
    }


def _judge_bundle(verdict: str) -> dict[str, Any]:
    objects: list[dict[str, Any]] = [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--0f1e2d3c-4b5a-4968-8776-655443332201",
            "name": "T1027",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1027"}],
        },
        {
            "type": "relationship",
            "id": "relationship--0f1e2d3c-4b5a-4968-8776-655443332202",
            "relationship_type": "uses",
            "source_ref": "malware--0f1e2d3c-4b5a-4968-8776-655443332203",
            "target_ref": "attack-pattern--0f1e2d3c-4b5a-4968-8776-655443332201",
            "x_maljan_confidence": 0.6,
            "x_maljan_technique_id": "T1027",
        },
        {
            "type": "malware",
            "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332203",
            "name": "the sample",
            "is_family": False,
        },
    ]
    return {
        "type": "bundle",
        "objects": objects,
        "x_maljan_assessment": {
            "verdict": verdict,
            "severity": {"rating": "Medium", "rationale": "stated by the judge"},
            "confidence": 0.7,
        },
    }


def _report(verdict: str, *, summary: str, file_hash: str | None = "e" * 64) -> MalwareReport:
    report = MalwareReportBuilder(
        file_hash=file_hash,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports=_isr(),
        stix_output=_judge_bundle(verdict),
        run_summary={},
        discussion_history=[],
        final_decision=verdict,
        overall_confidence=0.7,
        judge_assessment=None,
        malware_category="loader",
        sample_platform="windows",
        sample_file_type="pe",
        evidence_ledger=[],
    ).build_deterministic()
    report.executive_summary = summary
    return report


def _render(verdict: str, **kwargs: Any) -> Bundle:
    report = _report(verdict, **kwargs)
    return ExtendedSTIXRenderer().render(
        report, base_bundle=Bundle.model_validate(_judge_bundle(verdict))
    )


def _of_type(bundle: Bundle, kind: str) -> list[Any]:
    return [obj for obj in bundle.objects if str(getattr(obj, "type", "")) == kind]


class TestEveryVerdictExportsAValidBundle:
    def test_malware(self) -> None:
        assert_conforms(_render("Malware", summary="It hollows a process."))

    def test_suspicious(self) -> None:
        assert_conforms(_render("Suspicious", summary="The run could not settle it."))

    def test_benign(self) -> None:
        assert_conforms(_render("Benign", summary="A signed utility, and nothing else."))

    def test_the_benign_note_is_about_the_sample(self) -> None:
        bundle = _render("Benign", summary="A signed utility, and nothing else.")

        note = _of_type(bundle, "note")[0]
        assert note.object_refs, "a note with no refs is not valid STIX"
        target = next(obj for obj in bundle.objects if obj.id == note.object_refs[0])
        assert target.type == "indicator"
        assert "SHA-256" in target.pattern, "the note is about the object that names the sample"

    def test_the_malware_note_is_still_about_the_malware_object(self) -> None:
        bundle = _render("Malware", summary="It hollows a process.")

        note = _of_type(bundle, "note")[0]
        target = next(obj for obj in bundle.objects if obj.id == note.object_refs[0])
        assert target.type == "malware"


class TestWhatTheSampleOwnIndicatorClaims:
    """An exported indicator is acted on; the prose around it is not.

    The sample's own hash was typed ``malicious-activity`` whatever the run
    concluded, so a Benign export told every blocklist that the sample is
    malicious activity — with the run's own note, pointed at that indicator,
    saying Benign. That is a stronger contradiction than the malware object the
    same export declines, because a consumer blocks on the indicator.
    """

    @staticmethod
    def _sample_indicator(bundle: Bundle) -> Any:
        return next(
            obj
            for obj in bundle.objects
            if str(getattr(obj, "type", "")) == "indicator" and "SHA-256" in obj.pattern
        )

    def test_the_type_follows_the_published_verdict(self) -> None:
        expected = {
            "Malware": "malicious-activity",
            "Suspicious": "anomalous-activity",
            "Benign": "benign",
        }
        for verdict, claim in expected.items():
            bundle = _render(verdict, summary="something")
            assert self._sample_indicator(bundle).indicator_types == [claim], verdict

    def test_a_verdict_the_mapping_does_not_name_claims_nothing(self) -> None:
        assert indicator_type_for("Inconclusive") == "unknown"
        assert indicator_type_for(None) == "unknown"
        assert "unknown" in INDICATOR_TYPES

    def test_the_benign_note_is_attached_to_a_benign_indicator(self) -> None:
        bundle = _render("Benign", summary="A signed utility, and nothing else.")

        note = _of_type(bundle, "note")[0]
        target = next(obj for obj in bundle.objects if obj.id == note.object_refs[0])
        assert note.abstract.startswith("Benign")
        assert target.indicator_types == ["benign"]

    def test_an_endpoint_indicator_keeps_its_own_type_under_a_benign_verdict(self) -> None:
        """A benign sample still talks to hosts, and those rows are not about it."""
        report = _report("Benign", summary="A signed utility.")
        report.network = NetworkIOCs(
            domains=[NetworkDomain(fqdn="update.example.org", source="sandbox")]
        )

        bundle = ExtendedSTIXRenderer().render(
            report, base_bundle=Bundle.model_validate(_judge_bundle("Benign"))
        )

        domain = next(
            obj
            for obj in bundle.objects
            if str(getattr(obj, "type", "")) == "indicator" and "domain-name" in obj.pattern
        )
        assert domain.indicator_types == ["anomalous-activity"]
        assert_conforms(bundle)


class TestWhenThereIsNothingToReferTo:
    def test_no_note_is_emitted_and_the_summary_stays_in_the_report(self) -> None:
        """A Benign verdict on a run with no readable hash has no sample object."""
        report = _report("Benign", summary="Nothing was found.", file_hash="not-a-hash")
        report.ttp_mappings = []
        report.capability_matrix = []

        bundle = ExtendedSTIXRenderer().render(report, base_bundle=Bundle(objects=[]))

        assert _of_type(bundle, "note") == []
        assert report.executive_summary == "Nothing was found."
        assert_conforms(bundle)

    def test_a_bundle_with_nothing_in_it_emits_no_report_object(self) -> None:
        report = _report("Benign", summary="", file_hash="not-a-hash")
        report.ttp_mappings = []
        report.capability_matrix = []

        bundle = ExtendedSTIXRenderer().render(report, base_bundle=Bundle(objects=[]))

        assert [str(obj.type) for obj in bundle.objects] == ["identity"]
        assert_conforms(bundle)


class TestTheCapLeavesNothingDangling:
    def test_a_bundle_over_the_cap_still_conforms(self) -> None:
        report = _report("Malware", summary="It hollows a process.")
        report.network = NetworkIOCs(
            domains=[
                NetworkDomain(fqdn=f"c2-{n}.example.org", source="sandbox") for n in range(20)
            ],
            urls=[
                NetworkURL(url=f"https://obs{n}.example.net/p", source="sandbox") for n in range(20)
            ],
        )
        report.static = StaticAnalysis(
            interesting_strings=[
                StringIOC(kind="path", value=f"C:\\Windows\\Temp\\stage{n}.exe", notes="")
                for n in range(10)
            ]
        )

        bundle = ExtendedSTIXRenderer().render(
            report, base_bundle=Bundle.model_validate(_judge_bundle("Malware"))
        )

        assert len(_of_type(bundle, "indicator")) == 15
        assert_conforms(bundle)
