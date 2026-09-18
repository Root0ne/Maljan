"""Every technique surface of a report is built from one list.

The audit found the three of them disagreeing inside single runs. One report
carried ten techniques and a STIX bundle with no attack-pattern at all. Another
served three techniques from ``/mitre`` with an empty ``technique_id``, none in
``ttp_mappings``, and three attack-patterns in the bundle with no ATT&CK
reference and ids copied out of the STIX documentation. A third published a
technique the validator had already rejected as not being in the catalogue, in
the report, in the bundle and in the References section.

The list is ``ttp_mappings``: the techniques this run found, with the ids the
catalogue check accepted. The attack-patterns are minted from it with stable
ids and an ATT&CK reference, the References section is built from it, and the
``mitre_techniques`` column the API serves comes from it. An attack-pattern
with a name and no id is asked for one and, if it survives, is reported as a
behaviour — never as a technique.
"""

from __future__ import annotations

from typing import Any

from maljan.extractors.capability_matrix import build_capability_matrix, unmapped_behaviours
from maljan.pipeline.validation import MISSING_ID_CODE, validate_verdict_bundle
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport, TTPMapping
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.stix_models import Bundle

# Real, and not real: the catalogue check is asked about both.
KNOWN = "T1055"
INVENTED = "T1063"


def _attack_pattern(tid: str) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--0f1e2d3c-4b5a-4968-8776-6554433322{abs(hash(tid)) % 90 + 10}",
        "name": tid,
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
    }


def _isr(*technique_ids: str) -> dict[str, AgentISR]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim=f"the sample does what {tid} describes",
                    evidence_ref="[ev_0001] import table",
                    confidence=0.8,
                    technique_id=tid,
                )
                for tid in technique_ids
            ],
        )
    }


def _report(stix_output: dict[str, Any] | None, isr_reports: Any = None) -> MalwareReport:
    return MalwareReportBuilder(
        file_hash="c" * 64,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports=isr_reports or {},
        stix_output=stix_output or {"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Suspicious",
        overall_confidence=0.5,
        judge_assessment=None,
        malware_category=None,
        evidence_ledger=[],
    ).build_deterministic()


def _published(bundle: Bundle) -> dict[str, list[str]]:
    """Per technique id, the ATT&CK references the bundle's objects declare."""
    out: dict[str, list[str]] = {}
    for obj in bundle.objects:
        if getattr(obj, "type", "") != "attack-pattern":
            continue
        refs = [
            str(ref.get("external_id") or "")
            for ref in getattr(obj, "external_references", None) or []
        ]
        out[obj.id] = [ref for ref in refs if ref]
    return out


class TestAnIdTheCatalogueRejected:
    def test_it_stays_in_the_matrix_marked(self) -> None:
        cells, _mappings = build_capability_matrix(
            stix_output={"objects": [_attack_pattern(INVENTED)]}, isr_reports=_isr(INVENTED)
        )

        row = next(cell for cell in cells if cell.technique_id == INVENTED)
        assert row.technique_id_valid is False

    def test_it_is_not_in_the_published_list(self) -> None:
        _cells, mappings = build_capability_matrix(
            stix_output={"objects": [_attack_pattern(INVENTED), _attack_pattern(KNOWN)]},
            isr_reports=_isr(INVENTED, KNOWN),
        )

        assert [m.technique_id for m in mappings] == [KNOWN]

    def test_it_is_in_neither_the_references_nor_the_bundle(self) -> None:
        report = _report(
            {"objects": [_attack_pattern(INVENTED), _attack_pattern(KNOWN)]},
            _isr(INVENTED, KNOWN),
        )
        bundle = ExtendedSTIXRenderer().render(report)

        references = " ".join(ref.note or "" for ref in report.references)
        assert INVENTED not in references
        assert KNOWN in references
        published = [tid for refs in _published(bundle).values() for tid in refs]
        assert published == [KNOWN]


class TestTheBundleNamesWhatTheReportNames:
    def test_every_published_technique_becomes_an_attack_pattern(self) -> None:
        """The judge's fallback bundle has no attack-pattern of its own."""
        report = _report({"objects": []}, _isr(KNOWN, "T1027"))
        assert {m.technique_id for m in report.ttp_mappings} == {KNOWN, "T1027"}

        bundle = ExtendedSTIXRenderer().render(report, base_bundle=Bundle(objects=[]))

        assert {tid for refs in _published(bundle).values() for tid in refs} == {KNOWN, "T1027"}

    def test_the_object_ids_are_stable_across_exports(self) -> None:
        report = _report({"objects": []}, _isr(KNOWN))

        first = _published(ExtendedSTIXRenderer().render(report))
        second = _published(ExtendedSTIXRenderer().render(report))

        assert list(first) == list(second)
        assert all(object_id.startswith("attack-pattern--") for object_id in first)

    def test_each_one_carries_its_attack_reference(self) -> None:
        report = _report({"objects": []}, _isr(KNOWN))
        bundle = ExtendedSTIXRenderer().render(report)

        pattern = next(o for o in bundle.objects if getattr(o, "type", "") == "attack-pattern")
        reference = pattern.external_references[0]
        assert reference["source_name"] == "mitre-attack"
        assert reference["external_id"] == KNOWN
        assert reference["url"].endswith(f"/{KNOWN}/")

    def test_a_relationship_ties_it_to_the_sample(self) -> None:
        report = _report({"objects": []}, _isr(KNOWN))
        bundle = ExtendedSTIXRenderer().render(report)

        pattern = next(o for o in bundle.objects if getattr(o, "type", "") == "attack-pattern")
        assert any(
            getattr(obj, "target_ref", "") == pattern.id
            and getattr(obj, "relationship_type", "") == "uses"
            for obj in bundle.objects
        )


class TestATechniqueWithANameAndNoId:
    @staticmethod
    def _nameless() -> dict[str, Any]:
        return {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--d4e5f6a7-b8c9-4123-9efa-234567890123",
                    "name": "Obfuscated Files or Information",
                }
            ]
        }

    def test_the_judge_is_asked_for_the_id(self) -> None:
        violations = validate_verdict_bundle(Bundle.model_validate(self._nameless()))

        assert [v.code for v in violations] == [MISSING_ID_CODE]
        assert "Obfuscated Files or Information" in violations[0].message

    def test_it_is_published_as_a_behaviour_and_not_as_a_technique(self) -> None:
        report = _report(self._nameless())

        assert report.ttp_mappings == []
        assert report.unmapped_behaviours == ["Obfuscated Files or Information"]
        bundle = ExtendedSTIXRenderer().render(
            report, base_bundle=Bundle.model_validate(self._nameless())
        )
        assert _published(bundle) == {}

    def test_the_report_says_so_where_the_techniques_are(self) -> None:
        report = _report(self._nameless())

        markdown = MarkdownRenderer().render(report)

        assert "Behaviours with no mapped technique" in markdown
        assert "- Obfuscated Files or Information" in markdown

    def test_a_named_id_is_still_a_technique(self) -> None:
        """``name: "T1055"`` with no reference is an id, not a behaviour."""
        stix = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--d4e5f6a7-b8c9-4123-9efa-234567890124",
                    "name": KNOWN,
                }
            ]
        }

        assert unmapped_behaviours(stix) == []
        assert validate_verdict_bundle(Bundle.model_validate(stix)) == []


class TestWhatTheApiStores:
    @staticmethod
    def _extract(result: dict[str, Any]) -> Any:
        from app.worker.analysis_worker import _extract_mitre

        return _extract_mitre(result)

    def test_the_published_list_is_the_source(self) -> None:
        mapping = TTPMapping(technique_id=KNOWN, technique_name="Process Injection")
        rows = self._extract({"malware_report": {"ttp_mappings": [mapping.model_dump()]}})

        assert rows == [{"technique_id": KNOWN, "name": "Process Injection", "description": ""}]

    def test_a_technique_with_no_id_is_not_stored_as_one(self) -> None:
        rows = self._extract(
            {
                "malware_report": {"ttp_mappings": []},
                "stix_bundle_extended": {
                    "objects": [
                        {
                            "type": "attack-pattern",
                            "name": "Obfuscated Files or Information",
                            "external_references": [],
                        }
                    ]
                },
            }
        )

        assert rows is None
