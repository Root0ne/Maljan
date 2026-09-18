"""Rebuilding the published techniques keeps the judge's own annotations.

The attack-patterns of the exported bundle are minted from the validated
technique list, so the report and the bundle name the same techniques. The
judge's `uses` relationships point at the objects the judge minted, and those
objects are gone — so unless the refs are moved with them, the integrity pass
prunes every one of them as dangling and the export loses the confidence, the
evidence basis and the contributing agents the judge put on each technique.

They are model output. They are re-linked to the rebuilt attack-pattern of the
same technique id and carried verbatim; a relationship to a technique the
checks rejected goes with that technique, and the run summary says so.
"""

from __future__ import annotations

from typing import Any

from maljan.agents.judge_postprocess import enforce_bundle_integrity
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.stix_models import Bundle, ConfidenceAnnotatedRelationship

KNOWN = "T1055"
INVENTED = "T1063"
MALWARE_ID = "malware--0f1e2d3c-4b5a-4968-8776-655443332211"


def _judge_bundle(*technique_ids: str) -> dict[str, Any]:
    objects: list[dict[str, Any]] = [
        {
            "type": "malware",
            "id": MALWARE_ID,
            "name": "analyzed-sample",
            "is_family": False,
        }
    ]
    for index, tid in enumerate(technique_ids):
        pattern_id = f"attack-pattern--d4e5f6a7-b8c9-4123-9efa-2345678901{index:02d}"
        objects.append(
            {
                "type": "attack-pattern",
                "id": pattern_id,
                "name": tid,
                "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
            }
        )
        objects.append(
            {
                "type": "relationship",
                "id": f"relationship--d4e5f6a7-b8c9-4123-9efa-2345678902{index:02d}",
                "relationship_type": "uses",
                "source_ref": MALWARE_ID,
                "target_ref": pattern_id,
                "x_maljan_confidence": 0.82,
                "x_maljan_evidence_basis": "static",
                "x_maljan_contributing_agents": ["static", "dynamic"],
                "x_maljan_technique_id": tid,
            }
        )
    return {"type": "bundle", "objects": objects}


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


def _report(stix_output: dict[str, Any], isr_reports: Any = None) -> MalwareReport:
    return MalwareReportBuilder(
        file_hash="c" * 64,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports=isr_reports or {},
        stix_output=stix_output,
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.8,
        judge_assessment=None,
        malware_category=None,
        evidence_ledger=[],
    ).build_deterministic()


def _annotated(bundle: Bundle) -> list[ConfidenceAnnotatedRelationship]:
    return [obj for obj in bundle.objects if isinstance(obj, ConfidenceAnnotatedRelationship)]


def _technique_of(bundle: Bundle, relationship: Any) -> str:
    """The ATT&CK id of the object a relationship points at."""
    for obj in bundle.objects:
        if getattr(obj, "id", "") != relationship.target_ref:
            continue
        for ref in getattr(obj, "external_references", None) or []:
            if ref.get("external_id"):
                return str(ref["external_id"])
    return ""


class TestARelationshipToASurvivingTechnique:
    def test_it_is_still_in_the_bundle(self) -> None:
        stix = _judge_bundle(KNOWN)
        report = _report(stix, _isr(KNOWN))

        bundle = ExtendedSTIXRenderer().render(report, Bundle.model_validate(stix))

        assert len(_annotated(bundle)) == 1

    def test_it_points_at_the_rebuilt_attack_pattern(self) -> None:
        stix = _judge_bundle(KNOWN)
        report = _report(stix, _isr(KNOWN))

        bundle = ExtendedSTIXRenderer().render(report, Bundle.model_validate(stix))

        (annotated,) = _annotated(bundle)
        assert _technique_of(bundle, annotated) == KNOWN
        # The judge's own object is gone; the ref moved with the technique.
        assert annotated.target_ref not in {
            obj["id"] for obj in stix["objects"] if obj["type"] == "attack-pattern"
        }

    def test_the_judge_numbers_are_carried_verbatim(self) -> None:
        stix = _judge_bundle(KNOWN)
        report = _report(stix, _isr(KNOWN))

        bundle = ExtendedSTIXRenderer().render(report, Bundle.model_validate(stix))

        (annotated,) = _annotated(bundle)
        assert annotated.x_maljan_confidence == 0.82
        assert annotated.x_maljan_evidence_basis == "static"
        assert annotated.x_maljan_contributing_agents == ["static", "dynamic"]
        assert annotated.x_maljan_technique_id == KNOWN

    def test_the_count_survives_the_integrity_pass(self) -> None:
        """The pass is where they were being lost, so it is asked directly."""
        stix = _judge_bundle(KNOWN, "T1027")
        report = _report(stix, _isr(KNOWN, "T1027"))

        bundle = ExtendedSTIXRenderer().render(report, Bundle.model_validate(stix))
        before = len(_annotated(bundle))
        after = len(_annotated(Bundle(objects=enforce_bundle_integrity(list(bundle.objects)))))

        assert before == 2
        assert after == before

    def test_the_technique_is_not_related_twice(self) -> None:
        stix = _judge_bundle(KNOWN)
        report = _report(stix, _isr(KNOWN))

        bundle = ExtendedSTIXRenderer().render(report, Bundle.model_validate(stix))

        uses = [
            obj
            for obj in bundle.objects
            if getattr(obj, "relationship_type", "") == "uses"
            and getattr(obj, "source_ref", "") == MALWARE_ID
        ]
        assert len(uses) == 1


class TestARelationshipToATechniqueThatWasDropped:
    def test_it_goes_with_the_technique(self) -> None:
        stix = _judge_bundle(KNOWN, INVENTED)
        report = _report(stix, _isr(KNOWN, INVENTED))
        assert [m.technique_id for m in report.ttp_mappings] == [KNOWN]

        bundle = ExtendedSTIXRenderer().render(report, Bundle.model_validate(stix))

        assert [_technique_of(bundle, rel) for rel in _annotated(bundle)] == [KNOWN]

    def test_the_run_summary_is_told_what_went(self) -> None:
        stix = _judge_bundle(KNOWN, INVENTED)
        report = _report(stix, _isr(KNOWN, INVENTED))
        renderer = ExtendedSTIXRenderer()

        renderer.render(report, Bundle.model_validate(stix))

        assert renderer.unlinked == [(INVENTED, 1)]

    def test_the_row_names_the_technique_and_the_count(self) -> None:
        from maljan.pipeline.nodes import _note_unlinked_techniques

        stix = _judge_bundle(KNOWN, INVENTED)
        report = _report(stix, _isr(KNOWN, INVENTED))

        _note_unlinked_techniques(report, [(INVENTED, 2)])

        validation = report.run_summary["validation"]
        assert validation["by_code"]["stix.unlinked_technique"] == 1
        (row,) = validation["unresolved"]
        assert row["agent"] == "judge"
        assert INVENTED in row["message"]
        assert "2 judge relationship(s)" in row["message"]


class TestTheFallbackBundleKeepsThemToo:
    @staticmethod
    def _fallback() -> Bundle:
        from unittest.mock import MagicMock

        from maljan.agents.judge_agent import JudgeAgent

        judge = JudgeAgent(llm=MagicMock())
        return judge._fallback_bundle_from_text("This is malware.", {}, _isr(KNOWN))

    def test_its_annotated_relationship_survives_the_rebuild(self) -> None:
        base = self._fallback()
        report = _report(base.model_dump(mode="json"), _isr(KNOWN))

        bundle = ExtendedSTIXRenderer().render(report, base)
        after = Bundle(objects=enforce_bundle_integrity(list(bundle.objects)))

        assert len(_annotated(base)) == 1
        assert len(_annotated(bundle)) == 1
        assert len(_annotated(after)) == 1
        assert _technique_of(after, _annotated(after)[0]) == KNOWN
