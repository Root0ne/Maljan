"""A relationship annotation outside the schema is kept and asked about.

The annotated relationship declared its confidence in 0–1 and its basis from
a list, and the bundle's object union tried it first: a relationship whose
confidence was ``1.5`` or ``95``, or whose basis was ``static+dynamic+network``,
failed that model and parsed as a plain relationship — confidence, basis,
credited agents and technique id all gone, no row written, and the credit check
blind to the agents it had carried. The annotation is the judge's; what is
wrong with it is a question the judge is asked, and the values stay as written.
"""

from __future__ import annotations

from maljan.agents.judge_postprocess import postprocess_judge_bundle
from maljan.pipeline.validation import (
    ANNOTATION_OUT_OF_SCHEMA_CODE,
    CREDIT_WITHOUT_CLAIM_CODE,
    validate_verdict_bundle,
)
from maljan.schemas.stix_models import Bundle, ConfidenceAnnotatedRelationship


def _bundle(**annotation: object) -> Bundle:
    edge = {
        "type": "relationship",
        "id": "relationship--1",
        "relationship_type": "uses",
        "source_ref": "malware--1",
        "target_ref": "attack-pattern--1",
        "x_maljan_contributing_agents": ["nobody"],
        **annotation,
    }
    answer = {
        "type": "bundle",
        "objects": [
            {"type": "malware", "id": "malware--1", "name": "x", "is_family": False},
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Inhibit System Recovery",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1490"}],
            },
            edge,
        ],
        "x_maljan_assessment": {"verdict": "Malware", "confidence": 0.9},
    }
    return Bundle.model_validate(postprocess_judge_bundle(answer))


def _codes(bundle: Bundle) -> list[str]:
    return [
        v.code
        for v in validate_verdict_bundle(bundle, {"x"}, technique_sources={"T1071": ["static"]})
    ]


class TestTheAnnotationIsKept:
    def test_a_confidence_above_one_is_kept_as_written(self) -> None:
        edge = _bundle(x_maljan_confidence=1.5).objects[2]

        assert isinstance(edge, ConfidenceAnnotatedRelationship)
        assert edge.x_maljan_confidence == 1.5
        assert edge.x_maljan_contributing_agents == ["nobody"]

    def test_a_basis_outside_the_list_is_kept_as_written(self) -> None:
        edge = _bundle(x_maljan_evidence_basis="static+dynamic+network").objects[2]

        assert isinstance(edge, ConfidenceAnnotatedRelationship)
        assert edge.x_maljan_evidence_basis == "static+dynamic+network"


class TestItIsAskedAbout:
    def test_a_confidence_outside_the_scale_is_a_question(self) -> None:
        for value in (1.5, 95, -0.1, "high"):
            assert ANNOTATION_OUT_OF_SCHEMA_CODE in _codes(_bundle(x_maljan_confidence=value)), (
                value
            )

    def test_a_basis_outside_the_list_is_a_question(self) -> None:
        assert ANNOTATION_OUT_OF_SCHEMA_CODE in _codes(
            _bundle(x_maljan_evidence_basis="static+dynamic+network")
        )

    def test_the_credit_check_still_sees_the_agents(self) -> None:
        assert CREDIT_WITHOUT_CLAIM_CODE in _codes(_bundle(x_maljan_confidence=1.5))

    def test_an_annotation_inside_the_schema_is_asked_nothing(self) -> None:
        codes = _codes(_bundle(x_maljan_confidence=0.7, x_maljan_evidence_basis="static"))

        assert ANNOTATION_OUT_OF_SCHEMA_CODE not in codes
