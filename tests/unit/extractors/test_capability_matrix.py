"""The capability matrix is a projection, and a projection adjusts nothing.

Two properties. A technique with no confidence, no evidence and no source is
not emitted at all — it would render as a "verified" capability and seed
fabricated prose. And everything that is emitted carries the number its source
put on it: the cap this module used to apply to an obfuscation or injection
claim whose static evidence it could not find is gone, because a matrix builder
discounting an analyst's confidence is the analyst's finding rewritten by
something that read none of the evidence.
"""

from __future__ import annotations

from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _bundle(*, techniques: list[str], relationships: list[dict] | None = None) -> dict:
    objects: list[dict] = [
        {
            "type": "attack-pattern",
            "id": f"attack-pattern--{tid}",
            "name": tid,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
        }
        for tid in techniques
    ]
    objects.extend(relationships or [])
    return {"type": "bundle", "objects": objects}


def _isr(agent_id: str, *claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id=agent_id, domain=agent_id, claims=list(claims))


def _claim(technique_id: str, confidence: float = 0.8, claim: str = "it does the thing"):
    return ClaimEvidence(
        claim=claim, evidence_ref="ref", confidence=confidence, technique_id=technique_id
    )


class TestSignalQuality:
    def test_a_technique_with_no_signal_at_all_is_dropped(self) -> None:
        cells, mappings = build_capability_matrix(
            stix_output=_bundle(techniques=["T1000"]), isr_reports=None
        )

        assert cells == [] and mappings == []

    def test_a_technique_with_evidence_but_no_confidence_is_kept(self) -> None:
        cells, _ = build_capability_matrix(
            stix_output=None,
            isr_reports={"static": _isr("static", _claim("T1059", confidence=0.0))},
        )

        assert {c.technique_id for c in cells} == {"T1059"}


class TestItProjectsTheJudgeAndTheAnalysts:
    def test_the_judges_relationship_confidence_is_carried_through(self) -> None:
        bundle = _bundle(
            techniques=["T1055"],
            relationships=[
                {
                    "type": "relationship",
                    "x_maljan_technique_id": "T1055",
                    "x_maljan_confidence": 0.77,
                    "x_maljan_contributing_agents": ["static", "dynamic"],
                }
            ],
        )

        cells, mappings = build_capability_matrix(stix_output=bundle, isr_reports=None)

        assert [c.confidence for c in cells] == [0.77]
        assert cells[0].contributing_layers == ["static", "dynamic"]
        assert mappings[0].is_corroborated is True

    def test_an_analyst_claim_adds_its_own_evidence_quote(self) -> None:
        cells, _ = build_capability_matrix(
            stix_output=_bundle(techniques=["T1055"]),
            isr_reports={"static": _isr("static", _claim("T1055", 0.6, "writes into a peer"))},
        )

        assert cells[0].evidence == ["writes into a peer"]
        assert cells[0].contributing_layers == ["static"]

    def test_an_obfuscation_claim_keeps_the_confidence_the_analyst_gave_it(self) -> None:
        """The cap used to pull this to 0.40 whenever no packer was detected."""
        cells, _ = build_capability_matrix(
            stix_output=None,
            isr_reports={"static": _isr("static", _claim("T1027", 0.85))},
        )

        assert [c.confidence for c in cells] == [0.85]

    def test_an_injection_claim_is_not_discounted_either(self) -> None:
        cells, _ = build_capability_matrix(
            stix_output=None,
            isr_reports={"static": _isr("static", _claim("T1055", 0.80))},
        )

        assert [c.confidence for c in cells] == [0.80]

    def test_a_claim_whose_technique_id_failed_validation_is_left_out(self) -> None:
        isr = _isr("static", _claim("T1055", 0.9))
        isr.claims[0].technique_id_valid = False

        cells, _ = build_capability_matrix(stix_output=None, isr_reports={"static": isr})

        assert cells == []
