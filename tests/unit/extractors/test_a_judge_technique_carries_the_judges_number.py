"""A technique the judge named is published with the judge's own number.

Every judge-only technique in the forty stored runs — twenty of them — was
published at confidence 0.0, although the judge's own ``uses`` relationship to
it said 0.95 in the ELF run. The matrix read a relationship's technique only
from ``x_maljan_technique_id``, a property the prompt never asks for and the
judge wrote on none of the twenty-one relationships it annotated; the number
the judge gave was dropped and a zero nobody said was printed on three
surfaces. The technique a relationship is about is the attack-pattern it
points at, and that is where it is read from now.

And the agents the judge credits are the judge's words about the evidence, not
sources that named the technique. The same ELF run credits ``STATIC ANALYST``
with T1490, which the static analyst never claimed; read as a contributing
layer, that credit would make a technique one analyst claimed look like two
agreeing sources. A technique's layers are the judge and the analysts whose own
claims name it; the credit stays on the relationship, as the judge wrote it.
"""

from __future__ import annotations

from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _pattern(tid: str) -> dict:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{tid}",
        "name": tid,
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
    }


def _uses(tid: str, confidence: float | None, agents: list[str]) -> dict:
    edge = {
        "type": "relationship",
        "id": f"relationship--{tid}",
        "relationship_type": "uses",
        "source_ref": "malware--1",
        "target_ref": f"attack-pattern--{tid}",
        "x_maljan_evidence_basis": "static",
        "x_maljan_contributing_agents": agents,
    }
    if confidence is not None:
        edge["x_maljan_confidence"] = confidence
    return edge


def _static_claims(*tids: str, confidence: float = 0.75) -> dict[str, AgentISR]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="it does the thing",
                    evidence_ref="[ev_0018]",
                    confidence=confidence,
                    technique_id=tid,
                )
                for tid in tids
            ],
        )
    }


def _bundle(*objects: dict) -> dict:
    return {"type": "bundle", "objects": [{"type": "malware", "id": "malware--1"}, *objects]}


def _mapping(mappings: list, tid: str):
    (found,) = [m for m in mappings if m.technique_id == tid]
    return found


class TestTheJudgesNumber:
    def test_a_judge_only_technique_carries_the_confidence_the_judge_gave_it(self) -> None:
        bundle = _bundle(_pattern("T1490"), _uses("T1490", 0.95, ["STATIC ANALYST"]))

        _cells, mappings = build_capability_matrix(
            stix_output=bundle, isr_reports=_static_claims("T1071")
        )

        assert _mapping(mappings, "T1490").confidence == 0.95

    def test_a_claimed_technique_carries_the_highest_number_any_source_gave(self) -> None:
        bundle = _bundle(_pattern("T1027"), _uses("T1027", 0.95, ["STATIC ANALYST"]))

        _cells, mappings = build_capability_matrix(
            stix_output=bundle, isr_reports=_static_claims("T1027", confidence=0.75)
        )

        assert _mapping(mappings, "T1027").confidence == 0.95

    def test_an_edge_with_no_number_adds_none(self) -> None:
        bundle = _bundle(_pattern("T1027"), _uses("T1027", None, []))

        _cells, mappings = build_capability_matrix(
            stix_output=bundle, isr_reports=_static_claims("T1027", confidence=0.4)
        )

        assert _mapping(mappings, "T1027").confidence == 0.4


class TestTheJudgesCreditIsNotASource:
    def test_a_credited_agent_that_claimed_nothing_is_not_a_layer(self) -> None:
        bundle = _bundle(_pattern("T1490"), _uses("T1490", 0.95, ["STATIC ANALYST"]))

        _cells, mappings = build_capability_matrix(
            stix_output=bundle, isr_reports=_static_claims("T1071")
        )

        assert _mapping(mappings, "T1490").contributing_layers == ["judge"]

    def test_one_analysts_claim_credited_by_the_judge_is_not_corroboration(self) -> None:
        bundle = _bundle(
            _pattern("T1027"), _uses("T1027", 0.95, ["STATIC ANALYST", "DYNAMIC ANALYST"])
        )

        _cells, mappings = build_capability_matrix(
            stix_output=bundle, isr_reports=_static_claims("T1027")
        )

        found = _mapping(mappings, "T1027")
        assert found.contributing_layers == ["judge", "static"]
        assert found.is_corroborated is False
