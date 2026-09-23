"""A relationship the platform builds names the agent that made the claim.

When the judge's answer is not a bundle, this pipeline builds one from the
analysts' claims. Every ``uses`` edge it built carried ``x_maljan_confidence:
0.5`` and ``x_maljan_evidence_basis: unknown`` and credited no agent — 53 edges
across the stored fallback runs, each publishing a 0.5 as the judge's own
number although the judge gave none, and each saying nobody contributed to a
technique an analyst had claimed. An edge the platform mints names the agents
whose claims it carries and states no number nobody gave.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from maljan.agents.judge_agent import JudgeAgent
from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _claims() -> dict[str, AgentISR]:
    def isr(agent: str, *tids: str) -> AgentISR:
        return AgentISR(
            agent_id=agent,
            domain=agent,
            claims=[
                ClaimEvidence(
                    claim=f"claim for {tid}",
                    evidence_ref="import table [ev_0003]",
                    confidence=0.3,
                    technique_id=tid,
                )
                for tid in tids
            ],
        )

    return {"static": isr("static", "T1055", "T1027"), "dynamic": isr("dynamic", "T1055")}


def _edges(bundle) -> dict[str, dict]:
    return {
        o["x_maljan_technique_id"]: o
        for o in bundle.model_dump(mode="json")["objects"]
        if o.get("type") == "relationship"
    }


class TestTheFallbackEdges:
    def test_each_edge_credits_the_agents_whose_claims_it_carries(self) -> None:
        bundle = JudgeAgent(llm=MagicMock())._fallback_bundle_from_text(
            "Verdict: Malware.", {}, _claims()
        )
        edges = _edges(bundle)

        assert edges["T1055"]["x_maljan_contributing_agents"] == ["static", "dynamic"]
        assert edges["T1027"]["x_maljan_contributing_agents"] == ["static"]

    def test_no_edge_states_a_confidence(self) -> None:
        bundle = JudgeAgent(llm=MagicMock())._fallback_bundle_from_text(
            "Verdict: Malware.", {}, _claims()
        )

        for edge in _edges(bundle).values():
            assert "x_maljan_confidence" not in edge
            assert "x_maljan_evidence_basis" not in edge

    def test_the_published_technique_carries_the_analysts_number(self) -> None:
        bundle = JudgeAgent(llm=MagicMock())._fallback_bundle_from_text(
            "Verdict: Malware.", {}, _claims()
        )

        _cells, mappings = build_capability_matrix(
            stix_output=bundle.model_dump(mode="json"), isr_reports=_claims()
        )

        assert {m.technique_id: m.confidence for m in mappings} == {"T1055": 0.3, "T1027": 0.3}

    def test_a_sub_technique_reference_points_at_its_page(self) -> None:
        claims = {
            "static": AgentISR(
                agent_id="static",
                domain="static",
                claims=[
                    ClaimEvidence(
                        claim="runs a script",
                        evidence_ref="[ev_0004]",
                        confidence=0.6,
                        technique_id="T1059.001",
                    )
                ],
            )
        }
        bundle = JudgeAgent(llm=MagicMock())._fallback_bundle_from_text(
            "Verdict: Malware.", {}, claims
        )
        (pattern,) = [
            o for o in bundle.model_dump(mode="json")["objects"] if o["type"] == "attack-pattern"
        ]

        assert pattern["external_references"][0]["url"] == (
            "https://attack.mitre.org/techniques/T1059/001/"
        )
