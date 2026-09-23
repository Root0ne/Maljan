"""A judge relationship that credits an agent with a technique it never named is asked about.

The ELF run's bundle published ``malware uses T1490`` with
``x_maljan_contributing_agents: ["STATIC ANALYST"]``, and the same credit on
T1048.001; the static analyst claimed neither, and no tool named either. The
relationships were the judge's own — the platform mints no annotation — and
nothing asked about them, although the run knows exactly who named which
technique: it is the evidence summary the judge was shown.

The credit is the judge's to give, so nothing rewrites it. The judge is told,
once, which sources did name the technique, by the names the evidence summary
gives them, and what it answers is published.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

from maljan.agents.judge_agent import JudgeAgent
from maljan.pipeline.validation import CREDIT_WITHOUT_CLAIM_CODE, validate_verdict_bundle
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.judgement import JudgeAssessment
from maljan.schemas.stix_models import (
    AttackPattern,
    Bundle,
    ConfidenceAnnotatedRelationship,
    Malware,
)

SOURCES = {"T1071": ["static"], "T1027": ["static", "capa"]}


def _bundle(tid: str, agents: list[str], relationship_type: str = "uses") -> Bundle:
    malware = Malware(name="sample")
    pattern = AttackPattern(
        name=tid,
        external_references=[{"source_name": "mitre-attack", "external_id": tid}],
    )
    edge = ConfidenceAnnotatedRelationship(
        relationship_type=relationship_type,
        source_ref=malware.id,
        target_ref=pattern.id,
        x_maljan_confidence=0.95,
        x_maljan_evidence_basis="static",
        x_maljan_contributing_agents=agents,
    )
    return Bundle(
        objects=[malware, pattern, edge],
        x_maljan_assessment=JudgeAssessment(verdict="Malware", confidence=0.95),
    )


def _rows(bundle: Bundle, sources: dict[str, list[str]] | None = SOURCES) -> list:
    return [
        v
        for v in validate_verdict_bundle(bundle, {"x"}, technique_sources=sources)
        if v.code == CREDIT_WITHOUT_CLAIM_CODE
    ]


class TestTheQuestion:
    def test_a_credit_for_a_technique_nobody_named_is_asked_about(self) -> None:
        (row,) = _rows(_bundle("T1490", ["STATIC ANALYST"]))

        assert "'STATIC ANALYST'" in row.message
        assert "T1490" in row.message
        assert "no source in this run named T1490" in row.message
        assert row.path == "objects[2]"

    def test_the_sentence_names_the_sources_that_did(self) -> None:
        (row,) = _rows(_bundle("T1027", ["DYNAMIC ANALYST"]))

        assert "static, capa" in row.message

    def test_a_credit_to_a_source_that_named_it_is_asked_nothing(self) -> None:
        for agents in (["STATIC ANALYST", "capa"], ["static_analyst"], ["Static-Analyst"]):
            assert _rows(_bundle("T1027", agents)) == [], agents

    def test_a_sub_technique_of_a_named_technique_is_asked_nothing(self) -> None:
        assert _rows(_bundle("T1071.004", ["STATIC ANALYST"])) == []

    def test_no_record_of_the_sources_asks_nothing(self) -> None:
        assert _rows(_bundle("T1490", ["STATIC ANALYST"]), sources=None) == []

    def test_an_edge_that_is_not_about_a_technique_is_asked_nothing(self) -> None:
        bundle = _bundle("T1490", ["STATIC ANALYST"])
        bundle.objects[2] = bundle.objects[2].model_copy(
            update={"target_ref": bundle.objects[0].id, "source_ref": bundle.objects[0].id}
        )

        assert _rows(bundle) == []

    def test_nothing_is_rewritten(self) -> None:
        bundle = _bundle("T1490", ["STATIC ANALYST"])
        _rows(bundle)

        assert bundle.objects[2].x_maljan_contributing_agents == ["STATIC ANALYST"]


def _judge(answer: str) -> Any:
    judge = JudgeAgent.__new__(JudgeAgent)
    judge.logger = MagicMock()
    judge.tools = []
    judge.token_ledger = None
    judge.truncation_ledger = None
    judge._config = None
    judge.evidence_counter = None
    judge._evidence_entries = []
    judge._definition_tool_refs = lambda: []  # type: ignore[method-assign]

    class _Model:
        async def ainvoke(self, messages: Any) -> Any:
            return MagicMock(content=answer)

    judge.llm = _Model()
    return judge


_ANSWER = (
    '{"type": "bundle", "objects": ['
    '{"type": "malware", "id": "malware--1", "name": "sample", "is_family": false},'
    '{"type": "attack-pattern", "id": "attack-pattern--1", "name": "Inhibit System Recovery",'
    ' "external_references": [{"source_name": "mitre-attack", "external_id": "T1490"}]},'
    '{"type": "relationship", "id": "relationship--1", "relationship_type": "uses",'
    ' "source_ref": "malware--1", "target_ref": "attack-pattern--1",'
    ' "x_maljan_confidence": 0.95, "x_maljan_evidence_basis": "static",'
    ' "x_maljan_contributing_agents": ["STATIC ANALYST"]}],'
    ' "x_maljan_assessment": {"verdict": "Malware", "confidence": 0.95,'
    ' "severity": {"rating": "High", "rationale": "a reverse shell"}}}'
)


def test_the_judge_is_asked_in_its_own_round() -> None:
    claims = {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="reverse shell",
                    evidence_ref="ev_0018",
                    confidence=0.95,
                    technique_id="T1071",
                )
            ],
        )
    }
    verdict = asyncio.run(
        _judge(_ANSWER).give_verdict(
            reports={"static": "a reverse shell"},
            history=[],
            isr_reports=claims,
            evidence_corpus={"x"},
            ledger_ids=["ev_0018"],
            technique_sources={"T1071": ["static"]},
        )
    )

    assert verdict.fed_back.get(CREDIT_WITHOUT_CLAIM_CODE) == 1
    assert CREDIT_WITHOUT_CLAIM_CODE in [v.code for v in verdict.violations]
