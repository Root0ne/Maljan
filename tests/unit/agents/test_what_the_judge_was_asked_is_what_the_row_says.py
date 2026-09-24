"""A row says the judge was asked only when it was, and a judge-only technique says why.

The reference run's judge credited "Static Analyst" with two techniques no
source had named. Its first answer ran to the output cap, so its one retry was
spent on that; the credits first appeared in the retry's answer and nobody
asked about them. The run summary still recorded them as findings the judge
had been told about, and the export's record said "the judge kept the credit
when asked". A finding the judge was never shown is recorded ``"asked":
"false"`` now, and the sentence says what happened.

The two techniques were published by the rule for a technique the judge
states — the judge's own claim, asked the catalogue and platform questions,
published with the judge as its source — and the ATT&CK row now says that is
why, rather than leaving a reader to find no analyst beside it.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from langchain_core.messages import AIMessage

from maljan.agents.judge_agent import VERDICT_CUT_CODE, JudgeAgent
from maljan.core.config import get_settings
from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.pipeline.validation import Violation, not_asked, validation_metrics
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.stix_renderer import (
    UNPUBLISHABLE_CREDIT_CODE,
    ExtendedSTIXRenderer,
)
from maljan.schemas.isr_models import JUDGE_ONLY_TECHNIQUE_MARKER, AgentISR, ClaimEvidence
from maljan.schemas.stix_models import Bundle

CREDIT = "stix.credit_without_claim"


def _uuid(index: int) -> str:
    return f"00000000-0000-4000-8000-{index:012d}"


def _credited_bundle(technique: str = "T1003") -> dict[str, Any]:
    """A closed bundle crediting an analyst with a technique no source named."""
    return {
        "type": "bundle",
        "id": f"bundle--{_uuid(99)}",
        "x_maljan_assessment": {
            "verdict": "Malware",
            "confidence": 0.9,
            "severity": {"rating": "High", "rationale": "It does harm."},
        },
        "objects": [
            {"type": "malware", "id": f"malware--{_uuid(0)}", "name": "x", "is_family": False},
            {
                "type": "attack-pattern",
                "id": f"attack-pattern--{_uuid(1)}",
                "name": "OS Credential Dumping",
                "external_references": [{"source_name": "mitre-attack", "external_id": technique}],
            },
            {
                "type": "relationship",
                "id": f"relationship--{_uuid(2)}",
                "relationship_type": "uses",
                "source_ref": f"malware--{_uuid(0)}",
                "target_ref": f"attack-pattern--{_uuid(1)}",
                "x_maljan_confidence": 0.9,
                "x_maljan_evidence_basis": "static",
                "x_maljan_contributing_agents": ["Static Analyst"],
            },
        ],
    }


def _answer(text: str, *, tokens: int) -> AIMessage:
    return AIMessage(
        content=text,
        usage_metadata={
            "input_tokens": 1000,
            "output_tokens": tokens,
            "total_tokens": 1000 + tokens,
        },
    )


class _Llm:
    def __init__(self, *answers: AIMessage) -> None:
        self.answers = list(answers)
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> AIMessage:
        self.calls.append(list(messages))
        return self.answers.pop(0)


async def _verdict(*answers: AIMessage) -> list[Violation]:
    judge = JudgeAgent(llm=_Llm(*answers))  # type: ignore[arg-type]
    verdict = await judge.give_verdict(
        reports={"static": "It reads the host name."},
        history=[],
        technique_sources={"T1082": ["static"]},
    )
    return list(verdict.violations)


class TestWhatTheRecordSays:
    def test_a_finding_first_raised_by_the_retry_s_answer_is_not_asked(self) -> None:
        shown = [Violation(code=VERDICT_CUT_CODE, message="cut")]
        left = [Violation(code=CREDIT, message="the relationship at objects[46] credits x")]

        (row,) = not_asked(left, shown)

        assert row.asked is False
        assert row.to_dict()["asked"] == "false"

    def test_the_same_question_about_a_renumbered_object_was_asked(self) -> None:
        shown = [
            Violation(code=CREDIT, message="the relationship at objects[3] 'relationship--2' x")
        ]
        left = [
            Violation(code=CREDIT, message="the relationship at objects[7] 'relationship--9' x")
        ]

        (row,) = not_asked(left, shown)

        assert row.asked is True
        assert "asked" not in row.to_dict()

    def test_the_run_summary_row_carries_it(self) -> None:
        unasked = Violation(code=CREDIT, message="m", asked=False)

        (row,) = validation_metrics(1, [("judge", unasked)])["unresolved"]

        assert row["asked"] == "false"


class TestTheJudgesRound:
    @pytest.mark.asyncio
    async def test_a_credit_the_retry_raised_first_is_recorded_as_not_asked(self) -> None:
        cap = int(get_settings().llm.judge_max_tokens)
        cut = json.dumps(_credited_bundle())[:-40]

        found = await _verdict(
            _answer(cut, tokens=cap), _answer(json.dumps(_credited_bundle()), tokens=900)
        )

        (credit,) = [v for v in found if v.code == CREDIT]
        assert credit.asked is False

    @pytest.mark.asyncio
    async def test_a_credit_asked_about_and_kept_is_recorded_as_asked(self) -> None:
        whole = json.dumps(_credited_bundle())

        found = await _verdict(_answer(whole, tokens=900), _answer(whole, tokens=900))

        (credit,) = [v for v in found if v.code == CREDIT]
        assert credit.asked is True


def _export(asked: bool) -> list[str]:
    """The export's record for the kept credit, with the run summary saying whether it was asked."""
    row = {"agent": "judge", "code": CREDIT, "message": "credits 'Static Analyst' with T1003"}
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64)),
        verdict="Malware",
        run_summary={"validation": {"unresolved": [row if asked else {**row, "asked": "false"}]}},
    )
    renderer = ExtendedSTIXRenderer()
    renderer.render(
        report,
        Bundle.model_validate(_credited_bundle()),
        technique_sources={"T1082": ["static"]},
    )
    return [why for code, why in renderer.declined if code == UNPUBLISHABLE_CREDIT_CODE]


class TestTheExportsSentence:
    def test_it_says_the_judge_was_not_asked_when_it_was_not(self) -> None:
        (sentence,) = _export(asked=False)

        assert "the judge was not asked about it" in sentence
        assert "when asked" not in sentence

    def test_it_says_the_judge_kept_it_when_asked_when_it_was(self) -> None:
        (sentence,) = _export(asked=True)

        assert "the judge kept the credit when asked" in sentence


class TestAJudgeOnlyTechniqueSaysWhyItIsPublished:
    def test_a_technique_only_the_judge_named_carries_the_rule(self) -> None:
        cells, mappings = build_capability_matrix(stix_output=_credited_bundle(), isr_reports=None)

        (cell,) = [c for c in cells if c.technique_id == "T1003"]
        assert cell.note == JUDGE_ONLY_TECHNIQUE_MARKER
        assert not cell.not_published
        assert "T1003" in [m.technique_id for m in mappings]

    def test_one_an_analyst_also_claimed_carries_no_note(self) -> None:
        claimed = {
            "static": AgentISR(
                agent_id="static",
                domain="static",
                claims=[
                    ClaimEvidence(
                        claim="It reads credentials out of process memory.",
                        evidence_ref="[ev_0001]",
                        confidence=0.8,
                        technique_id="T1003",
                    )
                ],
            )
        }

        cells, _mappings = build_capability_matrix(
            stix_output=_credited_bundle(), isr_reports=claimed
        )

        (cell,) = [c for c in cells if c.technique_id == "T1003"]
        assert cell.note == ""
