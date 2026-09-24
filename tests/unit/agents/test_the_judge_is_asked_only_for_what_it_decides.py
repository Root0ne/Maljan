"""The judge is asked only for what it alone decides; the platform writes what it can derive.

A reference run's judge answered with about 25,850 characters twice, both cut at
the 8,192-token output cap, and its verdict fell back to text extraction. The
answer was pretty-printed, two spaces a level, and wrote a relationship for
every attack-pattern and indicator it named — ``malware uses attack-pattern``,
``indicator indicates malware`` — each restating what its object already said
and carrying the judge's confidence, basis and credits. The platform relates
those itself now: the judge writes the three annotations on the object, and
they move onto the relationship unchanged. The contract says so and asks for
the bundle on one line; the question after a cut says how large the answer
was and what filled it.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from langchain_core.messages import AIMessage

from maljan.agents.judge_agent import (
    COMPACT_BUNDLE_RULES,
    JUDGE_VERDICT_SYSTEM,
    VERDICT_CUT_CODE,
    JudgeAgent,
    verdict_cut_violation,
)
from maljan.agents.judge_postprocess import relate_to_the_sample
from maljan.extractors.capability_matrix import _judge_relationship_rows

ASSESSMENT = {"verdict": "Malware", "confidence": 0.9}


def _compact_bundle() -> dict[str, Any]:
    return {
        "type": "bundle",
        "id": "bundle--1",
        "x_maljan_assessment": ASSESSMENT,
        "objects": [
            {"type": "malware", "id": "malware--1", "name": "sample", "is_family": False},
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Scheduled Task",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1053"}],
                "x_maljan_confidence": 0.8,
                "x_maljan_evidence_basis": "static",
                "x_maljan_contributing_agents": ["static"],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2",
                "name": "Process Injection",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1055"}],
            },
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "uses",
                "source_ref": "malware--1",
                "target_ref": "attack-pattern--2",
                "x_maljan_confidence": 0.6,
            },
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[file:hashes.'SHA-256' = '" + "a" * 64 + "']",
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "x_maljan_confidence": 1.0,
            },
        ],
    }


class TestThePlatformRelatesWhatTheJudgeDidNot:
    def test_each_unrelated_object_gets_its_relationship(self) -> None:
        data = _compact_bundle()

        minted = relate_to_the_sample(data)

        edges = [(r["relationship_type"], r["source_ref"], r["target_ref"]) for r, _ in minted]
        assert edges == [
            ("uses", "malware--1", "attack-pattern--1"),
            ("indicates", "indicator--1", "malware--1"),
        ]

    def test_the_judge_s_annotations_move_onto_it_unchanged(self) -> None:
        data = _compact_bundle()

        (uses, pattern), (indicates, indicator) = relate_to_the_sample(data)

        assert uses["x_maljan_confidence"] == 0.8
        assert uses["x_maljan_evidence_basis"] == "static"
        assert uses["x_maljan_contributing_agents"] == ["static"]
        assert "x_maljan_confidence" not in pattern
        assert indicates["x_maljan_confidence"] == 1.0
        assert "x_maljan_evidence_basis" not in indicates

    def test_a_relationship_the_judge_wrote_is_left_alone(self) -> None:
        data = _compact_bundle()

        relate_to_the_sample(data)

        written = [o for o in data["objects"] if o.get("id") == "relationship--1"]
        assert written == [
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "uses",
                "source_ref": "malware--1",
                "target_ref": "attack-pattern--2",
                "x_maljan_confidence": 0.6,
            }
        ]
        targets = [o.get("target_ref") for o in data["objects"] if o.get("type") == "relationship"]
        assert targets.count("attack-pattern--2") == 1

    def test_no_malware_object_or_two_relates_nothing(self) -> None:
        none = _compact_bundle()
        none["objects"] = [o for o in none["objects"] if o["type"] != "malware"]
        two = _compact_bundle()
        two["objects"].append({"type": "malware", "id": "malware--2", "name": "b"})

        assert relate_to_the_sample(none) == []
        assert relate_to_the_sample(two) == []


class _Llm:
    def __init__(self, *answers: AIMessage) -> None:
        self.answers = list(answers)
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> AIMessage:
        self.calls.append(list(messages))
        return self.answers.pop(0)


class TestTheVerdictRound:
    def test_a_compact_answer_is_the_verdict_and_the_judge_s_number_reaches_the_matrix(
        self,
    ) -> None:
        llm = _Llm(AIMessage(content=json.dumps(_compact_bundle())))
        judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]

        verdict = asyncio.run(
            judge.give_verdict(reports={"static": "x"}, history=[], sample={"sha256": "a" * 64})
        )

        rows = dict(_judge_relationship_rows(verdict.bundle.model_dump(mode="json")))
        assert rows == {"T1053": 0.8, "T1055": 0.6}
        assert verdict.written is not None
        assert "relationship--1" in json.dumps(verdict.written)
        assert len(llm.calls) == 1

    def test_the_contract_asks_for_no_derived_relationship_and_one_line(self) -> None:
        text = " ".join(JUDGE_VERDICT_SYSTEM.split())

        assert COMPACT_BUNDLE_RULES in JUDGE_VERDICT_SYSTEM
        assert "Write no Relationship for malware uses attack-pattern" in text
        assert "on one line without indentation" in text
        assert '{"type": "bundle", "id": "bundle--1", "x_maljan_assessment": {' in text


class TestTheQuestionAfterACut:
    def test_it_says_how_large_the_answer_was_and_what_filled_it(self) -> None:
        cut = json.dumps(
            {
                "type": "bundle",
                "objects": [
                    {"type": "attack-pattern", "id": f"attack-pattern--{i}"} for i in range(3)
                ]
                + [{"type": "relationship", "id": f"relationship--{i}"} for i in range(3)],
            },
            indent=2,
        )[:-30]

        violation = verdict_cut_violation(8192, cut)

        assert violation.code == VERDICT_CUT_CODE
        assert f"It ran to {len(cut):,} characters" in violation.message
        assert "began 3 attack-pattern, 3 relationship object(s)" in violation.message
        assert "indented lines" in violation.message
        assert "the JSON on one line without indentation" in violation.message
        assert "which the platform writes" in violation.message

    def test_without_the_text_it_still_names_the_limit(self) -> None:
        message = verdict_cut_violation(8192).message

        assert "output limit of 8192 tokens" in message
        assert "It ran to" not in message
