"""The judge writes a compact bundle, and every relationship in it stays the judge's own.

A reference run's judge answered with about 25,850 characters twice, both cut at
the 8,192-token output cap, and its verdict fell back to text extraction. The
stored head of that answer is pretty-printed, two spaces a level, and its
indicators carry the confidence, basis and credits a relationship carries. The
contract now asks for the bundle on one line, those three annotations on the
relationship only, an attack-pattern with at most one sentence of description,
and no ``pattern_type`` (always ``stix``, filled in). It still asks the judge
for every relationship: which indicator indicates the sample, and which does
not, is the judge's decision, and the platform writes no edge of its own into
the judge's bundle. The question after a cut says how large the answer was and
what filled it.
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
from maljan.extractors.capability_matrix import _judge_relationship_rows

DIGEST = "a" * 64


def _compact_bundle() -> dict[str, Any]:
    """An answer written to the compact contract: annotations on the edges, no pattern_type."""
    return {
        "type": "bundle",
        "id": "bundle--1",
        "x_maljan_assessment": {"verdict": "Malware", "confidence": 0.9},
        "objects": [
            {"type": "malware", "id": "malware--1", "name": "sample", "is_family": False},
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Scheduled Task",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1053"}],
            },
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "uses",
                "source_ref": "malware--1",
                "target_ref": "attack-pattern--1",
                "x_maljan_confidence": 0.8,
                "x_maljan_evidence_basis": "static",
            },
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": f"[file:hashes.'SHA-256' = '{DIGEST}']",
                "indicator_types": ["malicious-activity"],
            },
            {
                "type": "indicator",
                "id": "indicator--2",
                "pattern": f"[file:hashes.'SHA-256' = '{DIGEST}'] AND [file:name = 'x.dll']",
                "indicator_types": ["benign"],
            },
            {
                "type": "relationship",
                "id": "relationship--2",
                "relationship_type": "indicates",
                "source_ref": "indicator--1",
                "target_ref": "malware--1",
                "x_maljan_confidence": 1.0,
            },
        ],
    }


class _Llm:
    def __init__(self, *answers: AIMessage) -> None:
        self.answers = list(answers)
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> AIMessage:
        self.calls.append(list(messages))
        return self.answers.pop(0)


def _verdict(answer: dict[str, Any]) -> tuple[Any, _Llm]:
    llm = _Llm(AIMessage(content=json.dumps(answer, separators=(",", ":"))))
    judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
    verdict = asyncio.run(
        judge.give_verdict(reports={"static": "x"}, history=[], sample={"sha256": DIGEST})
    )
    return verdict, llm


class TestACompactAnswer:
    def test_it_is_the_verdict_and_the_judge_s_number_reaches_the_matrix(self) -> None:
        verdict, llm = _verdict(_compact_bundle())

        rows = dict(_judge_relationship_rows(verdict.bundle.model_dump(mode="json")))
        assert rows == {"T1053": 0.8}
        assert len(llm.calls) == 1

    def test_an_indicator_left_unpublished_is_filled_in_as_stix(self) -> None:
        verdict, _llm = _verdict(_compact_bundle())

        kinds = [o.pattern_type for o in verdict.bundle.objects if o.type == "indicator"]
        assert kinds and set(kinds) == {"stix"}

    def test_the_platform_writes_no_relationship_of_its_own(self) -> None:
        """An indicator the judge related to nothing stays related to nothing."""
        verdict, _llm = _verdict(_compact_bundle())

        edges = [o for o in verdict.bundle.objects if o.type == "relationship"]
        assert len(edges) == 2
        written = {str(o.id) for o in verdict.bundle.objects if o.type == "indicator"}
        sources = {str(e.source_ref) for e in edges if e.relationship_type == "indicates"}
        assert len(sources) == 1 and sources < written


class TestTheContract:
    def test_it_asks_for_every_relationship_and_a_short_bundle(self) -> None:
        text = " ".join(JUDGE_VERDICT_SYSTEM.split())

        assert COMPACT_BUNDLE_RULES in JUDGE_VERDICT_SYSTEM
        assert "malware uses attack-pattern and indicator indicates malware" in text
        assert "relate an indicator only to what it indicates" in text
        assert "on the relationship only, never again on the attack-pattern or indicator" in text
        assert "leave out pattern_type" in text
        assert "on one line without indentation" in text
        assert '{"type": "bundle", "id": "bundle--1", "x_maljan_assessment": {' in text

    def test_it_does_not_say_the_platform_writes_a_relationship(self) -> None:
        assert "the platform relates" not in JUDGE_VERDICT_SYSTEM


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
        assert "on the relationship only, never repeated on the object" in violation.message
        assert "the platform writes" not in violation.message

    def test_without_the_text_it_still_names_the_limit(self) -> None:
        message = verdict_cut_violation(8192).message

        assert "output limit of 8192 tokens" in message
        assert "It ran to" not in message
