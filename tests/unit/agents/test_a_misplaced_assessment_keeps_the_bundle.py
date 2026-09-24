"""One item in the wrong place does not cost the judge its whole answer.

The prompt asks for ``x_maljan_assessment`` beside ``objects``. A live run put
it inside the list instead, and ``Bundle.model_validate`` answered with
twenty-one errors — the first of them ``objects.24.Indicator.type Input should
be 'indicator' [input_value='x_maljan_assessment']`` — so all twenty-five
objects were thrown away for a verdict extracted from the answer's prose. It
happened twice in that run and once in the next.

The block is moved to the property it belongs to, unchanged, and the move is
recorded as settled: nothing is left for the judge to fix and no retry is spent
on it. Anything else the bundle cannot hold is set aside and fed back once,
because only the model can say what it meant by it. What is left is validated,
which is the other twenty-four objects and the verdict they illustrate.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import MagicMock

from maljan.agents.judge_agent import VERDICT_FALLBACK_CODE, JudgeAgent
from maljan.agents.judge_postprocess import (
    ASSESSMENT_RELOCATED_CODE,
    UNKNOWN_OBJECT_CODE,
    lift_misplaced_extensions,
)
from maljan.schemas.stix_models import Bundle

ASSESSMENT: dict[str, Any] = {
    "type": "x_maljan_assessment",
    "verdict": "Malware",
    "severity": {"rating": "High", "rationale": "it hollows a process"},
    "malware_category": "loader",
    "confidence": 0.8,
}

MALWARE_ID = "malware--0f1e2d3c-4b5a-4968-8776-655443332211"


def _stix_objects() -> list[dict[str, Any]]:
    """Twenty-four objects, in the mix the live answer carried.

    One malware object, four attack-patterns with their ``uses`` relationships,
    and fifteen indicators — twenty-five items once the assessment the model
    wrote into the list is counted, which is the count that was lost.
    """
    objects: list[dict[str, Any]] = [
        {"type": "malware", "id": MALWARE_ID, "name": "loader", "is_family": False}
    ]
    for n, tid in enumerate(("T1055", "T1497", "T1059", "T1027")):
        pattern_id = f"attack-pattern--0f1e2d3c-4b5a-4968-8776-6554433330{n:02d}"
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
                "id": f"relationship--0f1e2d3c-4b5a-4968-8776-6554433331{n:02d}",
                "relationship_type": "uses",
                "source_ref": MALWARE_ID,
                "target_ref": pattern_id,
                "x_maljan_confidence": 0.5,
                "x_maljan_technique_id": tid,
                "x_maljan_evidence_basis": "static",
            }
        )
    objects.extend(
        {
            "type": "indicator",
            "id": f"indicator--0f1e2d3c-4b5a-4968-8776-6554433332{n:02d}",
            "pattern": f"[file:name = 'stage{n}.exe']",
            "pattern_type": "stix",
        }
        for n in range(15)
    )
    return objects


def _answer(objects: list[dict[str, Any]], **top: Any) -> str:
    return json.dumps({"type": "bundle", "objects": objects, **top})


def _judge(*answers: str) -> JudgeAgent:
    queue = list(answers)

    class _Llm:
        async def ainvoke(self, turns: Any) -> Any:
            return MagicMock(content=queue.pop(0) if len(queue) > 1 else queue[0])

    judge = JudgeAgent.__new__(JudgeAgent)
    judge.llm = _Llm()
    judge.logger = MagicMock()
    judge.token_ledger = None
    judge.truncation_ledger = None
    return judge


class TestTheLiftItself:
    def test_the_block_is_moved_to_the_property_it_belongs_to(self) -> None:
        data = {"type": "bundle", "objects": [*_stix_objects(), dict(ASSESSMENT)]}

        found = lift_misplaced_extensions(data)

        assert [v.code for v in found] == [ASSESSMENT_RELOCATED_CODE]
        assert found[0].path == "x_maljan_assessment"
        assert data["x_maljan_assessment"] == ASSESSMENT
        assert len(data["objects"]) == 24

    def test_the_bundle_then_validates_with_its_objects_intact(self) -> None:
        data = {"type": "bundle", "objects": [*_stix_objects(), dict(ASSESSMENT)]}
        lift_misplaced_extensions(data)

        bundle = Bundle.model_validate(data)

        assert len(bundle.objects) == 24
        assert bundle.x_maljan_assessment is not None
        assert bundle.x_maljan_assessment.verdict == "Malware"

    def test_a_top_level_block_wins_and_the_inner_one_is_set_aside(self) -> None:
        top = {"verdict": "Suspicious", "malware_category": "unknown"}
        data = {
            "type": "bundle",
            "objects": [*_stix_objects(), dict(ASSESSMENT)],
            "x_maljan_assessment": top,
        }

        found = lift_misplaced_extensions(data)

        assert [v.code for v in found] == [UNKNOWN_OBJECT_CODE]
        assert data["x_maljan_assessment"] == top
        assert len(data["objects"]) == 24

    def test_an_object_the_bundle_cannot_hold_is_set_aside_and_named(self) -> None:
        data = {
            "type": "bundle",
            "objects": [*_stix_objects(), {"type": "course-of-action", "id": "coa--1"}],
        }

        found = lift_misplaced_extensions(data)

        assert [v.code for v in found] == [UNKNOWN_OBJECT_CODE]
        assert "course-of-action" in found[0].message
        assert found[0].path == "objects[24]"
        assert len(data["objects"]) == 24

    def test_a_bundle_with_nothing_misplaced_is_untouched(self) -> None:
        objects = _stix_objects()
        data = {"type": "bundle", "objects": list(objects)}

        assert lift_misplaced_extensions(data) == []
        assert data["objects"] == objects


class TestWhatTheRoundDoesWithIt:
    def test_the_answer_is_kept_and_no_verdict_falls_back(self) -> None:
        judge = _judge(_answer([*_stix_objects(), dict(ASSESSMENT)]))

        verdict = asyncio.run(judge.give_verdict(reports={"static": "it hollows"}, history=[]))

        assert len(verdict.bundle.objects) == 24
        assert verdict.bundle.x_maljan_fallback_verdict is None
        assert VERDICT_FALLBACK_CODE not in [v.code for v in verdict.violations]

    def test_the_assessment_is_read_from_where_it_was_moved_to(self) -> None:
        judge = _judge(_answer([*_stix_objects(), dict(ASSESSMENT)]))

        verdict = asyncio.run(judge.give_verdict(reports={"static": "it hollows"}, history=[]))

        assessment = verdict.bundle.x_maljan_assessment
        assert assessment is not None
        assert (assessment.verdict, assessment.confidence) == ("Malware", 0.8)

    def test_the_move_costs_no_retry_and_is_counted(self) -> None:
        judge = _judge(_answer([*_stix_objects(), dict(ASSESSMENT)]))

        verdict = asyncio.run(judge.give_verdict(reports={"static": "it hollows"}, history=[]))

        assert verdict.retries == 0
        assert verdict.fed_back.get(ASSESSMENT_RELOCATED_CODE) == 1
        assert ASSESSMENT_RELOCATED_CODE not in [v.code for v in verdict.violations]

    def test_a_set_aside_object_is_fed_back_once(self) -> None:
        judge = _judge(
            _answer(
                [*_stix_objects(), {"type": "course-of-action", "id": "coa--1"}],
                x_maljan_assessment={k: v for k, v in ASSESSMENT.items() if k != "type"},
            ),
            _answer(
                _stix_objects(),
                x_maljan_assessment={k: v for k, v in ASSESSMENT.items() if k != "type"},
            ),
        )

        verdict = asyncio.run(judge.give_verdict(reports={"static": "it hollows"}, history=[]))

        assert verdict.retries == 1
        assert verdict.fed_back.get(UNKNOWN_OBJECT_CODE) == 1
        assert UNKNOWN_OBJECT_CODE not in [v.code for v in verdict.violations]
