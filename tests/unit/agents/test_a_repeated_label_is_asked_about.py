"""A label the judge gives to two objects is a question, never a choice.

The prompt invites short labels (``indicator--1``), and a short label is easy
to write twice. The id pass kept the first object a label named and rewired
every reference onto it: two indicators both labelled ``indicator--1``, each
with its own ``indicates`` edge at 0.9 and 0.4, came out with both edges on the
first indicator, and the integrity pass then folded the 0.4 edge away as a
duplicate — the judge's statement about the second indicator gone, and the
second indicator orphaned. Now neither object is chosen: the judge is asked
which it meant, and no reference naming the label is rewired onto either.

Feedback also names the judge's own positions. The bundle the checks read has
lost what the post-processor set aside or folded, so ``objects[1]`` there was
not the judge's ``objects[1]``; paths now carry the judge's position and the
label it wrote.
"""

from __future__ import annotations

import asyncio
import copy
from typing import Any
from unittest.mock import MagicMock

from maljan.agents.judge_agent import JudgeAgent
from maljan.agents.judge_postprocess import (
    DUPLICATE_LABEL_CODE,
    duplicate_label_violations,
    postprocess_judge_bundle,
)
from maljan.pipeline.validation import Violation, drop_ungrounded_indicators
from maljan.schemas.stix_models import Bundle, Indicator


def _answer() -> dict:
    return {
        "type": "bundle",
        "objects": [
            {"type": "malware", "id": "malware--1", "name": "x", "is_family": False},
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[ipv4-addr:value = '82.157.13.47']",
                "pattern_type": "stix",
            },
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[domain-name:value = 'gate.example.org']",
                "pattern_type": "stix",
            },
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "indicates",
                "source_ref": "indicator--1",
                "target_ref": "malware--1",
                "x_maljan_confidence": 0.9,
            },
            {
                "type": "relationship",
                "id": "relationship--2",
                "relationship_type": "indicates",
                "source_ref": "indicator--1",
                "target_ref": "malware--1",
                "x_maljan_confidence": 0.4,
            },
        ],
    }


class TestTheQuestion:
    def test_it_names_both_objects_and_the_label(self) -> None:
        (row,) = duplicate_label_violations(_answer())

        assert row.code == DUPLICATE_LABEL_CODE
        assert "objects[1]" in row.message and "objects[2]" in row.message
        assert "'indicator--1'" in row.message

    def test_a_bundle_with_distinct_labels_raises_nothing(self) -> None:
        answer = _answer()
        answer["objects"][2]["id"] = "indicator--2"

        assert duplicate_label_violations(answer) == []


class TestNothingIsChosen:
    def test_no_reference_is_rewired_onto_either_object(self) -> None:
        out = postprocess_judge_bundle(_answer())
        indicators = {o["id"] for o in out["objects"] if o["type"] == "indicator"}
        edges = [o for o in out["objects"] if o["type"] == "relationship"]

        assert len(indicators) == 2
        assert not [e for e in edges if e["source_ref"] in indicators]

    def test_the_label_map_holds_only_labels_that_name_one_object(self) -> None:
        labels: dict[str, str] = {}
        out = postprocess_judge_bundle(_answer(), labels=labels)

        assert "indicator--1" not in labels
        (malware,) = [o for o in out["objects"] if o["type"] == "malware"]
        assert labels["malware--1"] == malware["id"]


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


def _verdict(answer: dict) -> Any:
    import json

    answer = copy.deepcopy(answer)
    answer["x_maljan_assessment"] = {
        "verdict": "Malware",
        "confidence": 0.9,
        "severity": {"rating": "High", "rationale": "a loader"},
    }
    return asyncio.run(
        _judge(json.dumps(answer)).give_verdict(
            reports={"static": "a loader"},
            history=[],
            evidence_corpus={"82.157.13.47", "gate.example.org"},
            ledger_ids=["ev_0001"],
        )
    )


class TestTheJudgesOwnRound:
    def test_the_judge_is_asked_about_the_repeat(self) -> None:
        verdict = _verdict(_answer())

        assert verdict.fed_back.get(DUPLICATE_LABEL_CODE) == 1

    def test_a_path_names_the_judges_own_position_and_label(self) -> None:
        answer = {
            "type": "bundle",
            "objects": [
                {"type": "sighting", "id": "sighting--1"},
                {"type": "malware", "id": "malware--7", "name": "x"},
            ],
        }
        verdict = _verdict(answer)

        (row,) = [v for v in verdict.violations if v.code == "stix.is_family_missing"]
        assert row.path == "objects[1] 'malware--7'"

    def test_the_verdict_carries_the_label_map(self) -> None:
        answer = _answer()
        answer["objects"][2]["id"] = "indicator--2"
        verdict = _verdict(answer)

        published = {getattr(o, "id", "") for o in verdict.bundle.objects}
        assert set(verdict.labels) >= {"malware--1", "indicator--1", "indicator--2"}
        # Every object the judge's bundle kept is found from a label; a label
        # whose object the integrity pass folded maps to an id nothing holds.
        assert published <= set(verdict.labels.values())


def test_a_drop_follows_the_judges_positions_back_to_the_bundle() -> None:
    first = Indicator(pattern="[url:value = 'http://a.example.org/']")
    second = Indicator(pattern="[url:value = 'http://b.example.org/']")
    bundle = Bundle(objects=[first, second])
    # The judge wrote a set-aside object at 0, so its 2 is the bundle's 1.
    origins = [(1, "indicator--1"), (2, "indicator--2")]

    dropped = drop_ungrounded_indicators(
        bundle,
        [Violation(code="stix.ungrounded_indicator", message="m", path="objects[2] 'x'")],
        origins=origins,
    )

    assert dropped == 1
    assert [o.id for o in bundle.objects] == [first.id]
