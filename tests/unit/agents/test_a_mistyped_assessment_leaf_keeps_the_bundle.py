"""One badly typed assessment leaf does not cost the judge its whole answer.

``x_maljan_assessment`` was validated as part of the Bundle, so a confidence
of 85 where 0..1 is asked, a family written as a bare name, a severity written
as a bare rating or an ``evidence_ids`` written as one string failed the whole
model, and every STIX object the judge wrote went down the text fallback with
it. ``stated_assessment_in`` failed the same way and dropped the whole stated
assessment.

The assessment is read apart from the objects now, leaf by leaf. A leaf whose
reading is unambiguous — a list of one where one value is asked, a string where
a list is asked, a bare value where an object with one required field is asked,
an enumerated word in another case — is read so, and the reading is recorded as
settled. A leaf that cannot be read is left absent and the judge is asked about
it once (``verdict.assessment_unreadable``); a number is never guessed. Every
object is kept.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.agents.judge_agent import (
    VERDICT_FALLBACK_CODE,
    JudgeAgent,
    stated_assessment_in,
)
from maljan.agents.judge_postprocess import (
    ASSESSMENT_READ_LOOSELY_CODE,
    ASSESSMENT_UNREADABLE_CODE,
    ASSESSMENT_UNREADABLE_REASON,
    read_judge_assessment,
)
from maljan.schemas.judgement import JudgeAssessment, read_assessment

MALWARE_ID = "malware--0f1e2d3c-4b5a-4968-8776-655443332211"


def _objects() -> list[dict[str, Any]]:
    return [
        {"type": "malware", "id": MALWARE_ID, "name": "loader", "is_family": False},
        *(
            {
                "type": "indicator",
                "id": f"indicator--0f1e2d3c-4b5a-4968-8776-6554433332{n:02d}",
                "pattern": f"[file:name = 'stage{n}.exe']",
                "pattern_type": "stix",
            }
            for n in range(5)
        ),
    ]


def _good() -> dict[str, Any]:
    return {
        "verdict": "Malware",
        "severity": {"rating": "High", "rationale": "it hollows a process"},
        "malware_category": "loader",
        "family": {"name": "AsyncRAT", "confidence": 0.7, "evidence_ids": ["ev_0001"]},
        "confidence": 0.8,
    }


def _with(**leaves: Any) -> dict[str, Any]:
    out = _good()
    out.update(leaves)
    return out


def _with_family(**leaves: Any) -> dict[str, Any]:
    out = _good()
    out["family"] = {**out["family"], **leaves}
    return out


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


def _answer(assessment: Any) -> str:
    return json.dumps({"type": "bundle", "objects": _objects(), "x_maljan_assessment": assessment})


# The seven shapes, each with what is read and what is recorded.
SHAPES: list[tuple[str, dict[str, Any], str, Any, str]] = [
    # (name, assessment, attribute path, expected value, code recorded). The
    # row is on the attribute; a ">" marks a bare value read into an object,
    # whose row is on the object (the part before it).
    ("confidence 85", _with(confidence=85), "confidence", None, ASSESSMENT_UNREADABLE_CODE),
    (
        "family as a bare name",
        _with(family="AsyncRAT"),
        "family>name",
        "AsyncRAT",
        ASSESSMENT_READ_LOOSELY_CODE,
    ),
    (
        "severity as a bare rating",
        _with(severity="High"),
        "severity>rating",
        "High",
        ASSESSMENT_READ_LOOSELY_CODE,
    ),
    (
        "severity in another case",
        _with(severity={"rating": "high", "rationale": "r"}),
        "severity.rating",
        "High",
        ASSESSMENT_READ_LOOSELY_CODE,
    ),
    (
        "evidence_ids as a string",
        _with_family(evidence_ids="ev_0001"),
        "family.evidence_ids",
        ["ev_0001"],
        ASSESSMENT_READ_LOOSELY_CODE,
    ),
    (
        "family confidence 85",
        _with_family(confidence=85),
        "family.confidence",
        None,
        ASSESSMENT_UNREADABLE_CODE,
    ),
    (
        "category as a list of one",
        _with(malware_category=["ransomware"]),
        "malware_category",
        "ransomware",
        ASSESSMENT_READ_LOOSELY_CODE,
    ),
]


def _noted(path: str) -> str:
    return path.split(">")[0]


def _at(assessment: Any, path: str) -> Any:
    for part in path.replace(">", ".").split("."):
        assessment = getattr(assessment, part)
    return assessment


class TestTheReader:
    @pytest.mark.parametrize(
        ("assessment", "path", "expected", "code"),
        [shape[1:] for shape in SHAPES],
        ids=[shape[0] for shape in SHAPES],
    )
    def test_each_shape_is_read_or_left_absent(
        self, assessment: dict[str, Any], path: str, expected: Any, code: str
    ) -> None:
        read, notes = read_assessment(assessment)

        assert read is not None
        assert read.verdict == "Malware"
        assert _at(read, path) == expected
        assert [n.path for n in notes] == [_noted(path)]
        assert notes[0].readable is (code == ASSESSMENT_READ_LOOSELY_CODE)

    def test_a_well_typed_assessment_reads_as_the_schema_reads_it(self) -> None:
        read, notes = read_assessment(_good())

        assert notes == []
        assert read == JudgeAssessment.model_validate(_good())
        assert read is not None
        assert read.model_fields_set == JudgeAssessment.model_validate(_good()).model_fields_set

    def test_a_number_is_never_guessed(self) -> None:
        read, notes = read_assessment(_with(confidence=85))

        assert read is not None and read.confidence is None
        assert notes[0].written == 85
        assert not notes[0].readable

    def test_a_severity_with_an_unreadable_rating_is_absent_whole(self) -> None:
        read, notes = read_assessment(_with(severity={"rating": 3, "rationale": "r"}))

        assert read is not None and read.severity is None
        assert any(n.path == "severity" and not n.readable for n in notes)

    def test_an_assessment_that_is_not_an_object_reads_as_nothing(self) -> None:
        read, notes = read_assessment("Malware")

        assert read is None
        assert [(n.path, n.readable) for n in notes] == [("", False)]

    @pytest.mark.parametrize(
        "written", ["ev_0001, ev_0002", "ev_0001;ev_0002", "ev_0001 ev_0002", "ev_0001\tev_0002"]
    )
    def test_a_string_with_a_separator_is_not_one_id(self, written: str) -> None:
        read, notes = read_assessment(_with_family(evidence_ids=written))

        assert read is not None and read.family is not None
        assert read.family.evidence_ids == []
        assert [(n.path, n.readable) for n in notes] == [("family.evidence_ids", False)]

    @pytest.mark.parametrize(
        ("severity", "family", "path", "words"),
        [
            ({"rating": 0, "rationale": "r"}, None, "severity", "rating: Input should be"),
            (None, {"name": 5, "evidence_ids": ["ev_0001"]}, "family", "name: Input should be"),
        ],
    )
    def test_a_required_leaf_of_the_wrong_type_keeps_its_own_reason(
        self, severity: Any, family: Any, path: str, words: str
    ) -> None:
        leaves = {"severity": severity} if severity is not None else {"family": family}
        read, notes = read_assessment(_with(**leaves))

        assert read is not None and getattr(read, path) is None
        (note,) = notes
        assert (note.path, note.readable) == (path, False)
        assert note.reason.startswith(words)
        assert "Field required" not in note.reason

    def test_a_rating_in_a_list_of_one_is_folded_too(self) -> None:
        read, notes = read_assessment(_with(severity={"rating": ["high"], "rationale": "r"}))

        assert read is not None and read.severity is not None
        assert read.severity.rating == "High"
        (note,) = notes
        assert note.readable and note.path == "severity.rating"
        assert "list of one" in note.reason and "another case" in note.reason

    def test_two_readings_of_one_value_are_both_described(self) -> None:
        read, notes = read_assessment(_with(family=["AsyncRAT"]))

        assert read is not None and read.family is not None
        assert read.family.name == "AsyncRAT"
        (note,) = notes
        assert note.readable and note.path == "family"
        assert "list of one" in note.reason and "read as its name" in note.reason

    @pytest.mark.parametrize("written", ["Unknown", "none", "N/A", ["unknown"]])
    def test_a_placeholder_is_not_read_as_a_family(self, written: Any) -> None:
        read, notes = read_assessment(_with(family=written))

        assert read is not None and read.family is None
        assert [(n.path, n.readable) for n in notes] == [("family", False)]

    def test_a_bare_severity_placeholder_is_refused(self) -> None:
        read, notes = read_assessment(_with(severity="none"))

        assert read is not None and read.severity is None
        assert [(n.path, n.readable) for n in notes] == [("severity", False)]

    @pytest.mark.parametrize(
        ("leaves", "path"),
        [
            ({"confidence": True}, "confidence"),
            ({"confidence": False}, "confidence"),
            ({"family": {**_good()["family"], "confidence": True}}, "family.confidence"),
        ],
    )
    def test_a_bool_is_not_read_as_a_number(self, leaves: dict[str, Any], path: str) -> None:
        read, notes = read_assessment(_with(**leaves))

        assert read is not None
        assert _at(read, path) is None
        assert [(n.path, n.readable) for n in notes] == [(path, False)]

    def test_the_schema_still_loads_a_stored_bool(self) -> None:
        """The refusal is the reader's: a stored run's assessment loads as it did."""
        assert JudgeAssessment.model_validate(_with(confidence=True)).confidence == 1.0


class TestTheRowsThePostprocessorRecords:
    @pytest.mark.parametrize(
        ("written", "shown"), [([], "[]"), (0, "0"), (False, "false"), ({}, "{}")]
    )
    def test_a_falsy_value_is_quoted_as_written(self, written: Any, shown: str) -> None:
        data = {
            "type": "bundle",
            "objects": [],
            "x_maljan_assessment": _with(malware_category=written),
        }

        (row,) = read_judge_assessment(data)

        assert row.code == ASSESSMENT_UNREADABLE_CODE
        assert f"x_maljan_assessment.malware_category is {shown}," in row.message

    @pytest.mark.parametrize(
        ("assessment", "path", "code"),
        [(shape[1], shape[2], shape[4]) for shape in SHAPES],
        ids=[shape[0] for shape in SHAPES],
    )
    def test_each_shape_is_recorded_under_its_code(
        self, assessment: dict[str, Any], path: str, code: str
    ) -> None:
        data = {"type": "bundle", "objects": _objects(), "x_maljan_assessment": assessment}

        found = read_judge_assessment(data)

        assert [(v.code, v.path) for v in found] == [(code, f"x_maljan_assessment.{_noted(path)}")]
        assert isinstance(data["x_maljan_assessment"], JudgeAssessment)

    def test_an_unreadable_leaf_is_quoted_and_said_to_be_absent(self) -> None:
        data = {"type": "bundle", "objects": [], "x_maljan_assessment": _with(confidence=85)}

        (row,) = read_judge_assessment(data)

        assert "85" in row.message
        assert "absent" in row.message

    def test_a_bundle_without_an_assessment_is_untouched(self) -> None:
        data: dict[str, Any] = {"type": "bundle", "objects": _objects()}

        assert read_judge_assessment(data) == []
        assert "x_maljan_assessment" not in data


class TestWhatTheRoundDoesWithIt:
    @pytest.mark.parametrize(
        "assessment", [shape[1] for shape in SHAPES], ids=[shape[0] for shape in SHAPES]
    )
    def test_no_shape_costs_the_objects(self, assessment: dict[str, Any]) -> None:
        judge = _judge(_answer(assessment), _answer(_good()))

        verdict = asyncio.run(judge.give_verdict(reports={"static": "it hollows"}, history=[]))

        assert verdict.bundle.x_maljan_fallback_verdict is None
        assert len(verdict.bundle.objects) == len(_objects())
        assert VERDICT_FALLBACK_CODE not in [v.code for v in verdict.violations]

    def test_a_mixed_bundle_keeps_every_object_and_asks_about_the_bad_leaf_once(self) -> None:
        bad = _with(confidence=85, severity="High")
        judge = _judge(_answer(bad), _answer(_good()))

        verdict = asyncio.run(judge.give_verdict(reports={"static": "it hollows"}, history=[]))

        assert verdict.retries == 1
        assert verdict.fed_back.get(ASSESSMENT_UNREADABLE_CODE) == 1
        assert verdict.fed_back.get(ASSESSMENT_READ_LOOSELY_CODE) == 1
        assert len(verdict.bundle.objects) == len(_objects())
        assert verdict.bundle.x_maljan_assessment is not None
        assert verdict.bundle.x_maljan_assessment.confidence == 0.8
        assert ASSESSMENT_UNREADABLE_CODE not in [v.code for v in verdict.violations]

    @pytest.mark.parametrize(
        ("leaves", "path"),
        [
            ({"severity": "none"}, "x_maljan_assessment.severity"),
            ({"confidence": True}, "x_maljan_assessment.confidence"),
        ],
        ids=["bare severity none", "confidence true"],
    )
    def test_a_refused_leaf_is_asked_once(self, leaves: dict[str, Any], path: str) -> None:
        judge = _judge(_answer(_with(**leaves)), _answer(_good()))

        verdict = asyncio.run(judge.give_verdict(reports={"static": "it hollows"}, history=[]))

        assert verdict.retries == 1
        assert verdict.fed_back.get(ASSESSMENT_UNREADABLE_CODE) == 1
        assert len(verdict.bundle.objects) == len(_objects())
        assert ASSESSMENT_UNREADABLE_CODE not in [v.code for v in verdict.violations]

    def test_a_leaf_still_unreadable_after_the_retry_is_recorded_absent(self) -> None:
        bad = _with(confidence=85)
        judge = _judge(_answer(bad), _answer(bad))

        verdict = asyncio.run(judge.give_verdict(reports={"static": "it hollows"}, history=[]))

        assert len(verdict.bundle.objects) == len(_objects())
        assert verdict.bundle.x_maljan_assessment is not None
        assert verdict.bundle.x_maljan_assessment.verdict == "Malware"
        assert verdict.bundle.x_maljan_assessment.confidence is None
        rows = [v for v in verdict.violations if v.code == ASSESSMENT_UNREADABLE_CODE]
        assert [v.path for v in rows] == ["x_maljan_assessment.confidence"]

    def test_a_loose_reading_costs_no_retry(self) -> None:
        judge = _judge(_answer(_with(family="AsyncRAT")))

        verdict = asyncio.run(judge.give_verdict(reports={"static": "it hollows"}, history=[]))

        assert verdict.bundle.x_maljan_assessment is not None
        assert verdict.bundle.x_maljan_assessment.family is not None
        assert verdict.bundle.x_maljan_assessment.family.name == "AsyncRAT"
        assert verdict.fed_back.get(ASSESSMENT_READ_LOOSELY_CODE)
        assert ASSESSMENT_READ_LOOSELY_CODE not in {v.code for v in verdict.violations if v.asked}


class TestTheStatedAssessment:
    @pytest.mark.parametrize(
        "assessment", [shape[1] for shape in SHAPES], ids=[shape[0] for shape in SHAPES]
    )
    def test_a_cut_answer_keeps_its_stated_assessment(self, assessment: dict[str, Any]) -> None:
        text = '{"type": "bundle", "x_maljan_assessment": ' + json.dumps(assessment)
        text += ', "objects": [{"type": "malware", "id": "mal'

        stated = stated_assessment_in(text)

        assert stated is not None
        assert stated.verdict == "Malware"

    def test_its_unreadable_leaf_is_noted(self) -> None:
        text = '{"type": "bundle", "x_maljan_assessment": ' + json.dumps(_with(confidence=85))
        notes: list[Any] = []

        stated = stated_assessment_in(text, notes)

        assert stated is not None and stated.confidence is None
        assert [(n.path, n.readable) for n in notes] == [("confidence", False)]


class TestTheReportReaderIsTold:
    def test_a_leaf_left_absent_is_a_degradation_reason(self) -> None:
        from unittest.mock import AsyncMock

        from maljan.agents.judge_agent import JudgeVerdict
        from maljan.pipeline.nodes import make_judge_node
        from maljan.pipeline.validation import Violation
        from maljan.schemas.evidence import EvidenceCounter
        from maljan.schemas.stix_models import Bundle
        from tests.unit.pipeline.test_a_fallback_verdict_assesses_nothing import (
            _Container,
            _state,
        )

        container = _Container(EvidenceCounter())
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(
                bundle=Bundle.model_validate(
                    {"objects": _objects(), "x_maljan_assessment": {"verdict": "Malware"}}
                ),
                violations=[
                    Violation(
                        code=ASSESSMENT_UNREADABLE_CODE,
                        message="x_maljan_assessment.confidence is 85",
                        path="x_maljan_assessment.confidence",
                    )
                ],
                retries=1,
                fed_back={},
            )
        )

        update = asyncio.run(make_judge_node(container)(_state()))

        assert update["degraded_mode"] is True
        assert (
            f"{ASSESSMENT_UNREADABLE_REASON}: x_maljan_assessment.confidence"
            in update["degradation_reasons"]
        )
