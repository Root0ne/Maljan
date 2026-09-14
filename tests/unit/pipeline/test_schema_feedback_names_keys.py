"""A rejected key is told which keys would have been accepted.

Live run 2, ReportComposer: the ``conclusion`` section failed its schema twice
with "Extra inputs are not permitted" and was dropped from the delivered
report. The sentence names neither the key that was rejected nor the ones that
exist, so the retry turn asked the model to fix something it had not been told,
and it answered with the same shape.

The section schemas and the narrative schema both forbid extra keys, and both
feed their pydantic errors through the same place, so both are fixed here.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from maljan.pipeline.validation import feedback_text, schema_violations


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")

    heading: str = ""
    body: str = ""
    evidence_ids: list[str] = []


class _Required(BaseModel):
    heading: str
    body: str = ""


class TestTheFeedbackNamesTheKeys:
    def test_an_extra_key_is_answered_with_the_allowed_ones(self) -> None:
        violations = schema_violations(
            _Section, {"heading": "Conclusion", "summary": "…"}, code="composer.schema"
        )

        assert len(violations) == 1
        message = violations[0].message
        assert "Extra inputs are not permitted" in message
        for field in ("heading", "body", "evidence_ids"):
            assert field in message

    def test_it_says_the_others_are_rejected(self) -> None:
        message = schema_violations(_Section, {"nope": 1}, code="composer.schema")[0].message
        assert "rejects every other one" in message

    def test_the_retry_turn_carries_it(self) -> None:
        violations = schema_violations(_Section, {"nope": 1}, code="composer.schema")
        text = feedback_text(violations)
        assert "composer.schema" in text
        assert "evidence_ids" in text

    def test_the_narrative_schema_is_named_the_same_way(self) -> None:
        """It ignores extra keys, so its shape complaint is a missing one."""
        from maljan.reporting.narrative_agent import NarrativeOutput

        violations = schema_violations(
            NarrativeOutput, {"not_a_field": "x"}, code="narrative.schema"
        )
        assert violations
        for violation in violations:
            for field in NarrativeOutput.model_fields:
                assert field in violation.message

    def test_a_missing_field_is_answered_with_the_shape(self) -> None:
        violations = schema_violations(_Required, {}, code="composer.schema")
        assert [v.path for v in violations] == ["heading"]
        assert "this object's keys are body, heading." in violations[0].message

    def test_an_ordinary_complaint_is_left_alone(self) -> None:
        violations = schema_violations(_Section, {"heading": 5}, code="composer.schema")
        assert violations
        assert "accepts only these keys" not in violations[0].message
        assert "this object's keys are" not in violations[0].message


class TestANestedObjectNamesItsOwnKeys:
    """A bad key inside a list of sub-objects was answered with the outer
    answer's keys, none of which belong there."""

    def test_the_keys_belong_to_the_object_that_rejected_the_field(self) -> None:
        from maljan.reporting.narrative_agent import NarrativeOutput

        violations = schema_violations(
            NarrativeOutput,
            {
                "executive_summary": "x" * 130,
                "capabilities_narrative": ["a", "b", "c"],
                "defensive_recommendations": [{"title": "t"}],
            },
            code="narrative.schema",
        )

        nested = [v for v in violations if v.path.startswith("defensive_recommendations.0")]
        assert nested
        for violation in nested:
            assert "action" in violation.message
            assert "rationale" in violation.message
            assert "executive_summary" not in violation.message
