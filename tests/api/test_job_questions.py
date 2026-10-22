"""A job may be submitted with questions; each must say something, and the worker hands them on."""

from __future__ import annotations

import uuid

import pytest

from app.schemas.job import JobCreateRequest
from app.worker.analysis_worker import build_job_settings, job_questions


def test_questions_are_accepted_as_written() -> None:
    request = JobCreateRequest(
        sample_id=uuid.uuid4(), config={"questions": ["What is the C2?", "Does it persist?"]}
    )

    assert request.config == {"questions": ["What is the C2?", "Does it persist?"]}


@pytest.mark.parametrize("questions", [["What is the C2?", "  "], "What is the C2?", [3]])
def test_a_blank_question_or_another_shape_is_refused(questions: object) -> None:
    with pytest.raises(ValueError, match="questions"):
        JobCreateRequest(sample_id=uuid.uuid4(), config={"questions": questions})


def test_an_explicit_null_is_refused_like_every_other_known_key() -> None:
    with pytest.raises(ValueError, match="explicit null is not allowed for: questions"):
        JobCreateRequest(sample_id=uuid.uuid4(), config={"questions": None})


def test_the_worker_reads_the_questions_and_the_settings_ignore_them() -> None:
    config = {"questions": ["What is the C2?", ""]}

    assert job_questions(config) == ["What is the C2?"]
    assert job_questions({}) == []
    assert job_questions(None) == []
    assert build_job_settings({}, config) == build_job_settings({}, None)
