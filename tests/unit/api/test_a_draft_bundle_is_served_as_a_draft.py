"""The judge's draft bundle is stored, served and validated as the draft it is."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from stix2validator import ValidationOptions, validate_instance
from tests.unit.reporting.test_the_export_passes_the_official_validator import _judge

from app.api.v1.reports import get_stix_bundle
from app.services.report_service import ReportService
from app.worker.analysis_worker import _report_inputs
from maljan.core.config import Settings
from maljan.schemas.stix_models import UNPUBLISHED_NOTICE, UNPUBLISHED_PROPERTY

C2 = "82.157.13.47"


def _stored_draft() -> dict[str, Any]:
    judge = _judge(
        {
            "type": "bundle",
            "objects": [
                {"type": "malware", "id": "malware--1", "name": "shell", "is_family": False},
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "name": "C2 address",
                    "pattern": f"[ipv4-addr:value = '{C2}']",
                    "pattern_type": "stix",
                    "indicator_types": ["malicious-activity"],
                },
            ],
        }
    )
    stored, _ = _report_inputs(
        {"stix_output": judge.model_dump()},
        core_settings=Settings(_env_file=None),
        override_keys=(),
        hash_mismatch_reason=None,
    )
    assert stored is not None
    return stored


def test_the_stored_draft_is_labelled_and_passes_the_official_validator() -> None:
    stored = _stored_draft()

    assert stored[UNPUBLISHED_PROPERTY] is False
    result = validate_instance(stored, ValidationOptions(version="2.1"))
    assert [str(getattr(e, "message", e)) for e in result.errors] == []


@pytest.mark.asyncio
async def test_the_default_source_answers_a_draft_in_the_same_envelope() -> None:
    stored = _stored_draft()
    svc = ReportService(db=AsyncMock())
    svc.get_stix_bundle = AsyncMock(return_value=stored)  # type: ignore[method-assign]

    answer = await get_stix_bundle(uuid.uuid4(), "export", MagicMock(), svc)

    assert answer == {"published": False, "notice": UNPUBLISHED_NOTICE, "bundle": stored}


@pytest.mark.asyncio
async def test_a_published_export_is_served_as_it_always_was() -> None:
    export = {"type": "bundle", "id": "bundle--1", "objects": []}
    svc = ReportService(db=AsyncMock())
    svc.get_stix_bundle = AsyncMock(return_value=export)  # type: ignore[method-assign]

    assert await get_stix_bundle(uuid.uuid4(), "export", MagicMock(), svc) == export
