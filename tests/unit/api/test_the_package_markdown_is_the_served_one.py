"""The job package's report.md is the served Markdown, byte for byte.

The served exports read the report from its JSONB column, whose key order is
shorter keys first; the package reads it from the run export, written with
sorted keys. Where the renderer lists a mapping in its given order (two import
capabilities with the same count, here), the two once differed. Both now read
the report in sorted key order, so either store renders the same text.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services import job_package
from app.services.report_service import ReportService
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
    key_ordered,
)

JOB = {"completed_at": "2026-10-25T08:30:00+00:00"}


def _document() -> dict[str, Any]:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32, md5="cd" * 16)),
        verdict="Malware",
        generated_at="2026-10-25T08:00:00+00:00",
        static=StaticAnalysis(
            api_capabilities={"network": 2, "filesystem": 2},
            api_capability_rates={"network": 14.4, "filesystem": 35.6},
        ),
    ).model_dump(mode="json")


def _jsonb_order(value: Any) -> Any:
    """``value`` with each mapping's keys as Postgres JSONB returns them."""
    if isinstance(value, dict):
        return {k: _jsonb_order(value[k]) for k in sorted(value, key=lambda k: (len(k), k))}
    if isinstance(value, list):
        return [_jsonb_order(item) for item in value]
    return value


async def _served(document: dict[str, Any]) -> str | None:
    service = ReportService(db=AsyncMock())
    service.get_malware_report = AsyncMock(return_value=document)  # type: ignore[method-assign]
    return await service.get_malware_report_markdown(uuid.uuid4(), MagicMock())


@pytest.mark.asyncio
async def test_the_package_and_the_served_markdown_agree_across_stores() -> None:
    document = _document()
    packaged, why = job_package._markdown(key_ordered(document), JOB)
    assert why is None and packaged is not None
    assert "filesystem ×2 (35.6%), network ×2 (14.4%)" in packaged

    for stored in (document, _jsonb_order(document), key_ordered(document)):
        assert await _served(stored) == packaged
        assert job_package._markdown(stored, JOB)[0] == packaged


def test_key_order_is_sorted_at_every_depth_and_lists_keep_theirs() -> None:
    value = {"b": [{"z": 1, "a": 2}, 3], "a": {"y": None, "x": "v"}}

    ordered = key_ordered(value)

    assert ordered == value
    assert list(ordered) == ["a", "b"]
    assert list(ordered["a"]) == ["x", "y"]
    assert list(ordered["b"][0]) == ["a", "z"]
    assert ordered["b"][1] == 3
