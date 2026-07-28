"""New static-analysis fields must survive the trip through Postgres.

A report is persisted as JSONB and read back through
``ReportService._load_malware_report`` → ``MalwareReport.model_validate``.
``StaticAnalysis`` and ``FamilyAttribution`` are both declared
``extra="forbid"``, which makes that round trip the place a schema addition
fails — and fails *silently*, because validation errors there are caught and
logged, and the endpoint simply returns ``None``. A reader gets "no report"
rather than an error, and nothing points at the new field.

Both directions matter and both are tested here:

* **Forward** — a report written today, carrying carved payloads, packer
  matches, the ATT&CK audit trail and tool artifacts, must validate on the way
  back out with every field intact.
* **Backward** — a report written *before* those fields existed must still
  validate. Rows persisted by the previous version are the common case, not the
  edge case, and defaults are what make them readable.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

_API_PATH = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API_PATH) not in sys.path:
    sys.path.insert(0, str(_API_PATH))

from app.services.report_service import ReportService  # noqa: E402

from maljan.reporting.models import MalwareReport  # noqa: E402


def _fake_user() -> Any:
    return MagicMock(id=uuid.uuid4(), email="test@example.com")


def _base_report() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": "2026-07-28T00:00:00+00:00",
        "verdict": "Malware",
        "overall_confidence": 0.8,
        "identity": {
            "hashes": {"sha256": "a" * 64},
            "file_name": "sample.exe",
        },
    }


def _with_new_fields() -> dict[str, Any]:
    doc = _base_report()
    doc["static"] = {
        "sections": [
            {
                "name": ".text",
                "virtual_address": "0x1000",
                "raw_size": 4096,
                "raw_offset": 1024,
                "entropy": 6.2,
            }
        ],
        "imports": [
            {
                "dll": "KERNEL32.dll",
                "function": "WriteProcessMemory",
                "is_suspicious": True,
                "category": "process_injection",
            }
        ],
        "interesting_strings": [
            {"value": "AKIAIOSFODNN7EXAMPLE", "kind": "secret", "notes": "aws_access_key"},
            {"value": "0x" + "a1b2c3d4" * 5, "kind": "crypto_wallet", "notes": "ethereum"},
        ],
        "embedded_resources": [
            {
                "type": "carved:PE",
                "id": "overlay+0x1a400",
                "size": 51200,
                "offset": 107520,
                "source": "overlay",
                "sha256": "b" * 64,
                "entropy": 7.2,
                "carved": True,
            }
        ],
        "packer_hint": "UPX (packer)",
        "packer_matches": [
            {
                "name": "UPX",
                "kind": "packer",
                "confidence": 0.85,
                "method": "section",
                "evidence": ["UPX0"],
            }
        ],
        "api_capabilities": {"process_injection": 7, "network": 3},
        "api_technique_hits": [
            {
                "technique_id": "T1055",
                "name": "Process Injection",
                "confidence": 0.55,
                "matched_apis": ["WriteProcessMemory", "VirtualAllocEx"],
            }
        ],
    }
    doc["attribution"] = {
        "family": "CobaltStrike",
        "family_confidence": 0.75,
        "family_grounded": True,
        "tool_artifact_matches": [
            {
                "tool": "Cobalt Strike",
                "family": "CobaltStrike",
                "kind": "c2_framework",
                "confidence": 0.75,
                "markers": ["beacon.x64.dll", "ReflectiveLoader"],
            }
        ],
    }
    return doc


def _service_returning(doc: dict[str, Any]) -> ReportService:
    session = AsyncMock()
    service = ReportService(session)
    service.get_malware_report = AsyncMock(return_value=doc)  # type: ignore[method-assign]
    return service


class TestTheNewFieldsSurviveValidation:
    def test_every_new_field_round_trips(self) -> None:
        report = MalwareReport.model_validate(_with_new_fields())
        assert report.static is not None
        assert report.static.api_capabilities == {"process_injection": 7, "network": 3}
        assert report.static.api_technique_hits[0]["technique_id"] == "T1055"
        assert report.static.packer_matches[0]["confidence"] == 0.85
        assert report.static.sections[0].raw_offset == 1024
        assert report.static.embedded_resources[0]["carved"] is True
        assert report.attribution.tool_artifact_matches[0]["family"] == "CobaltStrike"

    def test_the_new_ioc_kinds_validate(self) -> None:
        """`secret` and `crypto_wallet` are Literal members; a stale enum here
        rejects the whole report, not just the string."""
        report = MalwareReport.model_validate(_with_new_fields())
        assert report.static is not None
        kinds = {s.kind for s in report.static.interesting_strings}
        assert kinds == {"secret", "crypto_wallet"}

    @pytest.mark.asyncio
    async def test_the_service_load_path_accepts_them(self) -> None:
        """The real seam: validation failures here are swallowed and the
        endpoint returns None, so a schema break looks like a missing report."""
        service = _service_returning(_with_new_fields())
        loaded = await service._load_malware_report(uuid.uuid4(), _fake_user(), "markdown")
        assert loaded is not None, "the report must not silently vanish"
        assert loaded.static is not None
        assert loaded.static.api_technique_hits

    @pytest.mark.asyncio
    async def test_the_markdown_export_includes_them(self) -> None:
        service = _service_returning(_with_new_fields())
        md = await service.get_malware_report_markdown(uuid.uuid4(), _fake_user())
        assert md is not None
        assert "T1055" in md
        assert "overlay+0x1a400" in md, "carved payloads must reach the export"
        assert "beacon.x64.dll" in md, "so must the family evidence"


class TestOldRowsStillLoad:
    @pytest.mark.asyncio
    async def test_a_report_without_any_new_field_validates(self) -> None:
        """Rows persisted before this work are the common case."""
        doc = _base_report()
        doc["static"] = {
            "sections": [{"name": ".text", "virtual_address": "0x1000"}],
            "imports": [],
            "packer_hint": "UPX",
        }
        service = _service_returning(doc)
        loaded = await service._load_malware_report(uuid.uuid4(), _fake_user(), "markdown")
        assert loaded is not None
        assert loaded.static is not None
        assert loaded.static.api_capabilities == {}
        assert loaded.static.packer_matches == []
        assert loaded.static.sections[0].raw_offset == 0

    @pytest.mark.asyncio
    async def test_an_old_row_still_renders(self) -> None:
        doc = _base_report()
        doc["static"] = {"sections": [], "imports": [], "packer_hint": "UPX"}
        service = _service_returning(doc)
        md = await service.get_malware_report_markdown(uuid.uuid4(), _fake_user())
        assert md is not None
        assert "UPX" in md
