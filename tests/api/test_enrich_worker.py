"""Service-level tests for the ARQ enrichment task + ReportService.enqueue_enrichment.

Hits both the worker logic (mock DB + mock Redis publish) and the service
layer (mock ARQ pool). End-to-end ARQ lifecycle is covered by manual smoke
during deployment.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_API_PATH = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API_PATH) not in sys.path:
    sys.path.insert(0, str(_API_PATH))


from app.services.report_service import EnrichmentEnqueueError, ReportService  # noqa: E402
from app.worker.enrich_worker import enrich_threat_intel  # noqa: E402


def _fake_user() -> Any:
    return MagicMock(id=uuid.uuid4())


def _enabled_patch():
    """Patch runtime_config so the enrichment-enabled gate is deterministic.

    Task 7 moved the ``enrichment_enabled`` / API-key / ``enrichment_max_lookups``
    reads from ``settings`` to ``runtime_config`` (a 5-second TTL cache over the
    UI-managed overrides). These tests exercise the worker directly, without a
    database, so ``runtime_config`` would otherwise fall back to a real (failed)
    DB connection attempt before landing on the static default.
    """
    return (
        patch(
            "app.worker.enrich_worker.runtime_config.get",
            AsyncMock(
                side_effect=lambda n: {
                    "enrichment_enabled": True,
                    "enrichment_max_lookups": 25,
                }[n]
            ),
        ),
        patch(
            "app.worker.enrich_worker.runtime_config.get_secret",
            AsyncMock(side_effect=lambda n: {"virustotal_api_key": "", "abuseipdb_api_key": ""}[n]),
        ),
    )


def _malware_report_dict() -> dict[str, Any]:
    return {
        "network": {
            "domains": [{"fqdn": "evil.com", "is_suspicious": True}],
            "ips": [{"address": "1.2.3.4", "is_suspicious": True}],
        }
    }


# ---------------------------------------------------------------------------
# Worker (enrich_threat_intel)
# ---------------------------------------------------------------------------


class TestEnrichWorkerHappy:
    @pytest.mark.asyncio
    async def test_populates_reputation_and_publishes_event(self) -> None:
        # Pretend the orchestrator filled the dict with one new reputation.
        updated_payload = {
            "network": {
                "domains": [
                    {
                        "fqdn": "evil.com",
                        "is_suspicious": True,
                        "reputation": {"source": "virustotal", "malicious": 9},
                    }
                ],
                "ips": [
                    {
                        "address": "1.2.3.4",
                        "is_suspicious": True,
                        "reputation": {"source": "abuseipdb", "abuse_confidence": 80},
                    }
                ],
            }
        }

        report_id = uuid.uuid4()
        job_id = uuid.uuid4()
        fake_report = MagicMock()
        fake_report.id = report_id
        fake_report.job_id = job_id
        fake_report.malware_report = _malware_report_dict()

        db = MagicMock()
        db.get = AsyncMock(return_value=fake_report)
        db.commit = AsyncMock()
        session_cm = AsyncMock()
        session_cm.__aenter__.return_value = db
        session_cm.__aexit__.return_value = None
        session_factory = MagicMock(return_value=session_cm)

        redis = AsyncMock()
        ctx = {"redis": redis, "db_session": session_factory}

        get_patch, get_secret_patch = _enabled_patch()
        with (
            patch(
                "maljan.enrichment.enrich_malware_report",
                new=AsyncMock(return_value=updated_payload),
            ),
            get_patch,
            get_secret_patch,
        ):
            result = await enrich_threat_intel(ctx, str(report_id))

        assert result["status"] == "ok"
        assert result["domains_enriched"] == 1
        assert result["ips_enriched"] == 1
        # Both reputation keys should be present on the persisted dict.
        assert fake_report.malware_report["network"]["domains"][0]["reputation"]
        assert fake_report.malware_report["network"]["ips"][0]["reputation"]
        redis.publish.assert_awaited()


class TestEnrichWorkerSkips:
    @pytest.mark.asyncio
    async def test_invalid_uuid(self) -> None:
        ctx = {"redis": AsyncMock(), "db_session": MagicMock()}
        get_patch, get_secret_patch = _enabled_patch()
        with get_patch, get_secret_patch:
            result = await enrich_threat_intel(ctx, "not-a-uuid")
        assert result["status"] == "invalid_id"

    @pytest.mark.asyncio
    async def test_report_missing(self) -> None:
        db = MagicMock()
        db.get = AsyncMock(return_value=None)
        session_cm = AsyncMock()
        session_cm.__aenter__.return_value = db
        session_cm.__aexit__.return_value = None
        ctx = {"redis": AsyncMock(), "db_session": MagicMock(return_value=session_cm)}
        get_patch, get_secret_patch = _enabled_patch()
        with get_patch, get_secret_patch:
            result = await enrich_threat_intel(ctx, str(uuid.uuid4()))
        assert result["status"] == "not_found"

    @pytest.mark.asyncio
    async def test_no_malware_report_payload(self) -> None:
        fake_report = MagicMock()
        fake_report.malware_report = None
        db = MagicMock()
        db.get = AsyncMock(return_value=fake_report)
        session_cm = AsyncMock()
        session_cm.__aenter__.return_value = db
        session_cm.__aexit__.return_value = None
        ctx = {"redis": AsyncMock(), "db_session": MagicMock(return_value=session_cm)}
        get_patch, get_secret_patch = _enabled_patch()
        with get_patch, get_secret_patch:
            result = await enrich_threat_intel(ctx, str(uuid.uuid4()))
        assert result["status"] == "skipped"


class TestEnrichWorkerErrorIsContained:
    @pytest.mark.asyncio
    async def test_orchestrator_exception_returns_error_status(self) -> None:
        fake_report = MagicMock()
        fake_report.id = uuid.uuid4()
        fake_report.job_id = uuid.uuid4()
        fake_report.malware_report = _malware_report_dict()

        db = MagicMock()
        db.get = AsyncMock(return_value=fake_report)
        db.commit = AsyncMock()
        session_cm = AsyncMock()
        session_cm.__aenter__.return_value = db
        session_cm.__aexit__.return_value = None
        ctx = {"redis": AsyncMock(), "db_session": MagicMock(return_value=session_cm)}

        get_patch, get_secret_patch = _enabled_patch()
        with (
            patch(
                "maljan.enrichment.enrich_malware_report",
                new=AsyncMock(side_effect=RuntimeError("boom")),
            ),
            get_patch,
            get_secret_patch,
        ):
            result = await enrich_threat_intel(ctx, str(fake_report.id))

        assert result["status"] == "error"
        # commit must NOT have been called when the orchestrator blew up.
        db.commit.assert_not_awaited()


# ---------------------------------------------------------------------------
# Service (ReportService.enqueue_enrichment)
# ---------------------------------------------------------------------------


class TestEnqueueEnrichment:
    @pytest.mark.asyncio
    async def test_enqueues_and_returns_job_id(self) -> None:
        svc = ReportService(db=AsyncMock())
        fake_report = MagicMock(id=uuid.uuid4())
        svc.get_report = AsyncMock(return_value=fake_report)  # type: ignore[method-assign]

        pool = AsyncMock()
        pool.enqueue_job = AsyncMock(return_value=MagicMock(job_id="enrich-xyz"))
        svc._get_arq_redis = AsyncMock(return_value=pool)  # type: ignore[method-assign]

        result = await svc.enqueue_enrichment(fake_report.id, _fake_user())
        assert result == "enrich-xyz"
        pool.enqueue_job.assert_awaited_once()
        call = pool.enqueue_job.await_args
        # ``_job_id`` keeps the enqueue idempotent.
        assert call.kwargs["_job_id"] == f"enrich:{fake_report.id}"

    @pytest.mark.asyncio
    async def test_missing_report_returns_none(self) -> None:
        svc = ReportService(db=AsyncMock())
        svc.get_report = AsyncMock(return_value=None)  # type: ignore[method-assign]
        # No ARQ access expected when the report is missing.
        svc._get_arq_redis = AsyncMock()  # type: ignore[method-assign]

        result = await svc.enqueue_enrichment(uuid.uuid4(), _fake_user())
        assert result is None
        svc._get_arq_redis.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_arq_already_queued_returns_none(self) -> None:
        svc = ReportService(db=AsyncMock())
        svc.get_report = AsyncMock(return_value=MagicMock())  # type: ignore[method-assign]
        pool = AsyncMock()
        pool.enqueue_job = AsyncMock(return_value=None)  # ARQ collision case
        svc._get_arq_redis = AsyncMock(return_value=pool)  # type: ignore[method-assign]

        result = await svc.enqueue_enrichment(uuid.uuid4(), _fake_user())
        assert result is None

    @pytest.mark.asyncio
    async def test_redis_failure_raises(self) -> None:
        svc = ReportService(db=AsyncMock())
        svc.get_report = AsyncMock(return_value=MagicMock())  # type: ignore[method-assign]
        svc._get_arq_redis = AsyncMock(side_effect=ConnectionError("no redis"))  # type: ignore[method-assign]
        with pytest.raises(EnrichmentEnqueueError):
            await svc.enqueue_enrichment(uuid.uuid4(), _fake_user())
