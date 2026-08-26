"""Regression tests for the 2026-07-26 live-audit findings.

Each test pins one fix so the defect cannot silently return. See
``other/docs/AUDIT_2026-07-26.md`` for the full findings and the live evidence.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# K4 — the degraded-run confidence cap must reach the persisted column
# ---------------------------------------------------------------------------


class TestConfidenceCapReachesPersistence:
    """The cap lives in ``MalwareReport``; the column used to keep the raw value.

    Live evidence: the analysis page showed a "DEGRADED RUN" banner and
    "Confidence: 91/100" at the same time, while that report's own capped value
    was 0.60.
    """

    @staticmethod
    def _extract(result: dict) -> float:
        from app.worker.analysis_worker import _extract_confidence

        return _extract_confidence(result)

    def test_prefers_capped_malware_report_value(self) -> None:
        result = {
            "malware_report": {"overall_confidence": 0.60},
            "run_summary": {"overall_confidence": 0.91},
            "confidence_history": [0.91],
        }
        assert self._extract(result) == pytest.approx(0.60)

    def test_falls_back_to_run_summary_without_a_report(self) -> None:
        result = {"run_summary": {"overall_confidence": 0.73}, "confidence_history": [0.5]}
        assert self._extract(result) == pytest.approx(0.73)

    def test_falls_back_to_history_when_nothing_else_is_present(self) -> None:
        assert self._extract({"confidence_history": [0.1, 0.42]}) == pytest.approx(0.42)

    def test_defaults_to_zero(self) -> None:
        assert self._extract({}) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# K2 — API keys must actually authenticate
# ---------------------------------------------------------------------------


class _FakeResult:
    def __init__(self, value: Any) -> None:
        self._value = value

    def scalar_one_or_none(self) -> Any:
        return self._value


class _FakeDB:
    """Returns a queued value per ``execute`` call, in order."""

    def __init__(self, *values: Any) -> None:
        self._values = list(values)

    async def execute(self, *_args: Any, **_kwargs: Any) -> _FakeResult:
        return _FakeResult(self._values.pop(0) if self._values else None)


class _Key:
    def __init__(
        self,
        *,
        is_active: bool = True,
        expires_at: datetime | None = None,
        user_id: uuid.UUID | None = None,
    ) -> None:
        self.is_active = is_active
        self.expires_at = expires_at
        self.user_id = user_id or uuid.uuid4()
        self.last_used_at: datetime | None = None


class _User:
    def __init__(self, *, is_active: bool = True) -> None:
        self.id = uuid.uuid4()
        self.is_active = is_active


class TestApiKeyAuthentication:
    """Keys used to be write-only: nothing ever read ``key_hash`` back."""

    def test_hash_matches_the_minting_algorithm(self) -> None:
        import hashlib

        from app.deps import hash_api_key

        raw = "mk_example-key"
        assert hash_api_key(raw) == hashlib.sha256(raw.encode()).hexdigest()

    @pytest.mark.asyncio
    async def test_valid_key_resolves_its_owner_and_stamps_last_used(self) -> None:
        from app.deps import _user_from_api_key

        user = _User()
        key = _Key(user_id=user.id)
        resolved = await _user_from_api_key("mk_raw", _FakeDB(key, user))  # type: ignore[arg-type]

        assert resolved is user
        assert key.last_used_at is not None, "last_used_at must be stamped for leak detection"

    @pytest.mark.asyncio
    async def test_unknown_key_is_rejected(self) -> None:
        from app.deps import _user_from_api_key
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            await _user_from_api_key("mk_nope", _FakeDB(None))  # type: ignore[arg-type]
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_revoked_key_is_rejected(self) -> None:
        from app.deps import _user_from_api_key
        from fastapi import HTTPException

        key = _Key(is_active=False)
        with pytest.raises(HTTPException) as exc:
            await _user_from_api_key("mk_revoked", _FakeDB(key))  # type: ignore[arg-type]
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_key_is_rejected(self) -> None:
        from app.deps import _user_from_api_key
        from fastapi import HTTPException

        key = _Key(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        with pytest.raises(HTTPException) as exc:
            await _user_from_api_key("mk_expired", _FakeDB(key))  # type: ignore[arg-type]
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_deactivated_owner_is_forbidden(self) -> None:
        from app.deps import _user_from_api_key
        from fastapi import HTTPException

        user = _User(is_active=False)
        key = _Key(user_id=user.id)
        with pytest.raises(HTTPException) as exc:
            await _user_from_api_key("mk_inactive", _FakeDB(key, user))  # type: ignore[arg-type]
        assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# K1 — the audit trail must survive a failed request
# ---------------------------------------------------------------------------


class TestAuditSchemaAcceptsAnonymousEvents:
    """Security events with no authenticated principal must serialise.

    ``user_id`` was declared required while the model (and the DB, after the
    accompanying migration) allow NULL, so ``GET /audit/logs`` raised a 500 the
    moment a failed-login row appeared.
    """

    def test_null_user_id_and_string_resource_id_validate(self) -> None:
        from app.schemas.audit import AuditLogResponse

        row = AuditLogResponse.model_validate(
            {
                "id": uuid.uuid4(),
                "user_id": None,
                "action": "auth.login.failure",
                "resource_type": "auth",
                "resource_id": "not-a-uuid",
                "details": None,
                "ip_address": "10.0.0.1",
                "created_at": datetime.now(UTC),
            }
        )
        assert row.user_id is None
        assert row.resource_id == "not-a-uuid"


# ---------------------------------------------------------------------------
# Ö1 — /health must actually probe its dependencies
# ---------------------------------------------------------------------------


class TestDeepHealthProbe:
    @pytest.mark.asyncio
    async def test_a_failing_probe_is_reported_not_raised(self, monkeypatch: Any) -> None:
        import app.main as main_mod

        async def _boom() -> None:
            raise RuntimeError("connection refused")

        async def _ok() -> None:
            return None

        monkeypatch.setattr(main_mod, "_probe_database", _boom)
        monkeypatch.setattr(main_mod, "_probe_redis", _ok)
        monkeypatch.setattr(main_mod, "_probe_minio", _ok)
        monkeypatch.setattr(main_mod, "_probe_qdrant", _ok)

        components = await main_mod._probe_components()

        assert components["database"]["ok"] is False
        assert "connection refused" in components["database"]["error"]
        assert components["redis"]["ok"] is True
