"""An object store anyone can read degrades the API and is not used for samples (T-575).

``/health?deep=true`` answers ``degraded`` (not ``degraded_optional``) while the
bucket lets an anonymous caller in, saying only that the check failed; a
sample or a sandbox report asked of the store then answers 503 with what to
read. The verdict itself is ``app.services.object_store.privacy``'s, tested
with the client doubles in tests/unit/api/test_one_object_store_client.py.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest


async def _ok() -> None:
    return None


async def _deep_health(monkeypatch: pytest.MonkeyPatch, minio: Any) -> dict[str, Any]:
    import app.main as main_mod

    monkeypatch.setattr(main_mod, "_probe_database", _ok)
    monkeypatch.setattr(main_mod, "_probe_redis", _ok)
    monkeypatch.setattr(main_mod, "_probe_memory", _ok)
    monkeypatch.setattr(main_mod, "_probe_minio", minio)
    transport = httpx.ASGITransport(app=main_mod.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health", params={"deep": "true"})
    assert response.status_code == 200
    return dict(response.json())


@pytest.mark.asyncio
async def test_a_bucket_that_is_not_private_degrades_the_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import object_store

    monkeypatch.setattr(
        object_store, "probe", lambda: {"ok": False, "error": "x", "required": True}
    )
    import app.main as main_mod

    body = await _deep_health(monkeypatch, main_mod._probe_minio)
    assert body["status"] == "degraded"
    assert body["components"]["minio"]["ok"] is False


@pytest.mark.asyncio
async def test_a_store_that_cannot_be_reached_stays_optional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _down() -> None:
        raise ConnectionError("refused")

    body = await _deep_health(monkeypatch, _down)
    assert body["status"] == "degraded_optional"


@pytest.mark.asyncio
async def test_a_refused_sample_answers_503_with_what_to_read() -> None:
    import app.main as main_mod
    from app.services.object_store import StoreNotPrivate

    handler = main_mod.app.exception_handlers[StoreNotPrivate]
    response = await handler(None, StoreNotPrivate())
    assert response.status_code == 503
    assert json.loads(response.body) == {"detail": "object store is not private; see the API log"}


# ---- through the routes, with the suite's fixture overridden to an open store --


class _OpenToAnyone:
    """The anonymous client of a bucket whose policy lets anyone read."""

    def bucket_exists(self, bucket: str) -> bool:
        from unittest.mock import MagicMock

        from minio.error import S3Error

        raise S3Error(MagicMock(), "AccessDenied", "", "", "", "")

    def stat_object(self, bucket: str, key: str) -> Any:
        from unittest.mock import MagicMock

        from minio.error import S3Error

        raise S3Error(MagicMock(), "NoSuchKey", "", "", "", "")


class _Store:
    """The platform's own client: the bucket is there and has no policy; writes are noted."""

    def __init__(self) -> None:
        self.written: list[str] = []

    def bucket_exists(self, bucket: str) -> bool:
        return True

    def get_bucket_policy(self, bucket: str) -> str:
        from unittest.mock import MagicMock

        from minio.error import S3Error

        raise S3Error(MagicMock(), "NoSuchBucketPolicy", "", "", "", "")

    def fput_object(self, bucket: str, path: str, *args: Any, **kwargs: Any) -> None:
        self.written.append(path)


def test_the_sample_upload_answers_503_and_stores_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uuid
    from unittest.mock import AsyncMock, MagicMock

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import app.main as main_mod
    from app.api.v1 import samples
    from app.database import get_db
    from app.deps import get_current_user
    from app.services import object_store

    sha256 = "e" * 64
    store = _Store()
    monkeypatch.setattr(object_store, "anonymous_client", lambda *_args: _OpenToAnyone())
    monkeypatch.setattr(samples, "_minio_client", lambda: store)
    monkeypatch.setattr(
        samples, "_streaming_hashes", lambda file, dest, cap: (sha256, "c" * 40, "d" * 32, 66)
    )
    monkeypatch.setattr(samples, "_detect_mime", lambda path: "application/x-dosexec")

    async def _get(name: str) -> Any:
        return {"upload_max_bytes": 1024 * 1024, "upload_allowed_mime_types": []}[name]

    monkeypatch.setattr(samples.runtime_config, "get", AsyncMock(side_effect=_get))
    prior = MagicMock()
    prior.scalar_one_or_none.return_value = None
    inserted = MagicMock()
    inserted.scalar_one_or_none.return_value = MagicMock(id=uuid.uuid4(), sha256=sha256)
    db = MagicMock()
    db.execute = AsyncMock(side_effect=[None, prior, inserted, MagicMock()])
    app = FastAPI()
    app.include_router(samples.router, prefix="/api/v1")
    app.add_exception_handler(object_store.StoreNotPrivate, main_mod.store_not_private_response)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: MagicMock(id=uuid.uuid4())

    response = TestClient(app).post(
        "/api/v1/samples/upload", files={"file": ("thing.exe", b"MZ" + b"\x00" * 64)}
    )

    assert response.status_code == 503, response.text
    assert response.json() == {"detail": "object store is not private; see the API log"}
    assert store.written == []
