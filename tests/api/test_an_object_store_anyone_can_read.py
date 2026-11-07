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
