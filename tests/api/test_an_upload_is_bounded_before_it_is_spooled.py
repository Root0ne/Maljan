"""An upload is held to its route's bound before Starlette spools it, and hashed off the loop.

A route taking an ``UploadFile`` sees the file only after the whole multipart
body was parsed and spooled to disk, so its own cap came after the disk had
taken whatever was sent. ``UploadBoundMiddleware`` holds the bound the route
declares (``upload_bound``) at the door: a ``Content-Length`` over it is
refused unread, and a body that runs past it is cut off at the first chunk
over (AUD-32). The bound is the route's operator setting; a route that
declares none is untouched.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI, UploadFile
from fastapi.testclient import TestClient

from app.middleware.upload_bound_middleware import (
    MULTIPART_FRAMING_BYTES,
    UploadBoundMiddleware,
    upload_bound,
)

BOUND = 4096
BOUNDARY = "maljanboundary"


def _app(calls: list[int], bound: int = BOUND) -> FastAPI:
    async def _bound() -> int:
        return bound

    app = FastAPI()
    app.add_middleware(UploadBoundMiddleware)

    @app.post("/bounded")
    @upload_bound(_bound)
    async def bounded(file: UploadFile) -> dict[str, int]:
        data = await file.read()
        calls.append(len(data))
        return {"size": len(data)}

    @app.post("/open")
    async def open_route(file: UploadFile) -> dict[str, int]:
        data = await file.read()
        calls.append(len(data))
        return {"size": len(data)}

    return app


def _multipart(size: int) -> bytes:
    head = (
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="file"; filename="s.bin"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    return head + b"A" * size + f"\r\n--{BOUNDARY}--\r\n".encode()


HEADERS = {"content-type": f"multipart/form-data; boundary={BOUNDARY}"}


def test_a_file_within_the_bound_is_accepted_as_before() -> None:
    calls: list[int] = []
    response = TestClient(_app(calls)).post("/bounded", files={"file": ("s.bin", b"A" * BOUND)})
    assert response.status_code == 200, response.text
    assert calls == [BOUND]


def test_a_declared_length_over_the_bound_is_refused_unread() -> None:
    calls: list[int] = []
    body = _multipart(BOUND + MULTIPART_FRAMING_BYTES + 1)
    response = TestClient(_app(calls)).post("/bounded", content=body, headers=HEADERS)

    assert response.status_code == 413
    assert "too large" in response.json()["detail"]
    assert calls == [], "the route never ran, so nothing was spooled"


def test_a_streamed_body_past_the_bound_is_cut_off() -> None:
    """No length to refuse on: the count of what arrives stops it."""
    calls: list[int] = []
    body = _multipart(BOUND + MULTIPART_FRAMING_BYTES + 1)

    def chunks() -> Any:
        for offset in range(0, len(body), 1024):
            yield body[offset : offset + 1024]

    response = TestClient(_app(calls)).post("/bounded", content=chunks(), headers=HEADERS)

    assert response.status_code == 413
    assert calls == []


def test_a_route_that_declares_no_bound_is_untouched() -> None:
    calls: list[int] = []
    size = BOUND + MULTIPART_FRAMING_BYTES + 10
    response = TestClient(_app(calls)).post("/open", files={"file": ("s.bin", b"A" * size)})

    assert response.status_code == 200
    assert calls == [size]


def test_the_bound_is_read_per_request() -> None:
    """An operator who raises the setting is answered by the next upload."""
    calls: list[int] = []
    big = BOUND * 4
    response = TestClient(_app(calls, bound=big + 1)).post(
        "/bounded", files={"file": ("s.bin", b"A" * big)}
    )
    assert response.status_code == 200
    assert calls == [big]


def test_both_upload_routes_declare_their_own_setting() -> None:
    from app.api.v1 import samples, sandbox_reports
    from app.middleware.upload_bound_middleware import UPLOAD_BOUND_ATTR

    assert getattr(samples.upload_sample, UPLOAD_BOUND_ATTR) is samples._upload_max_bytes
    assert (
        getattr(sandbox_reports.upload_sandbox_report, UPLOAD_BOUND_ATTR)
        is sandbox_reports._report_upload_max_bytes
    )


def test_the_api_installs_the_middleware_inside_every_other_layer() -> None:
    """Logging, the rate limiter, CORS and the security headers all wrap its answers."""
    from app.main import create_app

    # ``user_middleware`` runs outermost first.
    classes = [m.cls for m in create_app().user_middleware]
    assert classes[-1] is UploadBoundMiddleware
    assert len(classes) > 1


def test_a_route_with_a_bound_refuses_any_other_body_shape_unread() -> None:
    """An urlencoded form would be parsed whole into memory before the route ran."""
    calls: list[int] = []
    client = TestClient(_app(calls))

    form = client.post("/bounded", data={"file": "A" * (BOUND * 4)})
    raw = client.post("/bounded", content=b"A" * 10, headers={"content-type": "text/plain"})
    bare = client.post("/bounded", content=b"A" * 10)

    for response in (form, raw, bare):
        assert response.status_code == 415, response.text
    assert calls == []


def _layered_app(calls: list[int], seen: dict[str, Any]) -> FastAPI:
    """The bound inside logging, the rate limiter and CORS, added as ``create_app`` adds them."""
    from fastapi.middleware.cors import CORSMiddleware

    from app.middleware.logging_middleware import RequestLoggingMiddleware
    from app.middleware.rate_limit_middleware import RateLimitMiddleware

    async def _bound() -> int:
        seen["read_after_limiter"] = seen.get("limited", 0) > 0
        seen["reads"] = seen.get("reads", 0) + 1
        return BOUND

    app = FastAPI()
    app.add_middleware(UploadBoundMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RateLimitMiddleware, redis_url="redis://127.0.0.1:1/0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://console.test"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.post("/bounded")
    @upload_bound(_bound)
    async def bounded(file: UploadFile) -> dict[str, int]:
        calls.append(len(await file.read()))
        return {"size": 0}

    return app


def _limiter(monkeypatch: pytest.MonkeyPatch, seen: dict[str, Any], *, allowed: int) -> None:
    from app.middleware import rate_limit_middleware as limiter

    settings = {
        "rate_limit_enabled": True,
        "rate_limit_whitelist": [],
        "rate_limit_requests": allowed,
        "rate_limit_window_seconds": 60,
        "trusted_proxy_ips": [],
    }

    async def _get(name: str) -> Any:
        return settings[name]

    async def _count(self: Any, redis: Any, key: str, window: int) -> tuple[int, int]:
        seen["limited"] = seen.get("limited", 0) + 1
        return seen["limited"], window

    monkeypatch.setattr(limiter.runtime_config, "get", AsyncMock(side_effect=_get))
    monkeypatch.setattr(limiter.RateLimitMiddleware, "_incr_with_ttl", _count)


def test_a_413_from_the_bound_carries_cors_and_passes_the_rate_limiter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    seen: dict[str, Any] = {}
    _limiter(monkeypatch, seen, allowed=100)
    client = TestClient(_layered_app(calls, seen))

    response = client.post(
        "/bounded",
        content=_multipart(BOUND + MULTIPART_FRAMING_BYTES + 1),
        headers={**HEADERS, "origin": "http://console.test"},
    )

    assert response.status_code == 413
    assert "too large" in response.json()["detail"]
    assert response.headers["access-control-allow-origin"] == "http://console.test"
    assert response.headers["x-ratelimit-limit"] == "100"
    assert seen["limited"] == 1
    assert calls == []


def test_the_bound_is_read_only_after_the_rate_limiter_let_the_request_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    seen: dict[str, Any] = {}
    _limiter(monkeypatch, seen, allowed=1)
    client = TestClient(_layered_app(calls, seen))
    body = _multipart(16)

    first = client.post("/bounded", content=body, headers=HEADERS)
    second = client.post("/bounded", content=body, headers=HEADERS)

    assert first.status_code == 200
    assert seen["read_after_limiter"] is True
    assert second.status_code == 429
    assert seen["reads"] == 1, "a refused request never reaches the bound's settings read"


# ── hashing and reading off the loop ──────────────────────────────


def _not_on_a_loop() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return True
    return False


def test_a_sample_is_hashed_off_the_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api.v1 import samples as module
    from app.database import get_db
    from app.deps import get_current_user

    seen: dict[str, bool] = {}
    real = module._streaming_hashes

    def watched(file: Any, dest: Any, cap: int) -> Any:
        seen["hash"] = _not_on_a_loop()
        return real(file, dest, cap)

    def mime(path: Any) -> str:
        seen["mime"] = _not_on_a_loop()
        return "application/octet-stream"

    monkeypatch.setattr(module, "_streaming_hashes", watched)
    monkeypatch.setattr(module, "_detect_mime", mime)

    async def _get(name: str) -> Any:
        return {"upload_max_bytes": 1024 * 1024, "upload_allowed_mime_types": []}[name]

    monkeypatch.setattr(module.runtime_config, "get", AsyncMock(side_effect=_get))
    user = MagicMock(id=uuid.uuid4())
    prior = MagicMock()
    prior.scalar_one_or_none.return_value = uuid.uuid4()
    conflict = MagicMock()
    conflict.scalar_one_or_none.return_value = None
    lookup = MagicMock()
    lookup.scalar_one.return_value = MagicMock()
    db = MagicMock()
    db.execute = AsyncMock(side_effect=[None, prior, conflict, lookup])
    monkeypatch.setattr(module, "_audit_upload", AsyncMock())

    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: user
    TestClient(app, raise_server_exceptions=False).post(
        "/api/v1/samples/upload", files={"file": ("thing.bin", b"MZ" * 64)}
    )

    assert seen == {"hash": True, "mime": True}


@pytest.mark.asyncio
async def test_a_sandbox_report_is_read_and_inflated_off_the_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import gzip
    import io

    from app.api.v1 import sandbox_reports as module

    seen: list[bool] = []
    real = module._read_capped

    def watched(file: Any, limit: int) -> bytes:
        seen.append(_not_on_a_loop())
        return real(file, limit)

    monkeypatch.setattr(module, "_read_capped", watched)
    monkeypatch.setattr(module, "_max_report_bytes", AsyncMock(return_value=1024 * 1024))
    upload = MagicMock()
    upload.file = io.BytesIO(gzip.compress(b'{"info": {"id": 1}}'))

    body, payload = await module._read_payload(upload, MagicMock())

    assert seen == [True]
    assert payload == {"info": {"id": 1}}
    assert body == b'{"info": {"id": 1}}'


def test_a_report_over_its_bound_is_still_refused_by_the_route() -> None:
    import io

    from fastapi import HTTPException

    from app.api.v1 import sandbox_reports as module

    upload = MagicMock()
    upload.file = io.BytesIO(b"{" + b" " * 2048 + b"}")
    with pytest.raises(HTTPException) as refused:
        module._read_capped(upload, 1024)
    assert refused.value.status_code == 413
    assert refused.value.detail == "Report too large. Maximum: 0 MB"


# ── one sha's object, decided in order ────────────────────────────


def test_an_upload_and_a_delete_of_one_sha_take_the_same_lock() -> None:
    from app.api.v1 import samples as module

    db = MagicMock()
    db.execute = AsyncMock()
    asyncio.run(module.lock_sample_bytes(db, "a" * 64))

    statement, params = db.execute.await_args.args
    assert "pg_advisory_xact_lock" in str(statement)
    assert params == {"sha": "a" * 64}


def test_an_upload_takes_the_lock_before_it_asks_whether_the_bytes_are_stored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.v1 import samples as module
    from app.database import get_db
    from app.deps import get_current_user

    order: list[str] = []

    async def lock(db: Any, sha256: str) -> None:
        order.append("lock")

    prior = MagicMock()
    prior.scalar_one_or_none.return_value = uuid.uuid4()
    conflict = MagicMock()
    conflict.scalar_one_or_none.return_value = None
    lookup = MagicMock()
    lookup.scalar_one.return_value = MagicMock()

    async def execute(statement: Any, *args: Any) -> Any:
        order.append("query")
        return [prior, conflict, lookup][order.count("query") - 1]

    monkeypatch.setattr(module, "lock_sample_bytes", lock)
    monkeypatch.setattr(module, "_audit_upload", AsyncMock())

    async def _get(name: str) -> Any:
        return {"upload_max_bytes": 1024 * 1024, "upload_allowed_mime_types": []}[name]

    monkeypatch.setattr(module.runtime_config, "get", AsyncMock(side_effect=_get))
    db = MagicMock()
    db.execute = execute
    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: MagicMock(id=uuid.uuid4())
    TestClient(app, raise_server_exceptions=False).post(
        "/api/v1/samples/upload", files={"file": ("thing.bin", b"MZ" * 64)}
    )

    assert order[:2] == ["lock", "query"]


def test_a_delete_takes_the_lock_again_before_it_counts_the_rows_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After the commit that ends the jobs' transaction, the count is taken under the lock."""
    from app.api.v1 import samples as module
    from app.database import get_db
    from app.deps import require_active_user

    order: list[str] = []
    user = MagicMock(id=uuid.uuid4())
    sha256 = "f" * 64
    sample = MagicMock(id=uuid.uuid4(), sha256=sha256, storage_path=f"samples/ff/{sha256}")

    found = MagicMock()
    found.scalar_one_or_none.return_value = sample
    idle = MagicMock()
    idle.scalar.return_value = 0
    none_listed = MagicMock()
    none_listed.scalars.return_value.all.return_value = []
    jobs = MagicMock()
    jobs.scalars.return_value.all.return_value = [uuid.uuid4()]
    shared = MagicMock()
    shared.scalar.return_value = 1
    answers = iter([found, idle, none_listed, jobs, None, shared])

    async def execute(statement: Any, *args: Any) -> Any:
        order.append("count" if "count" in str(statement).lower() else "query")
        return next(answers)

    async def lock(db: Any, sha: str) -> None:
        order.append("lock")

    async def commit() -> None:
        order.append("commit")

    monkeypatch.setattr(module, "lock_sample_bytes", lock)
    monkeypatch.setattr(module, "_minio_client", lambda: MagicMock())
    db = MagicMock(execute=execute, commit=commit, delete=AsyncMock(), flush=AsyncMock())
    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_active_user] = lambda: user
    monkeypatch.setattr(module.audit, "record", AsyncMock())

    response = TestClient(app).delete(f"/api/v1/samples/{sample.id}")

    assert response.status_code == 204, response.text
    last_commit = len(order) - 1 - order[::-1].index("commit")
    assert "lock" in order[:last_commit]
    assert order[last_commit + 1] == "lock"
    assert order[last_commit + 2] == "count"


# ── Alembic reads a DSN as written ─────────────────────────────────


def test_a_dsn_with_a_percent_reads_back_as_written() -> None:
    from alembic.config import Config

    from app.database import config_option_value
    from tests.credential_shapes import password

    dsn = f"postgresql+asyncpg://maljan:{password()}%40x%25@db:5432/maljan"
    config = Config()
    config.set_main_option("sqlalchemy.url", config_option_value(dsn))

    assert config.get_main_option("sqlalchemy.url") == dsn
    assert config.get_section(config.config_ini_section, {})["sqlalchemy.url"] == dsn


def test_alembic_sets_the_url_escaped() -> None:
    from pathlib import Path

    env = (Path(__file__).resolve().parents[2] / "apps/api/alembic/env.py").read_text()
    assert 'set_main_option("sqlalchemy.url", config_option_value(settings.database_url))' in env
