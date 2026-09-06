"""Uploading a sandbox report: limits, sniffing, storage and the hash warning."""

from __future__ import annotations

import gzip
import io
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI, HTTPException, status
from fastapi.testclient import TestClient

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1 import sandbox_reports as module  # noqa: E402

SHA = "a" * 64


def _cape_blob(sha: str = SHA) -> bytes:
    return json.dumps(
        {
            "info": {"version": "CAPEv2 2.4", "id": 4242},
            "target": {"sha256": sha, "name": "x.exe", "md5": "b" * 32},
            "behavior": {"processes": [], "apistats": {}, "generic": []},
            "signatures": [],
            "network": {},
            "CAPE": {"payloads": []},
        }
    ).encode()


def _build_client(db: MagicMock, sample: MagicMock, user: MagicMock) -> TestClient:
    """A router-only app wired the same way the ``client`` fixture builds one.

    Used by the tests below that need their own ``db`` mock (a listing or a
    delete that actually reaches ``db.execute``) instead of the shared
    fixture's bare ``MagicMock``, which is never awaited because ``_load_sample``
    and ``_persist`` are the only DB-touching seams the upload path exercises.

    Overrides ``require_active_user`` the same way ``get_current_user`` is
    overridden — the delete route depends on it now, and this app's ``db`` is a
    stand-in for the *route's own* queries, not a real session that could answer
    ``require_active_user``'s own re-validation query too.
    """
    from app.database import get_db
    from app.deps import get_current_user, require_active_user

    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[require_active_user] = lambda: user
    return TestClient(app)


@pytest.fixture
def client(monkeypatch, tmp_path):
    from app.database import get_db
    from app.deps import get_current_user, require_active_user

    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    user = MagicMock(id=uuid.uuid4())
    sample = MagicMock(id=uuid.uuid4(), sha256=SHA, uploaded_by=user.id)
    db = MagicMock()
    monkeypatch.setattr(module, "_load_sample", MagicMock(return_value=sample))
    stored: dict[str, bytes] = {}
    monkeypatch.setattr(
        module, "_put_object", lambda path, blob, **kw: stored.setdefault(path, blob)
    )
    monkeypatch.setattr(module, "_persist", MagicMock(side_effect=lambda db, row: row))
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: user
    # upload_sandbox_report depends on require_active_user, not get_current_user
    # directly (SEC-TOCTOU-AUTHZ-01) — override it the same trivial way so these
    # tests keep exercising upload behavior, not the re-validation query itself.
    app.dependency_overrides[require_active_user] = lambda: user
    yield TestClient(app), sample, stored


def test_a_cape_json_is_accepted_and_sniffed(client):
    api, sample, stored = client
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json", _cape_blob(), "application/json")},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["format"] == "cape2"
    assert body["task_id"] == "4242"
    assert body["sample_sha256_match"] is True
    assert body["warning"] is None
    assert any(p.startswith(f"sandbox-reports/{SHA[:2]}/{SHA}/") for p in stored)


def test_a_gzipped_report_is_inflated_and_stored_as_json(client):
    api, sample, stored = client
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(_cape_blob())
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json.gz", buf.getvalue(), "application/gzip")},
    )
    assert r.status_code == 201
    assert json.loads(next(iter(stored.values())))["info"]["id"] == 4242


def test_a_hash_mismatch_is_a_warning_and_not_a_refusal(client):
    api, sample, _ = client
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json", _cape_blob("c" * 64), "application/json")},
    )
    assert r.status_code == 201
    assert r.json()["sample_sha256_match"] is False
    assert "does not match" in r.json()["warning"]


def _cape_blob_nested_target(sha: str = SHA) -> bytes:
    """A real CAPEv2 report: sample identity nested under ``target.file``.

    ``target`` itself carries only ``category``/``file`` — empirically the
    only shape every report under ``data/cape_reports/`` actually has (see
    ``loaders/cape2_client.py``); ``_cape_blob`` above is the simplified flat
    shape the older fixtures use.
    """
    return json.dumps(
        {
            "info": {"version": "CAPEv2 2.4", "id": 4243},
            "target": {
                "category": "file",
                "file": {"sha256": sha, "name": "x.exe", "md5": "b" * 32, "type": "PE32"},
            },
            "behavior": {"processes": [], "apistats": {}, "generic": []},
            "signatures": [],
            "network": {},
            "CAPE": {"payloads": []},
        }
    ).encode()


def test_a_nested_cape_target_hash_is_read_and_matched(client):
    """L1 regression: CAPE nests the hash at ``target.file.sha256``."""
    api, sample, stored = client
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json", _cape_blob_nested_target(), "application/json")},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["sample_sha256_match"] is True
    assert body["warning"] is None


def test_a_nested_cape_target_hash_mismatch_still_warns(client):
    api, sample, _ = client
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json", _cape_blob_nested_target("c" * 64), "application/json")},
    )
    assert r.status_code == 201
    assert r.json()["sample_sha256_match"] is False
    assert "does not match" in r.json()["warning"]


def test_an_unrecognised_format_is_refused(client):
    api, sample, _ = client
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("x.json", b'{"hello": "world"}', "application/json")},
    )
    assert r.status_code == 415
    assert "cape2" in r.json()["detail"]


def test_a_non_json_body_is_refused_before_anything_is_stored(client):
    api, sample, stored = client
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("x.json", b"not json at all", "application/json")},
    )
    assert r.status_code == 400
    assert stored == {}


def test_the_size_cap_is_enforced_while_streaming(client, monkeypatch):
    api, sample, stored = client
    monkeypatch.setattr(module, "_max_report_bytes", lambda: 64)
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json", _cape_blob(), "application/json")},
    )
    assert r.status_code == 413
    assert stored == {}


def test_the_inflated_size_cap_is_enforced_too(client, monkeypatch):
    api, sample, stored = client
    monkeypatch.setattr(module, "_max_report_bytes", lambda: 4096)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(b'{"info": {"version": "CAPEv2"}, "pad": "' + b"A" * 200_000 + b'"}')
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json.gz", buf.getvalue(), "application/gzip")},
    )
    assert r.status_code == 413
    assert stored == {}


# ── Fix round 1, Important 1: a crafted ``info.id`` longer than the
# ``task_id`` column's width (128) must be bounded before it is ever
# persisted. The pre-fix code stored the report object in MinIO *before*
# inserting the row, so a width violation on insert (which only Postgres, not
# this suite's SQLite, would actually raise) left an object nothing would ever
# reference and surfaced as an uncontrolled 500. Both tests below assert on
# the code path — bounding the value, and ordering the insert before the
# storage write — rather than on a database enforcing anything, since SQLite
# does not.


def test_an_overlong_task_id_is_truncated_before_it_is_stored(client):
    api, sample, _ = client
    payload = {
        "info": {"version": "CAPEv2 2.4", "id": "X" * 500},
        "target": {"sha256": sample.sha256, "name": "x.exe", "md5": "b" * 32},
        "behavior": {"processes": [], "apistats": {}, "generic": []},
        "signatures": [],
        "network": {},
        "CAPE": {"payloads": []},
    }
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json", json.dumps(payload).encode(), "application/json")},
    )
    assert r.status_code == 201, r.text
    assert r.json()["task_id"] == "X" * module._TASK_ID_MAX_LENGTH


def test_a_persist_failure_leaves_no_orphaned_storage_object(client, monkeypatch):
    api, sample, stored = client

    def _boom(db, row):
        raise RuntimeError("simulated persist failure")

    monkeypatch.setattr(module, "_persist", MagicMock(side_effect=_boom))
    with pytest.raises(RuntimeError):
        api.post(
            f"/api/v1/samples/{sample.id}/sandbox-reports",
            files={"file": ("report.json", _cape_blob(), "application/json")},
        )
    assert stored == {}


# ── Fix round 1, Important 2: the mutating routes must re-validate that the
# account is still active (SEC-TOCTOU-AUTHZ-01, ``require_active_user`` in
# ``app/deps.py``) rather than trust the JWT/API-key lookup alone. The
# read-only listing route correctly does not carry this cost.


def test_mutating_routes_require_an_active_user_but_listing_does_not(monkeypatch):
    from app.database import get_db
    from app.deps import get_current_user, require_active_user

    def _deactivated() -> None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "User account is deactivated")

    user = MagicMock(id=uuid.uuid4())
    sample = MagicMock(id=uuid.uuid4(), sha256=SHA, uploaded_by=user.id)
    monkeypatch.setattr(module, "_load_sample", MagicMock(return_value=sample))

    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[require_active_user] = _deactivated
    api = TestClient(app)

    upload_r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json", _cape_blob(), "application/json")},
    )
    assert upload_r.status_code == 403

    delete_r = api.delete(f"/api/v1/samples/{sample.id}/sandbox-reports/{uuid.uuid4()}")
    assert delete_r.status_code == 403

    # Listing depends on get_current_user only — require_active_user staying
    # broken above must not affect it.
    list_result = MagicMock()
    list_result.scalars.return_value.all.return_value = []
    list_db = MagicMock()
    list_db.execute = AsyncMock(return_value=list_result)
    app.dependency_overrides[get_db] = lambda: list_db
    list_r = api.get(f"/api/v1/samples/{sample.id}/sandbox-reports")
    assert list_r.status_code == 200


# ── Beyond the brief's literal listing: the pre-flight ruling in the task's
# own context is that ``sample_sha256_match`` is a *stored* column precisely so
# a mismatch found at upload survives into a later listing. That can't be
# exercised through the shared ``client`` fixture above — its ``db`` is a bare
# ``MagicMock`` never awaited, because ``_load_sample``/``_persist`` are the
# only DB-touching seams the upload path calls. The listing and delete routes
# call ``db.execute`` directly, so these tests wire an ``AsyncMock`` for it.


def test_the_hash_mismatch_warning_survives_into_the_listing(monkeypatch):
    user = MagicMock(id=uuid.uuid4())
    sample = MagicMock(id=uuid.uuid4(), sha256=SHA, uploaded_by=user.id)
    monkeypatch.setattr(module, "_load_sample", MagicMock(return_value=sample))

    matching = MagicMock(
        id=uuid.uuid4(),
        format="cape2",
        task_id="1",
        size_bytes=10,
        sample_sha256_match=True,
        created_at=datetime.now(UTC),
    )
    mismatching = MagicMock(
        id=uuid.uuid4(),
        format="cape2",
        task_id="2",
        size_bytes=20,
        sample_sha256_match=False,
        created_at=datetime.now(UTC),
    )
    result = MagicMock()
    result.scalars.return_value.all.return_value = [matching, mismatching]
    db = MagicMock()
    db.execute = AsyncMock(return_value=result)

    r = _build_client(db, sample, user).get(f"/api/v1/samples/{sample.id}/sandbox-reports")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2
    items = {item["task_id"]: item for item in body["items"]}
    assert items["1"]["sample_sha256_match"] is True
    assert items["1"]["warning"] is None
    assert items["2"]["sample_sha256_match"] is False
    assert "does not match" in items["2"]["warning"]


def test_deleting_a_report_removes_it_and_the_stored_object(monkeypatch):
    user = MagicMock(id=uuid.uuid4())
    sample = MagicMock(id=uuid.uuid4(), sha256=SHA, uploaded_by=user.id)
    monkeypatch.setattr(module, "_load_sample", MagicMock(return_value=sample))

    report_id = uuid.uuid4()
    row = MagicMock(id=report_id, storage_path=f"sandbox-reports/{SHA[:2]}/{SHA}/{report_id}.json")
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    db = MagicMock()
    db.execute = AsyncMock(return_value=result)
    minio = MagicMock()
    monkeypatch.setattr(module, "_minio_client", lambda: minio)

    r = _build_client(db, sample, user).delete(
        f"/api/v1/samples/{sample.id}/sandbox-reports/{report_id}"
    )
    assert r.status_code == 204
    minio.remove_object.assert_called_once_with(module.settings.minio_bucket, row.storage_path)


def test_deleting_an_unknown_report_is_a_404(monkeypatch):
    user = MagicMock(id=uuid.uuid4())
    sample = MagicMock(id=uuid.uuid4(), sha256=SHA, uploaded_by=user.id)
    monkeypatch.setattr(module, "_load_sample", MagicMock(return_value=sample))

    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db = MagicMock()
    db.execute = AsyncMock(return_value=result)

    r = _build_client(db, sample, user).delete(
        f"/api/v1/samples/{sample.id}/sandbox-reports/{uuid.uuid4()}"
    )
    assert r.status_code == 404
