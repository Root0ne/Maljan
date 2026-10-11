"""The upload route reads a report's format, task id and target hash from the declarations.

A third format, declared only as settings data, is accepted, named, given its
task id and checked against the sample's hash by the route as it stands. The
declared formats, with their signature scales, are served for any client.
"""

from __future__ import annotations

import json
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import sandbox_reports as module
from maljan.core.config import SandboxUploadConfig

SHA = "c" * 64

ACME = {
    "name": "acme",
    "detect": [
        [{"path": "/producer/name", "contains": "acme"}, {"path": "/run", "types": ["object"]}]
    ],
    "task_id_paths": ["/run/ticket"],
    "target_sha256_paths": ["/subject/digests/sha256"],
    "reader": "cape2",
    "signature_scale": {"name": "Acme 1–4", "rungs": ["Low", "Medium", "High", "Critical"]},
}


def _acme(sha: str = SHA) -> bytes:
    return json.dumps(
        {
            "producer": {"name": "ACME detonator"},
            "run": {"ticket": "T-77"},
            "subject": {"digests": {"sha256": sha}},
            "info": {"id": 1},
            "behavior": {},
        }
    ).encode()


def _client(monkeypatch: pytest.MonkeyPatch, upload: SandboxUploadConfig) -> tuple[TestClient, Any]:
    from app.database import get_db
    from app.deps import get_current_user, require_active_user

    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    app.include_router(module.formats_router, prefix="/api/v1")
    user = MagicMock(id=uuid.uuid4())
    sample = MagicMock(id=uuid.uuid4(), sha256=SHA, uploaded_by=user.id)
    monkeypatch.setattr(module, "_load_sample", MagicMock(return_value=sample))
    monkeypatch.setattr(module, "_upload_settings", AsyncMock(return_value=upload))
    monkeypatch.setattr(module, "put_object", AsyncMock())
    monkeypatch.setattr(module, "_persist", MagicMock(side_effect=lambda db, row: row))
    monkeypatch.setattr(module.audit, "record", AsyncMock())
    app.dependency_overrides[get_db] = lambda: MagicMock()
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[require_active_user] = lambda: user
    return TestClient(app), sample


def _upload(api: TestClient, sample: Any, blob: bytes) -> Any:
    return api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json", blob, "application/json")},
    )


def test_a_format_declared_only_as_data_is_accepted_named_and_read(monkeypatch):
    upload = SandboxUploadConfig.model_validate(
        {"formats": [ACME], "allowed_formats": ["cape2", "cuckoo", "triage", "acme"]}
    )
    api, sample = _client(monkeypatch, upload)
    r = _upload(api, sample, _acme())
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["format"] == "acme"
    assert body["task_id"] == "T-77"
    assert body["sample_sha256_match"] is True
    assert body["warning"] is None


def test_a_declared_format_reads_a_disagreeing_hash_as_a_warning(monkeypatch):
    upload = SandboxUploadConfig.model_validate({"formats": [ACME], "allowed_formats": ["acme"]})
    api, sample = _client(monkeypatch, upload)
    r = _upload(api, sample, _acme("d" * 64))
    assert r.status_code == 201, r.text
    assert r.json()["sample_sha256_match"] is False
    assert r.json()["warning"]


def test_a_declared_format_outside_the_allowed_list_is_refused(monkeypatch):
    upload = SandboxUploadConfig.model_validate({"formats": [ACME]})
    api, sample = _client(monkeypatch, upload)
    r = _upload(api, sample, _acme())
    assert r.status_code == 415
    assert "cape2, cuckoo, triage" in r.json()["detail"]


def test_without_the_declaration_the_payload_is_not_the_invented_format(monkeypatch):
    api, sample = _client(monkeypatch, SandboxUploadConfig(allowed_formats=["acme"]))
    assert _upload(api, sample, _acme()).status_code == 415


def test_the_declared_formats_are_served_in_the_order_they_are_tried(monkeypatch):
    upload = SandboxUploadConfig.model_validate(
        {"formats": [ACME], "allowed_formats": ["triage", "acme"]}
    )
    api, _sample = _client(monkeypatch, upload)
    r = api.get("/api/v1/sandbox-report-formats")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 4
    items = {item["name"]: item for item in body["items"]}
    assert [item["name"] for item in body["items"]] == ["acme", "triage", "cape2", "cuckoo"]
    assert items["acme"]["builtin"] is False and items["acme"]["allowed"] is True
    assert items["acme"]["signature_scale"] == {
        "name": "Acme 1–4",
        "max": 4,
        "rungs": ["Low", "Medium", "High", "Critical"],
    }
    assert items["acme"]["task_id_paths"] == ["/run/ticket"]
    assert items["acme"]["detect"][0][0]["contains"] == "acme"
    assert items["cape2"]["builtin"] is True and items["cape2"]["allowed"] is False
    assert items["cape2"]["signature_scale"]["name"] == "CAPE 1–3"
    assert items["triage"]["signature_scale"]["max"] == 10
    assert items["cape2"]["target_sha256_paths"] == ["/target/file/sha256", "/target/sha256"]
