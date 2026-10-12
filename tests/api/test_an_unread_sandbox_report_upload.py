"""An upload no format recognises: refused by default, accepted unread with a proposal when allowed.

With ``"unread"`` in ``sandbox.upload.allowed_formats`` the report is stored as
format ``unread`` and the answer carries a proposed declaration; an admin
accepts it (as written or edited), which saves the declaration with its name
allowed and reads the upload as it, only where the declaration recognises the
report. Without the opt-in nothing changes: 415.
"""

from __future__ import annotations

import json
import pathlib
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import sandbox_reports as module
from maljan.core.config import SandboxConfig

SHA = "a" * 64
FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "sandbox"


def _blob(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _sandbox(allowed: list[str]) -> SandboxConfig:
    return SandboxConfig.model_validate({"upload": {"allowed_formats": allowed}})


@pytest.fixture(autouse=True)
def _fresh_core_settings_cache():
    from app.services.settings_service import core_settings_cache

    core_settings_cache.invalidate()
    yield
    core_settings_cache.invalidate()


def _client(monkeypatch: pytest.MonkeyPatch, allowed: list[str]) -> tuple[Any, Any, dict[str, Any]]:
    from app.database import get_db
    from app.deps import get_current_user, require_active_user, require_admin

    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    app.include_router(module.formats_router, prefix="/api/v1")
    user = MagicMock(id=uuid.uuid4())
    sample = MagicMock(id=uuid.uuid4(), sha256=SHA, uploaded_by=user.id)
    state: dict[str, Any] = {"stored": {}, "rows": [], "sandbox": _sandbox(allowed)}

    async def _settings(_db: Any) -> SandboxConfig:
        return state["sandbox"]

    async def _store(path: str, blob: bytes, **kw: object) -> None:
        state["stored"][path] = blob

    def _persist(_db: Any, row: Any) -> Any:
        state["rows"].append(row)
        return row

    async def _owned(_db: Any, _sample: Any, report_id: uuid.UUID) -> Any:
        return next(row for row in state["rows"] if row.id == report_id)

    async def _get(path: str) -> bytes:
        return state["stored"][path]

    monkeypatch.setattr(module, "_sandbox_settings", _settings)
    monkeypatch.setattr(module, "_load_sample", MagicMock(return_value=sample))
    monkeypatch.setattr(module, "put_object", _store)
    monkeypatch.setattr(module, "_persist", MagicMock(side_effect=_persist))
    monkeypatch.setattr(module, "_owned_row", _owned)
    monkeypatch.setattr(module, "get_object_async", _get)
    monkeypatch.setattr(module.audit, "record", AsyncMock())
    db = MagicMock()
    db.flush = AsyncMock()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[require_active_user] = lambda: user
    app.dependency_overrides[require_admin] = lambda: user
    return TestClient(app), sample, state


def _upload(api: Any, sample: Any, blob: bytes) -> Any:
    return api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json", blob, "application/json")},
    )


def test_without_the_opt_in_an_unrecognised_report_is_refused_as_before(monkeypatch) -> None:
    api, sample, state = _client(monkeypatch, ["cape2", "cuckoo", "triage"])
    r = _upload(api, sample, _blob("unread_nested_report.json"))
    assert r.status_code == 415
    assert "Unrecognised sandbox report format" in r.json()["detail"]
    assert state["stored"] == {}


@pytest.mark.parametrize("name", ["unread_nested_report.json", "unread_flat_report.json"])
def test_with_the_opt_in_it_is_stored_unread_with_a_proposal(monkeypatch, name: str) -> None:
    api, sample, state = _client(monkeypatch, ["cape2", "unread"])
    r = _upload(api, sample, _blob(name))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["format"] == "unread"
    assert body["warning"] == module.UNREAD_WARNING
    proposal = body["proposal"]
    assert proposal["declaration"]["reader"] == "generic"
    assert proposal["fields"]["mapping.processes"]["evidence"]
    assert state["rows"][0].format == "unread"
    assert len(state["stored"]) == 1


def test_a_recognised_report_is_read_as_its_format_even_with_the_opt_in(monkeypatch) -> None:
    api, sample, _state = _client(monkeypatch, ["cape2", "cuckoo", "unread"])
    cape = _blob("cape2_synthetic.json")
    r = _upload(api, sample, cape)
    assert r.status_code == 201
    assert r.json()["format"] in ("cape2", "cuckoo")
    assert r.json()["proposal"] is None


def test_a_recognised_format_not_allowed_is_still_refused_with_the_opt_in(monkeypatch) -> None:
    # The opt-in reads what no format recognises; it never reads a format the
    # operator left out of the allowed ones.
    api, sample, state = _client(monkeypatch, ["unread"])
    r = _upload(api, sample, _blob("cape2_synthetic.json"))
    assert r.status_code == 415
    assert state["stored"] == {}


def test_a_ten_thousand_deep_upload_is_accepted_unread_and_never_raises(monkeypatch) -> None:
    api, sample, state = _client(monkeypatch, ["unread"])
    depth = 10_000
    deep = '{"deep": ' + "[" * depth + "1" + "]" * depth + ', "meta": {"k": 1}}'
    r = _upload(api, sample, deep.encode())
    assert r.status_code == 201, r.text
    assert r.json()["format"] == "unread"
    assert len(state["stored"]) == 1


def _accept(api: Any, sample: Any, row: Any, declaration: dict[str, Any]) -> Any:
    return api.post(
        "/api/v1/sandbox-report-formats/accept",
        json={"declaration": declaration, "sample_id": str(sample.id), "report_id": str(row.id)},
    )


def test_accepting_the_proposal_saves_it_and_reads_the_upload_as_it(monkeypatch) -> None:
    api, sample, state = _client(monkeypatch, ["cape2", "unread"])
    saved = AsyncMock()
    monkeypatch.setattr("app.services.settings_service.SettingsService.save", saved)
    body = _upload(api, sample, _blob("unread_flat_report.json")).json()
    row = state["rows"][0]
    declaration = body["proposal"]["declaration"]
    declaration["name"] = "acme_flat"  # an operator's edit
    r = _accept(api, sample, row, declaration)
    assert r.status_code == 200, r.text
    assert r.json()["format"] == "acme_flat"
    assert row.format == "acme_flat"
    assert row.task_id == "99812"
    changes = saved.await_args.args[0]
    assert [fmt["name"] for fmt in changes["sandbox.report_formats"]] == ["acme_flat"]
    assert changes["sandbox.upload.allowed_formats"] == ["cape2", "unread", "acme_flat"]


def test_a_declaration_that_does_not_recognise_the_upload_saves_nothing(monkeypatch) -> None:
    api, sample, state = _client(monkeypatch, ["unread"])
    saved = AsyncMock()
    monkeypatch.setattr("app.services.settings_service.SettingsService.save", saved)
    body = _upload(api, sample, _blob("unread_flat_report.json")).json()
    declaration = body["proposal"]["declaration"]
    declaration["detect"] = [[{"path": "/no_such_block", "types": ["object"]}]]
    r = _accept(api, sample, state["rows"][0], declaration)
    assert r.status_code == 422
    assert "does not recognise" in r.json()["detail"]
    saved.assert_not_awaited()
    assert state["rows"][0].format == "unread"


def test_a_declaration_that_does_not_validate_saves_nothing(monkeypatch) -> None:
    api, sample, state = _client(monkeypatch, ["unread"])
    saved = AsyncMock()
    monkeypatch.setattr("app.services.settings_service.SettingsService.save", saved)
    _upload(api, sample, _blob("unread_flat_report.json"))
    r = _accept(api, sample, state["rows"][0], {"name": "Bad Name", "detect": []})
    assert r.status_code == 422
    saved.assert_not_awaited()


def test_accepting_needs_an_admin() -> None:
    from app.deps import require_admin

    route = next(
        r for r in module.formats_router.routes if getattr(r, "path", "").endswith("/accept")
    )
    assert any(dep.call is require_admin for dep in route.dependant.dependencies)


def test_the_listing_says_an_unread_row_is_unread(monkeypatch) -> None:
    from app.database import get_db
    from app.deps import get_current_user

    user = MagicMock(id=uuid.uuid4())
    sample = MagicMock(id=uuid.uuid4(), sha256=SHA, uploaded_by=user.id)
    monkeypatch.setattr(module, "_load_sample", MagicMock(return_value=sample))
    row = MagicMock(
        id=uuid.uuid4(),
        format="unread",
        task_id=None,
        size_bytes=10,
        sample_sha256_match=False,
        created_at=datetime.now(UTC),
    )
    result = MagicMock()
    result.scalars.return_value.all.return_value = [row]
    db = MagicMock()
    db.execute = AsyncMock(return_value=result)
    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: user
    body = TestClient(app).get(f"/api/v1/samples/{sample.id}/sandbox-reports").json()
    assert body["items"][0]["warning"] == module.UNREAD_WARNING
    assert json.dumps(body).count("does not match") == 0


# A report shaped as a built-in's blocks, but missing what the built-in tests.
_BEHAVIOR_NETWORK = {
    "behavior": {"processes": [{"pid": 7, "ppid": 1, "name": "a.exe"}], "summary": {"x": 1}},
    "network": {"dns": [{"request": "own-i2.example", "type": "A", "answers": []}]},
}


def _sniffed(formats: list[Any]) -> str:
    from maljan.core.report_formats import ReportFormat, sniff
    from maljan.providers.sandbox.readers import sandbox_formats

    cape = json.loads(_blob("cape2_synthetic.json"))
    found = sniff(cape, sandbox_formats([ReportFormat.model_validate(f) for f in formats]))
    assert found is not None
    return found.name


@pytest.mark.parametrize("loosened", [False, True], ids=["as-proposed", "loosened"])
def test_an_accepted_format_never_takes_a_built_in_report(monkeypatch, loosened: bool) -> None:
    before = _sniffed([])
    api, sample, state = _client(monkeypatch, ["cape2", "cuckoo", "unread"])
    saved = AsyncMock()
    monkeypatch.setattr("app.services.settings_service.SettingsService.save", saved)
    body = _upload(api, sample, json.dumps(_BEHAVIOR_NETWORK).encode()).json()
    assert body["format"] == "unread"
    declaration = body["proposal"]["declaration"]
    if loosened:
        # An operator's edit: tested by the two blocks alone, as a built-in's report has them.
        declaration["detect"] = [
            [
                {"path": "/behavior", "types": ["object"]},
                {"path": "/network", "types": ["object"]},
            ]
        ]
    r = _accept(api, sample, state["rows"][0], declaration)
    assert r.status_code == 200, r.text
    accepted = saved.await_args.args[0]["sandbox.report_formats"]
    assert _sniffed(accepted) == before


def test_a_declaration_a_built_in_also_claims_for_the_report_is_refused(monkeypatch) -> None:
    api, sample, state = _client(monkeypatch, ["cape2", "cuckoo", "unread"])
    saved = AsyncMock()
    monkeypatch.setattr("app.services.settings_service.SettingsService.save", saved)
    body = _upload(api, sample, json.dumps(_BEHAVIOR_NETWORK).encode()).json()
    row = state["rows"][0]
    # The stored report as a built-in now reads it (the built-in's own test passes).
    claimed = {**_BEHAVIOR_NETWORK, "info": {"id": 3}}
    state["stored"][row.storage_path] = json.dumps(claimed).encode()
    r = _accept(api, sample, row, body["proposal"]["declaration"])
    assert r.status_code == 422
    assert "'cuckoo'" in r.json()["detail"]
    assert "nothing was saved" in r.json()["detail"]
    saved.assert_not_awaited()
    assert row.format == "unread"


def test_a_declaration_whose_mapping_reads_nothing_is_refused(monkeypatch) -> None:
    api, sample, state = _client(monkeypatch, ["unread"])
    saved = AsyncMock()
    monkeypatch.setattr("app.services.settings_service.SettingsService.save", saved)
    body = _upload(api, sample, _blob("unread_flat_report.json")).json()
    declaration = body["proposal"]["declaration"]
    declaration["mapping"] = {
        "target_sha256": "$['sample_info']['no_such_hash']",
        "processes": "$['no_such_list'][*]",
    }
    r = _accept(api, sample, state["rows"][0], declaration)
    assert r.status_code == 422
    assert "selects nothing" in r.json()["detail"]
    saved.assert_not_awaited()
    assert state["rows"][0].format == "unread"


def test_an_admin_reads_and_accepts_any_stored_report_s_proposal(monkeypatch) -> None:
    api, sample, state = _client(monkeypatch, ["unread"])
    saved = AsyncMock()
    monkeypatch.setattr("app.services.settings_service.SettingsService.save", saved)
    _upload(api, sample, _blob("unread_flat_report.json"))
    row = state["rows"][0]
    got = api.get(f"/api/v1/samples/{sample.id}/sandbox-reports/{row.id}/proposal")
    assert got.status_code == 200
    assert got.json()["proposal"]["declaration"]["reader"] == "generic"
    r = _accept(api, sample, row, got.json()["proposal"]["declaration"])
    assert r.status_code == 200, r.text
    calls = module._load_sample.call_args_list
    # The proposal and the accept reach any sample for an admin; the upload only the user's own.
    assert [c.kwargs.get("any_for_admin", False) for c in calls] == [False, True, True]


@pytest.mark.parametrize(("role", "owner_only"), [("admin", False), ("analyst", True)])
def test_only_an_admin_reaches_a_sample_they_did_not_upload(role: str, owner_only: bool) -> None:
    import asyncio

    seen: list[str] = []

    async def _execute(query: Any) -> Any:
        seen.append(str(query).split("WHERE", 1)[1])
        result = MagicMock()
        result.scalar_one_or_none.return_value = MagicMock()
        return result

    db = MagicMock()
    db.execute = _execute
    user = MagicMock(id=uuid.uuid4(), role=role)
    asyncio.run(module._load_sample(db, uuid.uuid4(), user, any_for_admin=True))
    asyncio.run(module._load_sample(db, uuid.uuid4(), user))
    assert ("uploaded_by" in seen[0]) is owner_only
    assert "uploaded_by" in seen[1]


def test_concurrent_accepts_keep_every_declaration(monkeypatch) -> None:
    import asyncio

    import httpx

    api, sample, state = _client(monkeypatch, ["unread"])
    flat = _upload(api, sample, _blob("unread_flat_report.json")).json()
    nested = _upload(api, sample, _blob("unread_nested_report.json")).json()

    async def _save(self: Any, changes: dict[str, Any], **_kw: Any) -> None:
        # The write lands after a pause, as a database round trip does.
        await asyncio.sleep(0.05)
        state["sandbox"] = SandboxConfig.model_validate(
            {
                "report_formats": changes["sandbox.report_formats"],
                "upload": {"allowed_formats": changes["sandbox.upload.allowed_formats"]},
            }
        )

    monkeypatch.setattr("app.services.settings_service.SettingsService.save", _save)

    async def _both() -> list[Any]:
        transport = httpx.ASGITransport(app=api.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            return list(
                await asyncio.gather(
                    *(
                        client.post(
                            "/api/v1/sandbox-report-formats/accept",
                            json={
                                "declaration": body["proposal"]["declaration"],
                                "sample_id": str(sample.id),
                                "report_id": str(row.id),
                            },
                        )
                        for body, row in zip((flat, nested), state["rows"], strict=True)
                    )
                )
            )

    answers = asyncio.run(_both())
    assert [a.status_code for a in answers] == [200, 200], [a.text for a in answers]
    names = {fmt.name for fmt in state["sandbox"].report_formats}
    assert names == {
        flat["proposal"]["declaration"]["name"],
        nested["proposal"]["declaration"]["name"],
    }


def test_the_upload_body_is_read_off_the_event_loop(monkeypatch) -> None:
    import asyncio

    api, sample, _state = _client(monkeypatch, ["unread"])
    on_loop: list[bool] = []
    real = module.loads

    def _loads(text: Any) -> Any:
        try:
            asyncio.get_running_loop()
            on_loop.append(True)
        except RuntimeError:
            on_loop.append(False)
        return real(text)

    monkeypatch.setattr(module, "loads", _loads)
    assert _upload(api, sample, _blob("unread_flat_report.json")).status_code == 201
    assert on_loop == [False]
