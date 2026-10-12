"""What was stored, shipped or exported before is read leniently; a new edit is strict.

A provider block's tool declarations are stored as typed, so an install may
hold a declaration with a key this version does not read. That row must keep
loading, jobs must keep running, an unrelated save must go through and an
export carrying it must import, each leaving the key out with a warning;
while a new hand edit that adds such a key is still refused.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models import RuntimeSetting
from app.services import settings_service as svc
from maljan.core import tool_declarations

LEAF = "core.static.ghidra.tool_facts"
STORED = {"decompile_function": {"kind": "decompile", "note": "kept from an older version"}}


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> Any:
        return SimpleNamespace(all=lambda: list(self._rows))


def _db(rows: list[Any]) -> Any:
    db = MagicMock()
    db.execute = AsyncMock(return_value=_Result(rows))
    db.add = MagicMock()
    db.delete = AsyncMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    return db


def _stored_row() -> RuntimeSetting:
    return RuntimeSetting(key=LEAF, value=STORED, is_secret=False)


@pytest.fixture(autouse=True)
def _fresh_warnings() -> None:
    tool_declarations._WARNED.clear()


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "_audit", AsyncMock())


def test_the_stored_row_builds_and_jobs_run(caplog: pytest.LogCaptureFixture) -> None:
    import logging

    from app.worker.analysis_worker import build_job_settings
    from maljan.core.settings_overrides import build_settings

    with caplog.at_level(logging.WARNING, logger="maljan"):
        built = build_settings({"static.ghidra.tool_facts": STORED})
        job = build_job_settings({"static.ghidra.tool_facts": STORED}, None)
    for settings in (built, job):
        facts = settings.static.ghidra.tool_facts["decompile_function"]
        assert facts.kind == "decompile"
    warnings = [r.getMessage() for r in caplog.records if "left out" in r.getMessage()]
    assert warnings and "note" in warnings[0] and "decompile_function" in warnings[0]


@pytest.mark.asyncio
async def test_an_unrelated_save_over_the_stored_row_goes_through() -> None:
    db = _db([_stored_row()])
    result = await svc.SettingsService(db).save(
        {"core.negotiation.max_iterations": 5}, user_id=uuid.uuid4(), ip=None
    )
    assert result.applied == ["core.negotiation.max_iterations"]
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_resending_the_stored_leaf_as_stored_or_as_shown_goes_through() -> None:
    from maljan.core.tool_declarations import ToolFacts

    shown = {
        tool: ToolFacts.model_validate(raw).model_dump(mode="json") for tool, raw in STORED.items()
    }
    for value in (STORED, shown):
        db = _db([_stored_row()])
        result = await svc.SettingsService(db).save({LEAF: value}, user_id=uuid.uuid4(), ip=None)
        assert result.applied == [LEAF]


@pytest.mark.asyncio
async def test_a_new_hand_edit_with_an_unknown_key_is_still_refused() -> None:
    from maljan.core.settings_overrides import shipped_tool_facts

    db = _db([_stored_row()])
    # The console edits the leaf as the API serves it: the stored whole map
    # as the changes that put the same in force.
    served = svc.served_tool_facts(STORED, shipped_tool_facts("static.ghidra"))
    edit = {**served, "new_tool": {"kind": "strings", "nott": "a typo"}}
    with pytest.raises(svc.SettingsValidationError) as refused:
        await svc.SettingsService(db).save({LEAF: edit}, user_id=uuid.uuid4(), ip=None)
    assert set(refused.value.errors) == {f"{LEAF}.new_tool.nott"}
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_new_hand_edit_a_kind_would_be_needed_to_read_is_refused() -> None:
    db = _db([])
    for declared, field in (
        ({}, ""),
        ({"rows": "/m/*"}, ""),
        ({"display_name": "Scanner", "report_sections": ["commands"]}, ""),
    ):
        with pytest.raises(svc.SettingsValidationError) as refused:
            await svc.SettingsService(db).save(
                {LEAF: {"t": declared}}, user_id=uuid.uuid4(), ip=None
            )
        assert set(refused.value.errors) == {f"{LEAF}.t{field}"}


def test_the_server_map_refuses_only_the_entries_a_save_adds_or_changes() -> None:
    from app.services.server_map import ServerMapError, validate_server_map

    stored = {
        "invented": {
            "command": "invented-server",
            "tool_facts": {"t": {"kind": "strings", "note": "older"}},
        }
    }
    # Left as stored: read leniently, saved without the key.
    saved = validate_server_map(stored, stored=stored)
    assert "note" not in saved["invented"]["tool_facts"]["t"]
    # Added by this save: refused.
    edited = {
        "invented": {
            "command": "invented-server",
            "tool_facts": {
                "t": {"kind": "strings", "note": "older"},
                "u": {"kind": "strings", "nott": "a typo"},
            },
        }
    }
    with pytest.raises(ServerMapError) as refused:
        validate_server_map(edited, stored=stored)
    assert set(refused.value.errors) == {"invented.tool_facts.u.nott"}


def _imported(
    document_format: str, *, marked: bool = False
) -> tuple[dict[str, Any], dict[str, str]]:
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(
        id="00000000-0000-0000-0000-000000000001"
    )
    app.dependency_overrides[get_db] = lambda: MagicMock()
    mark = tool_declarations.with_mark if marked else dict
    exported = {
        LEAF: mark(STORED),
        "core.mcp.servers": {
            "invented": {
                "command": "invented-server",
                "tool_facts": mark({"t": {"kind": "strings", "note": "older"}, "e": {"knd": "x"}}),
            }
        },
    }
    with (
        patch(
            "app.api.v1.settings.SettingsService.save",
            AsyncMock(return_value=svc.SaveResult([LEAF, "core.mcp.servers"], {})),
        ) as save,
        patch("app.api.v1.settings.audit_record", AsyncMock()),
    ):
        response = TestClient(app).post(
            "/api/v1/settings/import",
            json={"format": document_format, "values": exported},
        )
    assert response.status_code == 200
    return save.call_args.args[0], response.json()["warnings"]


def test_an_import_leaves_the_unknown_key_out_and_says_so() -> None:
    saved, warnings = _imported("maljan-settings/2", marked=True)
    # What is left of the provider's declaration is what it ships: no change.
    assert saved[LEAF] == tool_declarations.with_mark({})
    assert saved["core.mcp.servers"]["invented"]["tool_facts"] == tool_declarations.with_mark(
        {"t": {"kind": "strings"}}
    )
    assert "note" in warnings[f"{LEAF}.decompile_function"]
    assert "note" in warnings["core.mcp.servers.invented.tool_facts.t"]
    assert "declares nothing" in warnings["core.mcp.servers.invented.tool_facts.e"]


@pytest.mark.parametrize("document_format", ["maljan-settings/1", "maljan-settings/2"])
def test_an_import_written_whole_keeps_reading_whole(document_format: str) -> None:
    """A ``/1`` document, and a map of a ``/2`` one without the mark, are whole maps."""
    from maljan.core.settings_overrides import shipped_tool_facts

    saved, warnings = _imported(document_format)
    shipped = shipped_tool_facts("static.ghidra")
    # The map was the provider's whole map: every shipped tool it lacks was
    # removed, and the one it holds reads as written, its other fields at
    # their default rather than the shipped value.
    assert tool_declarations.holds_changes(saved[LEAF])
    removed = {
        tool
        for tool, change in tool_declarations.without_mark(saved[LEAF]).items()
        if change is None
    }
    assert removed == set(shipped) - {"decompile_function"}
    held = saved[LEAF]["decompile_function"]
    assert held and "kind" not in held
    assert all(value in ({}, [], "", None, False) for value in held.values())
    assert saved["core.mcp.servers"]["invented"]["tool_facts"] == tool_declarations.with_mark(
        {"t": {"kind": "strings"}}
    )
    assert "note" in warnings[f"{LEAF}.decompile_function"]


@pytest.mark.asyncio
async def test_the_cleaned_import_then_saves() -> None:
    values, _warnings = svc.lenient_imported_declarations({LEAF: STORED})
    db = _db([])
    result = await svc.SettingsService(db).save(values, user_id=uuid.uuid4(), ip=None)
    assert result.applied == [LEAF]


def test_every_import_warning_about_one_tool_is_kept() -> None:
    values, warnings = svc.lenient_imported_declarations(
        {
            LEAF: tool_declarations.with_mark(
                {"a": {"kind": "unclassified", "nott": 1}, "b": {"kind": "", "zz\x1b[31m": 1}}
            )
        }
    )
    assert values[LEAF] == tool_declarations.with_mark({})
    said = warnings[f"{LEAF}.a"]
    assert "left out nott" in said and "declares nothing" in said
    assert said.index("nott") < said.index("declares nothing")
    # The names stay sanitised.
    assert "\x1b" not in warnings[f"{LEAF}.b"] and "\\x1b" in warnings[f"{LEAF}.b"]
