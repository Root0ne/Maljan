"""A stored map of tool declarations of a form no release writes reads as absent.

The mark's key names no tool, so a stored map holding it with anything but
the mark cannot be read as changes or as a whole map: the block is read as
absent (what ships is in force), one sanitised warning says so, and the
schema lists the mark's key under ``tool_facts_conflicts``. ``GET`` and the
export serve it as no change, so a console resend never flips what is in
force. A stored ``tool_facts`` that is not a map at all reads the same way,
and a server-map tool spelled as its own server's renamed tool is left out
like any other refused stored tool. None of them stops the settings from
being built. Through the real router, over a fake database.
"""

from __future__ import annotations

import logging
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models import RuntimeSetting
from app.services import settings_service as svc
from app.services.server_map import validate_server_map
from maljan.core import settings_overrides as so
from maljan.core import tool_declarations
from maljan.core.settings_overrides import build_settings, refused_tool_changes
from maljan.core.tool_declarations import CHANGES_FORM, CHANGES_MARK, with_mark

LEAF = "core.static.ghidra.tool_facts"
BLOCK = "static.ghidra"
SERVER_MAP = "core.mcp.servers"
SERVER = "analysis"
DECLARED = {"kind": "strings", "display_name": "Strings"}


@pytest.fixture(autouse=True)
def _fresh_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    tool_declarations._WARNED.clear()
    monkeypatch.setattr(svc, "_audit", AsyncMock())


def _unreadable_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if "no release writes" in r.getMessage()]


def _db(rows: list[Any]) -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock(
        return_value=SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: list(rows)))
    )
    db.add = MagicMock()
    db.delete = AsyncMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    return db


def _client(db: MagicMock) -> TestClient:
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id=uuid.UUID(int=1))
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app, raise_server_exceptions=False)


def _call(db: MagicMock, method: str, path: str, body: Any = None) -> Any:
    with (
        patch("app.api.v1.settings.audit_record", AsyncMock()),
        patch("app.api.v1.settings._agent_warnings", AsyncMock(return_value={})),
    ):
        client = _client(db)
        answer = client.get(path) if method == "get" else client.patch(path, json=body)
    assert answer.status_code == 200, answer.text
    return answer.json()


UNREADABLE = [
    pytest.param({CHANGES_MARK: "Changes"}, id="a-mark-that-is-not-the-mark"),
    pytest.param({CHANGES_MARK: "Changes", "zz_mine": DECLARED}, id="beside-a-tool"),
    pytest.param({CHANGES_MARK: 1}, id="a-number-under-the-mark"),
    pytest.param({CHANGES_MARK: None}, id="null-under-the-mark"),
    pytest.param({CHANGES_MARK: DECLARED}, id="a-declaration-under-the-mark"),
]
NOT_A_MAP = [
    pytest.param(["scan"], id="a-list"),
    pytest.param("scan", id="a-string"),
    pytest.param(None, id="null"),
]


@pytest.mark.parametrize("stored", UNREADABLE + NOT_A_MAP)
def test_a_provider_leaf_of_a_form_no_release_writes_reads_as_absent(
    stored: Any, caplog: pytest.LogCaptureFixture
) -> None:
    shipped = so.shipped_tool_facts(BLOCK)
    with caplog.at_level(logging.WARNING):
        built = build_settings({f"{BLOCK}.tool_facts": stored})
        build_settings({f"{BLOCK}.tool_facts": stored})
    assert built.static.ghidra.model_dump(mode="json")["tool_facts"] == shipped
    assert len(_unreadable_warnings(caplog)) == 1
    assert refused_tool_changes({f"{BLOCK}.tool_facts": stored}) == {BLOCK: [CHANGES_MARK]}


@pytest.mark.parametrize("stored", UNREADABLE + NOT_A_MAP)
def test_a_server_entry_of_a_form_no_release_writes_reads_as_absent(
    stored: Any, caplog: pytest.LogCaptureFixture
) -> None:
    shipped = so.shipped_tool_facts(f"mcp.servers.{SERVER}")
    servers = {SERVER: {"tool_facts": stored}}
    with caplog.at_level(logging.WARNING):
        built = build_settings({"mcp.servers": servers})
    assert built.mcp.servers[SERVER].model_dump(mode="json")["tool_facts"] == shipped
    assert len(_unreadable_warnings(caplog)) == 1
    assert refused_tool_changes({"mcp.servers": servers}) == {
        f"mcp.servers.{SERVER}": [CHANGES_MARK]
    }


def test_the_warning_of_a_form_no_release_writes_is_sanitised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    servers = {"forged\nERROR x": {"tool_facts": {CHANGES_MARK: "Changes"}}}
    with caplog.at_level(logging.WARNING):
        tool_declarations.stored_in_force({}, servers["forged\nERROR x"]["tool_facts"], "a\nb")
    (line,) = _unreadable_warnings(caplog)
    assert "\n" not in line


@pytest.mark.parametrize("stored", UNREADABLE)
def test_get_export_and_a_console_resend_of_an_unreadable_leaf_keep_what_ships(
    stored: dict[str, Any],
) -> None:
    """The reviewer's ``{"": "Changes"}`` row: served as no change, resent, still what ships."""
    shipped = so.shipped_tool_facts(BLOCK)
    row = RuntimeSetting(key=LEAF, value=stored, is_secret=False)
    db = _db([row])
    served = _call(db, "get", "/api/v1/settings")["values"][LEAF]["value"]
    assert served == {CHANGES_MARK: CHANGES_FORM}
    exported = _call(db, "get", "/api/v1/settings/export")["values"][LEAF]
    assert exported == {CHANGES_MARK: CHANGES_FORM}
    _call(db, "patch", "/api/v1/settings", {"changes": {LEAF: served}})
    assert row.value == {CHANGES_MARK: CHANGES_FORM}
    built = build_settings({f"{BLOCK}.tool_facts": row.value})
    assert built.static.ghidra.model_dump(mode="json")["tool_facts"] == shipped
    assert refused_tool_changes({f"{BLOCK}.tool_facts": row.value}) == {}


@pytest.mark.parametrize("stored", UNREADABLE)
def test_get_and_a_console_resend_of_an_unreadable_server_entry_keep_what_ships(
    stored: dict[str, Any],
) -> None:
    shipped = so.shipped_tool_facts(f"mcp.servers.{SERVER}")
    stored_map = validate_server_map({})
    stored_map[SERVER] = {**stored_map[SERVER], "tool_facts": stored}
    row = RuntimeSetting(key=SERVER_MAP, value=stored_map, is_secret=False)
    db = _db([row])
    served = _call(db, "get", "/api/v1/settings")["values"][SERVER_MAP]["value"]
    assert served[SERVER]["tool_facts"] == {CHANGES_MARK: CHANGES_FORM}
    _call(db, "patch", "/api/v1/settings", {"changes": {SERVER_MAP: served}})
    # No change of a tool is left, so the entry stores no tool declarations.
    assert "tool_facts" not in row.value[SERVER]
    built = build_settings({"mcp.servers": row.value})
    assert built.mcp.servers[SERVER].model_dump(mode="json")["tool_facts"] == shipped


def test_a_raw_resend_of_an_unreadable_server_entry_is_refused_not_stored() -> None:
    stored_map = validate_server_map({})
    stored_map[SERVER] = {**stored_map[SERVER], "tool_facts": {CHANGES_MARK: "Changes"}}
    from app.services.server_map import ServerMapError

    with pytest.raises(ServerMapError) as refused:
        validate_server_map(stored_map, stored=stored_map)
    assert any(key.startswith(f"{SERVER}.tool_facts") for key in refused.value.errors)


@pytest.mark.parametrize("server", [SERVER, "mine"])
@pytest.mark.parametrize("marked", [True, False], ids=["marked", "unmarked"])
def test_a_stored_tool_spelled_as_its_server_s_renamed_tool_is_left_out(
    server: str, marked: bool, caplog: pytest.LogCaptureFixture
) -> None:
    renamed = f"{server}__scan"
    facts = {renamed: DECLARED, "zz_kept": DECLARED}
    stored_facts = with_mark(facts) if marked else facts
    servers = {
        server: {"transport": "http", "url": "http://127.0.0.1:9/mcp", "tool_facts": stored_facts}
    }
    with caplog.at_level(logging.WARNING):
        built = build_settings({"mcp.servers": servers})
    in_force = built.mcp.servers[server].tool_facts
    assert renamed not in in_force
    assert "zz_kept" in in_force
    assert refused_tool_changes({"mcp.servers": servers}) == {f"mcp.servers.{server}": [renamed]}
    assert [r for r in caplog.records if "does not validate" in r.getMessage()]


def test_an_unrelated_edit_keeps_a_stored_renamed_spelling_as_stored() -> None:
    stored_map = validate_server_map({})
    renamed = f"{SERVER}__scan"
    stored_map[SERVER] = {**stored_map[SERVER], "tool_facts": with_mark({renamed: DECLARED})}
    sent = {SERVER: {**stored_map[SERVER], "label": "edited"}}
    out = validate_server_map({**stored_map, **sent}, stored=stored_map)
    assert out[SERVER]["tool_facts"] == with_mark({renamed: DECLARED})
    assert out[SERVER]["label"] == "edited"


def test_a_new_tool_spelled_as_its_server_s_renamed_tool_is_still_refused() -> None:
    from app.services.server_map import ServerMapError

    stored_map = validate_server_map({})
    sent = {
        **stored_map,
        SERVER: {**stored_map[SERVER], "tool_facts": with_mark({f"{SERVER}__scan": DECLARED})},
    }
    with pytest.raises(ServerMapError):
        validate_server_map(sent, stored=stored_map)


def test_reading_a_hostile_unreadable_map_is_linear() -> None:
    import time

    def timed(n: int) -> float:
        stored = {CHANGES_MARK: "Changes", **{f"t{i}": DECLARED for i in range(n)}}
        start = time.perf_counter()
        svc.served_tool_facts(stored, {})
        tool_declarations.stored_in_force({}, stored, "x")
        tool_declarations.kept_stored_changes(stored, stored, {})
        return time.perf_counter() - start

    small, large = timed(2_000), timed(20_000)
    assert large < max(small, 0.001) * 40
