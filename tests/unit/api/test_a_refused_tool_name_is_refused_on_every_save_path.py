"""A sent tool name no tool can have is a 422 naming the key, on every save path.

A provider block's tool declarations (``core.<block>.tool_facts``) sent
through ``PATCH /settings`` or either import format with an empty or padded
tool name, or with the mark's key holding anything but the mark, is refused
with the leaf named, as the settings model refuses it; never a failed
request. The tool-server map refuses the same under ``<server>.tool_facts``.
Through the real router, over a fake database.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services import settings_service as svc
from maljan.core.tool_declarations import (
    CHANGES_FORM,
    CHANGES_MARK,
    refused_names_message,
    with_mark,
)

LEAF = "core.static.ghidra.tool_facts"
SERVER_MAP = "core.mcp.servers"
DECLARED = {"kind": "strings", "display_name": "Strings"}


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> SimpleNamespace:
        return SimpleNamespace(all=lambda: list(self._rows))


def _db(rows: list[Any]) -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock(return_value=_Result(rows))
    db.add = MagicMock()
    db.delete = AsyncMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    return db


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "_audit", AsyncMock())


def _client(db: MagicMock) -> TestClient:
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id=uuid.UUID(int=1))
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app, raise_server_exceptions=False)


def _send(method: str, path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any], MagicMock]:
    db = _db([])
    with (
        patch("app.api.v1.settings.audit_record", AsyncMock()),
        patch("app.api.v1.settings._agent_warnings", AsyncMock(return_value={})),
    ):
        answer = getattr(_client(db), method)(path, json=body)
    return answer.status_code, answer.json(), db


# Each spelling, marked and unmarked: the names refused, as the refusal names them.
REFUSED = [
    pytest.param({CHANGES_MARK: CHANGES_FORM, " pad": DECLARED}, [" pad"], id="padded-marked"),
    pytest.param({" pad": DECLARED}, [" pad"], id="padded-unmarked"),
    pytest.param({CHANGES_MARK: CHANGES_FORM, "t\n": DECLARED}, ["t\n"], id="newline-marked"),
    pytest.param({"t\n": DECLARED}, ["t\n"], id="newline-unmarked"),
    pytest.param({CHANGES_MARK: DECLARED}, [""], id="empty-unmarked"),
    pytest.param({CHANGES_MARK: DECLARED, "x": DECLARED}, [""], id="empty-beside-a-tool"),
    pytest.param({CHANGES_MARK: "Changes"}, [""], id="a-mark-that-is-not-the-mark"),
    pytest.param({CHANGES_MARK: "Changes", "x": DECLARED}, [""], id="not-the-mark-beside-a-tool"),
]


def _refused_on_the_leaf(status: int, body: dict[str, Any], names: list[str], db: Any) -> None:
    assert status == 422, body
    errors = body["errors"]
    assert errors == {LEAF: refused_names_message(names)}
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.parametrize(("value", "names"), REFUSED)
def test_a_patch_of_a_provider_leaf_with_a_refused_name_is_a_422_naming_the_leaf(
    value: dict[str, Any], names: list[str]
) -> None:
    status, body, db = _send("patch", "/api/v1/settings", {"changes": {LEAF: value}})
    _refused_on_the_leaf(status, body, names, db)


@pytest.mark.parametrize("fmt", ["maljan-settings/2", "maljan-settings/1"])
@pytest.mark.parametrize(("value", "names"), REFUSED)
def test_an_import_of_a_provider_leaf_with_a_refused_name_is_a_422_naming_the_leaf(
    fmt: str, value: dict[str, Any], names: list[str]
) -> None:
    status, body, db = _send(
        "post", "/api/v1/settings/import", {"format": fmt, "values": {LEAF: value}}
    )
    _refused_on_the_leaf(status, body, names, db)


@pytest.mark.parametrize("value", [["scan"], "scan", 1])
def test_a_provider_leaf_that_is_not_a_map_is_a_422_naming_the_leaf(value: Any) -> None:
    status, body, db = _send("patch", "/api/v1/settings", {"changes": {LEAF: value}})
    assert status == 422, body
    assert LEAF in body["errors"]
    db.commit.assert_not_awaited()


@pytest.mark.parametrize(("value", "names"), REFUSED)
def test_a_server_map_entry_with_a_refused_name_is_a_422_naming_the_entry(
    value: dict[str, Any], names: list[str]
) -> None:
    status, body, db = _send(
        "patch",
        "/api/v1/settings",
        {"changes": {SERVER_MAP: {"analysis": {"tool_facts": value}}}},
    )
    assert status == 422, body
    assert any(key.startswith(f"{SERVER_MAP}.analysis.tool_facts") for key in body["errors"])
    db.commit.assert_not_awaited()


def test_a_marked_map_with_a_well_named_tool_still_saves() -> None:
    status, body, db = _send(
        "patch", "/api/v1/settings", {"changes": {LEAF: with_mark({"zz_new": DECLARED})}}
    )
    assert status == 200, body
    db.commit.assert_awaited_once()


def test_a_refusal_the_checks_missed_is_still_a_settings_refusal_of_the_leaf() -> None:
    """The backstop: a refusal only the model says is the leaf's 422, never a failed request."""
    with (
        patch.object(svc, "changed_declaration_refusals", return_value={}),
        pytest.raises(svc.SettingsValidationError) as refused,
    ):
        svc.stored_declaration_leaves({LEAF: with_mark({" pad": DECLARED})}, {})
    assert list(refused.value.errors) == [LEAF]


def test_the_mark_always_wins_over_an_entry_under_its_key() -> None:
    assert with_mark({CHANGES_MARK: DECLARED, "x": DECLARED}) == {
        CHANGES_MARK: CHANGES_FORM,
        "x": DECLARED,
    }
    assert with_mark({CHANGES_MARK: "Changes"}) == {CHANGES_MARK: CHANGES_FORM}
    assert list(with_mark({"x": DECLARED, CHANGES_MARK: "Changes"})) == [CHANGES_MARK, "x"]


def test_an_empty_refused_name_is_shown_visibly() -> None:
    assert repr("") in refused_names_message([""])
    from maljan.core.tool_declarations import loggable_names

    assert loggable_names(["", "a"]) == '"", a'


# A refused name sent as ``null``: reading the map over what ships drops a
# ``null`` entry, so the names of the map as sent are checked first, on the
# server map as on a provider leaf.
CUSTOM = "own_tools"
SAVE_PATHS = ["patch", "maljan-settings/2", "maljan-settings/1"]


def _full_entry(server: str, tool_facts: Any) -> dict[str, Any]:
    from app.services.server_map import validate_server_map

    shipped = validate_server_map({}).get(server) or {
        "transport": "http",
        "url": "http://127.0.0.1:9/mcp",
    }
    return {**{k: v for k, v in shipped.items() if k != "tool_facts"}, "tool_facts": tool_facts}


def _save(path: str, values: dict[str, Any], rows: list[Any] | None = None) -> Any:
    db = _db(list(rows or []))
    with (
        patch("app.api.v1.settings.audit_record", AsyncMock()),
        patch("app.api.v1.settings._agent_warnings", AsyncMock(return_value={})),
    ):
        if path == "patch":
            answer = _client(db).patch("/api/v1/settings", json={"changes": values})
        else:
            answer = _client(db).post(
                "/api/v1/settings/import", json={"format": path, "values": values}
            )
    return answer.status_code, answer.json(), db


NULL_SPELLINGS = [
    pytest.param({CHANGES_MARK: None}, [CHANGES_MARK], id="empty-unmarked"),
    pytest.param({CHANGES_MARK: None, "zz": DECLARED}, [CHANGES_MARK], id="empty-beside-a-tool"),
    pytest.param({" pad": None}, [" pad"], id="padded-unmarked"),
    pytest.param({"t\n": None}, ["t\n"], id="newline-unmarked"),
    pytest.param({CHANGES_MARK: CHANGES_FORM, " pad": None}, [" pad"], id="padded-marked"),
    pytest.param({CHANGES_MARK: CHANGES_FORM, "t\n": None}, ["t\n"], id="newline-marked"),
]


@pytest.mark.parametrize("server", ["analysis", CUSTOM])
@pytest.mark.parametrize("path", SAVE_PATHS)
@pytest.mark.parametrize(("tool_facts", "names"), NULL_SPELLINGS)
def test_a_server_map_entry_with_a_refused_name_sent_as_null_is_a_422_naming_the_entry(
    server: str, path: str, tool_facts: dict[str, Any], names: list[str]
) -> None:
    status, body, db = _save(path, {SERVER_MAP: {server: _full_entry(server, tool_facts)}})
    assert status == 422, body
    assert body["errors"] == {f"{SERVER_MAP}.{server}.tool_facts": refused_names_message(names)}
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.parametrize("server", ["analysis", CUSTOM])
@pytest.mark.parametrize("path", SAVE_PATHS)
@pytest.mark.parametrize("marked", [False, True])
def test_a_server_map_entry_with_its_renamed_spelling_sent_as_null_is_a_422_naming_the_entry(
    server: str, path: str, marked: bool
) -> None:
    tool_facts: dict[str, Any] = {f"{server}__x": None}
    if marked:
        tool_facts = {CHANGES_MARK: CHANGES_FORM, **tool_facts}
    status, body, db = _save(path, {SERVER_MAP: {server: _full_entry(server, tool_facts)}})
    assert status == 422, body
    assert list(body["errors"]) == [f"{SERVER_MAP}.{server}.tool_facts"]
    assert f"{server}__x" in body["errors"][f"{SERVER_MAP}.{server}.tool_facts"]
    db.commit.assert_not_awaited()


@pytest.mark.parametrize("path", SAVE_PATHS)
def test_an_empty_name_sent_as_null_never_removes_what_a_server_ships(path: str) -> None:
    status, body, db = _save(path, {SERVER_MAP: {"analysis": _full_entry("analysis", {"": None})}})
    assert status == 422, body
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.parametrize("path", SAVE_PATHS)
@pytest.mark.parametrize(("value", "names"), NULL_SPELLINGS)
def test_a_provider_leaf_with_a_refused_name_sent_as_null_is_a_422_naming_the_leaf(
    path: str, value: dict[str, Any], names: list[str]
) -> None:
    status, body, db = _save(path, {LEAF: value})
    _refused_on_the_leaf(status, body, names, db)


def test_a_non_null_empty_name_on_a_server_map_is_refused_in_the_leaf_paths_words() -> None:
    status, body, _ = _save(
        "patch", {SERVER_MAP: {"analysis": _full_entry("analysis", {"": DECLARED})}}
    )
    assert status == 422, body
    assert body["errors"] == {
        f"{SERVER_MAP}.analysis.tool_facts": refused_names_message([CHANGES_MARK])
    }


@pytest.mark.parametrize("server", ["analysis", CUSTOM])
def test_a_refused_name_stored_as_null_and_sent_back_as_stored_never_blocks_a_save(
    server: str,
) -> None:
    from app.models import RuntimeSetting

    stored_facts = {CHANGES_MARK: CHANGES_FORM, " pad": None}
    stored = {server: _full_entry(server, stored_facts)}
    rows = [RuntimeSetting(key=SERVER_MAP, value=stored, is_secret=False)]
    sent = {server: {**_full_entry(server, stored_facts), "call_timeout_seconds": 77}}
    status, body, db = _save("patch", {SERVER_MAP: sent}, rows)
    assert status == 200, body
    db.commit.assert_awaited_once()
