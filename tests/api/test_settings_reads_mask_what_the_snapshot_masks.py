"""The console's read and the export mask what the run snapshot masks, and a save reads it back.

``GET /api/v1/settings`` and ``GET /export`` served a tool server's ``env``
values, the user name and password of a URL, a credential a server's
arguments carry, and an open mapping's credential-named entry
(``sandbox.cape2.submit_options``, ``sandbox.rest.submit.*_fields``) in clear.
They are masked now by the one masking the snapshot uses
(``maljan.core.settings_masking`` through ``settings_service.shown_setting``),
and a value sent back as it was shown keeps what is stored
(``settings_service.unmasked_changes``); a mask with nothing behind it is
refused, named, never stored as the literal mask.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models import RuntimeSetting
from app.services import settings_service as svc
from app.services.server_map import TOKEN_MASK
from app.services.settings_catalog_api import catalog_index
from app.services.settings_service import (
    SettingsValidationError,
    shown_setting,
    unmasked_changes,
)

SERVERS = "core.mcp.servers"
SUBMIT = "core.sandbox.cape2.submit_options"
BASE_URL = "core.llm.openai.base_url"
_PREFIX = "f10read"


def _marker(index: int) -> str:
    return f"{_PREFIX}{index:02d}zq"


def _server() -> dict[str, Any]:
    return {
        "enabled": False,
        "transport": "stdio",
        "command": "tool",
        "args": ["--api-key", _marker(1), f"--token={_marker(2)}", "--name", "plain"],
        "env": {"UPSTREAM_TOKEN": _marker(3), "MODE": _marker(4)},
        "url": f"https://u:{_marker(5)}@h.example/p?sig={_marker(6)}#f={_marker(7)}",
        "tools": [],
    }


STORED = {
    SERVERS: {"custom": _server()},
    SUBMIT: {"api_token": _marker(8), "route": "tor"},
    BASE_URL: f"https://u:{_marker(9)}@llm.example/v1?key={_marker(10)}",
}


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> SimpleNamespace:
        return SimpleNamespace(all=lambda: list(self._rows))


def _db() -> MagicMock:
    rows = [RuntimeSetting(key=key, value=value, is_secret=False) for key, value in STORED.items()]
    db = MagicMock()
    db.execute = AsyncMock(return_value=_Result(rows))
    db.add = MagicMock()
    db.delete = AsyncMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    return db


@pytest.fixture(autouse=True)
def _quiet(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(svc, "_audit", AsyncMock())
    logging.disable(logging.WARNING)
    yield
    logging.disable(logging.NOTSET)


def _client() -> TestClient:
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id=uuid.UUID(int=1))
    db = _db()
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app, raise_server_exceptions=False)


def _get(path: str) -> Any:
    with patch("app.api.v1.settings._agent_warnings", AsyncMock(return_value={})):
        answer = _client().get(path)
    assert answer.status_code == 200, answer.text[:300]
    return answer


def test_the_console_read_masks_what_the_snapshot_masks():
    answer = _get("/api/v1/settings")
    assert _PREFIX not in answer.text
    values = answer.json()["values"]
    server = values[SERVERS]["value"]["custom"]
    assert server["env"] == {"MODE": TOKEN_MASK, "UPSTREAM_TOKEN": TOKEN_MASK}
    assert server["args"] == ["--api-key", TOKEN_MASK, f"--token={TOKEN_MASK}", "--name", "plain"]
    assert server["url"] == f"https://{TOKEN_MASK}@h.example/p?sig={TOKEN_MASK}#{TOKEN_MASK}"
    assert values[SUBMIT]["value"] == {"api_token": TOKEN_MASK, "route": "tor"}
    assert values[BASE_URL]["value"] == f"https://{TOKEN_MASK}@llm.example/v1?key={TOKEN_MASK}"


def test_the_export_masks_the_same_and_lists_each_mask():
    answer = _get("/api/v1/settings/export")
    assert _PREFIX not in answer.text
    body = answer.json()
    assert body["values"][SERVERS]["custom"]["args"][1] == TOKEN_MASK
    assert body["values"][SUBMIT] == {"api_token": TOKEN_MASK, "route": "tor"}
    omitted = set(body["secrets_omitted"])
    assert {
        f"{SERVERS}.custom.args.1",
        f"{SERVERS}.custom.args.2",
        f"{SERVERS}.custom.env.MODE",
        f"{SERVERS}.custom.url",
        f"{SUBMIT}.api_token",
        BASE_URL,
    } <= omitted


def test_a_value_sent_back_as_shown_keeps_what_is_stored():
    index = catalog_index()
    shown = {key: shown_setting(index[key], value) for key, value in STORED.items()}
    edited = {**shown[SUBMIT], "route": "direct"}
    restored = unmasked_changes({**shown, SUBMIT: edited}, dict(STORED), index)
    assert restored[SERVERS] == STORED[SERVERS]
    assert restored[BASE_URL] == STORED[BASE_URL]
    # The part the reader changed is theirs; the masked part is the stored one.
    assert restored[SUBMIT] == {"api_token": _marker(8), "route": "direct"}


def test_a_changed_argument_list_keeps_each_masked_credential_by_position():
    index = catalog_index()
    shown = shown_setting(index[SERVERS], STORED[SERVERS])
    sent = {"custom": {**shown["custom"], "args": [*shown["custom"]["args"][:4], "other"]}}
    restored = unmasked_changes({SERVERS: sent}, dict(STORED), index)
    assert restored[SERVERS]["custom"]["args"] == [
        "--api-key",
        _marker(1),
        f"--token={_marker(2)}",
        "--name",
        "other",
    ]


def test_a_mask_with_nothing_stored_behind_it_is_refused_named():
    index = catalog_index()
    with pytest.raises(SettingsValidationError) as refused:
        unmasked_changes({SUBMIT: {"api_token": TOKEN_MASK}}, {}, index)
    assert SUBMIT in refused.value.errors


def test_an_env_mask_with_nothing_stored_is_left_to_the_server_map_rule():
    """An ``env`` value sent as the mask is dropped when nothing is stored, as before."""
    index = catalog_index()
    sent = {"custom": {**_server(), "env": {"NEW": TOKEN_MASK}}}
    restored = unmasked_changes({SERVERS: sent}, {}, index)
    assert restored[SERVERS]["custom"]["env"] == {"NEW": TOKEN_MASK}


def test_a_patch_carrying_an_unbacked_mask_is_refused():
    with patch("app.api.v1.settings._agent_warnings", AsyncMock(return_value={})):
        answer = _client().patch(
            "/api/v1/settings", json={"changes": {BASE_URL: f"https://{TOKEN_MASK}@other.example"}}
        )
    assert answer.status_code == 422, answer.text
    assert BASE_URL in answer.json()["errors"]


# ---- a stored value read back must stay masked where it lands -----------


def _sent_back(key: str, change: Any) -> dict[str, Any]:
    """``key``'s stored value as shown, changed by ``change``, through ``unmasked_changes``."""
    index = catalog_index()
    shown = shown_setting(index[key], STORED[key])
    return unmasked_changes({key: change(shown)}, dict(STORED), index)


def test_a_masked_argument_moved_behind_another_flag_is_refused():
    """The verification probe: the hidden value moved to a flag that names no credential."""
    stored = {SERVERS: {"s": {"command": "x", "args": ["--api-key", _marker(20), "--name", "n"]}}}
    index = catalog_index()
    shown = shown_setting(index[SERVERS], stored[SERVERS])
    attack = {"s": {**shown["s"], "args": ["--name", shown["s"]["args"][1], "--api-key", "x"]}}
    with pytest.raises(SettingsValidationError) as refused:
        unmasked_changes({SERVERS: attack}, stored, index)
    assert "s.args.1" in refused.value.errors[SERVERS]
    assert _marker(20) not in str(refused.value.errors)


def test_a_masked_argument_whose_flag_is_replaced_is_refused():
    def change(shown: dict[str, Any]) -> dict[str, Any]:
        args = list(shown["custom"]["args"])
        args[0] = "--verbose"
        return {"custom": {**shown["custom"], "args": args}}

    with pytest.raises(SettingsValidationError):
        _sent_back(SERVERS, change)


def test_arguments_sent_back_as_shown_are_restored_and_stay_masked():
    restored = _sent_back(SERVERS, lambda shown: shown)[SERVERS]["custom"]
    assert restored["args"] == STORED[SERVERS]["custom"]["args"]


def test_an_address_sent_back_as_shown_is_restored_whole():
    restored = _sent_back(BASE_URL, lambda shown: shown)
    assert restored[BASE_URL] == STORED[BASE_URL]
    server = _sent_back(SERVERS, lambda shown: shown)[SERVERS]["custom"]
    assert server["url"] == STORED[SERVERS]["custom"]["url"]


def test_an_env_value_sent_back_as_shown_is_restored():
    restored = _sent_back(SERVERS, lambda shown: shown)[SERVERS]["custom"]
    assert restored["env"] == STORED[SERVERS]["custom"]["env"]


def test_a_credential_entry_moved_to_a_plain_key_is_never_restored():
    def change(shown: dict[str, Any]) -> dict[str, Any]:
        return {"note": shown["api_token"], "route": "tor"}

    with pytest.raises(SettingsValidationError) as refused:
        _sent_back(SUBMIT, change)
    assert _marker(8) not in str(refused.value.errors)


def test_a_rest_field_map_sent_back_as_shown_is_restored_and_a_moved_one_refused():
    key = "core.sandbox.rest.submit.extra_fields"
    stored = {key: {"Authorization": f"Bearer {_marker(21)}", "mode": "fast"}}
    index = catalog_index()
    shown = shown_setting(index[key], stored[key])
    assert unmasked_changes({key: shown}, stored, index)[key] == stored[key]
    with pytest.raises(SettingsValidationError):
        unmasked_changes({key: {"mode": shown["Authorization"]}}, stored, index)


def test_an_edited_address_around_a_masked_fragment_is_refused_not_cut():
    key = BASE_URL
    stored = {key: "https://llm.example/v1#section-2"}
    index = catalog_index()
    shown = shown_setting(index[key], stored[key])
    assert shown == f"https://llm.example/v1#{TOKEN_MASK}"
    with pytest.raises(SettingsValidationError):
        unmasked_changes({key: shown.replace("v1", "v2")}, stored, index)


def test_a_url_credential_moved_behind_a_harmless_flag_is_refused():
    """A credential that is a URL still shows a mask in its query once moved; its host
    and path would show in clear, so the read-back must equal what was sent there."""
    secret_url = f"https://hooks.example/T/{_marker(22)}?x=1"
    stored = {SERVERS: {"s": {"command": "x", "args": ["--token", secret_url]}}}
    index = catalog_index()
    shown = shown_setting(index[SERVERS], stored[SERVERS])
    assert shown["s"]["args"] == ["--token", TOKEN_MASK]
    attack = {"s": {**shown["s"], "args": ["--name", TOKEN_MASK, "--token", "x"]}}
    with pytest.raises(SettingsValidationError) as refused:
        unmasked_changes({SERVERS: attack}, stored, index)
    assert "s.args.1" in refused.value.errors[SERVERS]
    assert _marker(22) not in str(refused.value.errors)
