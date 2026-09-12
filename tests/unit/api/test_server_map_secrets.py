"""A per-server token is stored the way every other secret is stored.

The map itself is one non-secret JSONB row. The tokens are not in it: each is
its own ``is_secret`` row, encrypted with the same Fernet box that protects
``core.static.ghidra.auth_token``, and merged back only when the effective
settings are assembled for a job.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.server_map import TOKEN_MASK, server_token_key
from app.services.settings_service import SettingsService, SettingsValidationError
from maljan.core import settings_secrets as box


@pytest.fixture()
def encryption_key(monkeypatch):
    """A real Fernet key, generated per run rather than committed."""
    from cryptography.fernet import Fernet

    monkeypatch.setenv(box.ENV_VAR, Fernet.generate_key().decode())


class _Rows(list):
    """A stand-in session: records adds and deletes, replays rows."""

    def __init__(self, rows=()):
        super().__init__(rows)
        self.added: list = []
        self.deleted: list = []

    def add(self, row):
        self.added.append(row)

    async def delete(self, row):
        self.deleted.append(row)

    async def commit(self):
        return None


def _service(rows=()) -> tuple[SettingsService, _Rows]:
    session = _Rows(rows)
    service = SettingsService(MagicMock())
    service._rows = AsyncMock(return_value=list(session))  # type: ignore[method-assign]
    service.db = session
    return service, session


@pytest.mark.asyncio
async def test_a_patch_with_a_token_stores_it_as_its_own_encrypted_row(encryption_key):
    service, session = _service()
    service.load_overrides = AsyncMock(return_value={})  # type: ignore[method-assign]
    await service.save(
        {
            "core.mcp.servers": {
                "x": {
                    "enabled": True,
                    "transport": "http",
                    "url": "https://h",
                    "auth_token": "s3cr3t",
                }
            }
        },
        user_id=None,
        ip=None,
    )
    map_row = next(r for r in session.added if r.key == "core.mcp.servers")
    token_row = next(r for r in session.added if r.key == server_token_key("x"))
    assert "auth_token" not in map_row.value["x"]
    assert "s3cr3t" not in str(map_row.value)
    assert token_row.is_secret is True
    assert box.is_encrypted(token_row.value)
    assert box.decrypt(str(token_row.value)) == "s3cr3t"


@pytest.mark.asyncio
async def test_a_patch_with_a_token_and_no_encryption_key_is_the_same_422(monkeypatch):
    monkeypatch.delenv(box.ENV_VAR, raising=False)
    service, _ = _service()
    service.load_overrides = AsyncMock(return_value={})  # type: ignore[method-assign]
    with pytest.raises(SettingsValidationError) as exc:
        await service.save(
            {
                "core.mcp.servers": {
                    "x": {"enabled": True, "command": "mcp", "auth_token": "s3cr3t"}
                }
            },
            user_id=None,
            ip=None,
        )
    assert exc.value.errors[server_token_key("x")] == (
        "secrets cannot be stored: SETTINGS_ENCRYPTION_KEY is not set"
    )


@pytest.mark.asyncio
async def test_a_null_token_deletes_the_row_and_a_removed_server_deletes_its_row(encryption_key):
    from app.models import RuntimeSetting

    existing = [
        RuntimeSetting(key=server_token_key("x"), value=box.encrypt("a"), is_secret=True),
        RuntimeSetting(key=server_token_key("gone"), value=box.encrypt("b"), is_secret=True),
    ]
    service, session = _service(existing)
    service.load_overrides = AsyncMock(
        return_value={"core.mcp.servers": {"x": {"command": "mcp"}, "gone": {"command": "mcp"}}}
    )  # type: ignore[method-assign]
    await service.save(
        {"core.mcp.servers": {"x": {"enabled": True, "command": "mcp", "auth_token": None}}},
        user_id=None,
        ip=None,
    )
    deleted = {r.key for r in session.deleted}
    assert server_token_key("x") in deleted, "an explicit null clears the token"
    assert server_token_key("gone") in deleted, "a removed server takes its token with it"


@pytest.mark.asyncio
async def test_an_explicit_null_for_the_whole_map_drops_it_and_every_token_row(encryption_key):
    """``null`` clears an override for every key (settings_service.save's own
    rule); the server map is no exception, and dropping it must not leave a
    per-server token orphaned with no map entry to belong to.
    """
    from app.models import RuntimeSetting

    existing = [
        RuntimeSetting(key="core.mcp.servers", value={"x": {"command": "mcp"}}, is_secret=False),
        RuntimeSetting(key=server_token_key("x"), value=box.encrypt("s3cr3t"), is_secret=True),
    ]
    service, session = _service(existing)
    service.load_overrides = AsyncMock(return_value={"core.mcp.servers": {"x": {"command": "mcp"}}})  # type: ignore[method-assign]
    await service.save({"core.mcp.servers": None}, user_id=None, ip=None)
    deleted = {r.key for r in session.deleted}
    assert "core.mcp.servers" in deleted, "the map row itself is dropped like any other key"
    assert server_token_key("x") in deleted, "its token has nothing left to belong to"

    # With every row gone, the values endpoint falls back to the built-ins --
    # the same shape ``test_an_unset_token_shows_empty_and_a_dot_env_token_shows_env``
    # exercises for a map that was never stored at all.
    empty_service, _ = _service()
    values = await empty_service.values()
    shown = values["core.mcp.servers"].value
    assert set(shown) == {"analysis", "knowledge", "network", "threatintel"}
    assert shown["network"]["auth_token"] == ""
    assert shown["network"]["auth_token_source"] == "default"


@pytest.mark.asyncio
async def test_the_effective_overrides_carry_the_plain_token_to_the_worker(encryption_key):
    from app.models import RuntimeSetting

    rows = [
        RuntimeSetting(key="core.mcp.servers", value={"x": {"command": "mcp"}}, is_secret=False),
        RuntimeSetting(key=server_token_key("x"), value=box.encrypt("s3cr3t"), is_secret=True),
    ]
    service, _ = _service(rows)
    overrides = await service.load_overrides()
    assert overrides["core.mcp.servers"]["x"]["auth_token"] == "s3cr3t"
    assert server_token_key("x") not in overrides


@pytest.mark.asyncio
async def test_the_effective_settings_build_with_the_merged_token(encryption_key):
    from app.models import RuntimeSetting
    from maljan.core.settings_overrides import build_settings, split_key

    rows = [
        RuntimeSetting(
            key="core.mcp.servers",
            value={"x": {"enabled": True, "transport": "http", "url": "https://h"}},
            is_secret=False,
        ),
        RuntimeSetting(key=server_token_key("x"), value=box.encrypt("s3cr3t"), is_secret=True),
    ]
    service, _ = _service(rows)
    overrides = await service.load_overrides()
    core = {split_key(k)[1]: v for k, v in overrides.items() if k.startswith("core.")}
    cfg = build_settings(core)
    assert cfg.mcp.servers["x"].auth_token.get_secret_value() == "s3cr3t"


@pytest.mark.asyncio
async def test_the_values_endpoint_masks_a_set_token_and_reports_its_source(encryption_key):
    from app.models import RuntimeSetting

    rows = [
        RuntimeSetting(key="core.mcp.servers", value={"x": {"command": "mcp"}}, is_secret=False),
        RuntimeSetting(key=server_token_key("x"), value=box.encrypt("s3cr3t"), is_secret=True),
    ]
    service, _ = _service(rows)
    values = await service.values()
    shown = values["core.mcp.servers"].value
    assert shown["x"]["auth_token"] == TOKEN_MASK
    assert shown["x"]["auth_token_source"] == "ui"
    assert "s3cr3t" not in str(shown)


@pytest.mark.asyncio
async def test_an_unset_token_shows_empty_and_the_environment_is_never_consulted(
    monkeypatch, encryption_key
):
    """Task 3: ``values()`` builds the default map through ``build_settings({})``,
    which is store-only -- a token set only via the environment must not be
    picked up, let alone reported as its own source. Both built-in servers
    with no stored row show empty, ``"default"``."""
    monkeypatch.setenv("MCP__SERVERS__NETWORK__AUTH_TOKEN", "from-env")
    service, _ = _service()
    values = await service.values()
    shown = values["core.mcp.servers"].value
    assert shown["network"]["auth_token"] == ""
    assert shown["network"]["auth_token_source"] == "default"
    assert shown["threatintel"]["auth_token"] == ""
    assert shown["threatintel"]["auth_token_source"] == "default"
    assert "from-env" not in str(shown)


def test_a_masked_env_value_keeps_the_stored_one():
    """The export masks every ``env`` value; importing it back must not write
    ten asterisks into the variable the server reads its credential from."""
    from app.services.server_map import split_server_secrets

    stored = {
        "custom": {
            "enabled": True,
            "transport": "stdio",
            "command": "my-mcp",
            "env": {"API_TOKEN": "s3cr3t", "MODE": "fast"},
        }
    }
    incoming = {
        "custom": {
            "enabled": True,
            "transport": "stdio",
            "command": "my-mcp",
            "env": {"API_TOKEN": TOKEN_MASK, "MODE": "slow", "NEW": TOKEN_MASK},
        }
    }
    cleaned, _ = split_server_secrets(incoming, stored=stored)
    # The mask with a stored value behind it keeps it; the one naming a
    # variable this deployment never had is dropped rather than stored.
    assert cleaned["custom"]["env"] == {"API_TOKEN": "s3cr3t", "MODE": "slow"}


# ---- the legacy import and the one-off repair ------------------------


class _RepairDB:
    """A fake session for the repair: one row lookup, then the key lookup."""

    def __init__(self, row):
        self.row = row
        self.added: list = []
        self.committed = False
        self.flushed_before_strip = False
        self._calls = 0

    async def flush(self):
        self.flushed_before_strip = all("auth_token" in entry for entry in self.row.value.values())

    async def execute(self, _stmt):
        self._calls += 1
        if self._calls == 1:
            return SimpleNamespace(scalar_one_or_none=lambda: self.row)
        keys = [(self.row.key,)] if self.row is not None else []
        keys += [(r.key,) for r in self.added]
        return SimpleNamespace(all=lambda: keys)

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        self.committed = True


def _server(**over):
    entry = {"enabled": True, "transport": "http", "url": "https://h"}
    entry.update(over)
    return entry


@pytest.mark.asyncio
async def test_the_repair_moves_a_clear_token_into_an_encrypted_row(encryption_key):
    from app.models import RuntimeSetting
    from app.services.composite_secrets import repair_server_auth_tokens

    row = RuntimeSetting(
        key="core.mcp.servers", value={"x": _server(auth_token="tok-real")}, is_secret=False
    )
    db = _RepairDB(row)

    moved = await repair_server_auth_tokens(db)

    assert moved == 1
    assert "auth_token" not in row.value["x"]
    assert db.flushed_before_strip is True
    stored = db.added[0]
    assert stored.key == server_token_key("x")
    assert stored.is_secret is True
    assert box.decrypt(stored.value) == "tok-real"


@pytest.mark.asyncio
async def test_the_repair_never_strips_a_token_it_did_not_store(encryption_key, caplog):
    """Re-review I2: the mask is what the legacy import wrote for a token.

    Keeping it is the point. ``merge_server_secrets`` leaves a token the
    composite itself carries in place, so silently deleting the field would
    erase the only record that the server had one -- and silently keeping it
    without a word would hand a job the literal bearer token.
    """
    from app.models import RuntimeSetting
    from app.services.composite_secrets import repair_server_auth_tokens

    row = RuntimeSetting(
        key="core.mcp.servers", value={"generic": _server(auth_token=TOKEN_MASK)}, is_secret=False
    )
    db = _RepairDB(row)

    with caplog.at_level(logging.WARNING):
        moved = await repair_server_auth_tokens(db)

    assert moved == 0
    assert db.added == []
    assert db.committed is False
    assert row.value["generic"]["auth_token"] == TOKEN_MASK
    assert "generic" in caplog.text


@pytest.mark.asyncio
async def test_the_server_repair_is_idempotent(encryption_key):
    from app.models import RuntimeSetting
    from app.services.composite_secrets import repair_server_auth_tokens

    row = RuntimeSetting(key="core.mcp.servers", value={"x": _server()}, is_secret=False)
    db = _RepairDB(row)

    assert await repair_server_auth_tokens(db) == 0
    assert db.added == []
    assert db.committed is False


@pytest.mark.asyncio
async def test_the_server_repair_leaves_the_row_alone_without_an_encryption_key(monkeypatch):
    monkeypatch.delenv(box.ENV_VAR, raising=False)
    from app.models import RuntimeSetting
    from app.services.composite_secrets import repair_server_auth_tokens

    row = RuntimeSetting(
        key="core.mcp.servers", value={"x": _server(auth_token="tok-real")}, is_secret=False
    )
    db = _RepairDB(row)

    assert await repair_server_auth_tokens(db) == 0
    assert row.value["x"]["auth_token"] == "tok-real"
    assert db.committed is False


def test_a_masked_token_inside_the_composite_is_dropped_by_the_merge():
    from app.services.server_map import SERVER_MAP_KEY, merge_server_secrets

    entry = {"transport": "http", "url": "http://x", "auth_token": TOKEN_MASK}
    merged = merge_server_secrets({SERVER_MAP_KEY: {"threatintel": entry}})
    assert "auth_token" not in merged[SERVER_MAP_KEY]["threatintel"]
    merged = merge_server_secrets(
        {SERVER_MAP_KEY: {"threatintel": entry}, server_token_key("threatintel"): "real-token"}
    )
    assert merged[SERVER_MAP_KEY]["threatintel"]["auth_token"] == "real-token"
