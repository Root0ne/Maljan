"""A per-server token is stored the way every other secret is stored.

The map itself is one non-secret JSONB row. The tokens are not in it: each is
its own ``is_secret`` row, encrypted with the same Fernet box that protects
``core.static.ghidra.auth_token``, and merged back only when the effective
settings are assembled for a job.
"""

from __future__ import annotations

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
    assert set(shown) == {"network", "threatintel"}
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
async def test_an_unset_token_shows_empty_and_a_dot_env_token_shows_env(
    monkeypatch, encryption_key
):
    monkeypatch.setenv("MCP__SERVERS__NETWORK__AUTH_TOKEN", "from-env")
    service, _ = _service()
    values = await service.values()
    shown = values["core.mcp.servers"].value
    assert shown["network"]["auth_token"] == TOKEN_MASK
    assert shown["network"]["auth_token_source"] == "env"
    assert shown["threatintel"]["auth_token"] == ""
    assert shown["threatintel"]["auth_token_source"] == "default"
    assert "from-env" not in str(shown)
