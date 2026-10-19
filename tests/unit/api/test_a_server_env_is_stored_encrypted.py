"""A tool server's ``env`` map is stored encrypted, shown masked and audited masked.

The ``env`` map is where a server's own credentials live (an API key its
sidecar reads from the environment). It sat in the server map's clear JSONB
row and every save copied it, unmasked, into the settings audit row. It now
gets the token's treatment: one encrypted row per server, merged back for a
job, shown as names with the mask, and every value the audit row keeps is
masked as the console shows it (AUD-36).
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from tests.credential_shapes import password

from app.services.server_map import (
    TOKEN_MASK,
    merge_server_secrets,
    server_env_key,
    split_server_env,
)
from app.services.settings_service import SettingsService
from maljan.core import settings_secrets as box

SECRET = password(20)


@pytest.fixture()
def encryption_key(monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv(box.ENV_VAR, Fernet.generate_key().decode())


class _Rows(list):
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


def _server(**over):
    entry = {"enabled": True, "transport": "stdio", "command": "my-mcp"}
    entry.update(over)
    return entry


def test_split_and_merge_are_exact_inverses():
    servers = {
        "a": _server(env={"API_KEY": SECRET, "MODE": "fast"}),
        "b": _server(env={}),
        "c": _server(),
    }
    stored, envs = split_server_env(servers)

    assert "env" not in stored["a"]
    assert stored["b"]["env"] == {}
    assert "env" not in stored["c"]
    assert envs["b"] is None and envs["c"] is None
    overrides = {"core.mcp.servers": stored, server_env_key("a"): envs["a"]}
    assert merge_server_secrets(overrides)["core.mcp.servers"] == servers


@pytest.mark.asyncio
async def test_a_save_stores_the_env_encrypted_and_out_of_the_map(encryption_key, monkeypatch):
    import app.services.settings_service as module

    audited = AsyncMock()
    monkeypatch.setattr(module, "_audit", audited)
    service, session = _service()
    service.load_overrides = AsyncMock(return_value={})  # type: ignore[method-assign]

    await service.save(
        {"core.mcp.servers": {"x": _server(env={"API_KEY": SECRET})}}, user_id=None, ip=None
    )

    map_row = next(r for r in session.added if r.key == "core.mcp.servers")
    env_row = next(r for r in session.added if r.key == server_env_key("x"))
    assert SECRET not in json.dumps(map_row.value)
    assert env_row.is_secret is True
    assert box.is_encrypted(env_row.value)
    assert json.loads(box.decrypt(str(env_row.value))) == {"API_KEY": SECRET}
    details = audited.await_args.args[2]
    assert SECRET not in json.dumps(details, default=str)


@pytest.mark.asyncio
async def test_the_audit_row_masks_what_the_console_masks(encryption_key, monkeypatch):
    """A clear env saved before the rows existed is masked in ``before`` too."""
    import app.services.settings_service as module
    from app.models import RuntimeSetting

    audited = AsyncMock()
    monkeypatch.setattr(module, "_audit", audited)
    legacy = {"x": _server(env={"API_KEY": SECRET}, args=["--api-key", SECRET])}
    service, _ = _service([RuntimeSetting(key="core.mcp.servers", value=legacy, is_secret=False)])
    service.load_overrides = AsyncMock(return_value={"core.mcp.servers": legacy})  # type: ignore[method-assign]

    await service.save(
        {"core.mcp.servers": {"x": _server(env={"API_KEY": SECRET}, args=["--api-key", SECRET])}},
        user_id=None,
        ip=None,
    )

    details = audited.await_args.args[2]
    said = json.dumps(details, default=str)
    assert SECRET not in said
    assert "API_KEY" in said, "the names stay, so the trail still says what changed"


@pytest.mark.asyncio
async def test_a_job_reads_the_env_back_in_clear(encryption_key):
    from app.models import RuntimeSetting

    rows = [
        RuntimeSetting(key="core.mcp.servers", value={"x": _server()}, is_secret=False),
        RuntimeSetting(
            key=server_env_key("x"),
            value=box.encrypt(json.dumps({"API_KEY": SECRET})),
            is_secret=True,
        ),
    ]
    service, _ = _service(rows)
    overrides = await service.load_overrides()

    assert overrides["core.mcp.servers"]["x"]["env"] == {"API_KEY": SECRET}
    assert server_env_key("x") not in overrides


@pytest.mark.asyncio
async def test_the_console_shows_the_names_with_the_mask(encryption_key):
    from app.models import RuntimeSetting

    rows = [
        RuntimeSetting(key="core.mcp.servers", value={"x": _server()}, is_secret=False),
        RuntimeSetting(
            key=server_env_key("x"),
            value=box.encrypt(json.dumps({"API_KEY": SECRET})),
            is_secret=True,
        ),
    ]
    service, _ = _service(rows)
    shown = (await service.values())["core.mcp.servers"].value

    assert shown["x"]["env"] == {"API_KEY": TOKEN_MASK}
    assert SECRET not in json.dumps(shown, default=str)


@pytest.mark.asyncio
async def test_a_mask_sent_back_keeps_the_encrypted_value(encryption_key, monkeypatch):
    import app.services.settings_service as module
    from app.models import RuntimeSetting

    monkeypatch.setattr(module, "_audit", AsyncMock())
    rows = [
        RuntimeSetting(key="core.mcp.servers", value={"x": _server()}, is_secret=False),
        RuntimeSetting(
            key=server_env_key("x"),
            value=box.encrypt(json.dumps({"API_KEY": SECRET})),
            is_secret=True,
        ),
    ]
    service, session = _service(rows)

    await service.save(
        {"core.mcp.servers": {"x": _server(env={"API_KEY": TOKEN_MASK, "MODE": "slow"})}},
        user_id=None,
        ip=None,
    )

    env_row = rows[1]
    assert json.loads(box.decrypt(str(env_row.value))) == {"API_KEY": SECRET, "MODE": "slow"}


@pytest.mark.asyncio
async def test_a_server_removed_from_the_map_takes_its_env_row(encryption_key, monkeypatch):
    import app.services.settings_service as module
    from app.models import RuntimeSetting

    monkeypatch.setattr(module, "_audit", AsyncMock())
    gone = RuntimeSetting(
        key=server_env_key("old"), value=box.encrypt(json.dumps({"K": SECRET})), is_secret=True
    )
    service, session = _service([gone])
    service.load_overrides = AsyncMock(return_value={})  # type: ignore[method-assign]

    await service.save({"core.mcp.servers": {"x": _server()}}, user_id=None, ip=None)

    assert gone in session.deleted


@pytest.mark.asyncio
async def test_a_reset_of_the_map_takes_every_env_row(encryption_key, monkeypatch):
    import app.services.settings_service as module
    from app.models import RuntimeSetting

    monkeypatch.setattr(module, "_audit", AsyncMock())
    env_row = RuntimeSetting(
        key=server_env_key("x"), value=box.encrypt(json.dumps({"K": SECRET})), is_secret=True
    )
    service, session = _service(
        [RuntimeSetting(key="core.mcp.servers", value={"x": _server()}, is_secret=False), env_row]
    )

    await service.reset(["core.mcp.servers"], user_id=None, ip=None)

    assert env_row in session.deleted


# ---- the repair of a map saved before the rows existed ---------------


class _RepairDB:
    def __init__(self, row, existing=()):
        self.row = row
        self.existing = list(existing)
        self.added: list = []
        self.committed = False
        self._calls = 0

    async def flush(self):
        return None

    async def execute(self, _stmt):
        self._calls += 1
        if self._calls == 1:
            return SimpleNamespace(scalar_one_or_none=lambda: self.row)
        keys = [(self.row.key,)] + [(k,) for k in self.existing] + [(r.key,) for r in self.added]
        return SimpleNamespace(all=lambda: keys)

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        self.committed = True


@pytest.mark.asyncio
async def test_the_repair_moves_a_clear_env_into_an_encrypted_row(encryption_key):
    from app.models import RuntimeSetting
    from app.services.composite_secrets import repair_server_env

    row = RuntimeSetting(
        key="core.mcp.servers", value={"x": _server(env={"API_KEY": SECRET})}, is_secret=False
    )
    db = _RepairDB(row)

    assert await repair_server_env(db) == 1
    assert "env" not in row.value["x"]
    stored = db.added[0]
    assert stored.key == server_env_key("x")
    assert json.loads(box.decrypt(stored.value)) == {"API_KEY": SECRET}
    assert db.committed is True


@pytest.mark.asyncio
async def test_the_repair_leaves_a_masked_env_it_cannot_recover(encryption_key, caplog):
    from app.models import RuntimeSetting
    from app.services.composite_secrets import repair_server_env

    row = RuntimeSetting(
        key="core.mcp.servers", value={"x": _server(env={"API_KEY": TOKEN_MASK})}, is_secret=False
    )
    db = _RepairDB(row)

    with caplog.at_level(logging.WARNING):
        assert await repair_server_env(db) == 0
    assert row.value["x"]["env"] == {"API_KEY": TOKEN_MASK}
    assert db.committed is False
    assert "x" in caplog.text


@pytest.mark.asyncio
async def test_the_repair_strips_a_clear_env_a_row_already_holds(encryption_key):
    from app.models import RuntimeSetting
    from app.services.composite_secrets import repair_server_env

    row = RuntimeSetting(
        key="core.mcp.servers", value={"x": _server(env={"API_KEY": SECRET})}, is_secret=False
    )
    db = _RepairDB(row, existing=[server_env_key("x")])

    assert await repair_server_env(db) == 0
    assert "env" not in row.value["x"]
    assert db.added == []


@pytest.mark.asyncio
async def test_the_repair_waits_for_an_encryption_key(monkeypatch):
    monkeypatch.delenv(box.ENV_VAR, raising=False)
    from app.models import RuntimeSetting
    from app.services.composite_secrets import repair_server_env

    row = RuntimeSetting(
        key="core.mcp.servers", value={"x": _server(env={"API_KEY": SECRET})}, is_secret=False
    )
    db = _RepairDB(row)

    assert await repair_server_env(db) == 0
    assert row.value["x"]["env"] == {"API_KEY": SECRET}
    assert db.committed is False


# ---- audit rows written before the masking ----------------------------


class _AuditDB:
    """The marker lookup first, then the settings audit rows; records the marker."""

    def __init__(self, rows, *, marked=False):
        self.rows = rows
        self.marked = marked
        self.added: list = []
        self.commits = 0
        self.row_reads = 0

    async def execute(self, stmt):
        if "runtime_settings" in str(stmt):
            marked = self.marked or any(
                getattr(r, "key", "").startswith("maljan.repair.") for r in self.added
            )
            return SimpleNamespace(scalar_one_or_none=lambda: "marker" if marked else None)
        self.row_reads += 1
        rows = self.rows
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: list(rows)))

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        self.commits += 1


def _audit_row(details):
    from app.models import AuditLog

    return AuditLog(action="settings.update", resource_type="settings", details=details)


def _keyed_url() -> str:
    return f"https://user:{SECRET}@h.example/p?api_key={SECRET}&mode=x"


@pytest.mark.asyncio
async def test_old_audit_rows_are_masked_as_a_new_row_is():
    """Env values, a credential flag's value, URL userinfo and query values, a credential key."""
    from app.services.composite_secrets import mask_audited_settings
    from app.services.settings_catalog_api import catalog_index
    from app.services.settings_service import _audited

    before = {
        "core.mcp.servers": {
            "x": _server(env={"Z_KEY": SECRET}, args=["--api-key", SECRET, _keyed_url()])
        },
        "core.llm.provider": "ollama",
        "core.plugin_block.api_token": SECRET,
    }
    row = _audit_row(
        {
            "changed": ["core.mcp.servers", "core.llm.provider"],
            "before": before,
            "after": {"core.llm.provider": "openai", "core.memory.url": _keyed_url()},
        }
    )
    expected_before = _audited(before, catalog_index())
    db = _AuditDB([row])

    assert await mask_audited_settings(db) == 1

    assert SECRET not in json.dumps(row.details)
    assert row.details["before"] == expected_before
    assert row.details["before"]["core.llm.provider"] == "ollama"
    assert row.details["after"]["core.llm.provider"] == "openai"
    assert "h.example/p?api_key=" in row.details["after"]["core.memory.url"]
    assert row.details["changed"] == ["core.mcp.servers", "core.llm.provider"]


@pytest.mark.asyncio
async def test_the_audit_masking_is_idempotent():
    from app.services.composite_secrets import mask_audited_settings

    row = _audit_row(
        {
            "before": {"core.mcp.servers": {"x": _server(env={"K": SECRET})}},
            "after": {"core.memory.url": _keyed_url()},
        }
    )
    db = _AuditDB([row])
    assert await mask_audited_settings(db) == 1
    masked = json.loads(json.dumps(row.details))

    again = _AuditDB([row])
    assert await mask_audited_settings(again) == 0
    assert row.details == masked


@pytest.mark.asyncio
async def test_an_audit_row_with_nothing_to_mask_is_left_alone():
    from app.services.composite_secrets import mask_audited_settings

    details = {"before": {"core.llm.provider": "ollama"}, "after": {"core.llm.provider": "x"}}
    row = _audit_row(details)
    db = _AuditDB([row])

    assert await mask_audited_settings(db) == 0
    assert row.details is details


@pytest.mark.asyncio
async def test_a_finished_pass_is_recorded_and_later_starts_skip_the_scan():
    from app.services.composite_secrets import mask_audited_settings
    from app.services.settings_service import AUDIT_MASKED_MARKER

    db = _AuditDB([_audit_row({"before": {"core.memory.url": _keyed_url()}})])

    assert await mask_audited_settings(db) == 1
    assert [r.key for r in db.added] == [AUDIT_MASKED_MARKER]
    assert db.row_reads == 1

    assert await mask_audited_settings(db) == 0
    assert db.row_reads == 1, "the marker is read in one lookup; the trail is not scanned again"
    assert len(db.added) == 1


@pytest.mark.asyncio
async def test_a_marked_store_is_never_scanned():
    from app.services.composite_secrets import mask_audited_settings

    db = _AuditDB([_audit_row({"before": {"core.memory.url": _keyed_url()}})], marked=True)

    assert await mask_audited_settings(db) == 0
    assert db.row_reads == 0
    assert db.commits == 0


def test_only_unchained_settings_rows_are_read():
    import inspect

    from app.services import composite_secrets

    source = inspect.getsource(composite_secrets.mask_audited_settings)
    assert 'AuditLog.action == "settings.update"' in source
    assert "AuditLog.chain_seq.is_(None)" in source


@pytest.mark.asyncio
async def test_the_marker_row_is_never_read_as_a_setting(encryption_key):
    from app.models import RuntimeSetting
    from app.services.settings_service import AUDIT_MASKED_MARKER

    service, _ = _service(
        [RuntimeSetting(key=AUDIT_MASKED_MARKER, value={"done": True}, is_secret=False)]
    )

    assert AUDIT_MASKED_MARKER not in await service.load_overrides()
