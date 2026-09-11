"""A frontier arm's API key is stored the way every other secret is stored.

Walkthrough finding W3: the ``core.llm.frontier.arms`` map is one non-secret
JSONB row, and the keys used to sit inside it in clear text. They are their
own ``is_secret`` rows now -- encrypted with the same Fernet box that protects
``core.mcp.servers.<name>.auth_token`` -- and merged back only when the
effective settings are assembled for a job.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.fernet import Fernet

from app.models import RuntimeSetting
from app.services.frontier_arms import (
    ARMS_KEY,
    arm_key_key,
    masked_arms,
    merge_arm_secrets,
    split_arm_secrets,
)
from app.services.legacy_env_import import repair_frontier_arm_keys
from app.services.server_map import TOKEN_MASK
from app.services.settings_service import SettingsService, SettingsValidationError
from maljan.core import settings_secrets as box


@pytest.fixture()
def encryption_key(monkeypatch):
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


def _arm(**over):
    entry = {"base_url": "https://f", "model": "m", "input_usd_per_mtok": 1.0}
    entry.update(over)
    return entry


# ---- split / merge ---------------------------------------------------


def test_the_composite_never_carries_a_key():
    cleaned, keys = split_arm_secrets({"glm": _arm(api_key="sk-real")})
    assert "api_key" not in cleaned["glm"]
    assert keys == {"glm": "sk-real"}


def test_the_mask_means_unchanged_and_an_empty_string_means_clear():
    _, masked = split_arm_secrets({"glm": _arm(api_key=TOKEN_MASK)})
    assert masked == {}
    _, cleared = split_arm_secrets({"glm": _arm(api_key="")})
    assert cleared == {"glm": None}
    _, nulled = split_arm_secrets({"glm": _arm(api_key=None)})
    assert nulled == {"glm": None}
    _, absent = split_arm_secrets({"glm": _arm()})
    assert absent == {}


def test_merge_is_order_independent():
    forward = merge_arm_secrets({ARMS_KEY: {"glm": _arm()}, arm_key_key("glm"): "sk-real"})
    backward = merge_arm_secrets({arm_key_key("glm"): "sk-real", ARMS_KEY: {"glm": _arm()}})
    assert forward == backward
    assert forward[ARMS_KEY]["glm"]["api_key"] == "sk-real"
    assert arm_key_key("glm") not in forward


def test_a_row_for_an_arm_that_is_gone_is_dropped():
    merged = merge_arm_secrets({ARMS_KEY: {}, arm_key_key("old"): "sk-real"})
    assert merged == {ARMS_KEY: {}}


# ---- save / read -----------------------------------------------------


@pytest.mark.asyncio
async def test_a_saved_arm_key_becomes_its_own_encrypted_row(encryption_key):
    service, session = _service()
    service.load_overrides = AsyncMock(return_value={})  # type: ignore[method-assign]

    await service.save({ARMS_KEY: {"glm": _arm(api_key="sk-real")}}, user_id=None, ip=None)

    composite = next(r for r in session.added if r.key == ARMS_KEY)
    assert "api_key" not in composite.value["glm"]
    assert composite.is_secret is False
    key_row = next(r for r in session.added if r.key == arm_key_key("glm"))
    assert key_row.is_secret is True
    assert key_row.value != "sk-real"
    assert box.decrypt(key_row.value) == "sk-real"


@pytest.mark.asyncio
async def test_saving_the_mask_keeps_the_stored_key(encryption_key):
    stored = RuntimeSetting(key=arm_key_key("glm"), value=box.encrypt("sk-real"), is_secret=True)
    service, session = _service([stored])
    service.load_overrides = AsyncMock(return_value={ARMS_KEY: {"glm": _arm()}})  # type: ignore[method-assign]

    await service.save({ARMS_KEY: {"glm": _arm(api_key=TOKEN_MASK)}}, user_id=None, ip=None)

    assert session.deleted == []
    assert box.decrypt(stored.value) == "sk-real"


@pytest.mark.asyncio
async def test_saving_an_empty_key_clears_the_row(encryption_key):
    stored = RuntimeSetting(key=arm_key_key("glm"), value=box.encrypt("sk-real"), is_secret=True)
    service, session = _service([stored])
    service.load_overrides = AsyncMock(return_value={ARMS_KEY: {"glm": _arm()}})  # type: ignore[method-assign]

    await service.save({ARMS_KEY: {"glm": _arm(api_key="")}}, user_id=None, ip=None)

    assert session.deleted == [stored]


@pytest.mark.asyncio
async def test_a_key_row_for_a_deleted_arm_goes_with_it(encryption_key):
    stored = RuntimeSetting(key=arm_key_key("old"), value=box.encrypt("sk-real"), is_secret=True)
    service, session = _service([stored])
    service.load_overrides = AsyncMock(return_value={ARMS_KEY: {"old": _arm()}})  # type: ignore[method-assign]

    await service.save({ARMS_KEY: {"glm": _arm()}}, user_id=None, ip=None)

    assert session.deleted == [stored]


@pytest.mark.asyncio
async def test_a_key_cannot_be_stored_without_an_encryption_key(monkeypatch):
    monkeypatch.delenv(box.ENV_VAR, raising=False)
    service, _ = _service()
    service.load_overrides = AsyncMock(return_value={})  # type: ignore[method-assign]

    with pytest.raises(SettingsValidationError) as exc:
        await service.save({ARMS_KEY: {"glm": _arm(api_key="sk-real")}}, user_id=None, ip=None)
    assert arm_key_key("glm") in exc.value.errors


@pytest.mark.asyncio
async def test_load_overrides_folds_the_key_back_in(encryption_key):
    rows = [
        SimpleNamespace(key=ARMS_KEY, value={"glm": _arm()}, is_secret=False),
        SimpleNamespace(key=arm_key_key("glm"), value=box.encrypt("sk-real"), is_secret=True),
    ]
    service, _ = _service(rows)

    overrides = await service.load_overrides()

    assert overrides == {ARMS_KEY: {"glm": {**_arm(), "api_key": "sk-real"}}}


def test_values_shows_the_mask_never_the_key(encryption_key):
    shown = masked_arms({"glm": _arm(), "free": _arm()}, {arm_key_key("glm"): object()})
    assert shown["glm"]["api_key"] == TOKEN_MASK
    assert shown["free"]["api_key"] is None


@pytest.mark.asyncio
async def test_a_real_key_replaces_the_stored_one(encryption_key):
    stored = RuntimeSetting(key=arm_key_key("glm"), value=box.encrypt("sk-old"), is_secret=True)
    service, session = _service([stored])
    service.load_overrides = AsyncMock(  # type: ignore[method-assign]
        return_value={ARMS_KEY: {"glm": {**_arm(), "api_key": "sk-old"}}}
    )

    await service.save({ARMS_KEY: {"glm": _arm(api_key="sk-new")}}, user_id=None, ip=None)

    assert session.deleted == []
    assert box.decrypt(stored.value) == "sk-new"


@pytest.mark.asyncio
async def test_a_save_never_drops_a_key_the_composite_alone_was_holding(encryption_key):
    """Fix round 1, the same rule on the save path.

    An upgraded deployment can still carry a key in the composite in clear (the
    repair has not run yet, or it ran while the encryption key was unusable).
    An import document omits ``api_key`` entirely, so the strip would take that
    key with it and store nothing. It is carried into an encrypted row instead.
    """
    service, session = _service()
    service.load_overrides = AsyncMock(  # type: ignore[method-assign]
        return_value={ARMS_KEY: {"glm": {**_arm(), "api_key": "sk-legacy"}}}
    )

    await service.save({ARMS_KEY: {"glm": _arm()}}, user_id=None, ip=None)

    composite = next(r for r in session.added if r.key == ARMS_KEY)
    assert "api_key" not in composite.value["glm"]
    key_row = next(r for r in session.added if r.key == arm_key_key("glm"))
    assert box.decrypt(key_row.value) == "sk-legacy"


def test_a_masked_entry_with_nothing_stored_instructs_nothing():
    """The mask is not a key: with no stored value behind it there is nothing
    to write, and nothing is claimed to have been written."""
    _, keys = split_arm_secrets({"glm": _arm(api_key=TOKEN_MASK)}, stored={})
    assert keys == {}


# ---- the one-off repair ----------------------------------------------


class _RepairDB:
    def __init__(self, row):
        self.row = row
        self.added: list = []
        self.committed = False
        self.flushed_before_strip = False
        self._calls = 0

    async def flush(self):
        # Recorded rather than counted: what matters is that nothing was
        # removed from the composite before every leaf row reached the
        # transaction.
        self.flushed_before_strip = all("api_key" in entry for entry in self.row.value.values())

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


@pytest.mark.asyncio
async def test_the_repair_moves_a_clear_key_into_an_encrypted_row(encryption_key):
    row = RuntimeSetting(key=ARMS_KEY, value={"glm": _arm(api_key="sk-real")}, is_secret=False)
    db = _RepairDB(row)

    moved = await repair_frontier_arm_keys(db)

    assert moved == 1
    assert "api_key" not in row.value["glm"]
    stored = db.added[0]
    assert stored.key == arm_key_key("glm")
    assert stored.is_secret is True
    assert box.decrypt(stored.value) == "sk-real"
    assert db.committed is True


@pytest.mark.asyncio
async def test_the_repair_is_idempotent(encryption_key):
    row = RuntimeSetting(key=ARMS_KEY, value={"glm": _arm()}, is_secret=False)
    db = _RepairDB(row)

    assert await repair_frontier_arm_keys(db) == 0
    assert db.added == []
    assert db.committed is False


@pytest.mark.asyncio
async def test_the_repair_never_strips_a_key_it_did_not_store(encryption_key, caplog):
    """Fix round 1: the mask is what the legacy import actually wrote.

    ``flatten_leaves`` dumps the arms map through ``model_dump(mode="json")``,
    which renders every ``SecretStr`` as ten asterisks -- so the composite row
    on an upgraded deployment holds the mask, not the key. The first repair
    reused ``split_arm_secrets``, whose contract is the UI's ("the mask means
    leave the stored row alone"), and there is no stored row behind it here:
    it stripped the field from all four arms, stored nothing, and reported 0.
    The composite must keep what the repair cannot store.
    """
    arms = {name: _arm(api_key=TOKEN_MASK) for name in ("glm", "nim", "or", "dsk")}
    row = RuntimeSetting(key=ARMS_KEY, value=arms, is_secret=False)
    db = _RepairDB(row)

    with caplog.at_level(logging.WARNING):
        moved = await repair_frontier_arm_keys(db)

    assert moved == 0
    assert db.added == []
    assert db.committed is False
    for name in arms:
        assert row.value[name]["api_key"] == TOKEN_MASK
    assert "glm" in caplog.text


@pytest.mark.asyncio
async def test_the_repair_strips_a_masked_arm_once_it_has_a_row(encryption_key):
    """With the leaf in place the mask in the composite is only a leftover."""
    row = RuntimeSetting(key=ARMS_KEY, value={"glm": _arm(api_key=TOKEN_MASK)}, is_secret=False)
    db = _RepairDB(row)
    db.added.append(RuntimeSetting(key=arm_key_key("glm"), value=box.encrypt("sk-real")))

    assert await repair_frontier_arm_keys(db) == 0
    assert "api_key" not in row.value["glm"]
    assert db.committed is True


@pytest.mark.asyncio
async def test_the_repair_strips_an_arm_whose_key_was_never_set(encryption_key):
    row = RuntimeSetting(key=ARMS_KEY, value={"free": _arm(api_key=None)}, is_secret=False)
    db = _RepairDB(row)

    assert await repair_frontier_arm_keys(db) == 0
    assert "api_key" not in row.value["free"]
    assert db.committed is True


@pytest.mark.asyncio
async def test_the_repair_keeps_the_mask_and_moves_the_real_key_beside_it(encryption_key):
    row = RuntimeSetting(
        key=ARMS_KEY,
        value={"glm": _arm(api_key="sk-real"), "nim": _arm(api_key=TOKEN_MASK)},
        is_secret=False,
    )
    db = _RepairDB(row)

    assert await repair_frontier_arm_keys(db) == 1
    assert "api_key" not in row.value["glm"]
    assert row.value["nim"]["api_key"] == TOKEN_MASK
    assert box.decrypt(db.added[0].value) == "sk-real"


@pytest.mark.asyncio
async def test_every_leaf_is_written_before_the_composite_is_stripped(encryption_key):
    """(c): the strip only ever follows a flush of every leaf row."""
    arms = {name: _arm(api_key=f"sk-{name}") for name in ("glm", "nim", "or", "dsk")}
    row = RuntimeSetting(key=ARMS_KEY, value=arms, is_secret=False)
    db = _RepairDB(row)

    moved = await repair_frontier_arm_keys(db)

    assert moved == 4
    assert db.flushed_before_strip is True
    assert [r.key for r in db.added] == [arm_key_key(n) for n in arms]
    for name in arms:
        stored = next(r for r in db.added if r.key == arm_key_key(name))
        assert box.decrypt(stored.value) == f"sk-{name}"
        assert "api_key" not in row.value[name]


@pytest.mark.asyncio
async def test_the_repair_leaves_the_row_alone_without_an_encryption_key(monkeypatch):
    monkeypatch.delenv(box.ENV_VAR, raising=False)
    row = RuntimeSetting(key=ARMS_KEY, value={"glm": _arm(api_key="sk-real")}, is_secret=False)
    db = _RepairDB(row)

    assert await repair_frontier_arm_keys(db) == 0
    assert row.value["glm"]["api_key"] == "sk-real"
    assert db.committed is False


@pytest.mark.asyncio
async def test_the_repair_never_overwrites_a_key_the_operator_already_saved(encryption_key):
    row = RuntimeSetting(key=ARMS_KEY, value={"glm": _arm(api_key="sk-old")}, is_secret=False)
    db = _RepairDB(row)
    db.added.append(RuntimeSetting(key=arm_key_key("glm"), value=box.encrypt("sk-new")))

    moved = await repair_frontier_arm_keys(db)

    assert moved == 0
    assert "api_key" not in row.value["glm"]
    assert box.decrypt(db.added[0].value) == "sk-new"


@pytest.mark.asyncio
async def test_resetting_the_composite_removes_every_key_row(encryption_key):
    """Re-review M1: an orphaned row let a re-created arm inherit a key.

    ``merge_arm_secrets`` folds a row back in by name, so a leftover row made
    a freshly added arm of the same name show up as already configured.
    """
    composite = RuntimeSetting(key=ARMS_KEY, value={"glm": _arm()}, is_secret=False)
    key_row = RuntimeSetting(key=arm_key_key("glm"), value=box.encrypt("sk-real"), is_secret=True)
    service, session = _service([composite, key_row])

    removed = await service.reset([ARMS_KEY], user_id=None, ip=None)

    assert session.deleted == [composite, key_row]
    assert set(removed) == {ARMS_KEY, arm_key_key("glm")}


@pytest.mark.asyncio
async def test_resetting_one_composite_leaves_the_other_alone(encryption_key):
    composite = RuntimeSetting(key=ARMS_KEY, value={"glm": _arm()}, is_secret=False)
    arm_row = RuntimeSetting(key=arm_key_key("glm"), value=box.encrypt("sk-a"), is_secret=True)
    server_row = RuntimeSetting(
        key="core.mcp.servers.x.auth_token", value=box.encrypt("tok"), is_secret=True
    )
    service, session = _service([composite, arm_row, server_row])

    await service.reset([ARMS_KEY], user_id=None, ip=None)

    assert server_row not in session.deleted
