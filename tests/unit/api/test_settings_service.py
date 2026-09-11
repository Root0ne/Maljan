import logging
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.fernet import Fernet

from app import observability
from app.models import AuditLog, RuntimeSetting
from app.services import audit as audit_module
from app.services import settings_service as svc
from app.services.settings_catalog_api import catalog_index, full_catalog


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._rows))


def make_db(rows):
    db = MagicMock()
    db.execute = AsyncMock(return_value=FakeResult(rows))
    db.add = MagicMock()
    db.delete = AsyncMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    return db


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())


def test_full_catalog_has_core_and_api_entries():
    keys = {e.key for e in full_catalog()}
    assert "core.llm.provider" in keys
    assert "api.enrichment_enabled" in keys
    assert "api.debug" in keys
    ro = catalog_index()["api.debug"]
    assert ro.editable is False and ro.applies == "restart"
    assert catalog_index()["api.enrichment_enabled"].applies == "live"


def test_validate_rejects_bad_core_and_api_values():
    s = svc.SettingsService(make_db([]))
    with pytest.raises(svc.SettingsValidationError) as ei:
        s.validate({"negotiation.max_iterations": "x"}, {"enrichment_max_lookups": "y"})
    assert set(ei.value.errors) == {"core.negotiation.max_iterations", "api.enrichment_max_lookups"}


def test_validate_rejects_unknown_and_readonly_keys():
    s = svc.SettingsService(make_db([]))
    with pytest.raises(svc.SettingsValidationError) as ei:
        s.check_keys({"core.nope": 1, "api.debug": True})
    assert "core.nope" in ei.value.errors and "api.debug" in ei.value.errors


@pytest.mark.asyncio
async def test_save_is_atomic_on_validation_failure():
    db = make_db([])
    s = svc.SettingsService(db)
    with pytest.raises(svc.SettingsValidationError):
        await s.save(
            {"core.llm.provider": "openai", "core.negotiation.max_iterations": "x"},
            user_id=uuid.uuid4(),
            ip=None,
        )
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_save_encrypts_secrets_and_reports_applies(key):
    db = make_db([])
    s = svc.SettingsService(db)
    res = await s.save(
        {"core.llm.openai.api_key": "sk-secret-value-1234", "api.enrichment_enabled": False},
        user_id=uuid.uuid4(),
        ip="127.0.0.1",
    )
    assert sorted(res.applied) == ["api.enrichment_enabled", "core.llm.openai.api_key"]
    assert res.applies == {"next_job": 1, "live": 1}
    added = [c.args[0] for c in db.add.call_args_list if isinstance(c.args[0], RuntimeSetting)]
    secret_row = next(r for r in added if r.key == "core.llm.openai.api_key")
    assert secret_row.is_secret and str(secret_row.value).startswith("enc:v1:")
    assert "sk-secret" not in str(secret_row.value)


@pytest.mark.asyncio
async def test_values_masks_secrets_and_labels_source(key):
    from maljan.core import settings_secrets as box

    rows = [
        RuntimeSetting(
            key="core.llm.openai.api_key",
            value=box.encrypt("sk-secret-value-1234"),
            is_secret=True,
        ),
        RuntimeSetting(key="core.negotiation.max_iterations", value=7, is_secret=False),
    ]
    s = svc.SettingsService(make_db(rows))
    vals = await s.values()
    sec = vals["core.llm.openai.api_key"]
    assert sec.value is None and sec.is_set is True and sec.hint == "1234" and sec.source == "ui"
    assert vals["core.negotiation.max_iterations"].value == 7
    assert vals["core.negotiation.max_iterations"].source == "ui"
    assert vals["core.chunking.overlap_tokens"].source == "default"


@pytest.mark.asyncio
async def test_values_reports_is_set_when_stored_secret_cannot_be_decrypted(monkeypatch):
    """Finding 1: a row exists but the current key can't open it (missing,
    rotated, or wrong SETTINGS_ENCRYPTION_KEY, or a corrupted value). The
    secret is still set -- is_set must come from the row's existence, not
    from a successful decrypt."""
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    rows = [
        RuntimeSetting(
            key="core.llm.openai.api_key",
            value="enc:v1:not-a-real-token",
            is_secret=True,
        ),
    ]
    s = svc.SettingsService(make_db(rows))
    vals = await s.values()
    sec = vals["core.llm.openai.api_key"]
    assert sec.is_set is True
    assert sec.hint is None
    assert sec.source == "ui"


@pytest.mark.asyncio
async def test_values_never_hints_a_core_secret_from_the_environment(monkeypatch):
    """Finding 2 (historical) was that a core secret configured only via
    ``.env`` had to be hinted by reading ``build_settings({})`` by attribute,
    not from ``model_dump(mode="json")`` (whose default SecretStr dump masks
    any non-empty secret to "**********"). Task 3 makes the premise
    impossible instead: ``values()`` resolves the default through
    ``build_settings({})``, which is store-only, so an env-only secret is
    never set at all -- no row, no hint, no source claiming otherwise, and
    the value never leaks into any string representation."""
    monkeypatch.setenv("LLM__OPENAI__API_KEY", "sk-envonly-9999")
    s = svc.SettingsService(make_db([]))
    vals = await s.values()
    sec = vals["core.llm.openai.api_key"]
    assert sec.is_set is False
    assert sec.hint is None
    assert sec.source == "default"
    assert "sk-envonly-9999" not in str(vals)


@pytest.mark.asyncio
async def test_save_secret_without_key_is_refused(monkeypatch):
    monkeypatch.delenv("SETTINGS_ENCRYPTION_KEY", raising=False)
    s = svc.SettingsService(make_db([]))
    with pytest.raises(svc.SettingsValidationError) as ei:
        await s.save({"core.llm.openai.api_key": "x"}, user_id=None, ip=None)
    assert "SETTINGS_ENCRYPTION_KEY" in ei.value.errors["core.llm.openai.api_key"]


class FakeAuditSession:
    """Async-context-manager fake standing in for async_session_factory()."""

    def __init__(self, fail: bool = False):
        self.fail = fail
        self.added: list[Any] = []
        self.commit = AsyncMock(side_effect=RuntimeError("boom") if fail else None)

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def __aenter__(self) -> "FakeAuditSession":
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False


@pytest.mark.asyncio
async def test_save_writes_audit_log_with_masked_secrets(monkeypatch, key):
    session = FakeAuditSession()
    monkeypatch.setattr(audit_module, "async_session_factory", lambda: session)
    db = make_db([])
    s = svc.SettingsService(db)
    await s.save(
        {"core.llm.openai.api_key": "sk-secret-value-1234", "api.enrichment_enabled": False},
        user_id=uuid.uuid4(),
        ip="127.0.0.1",
    )
    assert len(session.added) == 1
    entry = session.added[0]
    assert isinstance(entry, AuditLog)
    assert entry.action == "settings.update"
    assert entry.resource_type == "settings"
    assert set(entry.details["changed"]) == {"core.llm.openai.api_key", "api.enrichment_enabled"}
    assert entry.details["before"]["core.llm.openai.api_key"] == "unset"
    assert entry.details["after"]["core.llm.openai.api_key"] == "set"
    assert entry.details["after"]["api.enrichment_enabled"] is False
    assert "sk-secret" not in str(entry.details)
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_reset_writes_audit_log_with_keys(monkeypatch):
    session = FakeAuditSession()
    monkeypatch.setattr(audit_module, "async_session_factory", lambda: session)
    rows = [RuntimeSetting(key="api.enrichment_enabled", value=False, is_secret=False)]
    db = make_db(rows)
    s = svc.SettingsService(db)
    removed = await s.reset(["api.enrichment_enabled"], user_id=uuid.uuid4(), ip=None)
    assert removed == ["api.enrichment_enabled"]
    assert len(session.added) == 1
    entry = session.added[0]
    assert entry.action == "settings.reset"
    assert entry.details["keys"] == ["api.enrichment_enabled"]
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_save_does_not_raise_when_audit_session_fails(monkeypatch, key):
    session = FakeAuditSession(fail=True)
    monkeypatch.setattr(audit_module, "async_session_factory", lambda: session)
    db = make_db([])
    s = svc.SettingsService(db)
    before = observability.counters.audit_write_failures
    res = await s.save({"api.enrichment_enabled": False}, user_id=uuid.uuid4(), ip=None)
    assert res.applied == ["api.enrichment_enabled"]
    session.commit.assert_awaited_once()
    assert observability.counters.audit_write_failures == before + 1


@pytest.mark.asyncio
async def test_readonly_key_reports_env_value_and_database_url_is_masked():
    """Ruling 1: read-only settings show the effective env value, not the code
    default, and a URL-shaped one never leaks its credentials."""
    s = svc.SettingsService(make_db([]))
    vals = await s.values()
    db_info = vals["api.database_url"]
    assert db_info.source in ("env", "default")
    assert "maljan_dev" not in str(db_info.value)
    assert "***" in str(db_info.value)


@pytest.mark.asyncio
async def test_load_overrides_drops_undecryptable_secret_and_warns_by_key_only(monkeypatch, caplog):
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    rows = [
        RuntimeSetting(
            key="core.llm.openai.api_key", value="enc:v1:not-a-real-token", is_secret=True
        ),
        RuntimeSetting(key="core.llm.provider", value="ollama", is_secret=False),
    ]
    s = svc.SettingsService(make_db(rows))
    with caplog.at_level(logging.WARNING, logger="app.services.settings_service"):
        out = await s.load_overrides()
    assert out == {"core.llm.provider": "ollama"}
    msgs = [r.getMessage() for r in caplog.records if "cannot be decrypted" in r.getMessage()]
    assert len(msgs) == 1 and "core.llm.openai.api_key" in msgs[0]
    assert "not-a-real-token" not in caplog.text


@pytest.mark.asyncio
async def test_save_rejects_values_the_pipeline_could_not_use():
    """Found live on 2026-09-03: provider "bedrock" and max_iterations 0 were
    accepted because the model left both unconstrained. The catalog derives
    choices and bounds from pydantic, so the constraint lives there."""
    s = svc.SettingsService(make_db([]))
    with pytest.raises(svc.SettingsValidationError) as exc:
        await s.save(
            {"core.llm.provider": "bedrock", "core.negotiation.max_iterations": 0},
            user_id=None,
            ip=None,
        )
    assert set(exc.value.errors) == {"core.llm.provider", "core.negotiation.max_iterations"}


@pytest.mark.asyncio
async def test_the_mask_for_a_secret_leaf_means_unchanged(key):
    """An import document carries the mask wherever a secret was omitted.

    Storing it would set the credential to ten literal asterisks; the key is
    dropped from the change set instead, so the stored row survives untouched.
    """
    from app.services.server_map import TOKEN_MASK

    stored = RuntimeSetting(
        key="core.llm.openai.api_key",
        value=svc.box.encrypt("sk-real"),
        is_secret=True,
    )
    db = make_db([stored])
    service = svc.SettingsService(db)
    service.load_overrides = AsyncMock(return_value={})  # type: ignore[method-assign]

    result = await service.save(
        {"core.llm.openai.api_key": TOKEN_MASK, "core.llm.provider": "anthropic"},
        user_id=None,
        ip=None,
    )

    assert result.applied == ["core.llm.provider"]
    assert svc.box.decrypt(stored.value) == "sk-real"
