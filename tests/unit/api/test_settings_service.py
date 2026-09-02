import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.fernet import Fernet

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.models import RuntimeSetting  # noqa: E402
from app.services import settings_service as svc  # noqa: E402
from app.services.settings_catalog_api import catalog_index, full_catalog  # noqa: E402


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
    assert vals["core.chunking.overlap_tokens"].source in ("env", "default")


@pytest.mark.asyncio
async def test_save_secret_without_key_is_refused(monkeypatch):
    monkeypatch.delenv("SETTINGS_ENCRYPTION_KEY", raising=False)
    s = svc.SettingsService(make_db([]))
    with pytest.raises(svc.SettingsValidationError) as ei:
        await s.save({"core.llm.openai.api_key": "x"}, user_id=None, ip=None)
    assert "SETTINGS_ENCRYPTION_KEY" in ei.value.errors["core.llm.openai.api_key"]


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
