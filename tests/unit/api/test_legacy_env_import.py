"""The one-shot legacy ``.env`` -> settings-store import.

Every test builds its own ``Settings``/``LegacyAPIView`` instance against a
throwaway ``.env`` in ``tmp_path`` and passes it in explicitly -- the bare
constructors ``run_legacy_import`` falls back to when neither is supplied
resolve the *real* project ``.env`` (secrets included), which a test must
never touch.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.fernet import Fernet

from app.models import RuntimeSetting
from app.services import legacy_env_import as mod
from app.services.legacy_env_import import LegacyAPIView, run_legacy_import
from maljan.core import settings_secrets as box
from maljan.core.config import Settings


class FakeResult:
    def __init__(self, rows=None, scalar=None):
        self._rows = rows or []
        self._scalar = scalar

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._rows))

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._scalar


def make_db(*, marker=None, existing_keys: list[str] | None = None):
    """A fake ``AsyncSession``: first ``execute`` answers the marker lookup,
    the second answers the existing-key lookup -- the same two-query order
    ``run_legacy_import`` uses.
    """
    existing_keys = existing_keys or []
    responses = [
        FakeResult(scalar=marker),
        FakeResult(rows=[(k,) for k in existing_keys]),
    ]
    db = MagicMock()
    db.execute = AsyncMock(side_effect=responses)
    db.add = MagicMock()
    db.commit = AsyncMock()
    return db


@pytest.fixture
def encryption_key(monkeypatch):
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())


@pytest.fixture
def no_op_audit(monkeypatch):
    recorded = []
    monkeypatch.setattr(
        mod.audit, "record", AsyncMock(side_effect=lambda *a, **k: recorded.append((a, k)))
    )
    return recorded


def _env_file(tmp_path, lines: list[str]):
    path = tmp_path / ".env"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.mark.asyncio
async def test_writes_rows_encrypts_secrets_audits_and_marks(tmp_path, encryption_key, no_op_audit):
    env_file = _env_file(
        tmp_path,
        [
            "LLM__PROVIDER=anthropic",
            "LLM__OPENAI__API_KEY=x",
        ],
    )
    legacy_core = Settings(_env_file=env_file)
    legacy_api = LegacyAPIView(_env_file=env_file)
    db = make_db()

    keys = await run_legacy_import(db, legacy_core=legacy_core, legacy_api=legacy_api)

    assert "core.llm.provider" in keys
    assert "core.llm.openai.api_key" in keys

    added = [call.args[0] for call in db.add.call_args_list]
    provider_row = next(r for r in added if getattr(r, "key", None) == "core.llm.provider")
    assert isinstance(provider_row, RuntimeSetting)
    assert provider_row.value == "anthropic"
    assert provider_row.is_secret is False
    assert provider_row.updated_by is None

    key_row = next(r for r in added if getattr(r, "key", None) == "core.llm.openai.api_key")
    assert key_row.is_secret is True
    assert key_row.value != "x"
    assert box.decrypt(key_row.value) == "x"

    marker_row = next(r for r in added if not isinstance(r, RuntimeSetting))
    assert marker_row.key == "legacy_env_import"
    assert marker_row.value["imported"] == len(keys)
    assert "at" in marker_row.value

    db.commit.assert_awaited_once()
    assert len(no_op_audit) == 1
    (args, kwargs) = no_op_audit[0]
    assert args[0] == "settings.legacy_import"
    assert kwargs["details"]["keys"] == keys
    assert kwargs["details"]["count"] == len(keys)
    assert "skipped_invalid" in kwargs["details"]
    # Never the value.
    assert "x" not in str(kwargs["details"])


@pytest.mark.asyncio
async def test_second_call_is_a_no_op_when_the_marker_exists(encryption_key, no_op_audit):
    db = make_db(marker=SimpleNamespace(value={"imported": 3}))

    keys = await run_legacy_import(db)

    assert keys == []
    db.add.assert_not_called()
    db.commit.assert_not_called()
    assert no_op_audit == []


@pytest.mark.asyncio
async def test_a_key_with_an_existing_row_is_left_untouched(tmp_path, encryption_key, no_op_audit):
    env_file = _env_file(tmp_path, ["LLM__PROVIDER=anthropic"])
    legacy_core = Settings(_env_file=env_file)
    legacy_api = LegacyAPIView(_env_file=env_file)
    db = make_db(existing_keys=["core.llm.provider"])

    keys = await run_legacy_import(db, legacy_core=legacy_core, legacy_api=legacy_api)

    assert "core.llm.provider" not in keys
    added_keys = [getattr(call.args[0], "key", None) for call in db.add.call_args_list]
    assert "core.llm.provider" not in added_keys


@pytest.mark.asyncio
async def test_a_legacy_value_equal_to_the_catalog_default_is_skipped(
    tmp_path, encryption_key, no_op_audit
):
    env_file = _env_file(tmp_path, [])
    legacy_core = Settings(_env_file=env_file)
    legacy_api = LegacyAPIView(_env_file=env_file)
    db = make_db()

    keys = await run_legacy_import(db, legacy_core=legacy_core, legacy_api=legacy_api)

    assert keys == []
    added = [call.args[0] for call in db.add.call_args_list]
    # Only the marker row is written -- nothing differed from the default.
    assert all(not isinstance(r, RuntimeSetting) for r in added)
    assert len(added) == 1


@pytest.mark.asyncio
async def test_an_api_editable_env_var_is_imported(tmp_path, encryption_key, no_op_audit):
    env_file = _env_file(tmp_path, ["ENRICHMENT_ENABLED=false", "LOGIN_MAX_ATTEMPTS=3"])
    legacy_core = Settings(_env_file=env_file)
    legacy_api = LegacyAPIView(_env_file=env_file)
    db = make_db()

    keys = await run_legacy_import(db, legacy_core=legacy_core, legacy_api=legacy_api)

    assert "api.enrichment_enabled" in keys
    assert "api.login_max_attempts" in keys
    added = [call.args[0] for call in db.add.call_args_list]
    row = next(r for r in added if getattr(r, "key", None) == "api.login_max_attempts")
    assert row.value == 3
