"""Task 2: token expiry comes from the settings store, not APISettings.

``create_access_token`` stays sync (called from sync and async paths alike),
so it reads the expiry minutes through ``runtime_config.get_cached`` instead
of awaiting a settings read on every token. The cache is warmed by an async
caller invoking ``runtime_config.get`` once; ``invalidate()`` clears it so a
freshly-saved override is picked up by the next warm.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.auth.jwt import create_access_token, decode_token
from app.runtime_config import runtime_config

_APPS_API_DIR = Path(__file__).resolve().parents[3] / "apps" / "api"


def test_importing_jwt_does_not_import_database():
    """Fix round 1, minor 3: ``app.runtime_config`` (and so ``app.database``,
    which calls ``create_async_engine`` at import time) must be a lazy import
    inside the two token builders, not a module-level import of
    ``app.auth.jwt`` — a script that only wants to mint/verify a token should
    not pay that import-time cost."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import app.auth.jwt, sys; sys.exit(1 if 'app.database' in sys.modules else 0)",
        ],
        cwd=str(_APPS_API_DIR),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"importing app.auth.jwt pulled in app.database as a side effect "
        f"(stdout={result.stdout!r} stderr={result.stderr!r})"
    )


@pytest.mark.asyncio
async def test_a_stored_override_changes_the_exp_claim_after_invalidate_and_get(monkeypatch):
    async def _overrides_none():
        return {}

    monkeypatch.setattr(runtime_config, "_overrides", _overrides_none)
    runtime_config.invalidate()

    token_before = create_access_token({"sub": "user-1"})
    payload_before = decode_token(token_before)
    assert payload_before is not None
    exp_before = payload_before["exp"]

    async def _overrides_with_override():
        return {"api.jwt_access_token_expire_minutes": 120}

    monkeypatch.setattr(runtime_config, "_overrides", _overrides_with_override)
    runtime_config.invalidate()
    await runtime_config.get("jwt_access_token_expire_minutes")

    token_after = create_access_token({"sub": "user-1"})
    payload_after = decode_token(token_after)
    assert payload_after is not None
    exp_after = payload_after["exp"]

    assert exp_after > exp_before
    now = datetime.now(UTC).timestamp()
    # 120 minutes out is well past the default 30-minute expiry's window.
    assert exp_after - now > 60 * 60
