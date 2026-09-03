import logging
import sys
from pathlib import Path

import pytest

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app import observability  # noqa: E402
from app.api.v1 import auth as auth_module  # noqa: E402


class _BrokenFactory:
    def __call__(self):
        return self

    async def __aenter__(self):
        raise RuntimeError("db down")

    async def __aexit__(self, *exc):
        return False


@pytest.mark.asyncio
async def test_auth_audit_failure_is_an_error_and_is_counted(monkeypatch, caplog):
    monkeypatch.setattr(auth_module, "async_session_factory", _BrokenFactory())
    before = observability.counters.audit_write_failures
    with caplog.at_level(logging.ERROR, logger="maljan.api.auth"):
        await auth_module._audit(None, None, "auth.login.success", request=None)
    assert observability.counters.audit_write_failures == before + 1
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert errors and "auth.login.success" in errors[0].getMessage()
    assert "RuntimeError" in errors[0].getMessage()
