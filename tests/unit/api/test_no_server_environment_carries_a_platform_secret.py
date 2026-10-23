"""No tool server's environment carries one of the platform's own secrets.

The variables the API and the worker are started with that open the platform's
stores (the database and Redis URLs, the object store's keys, the settings key,
the JWT signing keys) are declared once, on ``PlatformSecrets``, which the
bootstrap model inherits. The names refused in a server block's ``env_allow``
and ``env`` are read from that declaration: refused where the block is
validated, so at a save, at a stored row's load for a job and in a connection
test, and dropped at the spawn whatever the block says.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from tests.credential_shapes import lowercase_body, password

from app.config import APISettings
from maljan.core import settings_secrets
from maljan.core.config import MCPServerConfig, Settings
from maljan.core.platform_secrets import (
    PLATFORM_SECRET_NAMES,
    PlatformSecret,
    PlatformSecrets,
    is_platform_secret,
)
from maljan.core.settings_catalog import names_a_credential_value
from maljan.core.settings_overrides import StoredValueRefused

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "docker" / "docker-compose.yml"
_REQUIRED = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):\?")


def _mark(field: str) -> PlatformSecret | None:
    info = PlatformSecrets.model_fields[field]
    return next((m for m in info.metadata if isinstance(m, PlatformSecret)), None)


def _opens(name: str) -> str:
    """What the field ``name`` is read or written as opens, from its mark."""
    for field in PlatformSecrets.model_fields:
        mark = _mark(field)
        if mark is not None and name in (field.upper(), *mark.written_as):
            return mark.opens
    raise AssertionError(f"{name} is no field's name")


def _value(name: str) -> str:
    """A value for ``name`` that no refusal, answer or log line may repeat."""
    return f"{name.lower()}-{password(18)}"


# ---------------------------------------------------------------------------
# The list is read from the bootstrap model, never kept beside it
# ---------------------------------------------------------------------------


def test_the_names_are_the_bootstrap_models_own_and_what_the_deployment_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected: set[str] = set()
    for field, info in PlatformSecrets.model_fields.items():
        # The bootstrap model reads this field, with the same type and a default
        # of its own, so building it still never refuses.
        assert APISettings.model_fields[field].annotation is info.annotation, field
        assert not APISettings.model_fields[field].is_required(), field
        mark = _mark(field)
        assert mark is not None and mark.opens, f"{field} says nothing of what it opens"
        expected |= {field.upper(), *mark.written_as}
        written = _value(field)
        monkeypatch.setenv(field.upper(), written)
        read = getattr(APISettings(), field)
        assert (read.get_secret_value() if isinstance(read, SecretStr) else read) == written
    assert PLATFORM_SECRET_NAMES == expected
    assert settings_secrets.ENV_VAR in PLATFORM_SECRET_NAMES


def test_a_bootstrap_variable_that_opens_a_store_is_declared_with_them() -> None:
    """A secret typed, named or shaped as one on the bootstrap model is covered by being there.

    Added to ``APISettings`` directly instead, it would be read from the
    environment and handed to any server that asked for it.
    """
    for field, info in APISettings.model_fields.items():
        default = info.default
        holds_a_store = (
            info.annotation is SecretStr
            or names_a_credential_value(field)
            or (isinstance(default, str) and "://" in default)
        )
        if holds_a_store:
            assert field in PlatformSecrets.model_fields, (
                f"APISettings.{field} looks like a variable that opens a store: declare it "
                "on PlatformSecrets so no tool server's environment may carry it"
            )


# The variables ``app.bootstrap`` reads straight from the environment that open
# no store. Anything else it reads that way must be a platform secret.
_BOOTSTRAP_READS_NOT_A_STORE: frozenset[str] = frozenset()
_ENV_READ = re.compile(r"os\.(?:environ\.get|getenv|environ\[)\(?\s*[\"']([A-Za-z_][A-Za-z0-9_]*)")


def test_every_variable_bootstrap_reads_from_the_environment_is_covered() -> None:
    """A credential the startup check reads directly, not through the model, is covered too."""
    text = (ROOT / "apps" / "api" / "app" / "bootstrap.py").read_text(encoding="utf-8")
    read = set(_ENV_READ.findall(text))
    assert "JWT_SECRET_KEY" in read, "the guard no longer sees bootstrap's own read"
    uncovered = {n for n in read if n not in _BOOTSTRAP_READS_NOT_A_STORE}
    assert all(is_platform_secret(n) for n in uncovered), sorted(
        n for n in uncovered if not is_platform_secret(n)
    )


def test_every_secret_the_compose_file_requires_is_refused() -> None:
    """Each ``:?`` variable, and the one a bootstrap variable is composed around."""
    text = COMPOSE.read_text(encoding="utf-8")
    required = set(_REQUIRED.findall(text))
    assert required, "the compose file names no required variable; this guard reads nothing"
    assert required <= PLATFORM_SECRET_NAMES, sorted(required - PLATFORM_SECRET_NAMES)

    services = yaml.safe_load(text)["services"]
    composed = 0
    for service in services.values():
        environment = service.get("environment") or {}
        for variable, value in environment.items():
            field = str(variable).lower()
            if field not in PlatformSecrets.model_fields:
                continue
            mark = _mark(field)
            assert mark is not None
            for source in _REQUIRED.findall(str(value)):
                composed += 1
                assert source in {variable, *mark.written_as}, (variable, source)
    assert composed, "no backend service composes a bootstrap variable; this guard reads nothing"


# ---------------------------------------------------------------------------
# Refused where a block is validated
# ---------------------------------------------------------------------------


def test_every_name_is_refused_in_env_allow_and_in_env() -> None:
    for name in sorted(PLATFORM_SECRET_NAMES):
        for spelled in (name, name.lower()):
            for field, payload in (
                ("env_allow", {"env_allow": ["PATH", spelled]}),
                ("env", {"env": {"JAVA_HOME": "/opt/jdk", spelled: _value(name)}}),
            ):
                with pytest.raises(ValidationError) as refused:
                    MCPServerConfig(transport="stdio", command="/bin/true", **payload)
                (error,) = refused.value.errors()
                assert error["loc"] == (field,)
                message = error["msg"]
                assert spelled in message and _opens(name) in message, message
                assert spelled == name or f"read as {name}" in message, message
                assert f"remove it from {field}." in message, message
                assert _value(name) not in str(refused.value)


def test_a_declaration_that_needs_one_is_refused_the_same_way() -> None:
    with pytest.raises(ValidationError) as refused:
        MCPServerConfig(
            transport="stdio",
            command="/bin/true",
            required_env_allow=["MALJAN_SAMPLE_ROOTS", "DATABASE_URL"],
        )
    (error,) = refused.value.errors()
    assert error["loc"] == ("required_env_allow",)
    assert "DATABASE_URL opens the platform's database" in error["msg"]
    assert "remove it from required_env_allow." in error["msg"]
    # A non-secret name it may list still passes, and so does one in ``variable_names``.
    MCPServerConfig(
        transport="stdio",
        command="/bin/true",
        required_env_allow=["MALJAN_SAMPLE_ROOTS"],
        variable_names=["MALJAN_SAMPLE_ROOTS"],
    )


def test_a_provider_block_is_refused_the_same_way() -> None:
    signing_key = lowercase_body(40)
    with pytest.raises(ValidationError) as refused:
        Settings.model_validate({"static": {"ghidra": {"env": {"JWT_SECRET_KEY": signing_key}}}})
    (error,) = refused.value.errors()
    assert error["loc"] == ("static", "ghidra", "env")
    assert "JWT_SECRET_KEY signs a session for any user" in error["msg"]
    assert signing_key not in str(refused.value)


def test_ordinary_names_still_pass() -> None:
    config = MCPServerConfig(
        transport="stdio",
        command="/bin/true",
        env_allow=["PATH", "VIRUSTOTAL_API_KEY", "OPENAI_API_KEY", "MALJAN_SAMPLE_ROOTS"],
        env={"JAVA_HOME": "/opt/jdk", "ANTHROPIC_API_KEY": lowercase_body(24)},
    )
    assert config.env_allow == [
        "PATH",
        "VIRUSTOTAL_API_KEY",
        "OPENAI_API_KEY",
        "MALJAN_SAMPLE_ROOTS",
    ]
    assert not any(is_platform_secret(name) for name in (*config.env_allow, *config.env))
    # Every block that ships validates: none of them names one.
    shipped = Settings(_env_file=None)
    for server in shipped.mcp.servers.values():
        assert not any(is_platform_secret(n) for n in (*server.env_allow, *server.env))


# ---------------------------------------------------------------------------
# At a save, at a stored row's load, in a connection test
# ---------------------------------------------------------------------------


@pytest.fixture
def client() -> TestClient:
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(
        id="00000000-0000-0000-0000-000000000001"
    )
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app)


def test_a_save_is_refused_through_the_api_with_the_reason(client: TestClient) -> None:
    url = "redis://:" + password(20) + "@cache:6379/0"
    changes: dict[str, Any] = {
        "core.mcp.servers": {
            "mine": {
                "enabled": True,
                "transport": "stdio",
                "command": "mine-mcp",
                "env_allow": ["DATABASE_URL"],
                "env": {"REDIS_URL": url},
            }
        },
    }
    with patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})):
        r = client.patch("/api/v1/settings", json={"changes": changes})

    assert r.status_code == 422
    errors = r.json()["errors"]
    assert "DATABASE_URL opens the platform's database" in errors["core.mcp.servers.mine.env_allow"]
    assert "REDIS_URL opens the platform's job queue" in errors["core.mcp.servers.mine.env"]
    assert "remove it from env." in errors["core.mcp.servers.mine.env"]
    assert url not in r.text


def test_a_save_of_a_provider_block_is_refused_with_the_reason(client: TestClient) -> None:
    signing_key = lowercase_body(40)
    with patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})):
        r = client.patch(
            "/api/v1/settings",
            json={"changes": {"core.static.ghidra.env": {"JWT_SECRET_KEY": signing_key}}},
        )
    assert r.status_code == 422
    reason = r.json()["errors"]["core.static.ghidra.env"]
    assert "JWT_SECRET_KEY signs a session for any user" in reason
    assert signing_key not in r.text


def test_a_stored_block_fails_the_job_with_the_reason(caplog: pytest.LogCaptureFixture) -> None:
    """The rule for a refused stored value: the job fails by name, never on defaults."""
    from app.worker.analysis_worker import build_job_settings

    stored = {
        "mcp.servers": {
            "mine": {
                "enabled": True,
                "transport": "stdio",
                "command": "mine-mcp",
                "env_allow": ["SETTINGS_ENCRYPTION_KEY"],
            }
        }
    }
    with caplog.at_level("ERROR"), pytest.raises(StoredValueRefused) as refused:
        build_job_settings(stored, None)

    assert list(refused.value.refused) == ["core.mcp.servers"]
    reason = refused.value.refused["core.mcp.servers"]
    assert "SETTINGS_ENCRYPTION_KEY decrypts every value the settings store keeps" in reason
    assert "remove it from env_allow" in reason
    assert "SETTINGS_ENCRYPTION_KEY" in caplog.text


def test_a_stored_provider_block_fails_the_job_with_the_reason() -> None:
    from app.worker.analysis_worker import build_job_settings

    secret_key = lowercase_body(32)
    with pytest.raises(StoredValueRefused) as refused:
        build_job_settings({"static.ghidra.env": {"MINIO_SECRET_KEY": secret_key}}, None)
    assert list(refused.value.refused) == ["core.static.ghidra.env"]
    assert "MINIO_SECRET_KEY opens the platform's object store" in str(refused.value)
    assert secret_key not in str(refused.value)


@pytest.mark.asyncio
async def test_a_connection_test_names_the_refusal_and_starts_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.settings_probes import probe_mcp

    started: list[Any] = []
    monkeypatch.setattr("mcp.StdioServerParameters", lambda **kw: started.append(kw))
    result = await probe_mcp(
        {
            "name": "mine",
            "entry": {
                "enabled": True,
                "transport": "stdio",
                "command": "mine-mcp",
                "env_allow": ["POSTGRES_PASSWORD"],
            },
        }
    )
    assert result.ok is False
    assert "env_allow: POSTGRES_PASSWORD opens the platform's database" in result.detail
    assert started == []
