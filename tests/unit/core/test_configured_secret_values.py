"""Every secret-kind setting value the platform holds, collected for the scrub.

The scrub masks these by exact value, whatever their shape, so a passphrase an
operator configured is not published because it reads like words. What counts
is the settings catalogue's own secret kind — a ``SecretStr``, or a field the
catalogue names secret — plus the password inside a service URL and a
credential-named entry of a mapping (a tool server's environment or headers).
"""

from __future__ import annotations

from pydantic import BaseModel, SecretStr
from tests.credential_shapes import password

from maljan.core.settings_catalog import configured_secret_values


class _Server(BaseModel):
    env: dict[str, str] = {}
    headers: dict[str, str] = {}
    command: str = "run-the-server"


class _Section(BaseModel):
    api_key: SecretStr | None = None
    auth_token: str = ""
    base_url: str = ""
    session_dir: str = "/var/lib/maljan/sessions"


class _Settings(BaseModel):
    llm: _Section = _Section()
    servers: list[_Server] = []
    database_url: str = ""
    minio_secret_key: SecretStr = SecretStr("")


def test_every_secret_kind_value_is_collected() -> None:
    llm_key, ghidra, db, minio, vt, header = (password(20, variant=v) for v in range(6))
    settings = _Settings(
        llm=_Section(api_key=SecretStr(llm_key), auth_token=ghidra),
        servers=[_Server(env={"VT_API_KEY": vt}, headers={"Authorization": f"Bearer {header}"})],
        database_url="postgresql+asyncpg://maljan:" + db + "@db.example:5432/maljan",
        minio_secret_key=SecretStr(minio),
    )

    found = configured_secret_values(settings)

    assert {llm_key, ghidra, db, minio, vt, header} <= found


def test_what_is_not_a_secret_is_not_collected() -> None:
    found = configured_secret_values(_Settings(llm=_Section(base_url="http://127.0.0.1:8080")))

    assert "/var/lib/maljan/sessions" not in found
    assert "run-the-server" not in found
    assert "http://127.0.0.1:8080" not in found
    assert "" not in found


def test_several_sources_are_read() -> None:
    first, second = password(20), password(20, variant=1)
    found = configured_secret_values(
        _Settings(minio_secret_key=SecretStr(first)),
        _Settings(llm=_Section(api_key=SecretStr(second))),
    )
    assert {first, second} <= found


def test_only_a_credential_value_is_collected_from_a_mapping() -> None:
    """A key that names a credential value is collected; a key that mentions one is not."""
    secret = password(20)
    server = _Server(
        env={
            "AUTH_MODE": "disabled",
            "AUTH_TYPE": "anonymous",
            "SESSION_DIR": "/var/lib/sessions",
            "TOKEN_LIMIT": "100000000",
            "PASSWORD_FILE": "/run/secrets/db_password",
            "API_TOKEN_URL": "https://auth.example/token",
            "VT_API_KEY": secret,
        },
        headers={"X-Session-Mode": "stateless", "X-Auth-Timeout": "30"},
    )

    found = configured_secret_values(_Settings(servers=[server]))

    assert found == {secret}


def test_the_rest_sandbox_jsonpath_maps_are_not_read_and_its_form_fields_are() -> None:
    """``field_names`` and ``channels`` hold where a response keeps a value; the others are sent."""
    form_key, extra_key = password(20), password(20, variant=1)

    class _Rest(BaseModel):
        field_names: dict[str, str] = {"token": "$.data.token_value"}
        channels: dict[str, str] = {"api_key": "$.report.api_key_field"}
        submit_fields: dict[str, str] = {"apikey": form_key, "priority": "normalpriority"}
        extra_fields: dict[str, str] = {"auth_token": extra_key}

    class _Holder(BaseModel):
        rest: _Rest = _Rest()

    assert configured_secret_values(_Holder()) == {form_key, extra_key}


def test_a_setting_about_a_credential_is_not_collected() -> None:
    """Only a key whose last word names a credential holds one."""
    server = _Server(
        env={
            "TOKEN_TTL": "86400000",
            "PASSWORD_POLICY": "stronglong",
            "SECRET_MANAGER": "vaultserver",
            "GITHUB_TOKEN_SCOPES": "repo,read:org",
            "USE_TOKEN_CACHE": "enabledyes",
        }
    )

    assert configured_secret_values(_Settings(servers=[server])) == set()


def test_a_number_or_a_boolean_word_is_not_a_secret() -> None:
    server = _Server(env={"API_TOKEN": "12345678901", "DB_PASSWORD": "false", "SECRET": "none"})

    assert configured_secret_values(_Settings(servers=[server])) == set()


def test_each_credential_key_is_collected() -> None:
    names = (
        "password",
        "DB_PASSWD",
        "client_secret",
        "API_KEY",
        "apikey",
        "token",
        "ACCESS_TOKEN",
        "auth_token",
        "bearer",
        "private_key",
        "credentials",
        "Authorization",
        "GITLAB_PAT",
        "DB_PASS",
        "API_KEY_VALUE",
    )
    values = {name: password(20, variant=index) for index, name in enumerate(names)}

    found = configured_secret_values(_Settings(servers=[_Server(env=values)]))

    assert set(values.values()) <= found


def test_a_disabled_setting_leaves_the_word_in_a_report() -> None:
    from maljan.pipeline import events as ev

    ev.remember_secret_values(
        configured_secret_values(_Settings(servers=[_Server(env={"AUTH_MODE": "disabled"})]))
    )
    assert ev.scrub("Defender is disabled.") == "Defender is disabled."
