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
