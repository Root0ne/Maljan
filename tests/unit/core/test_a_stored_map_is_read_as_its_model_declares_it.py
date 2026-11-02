"""A stored map is read for secrets as the settings model declares it (T-506).

The store holds a team's stages as a plain map, and each stage's name sits
under ``key``, a word that names a credential in an ``env`` map or a query.
Read by its name, every stage key (``analysis``, ``reversing``,
``android_static``) was registered as a secret and masked wherever the console
showed it: a server, an agent and a profile of the same name, every prompt
that says the word. A declared field the model holds to a name pattern is no
credential; everything read as a credential before is read as one still,
whatever word it is.
"""

from __future__ import annotations

import typing

import pytest
from pydantic import BaseModel, SecretStr
from tests.credential_shapes import password

from maljan.core import settings_masking as sm
from maljan.core.config import Settings
from maljan.core.settings_catalog import (
    _SECRET_NAMES,
    _names_an_identifier,
    configured_secret_values,
    names_a_credential_value,
    shown_secret_values,
)


def _stage(key: str, kind: str = "analysis", **extra: object) -> dict[str, object]:
    return {"key": key, "kind": kind, **extra}


def _stored(token: str) -> dict[str, object]:
    """Stored rows of the same shape as a store that met the fault: stage keys that are
    also a server's, an agent's and an analyst's names, and one real credential."""
    return {
        "core.agents.profiles": {
            "default": {
                "stages": [
                    _stage("triage", "triage"),
                    _stage("analysis", agents=["static"]),
                    _stage("reversing", agents=["reverser"], depends_on=["analysis"]),
                    _stage("android_static", agents=["android_static"], depends_on=["triage"]),
                    _stage("verdict", "verdict", depends_on=["reversing", "android_static"]),
                ]
            }
        },
        "core.mcp.servers": {
            "analysis": {"command": "tool", "env": {"UPSTREAM_TOKEN": token}},
        },
        "core.agents.definitions": {
            "reverser": {"prompt": "Reverse what the analysis stage found.", "tools": []},
            "android_static": {"prompt": "Read the APK.", "tools": [{"server": "analysis"}]},
        },
    }


def test_a_stage_key_in_a_stored_team_is_not_held() -> None:
    token = password(20)

    found = shown_secret_values(_stored(token))

    assert token in found
    assert not {"analysis", "reversing", "android_static", "triage", "verdict"} & found


def test_shown_text_keeps_every_stage_name_and_masks_the_credential() -> None:
    token = password(20, variant=1)
    sm.remember_settings_values(_stored(token), scope="store")

    shown = sm.masked_text(f"analysis reverser reversing android_static {token}")

    assert shown == "analysis reverser reversing android_static ***"


def test_the_default_settings_hold_nothing() -> None:
    from maljan.core.settings_overrides import build_settings

    assert shown_secret_values(build_settings({})) == set()


def test_a_declared_credential_in_a_stored_map_is_still_held() -> None:
    token, key, header = (password(20, variant=v) for v in (5, 6, 7))
    stored = {
        "core.sandbox.rest.auth": {"token": token, "header": "Authorization"},
        "core.llm.frontier.arms": {"analysis": {"api_key": key}},
        "core.mcp.servers": {"analysis": {"command": "tool", "headers": {"X-Api-Key": header}}},
    }

    found = configured_secret_values(stored)

    assert {token, key, header} <= found
    assert not {"analysis", "Authorization"} & found


def test_a_credential_under_a_key_no_model_declares_is_still_held() -> None:
    """A plugin's block is read by its keys' names, as before: a credential-named
    entry is held whatever it holds, a server's name or a stage's key included."""
    stored = _stored(password(20, variant=2))
    found = configured_secret_values(
        {
            **stored,
            "core.memory.plugin_x.key": "android_static",
            "core.memory.plugin_x.api_token": "analysis",
        }
    )

    assert {"android_static", "analysis"} <= found


# Every place a value read as a credential before stands, holding a word the
# settings also use as a name: each is still held (dev's masking survives).
_SERVER_NAME = "upstream_svc"


def _named_credentials(secret: str) -> list[tuple[str, dict[str, object]]]:
    return [
        (
            "env entry equal to a server's name",
            {
                "core.mcp.servers": {
                    secret: {"command": "x"},
                    "s": {"command": "x", "env": {"API_TOKEN": secret}},
                }
            },
        ),
        (
            "env entry equal to a profile's name",
            {
                "core.mcp.servers": {"s": {"command": "x", "env": {"API_TOKEN": secret}}},
                "core.agents.profiles": {secret: {"stages": []}},
            },
        ),
        (
            "URL password equal to a server's name",
            {
                "core.mcp.servers": {
                    secret: {"command": "x"},
                    "s": {"command": "x", "url": f"https://u:{secret}@h.example/"},
                }
            },
        ),
        (
            "header equal to an agent's name",
            {
                "core.mcp.servers": {"s": {"command": "x", "headers": {"X-Api-Key": secret}}},
                "core.agents.definitions": {secret: {"prompt": "p"}},
            },
        ),
        (
            "plugin credential equal to a stage key",
            {
                "core.memory.plug.api_token": secret,
                "core.agents.profiles": {"t": {"stages": [_stage(secret)]}},
            },
        ),
    ]


@pytest.mark.parametrize("secret", [_SERVER_NAME, "analysis"])
@pytest.mark.parametrize("case", range(5))
def test_a_credential_equal_to_a_name_the_settings_give_is_still_held(
    case: int, secret: str
) -> None:
    _label, stored = _named_credentials(secret)[case]

    assert secret in shown_secret_values(stored)


@pytest.mark.parametrize("field_name", ["sandbox", "model", "provider"])
def test_an_env_credential_equal_to_a_settings_field_name_is_still_held(field_name: str) -> None:
    stored = {"core.mcp.servers": {"s": {"command": "x", "env": {"API_TOKEN": field_name}}}}
    settings = Settings.model_validate(
        {"mcp": {"servers": {"s": {"command": "x", "env": {"API_TOKEN": field_name}}}}}
    )

    assert field_name in shown_secret_values(stored)
    assert field_name in shown_secret_values(settings)


def test_an_env_credential_of_the_model_equal_to_a_server_name_is_still_held() -> None:
    secret = password(20, variant=9)
    settings = Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    secret: {"command": "x"},
                    "s": {"command": "x", "env": {"API_TOKEN": secret}},
                }
            }
        }
    )

    assert secret in shown_secret_values(settings)


def test_a_database_password_equal_to_a_core_name_is_held_beside_the_core_settings() -> None:
    """The worker hands its own settings and the core settings in one call
    (``remember_process_secrets``): a password that is also a stage's or a
    server's name is still held."""
    from app.config import APISettings

    worker = APISettings(database_url="postgresql://u:analysis@h.example/db")
    core = _stored(password(20, variant=10))

    assert "analysis" in shown_secret_values(worker, core)
    assert "analysis" in configured_secret_values(worker, core)


def test_a_typed_credential_is_held_even_where_it_reads_as_a_name() -> None:
    from maljan.core.settings_overrides import build_settings

    settings = build_settings({"llm.provider": "openai", "llm.openai.api_key": "ollama"})
    stored = {**_stored(password(20, variant=8)), "core.llm.openai.api_key": "analysis"}

    assert "ollama" in configured_secret_values(settings)
    assert "analysis" in configured_secret_values(stored)


# The fields the model holds to a name pattern whose name also reads as a
# credential's: each is a name, so reading it as no credential loses nothing.
_IDENTIFIER_FIELDS_NAMED_LIKE_A_CREDENTIAL = {("StageDefinition", "key")}


def _models(tp: object) -> list[type[BaseModel]]:
    found = [tp] if isinstance(tp, type) and issubclass(tp, BaseModel) else []
    for arg in typing.get_args(tp):
        found.extend(_models(arg))
    return found


def test_no_credential_field_is_held_to_a_name_pattern() -> None:
    """A pattern makes a field a name (``_names_an_identifier``), so a credential
    field given a pattern would no longer be held from a stored map: none is."""
    seen: set[type[BaseModel]] = set()
    stack: list[type[BaseModel]] = [Settings]
    named_like_a_credential = set()
    while stack:
        model = stack.pop()
        if model in seen:
            continue
        seen.add(model)
        for name, field in model.model_fields.items():
            stack.extend(_models(field.annotation))
            if not _names_an_identifier(field):
                continue
            assert SecretStr not in (field.annotation, *typing.get_args(field.annotation)), name
            assert name not in _SECRET_NAMES, name
            if names_a_credential_value(name):
                named_like_a_credential.add((model.__name__, name))

    assert named_like_a_credential == _IDENTIFIER_FIELDS_NAMED_LIKE_A_CREDENTIAL
