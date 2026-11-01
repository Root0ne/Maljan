"""A name the settings give something is never a secret value, wherever it stands (T-506).

The store holds a team's stages as a plain map, and each stage's identifier
sits under ``key``, a word that names a credential in an ``env`` map or a
query. Read by its name, every stage key (``analysis``, ``reversing``,
``android_static``) was registered as a secret and masked wherever the console
showed it: a server, an agent and a profile of the same name, every prompt
that says the word. A stored map is read as the model declares it, and a name
the settings give a server, an agent, a profile or a stage is never held.
"""

from __future__ import annotations

from tests.credential_shapes import password

from maljan.core import settings_masking as sm
from maljan.core.settings_catalog import configured_secret_values, shown_secret_values


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


def test_shown_text_keeps_every_name_and_masks_the_credential() -> None:
    token = password(20, variant=1)
    sm.remember_settings_values(_stored(token), scope="store")

    shown = sm.masked_text(f"analysis reverser reversing android_static {token}")

    assert shown == "analysis reverser reversing android_static ***"


def test_a_name_under_a_key_no_model_declares_is_not_held() -> None:
    """A plugin's block is read by its keys' names; a server's or an agent's name
    there is still a name."""
    stored = {**_stored(password(20, variant=2)), "core.memory.plugin_x.key": "android_static"}

    assert "android_static" not in configured_secret_values(stored)


def test_a_credential_under_a_key_no_model_declares_is_still_held() -> None:
    secret = password(20, variant=3)
    stored = {**_stored(password(20, variant=4)), "core.memory.plugin_x.key": secret}

    assert secret in configured_secret_values(stored)


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


def test_a_typed_credential_is_held_even_where_it_reads_as_a_name() -> None:
    """A field the catalogue types a secret is one whatever its value says: an API key
    that is a provider's or a server's name (``ollama``) is still held."""
    from maljan.core.settings_overrides import build_settings

    settings = build_settings({"llm.provider": "openai", "llm.openai.api_key": "ollama"})
    stored = {**_stored(password(20, variant=8)), "core.llm.openai.api_key": "analysis"}

    assert "ollama" in configured_secret_values(settings)
    assert "analysis" in configured_secret_values(stored)
