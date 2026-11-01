"""Which mapping keys name a credential value, and what that holds by value (T-488).

One rule (``settings_catalog.names_a_credential_value``) decides it for the
event scrub's configured values and for masking by value: a tool server's
``env`` entry is held by value only where its name names a credential.
"""

from __future__ import annotations

import pytest
from tests.credential_shapes import lowercase_body, password

from maljan.core import settings_masking as sm
from maljan.core.config import MCPServerConfig
from maljan.core.settings_catalog import (
    configured_secret_values,
    names_a_credential_value,
    shown_secret_values,
)

MASK = sm.SNAPSHOT_MASK

# Named credentials the rule read before, kept.
_ALREADY = [
    "VT_API_KEY",
    "GITHUB_TOKEN",
    "JWT_SECRET",
    "PASSWORD",
    "PASSWD",
    "DB_PASS",
    "API_KEY",
    "APIKEY",
    "AUTHORIZATION",
    "BEARER",
    "CREDENTIALS",
    "X_API_KEY",
    "X-Api-Key",
    "apiKey",
    "accessToken",
]
# Named credentials it missed.
_NEW = [
    "PGPASSWORD",
    "MYSQLPASSWD",
    "pgPassword",
    "COOKIE",
    "SESSION_COOKIE",
    "Cookie",
    "sessionCookie",
    "JWT",
    "ACCESS_JWT",
    "AUTH",
    "PROXY_AUTH",
    "REDISCLI_AUTH",
    "basic-auth",
    "auth_value",
]
# Settings about a credential, or words that only begin like one.
_NOT = [
    "author",
    "AUTHOR",
    "authority",
    "oauth",
    "oauth_url",
    "OAUTH_URL",
    "auth_mode",
    "AUTH_TYPE",
    "AUTH_DISABLED",
    # The REST sandbox's ``auth.header`` holds a header's name ("Authorization"),
    # which held by value would be masked out of every event.
    "AUTH_HEADER",
    "header",
    "authEnabled",
    "COOKIE_SECURE",
    "cookie_name",
    "COOKIE_DOMAIN",
    "JWT_ALGORITHM",
    "JWT_EXPIRES_IN",
    "PASSWORD_POLICY",
    "password_min_length",
    "passwordless",
    "TOKEN_TTL",
    "PWD",
    "jwks_url",
    "cookies_enabled",
]


@pytest.mark.parametrize("name", _ALREADY + _NEW)
def test_a_name_that_holds_a_credential_is_one(name):
    assert names_a_credential_value(name)


@pytest.mark.parametrize("name", _NOT)
def test_a_name_about_a_credential_is_not_one(name):
    assert not names_a_credential_value(name)


def _secret(variant: int = 0) -> str:
    return "Vb" + lowercase_body(14 + variant)


@pytest.mark.parametrize("name", ["PGPASSWORD", "COOKIE", "JWT", "AUTH", "SESSION_COOKIE"])
def test_an_env_value_under_a_credential_name_is_masked_by_value(name):
    value = _secret()
    settings = {"core.mcp.servers": {"any": {"env": {name: value, "TOOL_HOME": _secret(1)}}}}
    held = shown_secret_values(settings)
    assert value in held
    assert _secret(1) not in held
    assert value in configured_secret_values(settings)

    sm.remember_values(held, scope="test")
    try:
        shown = sm.masked_text(f"the server said: {value} refused")
    finally:
        sm.forget_values("test")
    assert shown == f"the server said: {MASK} refused"


def test_an_env_value_of_a_server_model_under_a_credential_name_is_held():
    value = password(16, variant=4)
    server = MCPServerConfig(command="tool", env={"PGPASSWORD": value, "JWT": _secret(2)})
    assert {value, _secret(2)} <= shown_secret_values({"servers": {"db": server}})


@pytest.mark.parametrize(
    "switch", ["basic", "Bearer", "disabled", "required", "optional", "kerberos", "oauth2"]
)
def test_a_switch_or_a_scheme_name_under_auth_is_a_setting(switch):
    """``AUTH=disabled`` says how a server authenticates; the word is in every event."""
    assert not shown_secret_values({"env": {"AUTH": switch}})
    assert not configured_secret_values({"env": {"AUTH": switch}})


def test_an_auth_block_is_read_by_its_keys_not_masked_whole():
    """The REST sandbox's ``auth`` block: its header and scheme stay, its token is held."""
    token = _secret(3)
    block = {"auth": {"header": "Authorization", "scheme": "Bearer", "token": token}}
    assert configured_secret_values(block) == {token}
    assert sm.masked_value(block, by_value=False) == {
        "auth": {"header": "Authorization", "scheme": "Bearer", "token": MASK}
    }


def test_cookies_is_a_credential_and_cookies_enabled_a_setting():
    assert names_a_credential_value("COOKIES")
    assert names_a_credential_value("session_cookies")
    assert not names_a_credential_value("cookies_enabled")


def test_the_structural_rules_mask_a_credential_named_entry_whatever_its_value():
    """A switch is kept out of the values held, never out of the masking where it stands."""
    assert sm.masked_value({"AUTH": "basic"}, by_value=False) == {"AUTH": MASK}
    assert sm.masked_server({"env": {"AUTH": "basic"}}, by_value=False) == {"env": {"AUTH": MASK}}


@pytest.mark.parametrize("key", ["auth", "jwt", "cookie", "session_cookies", "PGPASSWORD"])
def test_a_credential_named_query_value_is_masked_in_an_event(key):
    from maljan.pipeline import events

    value = _secret(4)
    events.remember_secret_values([_secret(5)], scope="test")
    try:
        kept = events.safe_answer_text(f"fetched https://h.example/p?{key}={value}&page=2")
    finally:
        events.forget_secret_values()
    assert kept == f"fetched https://h.example/p?{key}=***&page=2"


@pytest.mark.parametrize("key", ["author", "oauth", "authority", "auth_mode"])
def test_a_query_value_about_a_credential_is_kept_in_an_event(key):
    from maljan.pipeline import events

    events.remember_secret_values([_secret(5)], scope="test")
    try:
        kept = events.safe_answer_text(f"fetched https://h.example/p?{key}=someone&page=2")
    finally:
        events.forget_secret_values()
    assert kept == f"fetched https://h.example/p?{key}=someone&page=2"


@pytest.mark.parametrize(
    "flag", ["--no-auth", "--disable-token", "--skip-password", "--require-auth", "--no-password"]
)
def test_a_switch_flag_takes_no_value(flag):
    assert sm.masked_args([flag, "/x"], by_value=False) == [flag, "/x"]


@pytest.mark.parametrize("flag", ["--auth", "--jwt", "--cookie", "--api-key"])
def test_a_credential_flag_still_masks_its_value(flag):
    value = _secret(6)
    assert sm.masked_args([flag, value], by_value=False) == [flag, MASK]
    assert sm.masked_args([f"{flag}={value}"], by_value=False) == [f"{flag}={MASK}"]
