"""A provider's API key never crosses a network outside the deployment over plain http.

Every address a provider sends a configured credential to — its own block's
address, an agent entry's or a fallback's own endpoint, a frontier arm's —
takes ``https`` anywhere and plain ``http`` only to a host inside this
deployment as ``core.host_locality`` places it, never to an IPv6 address that
tunnels to IPv4 elsewhere. Any other host is refused, at the setting that names
it, with the reason. Not held to it: an address with no key to carry, and a
provider whose ``allow_plain_http`` the operator set.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError
from tests.credential_shapes import password

from maljan.core.config import Settings, credential_in_clear_refusal
from maljan.core.settings_overrides import build_settings, stored_settings

KEY = password(variant=8)

INSIDE = [
    "http://127.0.0.1:8080/v1",
    "http://localhost:8080/v1",
    "http://[::1]:8080/v1",
    "http://192.168.1.20:8080/v1",
    "http://10.0.0.5:8080/v1",
    "http://host.docker.internal:8080/v1",
    "http://llama:8080/v1",
    "http://gpu-box.local:8080/v1",
    "http://llm.internal:8080/v1",
]
OUTSIDE = [
    "http://api.example.org/v1",
    "http://8.8.8.8:8080/v1",
    "http://llm.example.org.",
    # 6to4, Teredo and NAT64 forms of a private address: the relay hop is outside.
    "http://[2002:a00:1::1]/v1",
    "http://[2001:0:4136:e378:8000:63bf:f5ff:fffe]/v1",
    "http://[64:ff9b::a00:1]/v1",
    "http://[64:ff9b:1::a00:1]/v1",
]


def _openai(url: str, **more: Any) -> Any:
    return build_settings(
        {
            "llm.provider": "openai",
            "llm.openai.api_key": KEY,
            "llm.openai.base_url": url,
            **more,
        }
    )


def _agent(**entry: Any) -> dict:
    return {"static": {"provider": "openai", "model": "m", **entry}}


@pytest.mark.parametrize("url", INSIDE)
def test_plain_http_inside_the_deployment_keeps_working(url: str) -> None:
    assert _openai(url).llm.openai.base_url == url


@pytest.mark.parametrize("url", ["https://api.example.org/v1", "https://8.8.8.8/v1"])
def test_https_is_taken_anywhere(url: str) -> None:
    assert _openai(url).llm.openai.base_url == url


@pytest.mark.parametrize("url", OUTSIDE)
def test_plain_http_to_a_host_outside_is_refused_at_its_own_key(url: str) -> None:
    with pytest.raises(ValidationError) as caught:
        _openai(url)
    (error,) = caught.value.errors()
    assert error["loc"] == ("llm", "openai", "base_url")
    assert "in clear" in error["msg"] and "allow_plain_http" in error["msg"]


@pytest.mark.parametrize("url", ["http://gpu.lan:8080/v1", "http://api.example.org/v1"])
def test_with_no_key_set_any_address_keeps_working(url: str) -> None:
    """A key-less llama.cpp or vLLM server on a LAN carries no key to send in clear."""
    built = build_settings({"llm.provider": "openai", "llm.openai.base_url": url})
    assert built.llm.openai.base_url == url
    entry = build_settings({"llm.agents": _agent(base_url=url)})
    assert entry.llm.agents["static"].base_url == url


def test_the_flat_key_setting_counts_as_a_key() -> None:
    with pytest.raises(ValidationError, match="in clear"):
        Settings(
            _env_file=None,
            openai_api_key=KEY,
            llm={"openai": {"base_url": "http://api.example.org/v1"}},
        )


def test_allow_plain_http_takes_a_keyed_server_on_any_host() -> None:
    built = _openai("http://gpu.lan:8080/v1", **{"llm.openai.allow_plain_http": True})
    assert built.llm.openai.base_url == "http://gpu.lan:8080/v1"
    entry = build_settings(
        {
            "llm.openai.api_key": KEY,
            "llm.openai.allow_plain_http": True,
            "llm.agents": _agent(base_url="http://gpu.lan:8080/v1"),
        }
    )
    assert entry.llm.agents["static"].base_url == "http://gpu.lan:8080/v1"
    assert Settings(_env_file=None).llm.openai.allow_plain_http is False


def test_allow_plain_http_is_in_the_catalogue_and_says_the_key_travels_in_clear() -> None:
    from maljan.core.settings_catalog import core_catalog

    (entry,) = [e for e in core_catalog() if e.path == "llm.openai.allow_plain_http"]
    assert "in clear" in entry.description


def test_the_refusal_never_echoes_the_address() -> None:
    secret = password()
    with pytest.raises(ValidationError) as caught:
        _openai(f"http://user:{secret}@api.example.org/v1")
    assert secret not in str(caught.value)
    assert secret not in repr(caught.value.errors())
    assert KEY not in str(caught.value)


def test_an_agent_s_own_endpoint_is_held_to_the_same_rule() -> None:
    with pytest.raises(ValidationError, match="agent 'static''s base_url would send") as e:
        build_settings(
            {
                "llm.openai.api_key": KEY,
                "llm.agents": _agent(base_url="http://api.example.org/v1"),
            }
        )
    assert [err["loc"] for err in e.value.errors()] == [("llm", "agents", "static", "base_url")]
    kept = build_settings(
        {"llm.openai.api_key": KEY, "llm.agents": _agent(base_url="http://10.1.2.3/v1")}
    )
    assert kept.llm.agents["static"].base_url == "http://10.1.2.3/v1"


def test_a_fallback_s_own_endpoint_is_held_to_the_same_rule() -> None:
    fallback = {"provider": "openai", "model": "n", "base_url": "http://api.example.org/v1"}
    with pytest.raises(ValidationError, match="would send the API key in clear") as e:
        build_settings({"llm.openai.api_key": KEY, "llm.agents": _agent(fallbacks=[fallback])})
    assert [err["loc"] for err in e.value.errors()] == [
        ("llm", "agents", "static", "fallbacks", 0, "base_url")
    ]


def test_a_provider_with_no_credential_is_not_held_to_it() -> None:
    # Ollama sends no key, so its per-agent address may be any host.
    built = Settings(
        _env_file=None,
        llm={
            "agents": {
                "static": {
                    "provider": "ollama",
                    "model": "m",
                    "base_url": "http://ollama.example.org:11434",
                }
            }
        },
    )
    assert built.llm.agents["static"].base_url == "http://ollama.example.org:11434"


def test_a_frontier_arm_with_a_key_is_held_to_the_same_rule() -> None:
    key = password(variant=6)
    with pytest.raises(ValidationError, match="the frontier arm's base_url"):
        Settings(
            _env_file=None,
            llm={"frontier": {"base_url": "http://api.example.org/v1", "api_key": key}},
        )
    with pytest.raises(ValidationError, match="the frontier arm's base_url") as caught:
        Settings(
            _env_file=None,
            llm={
                "frontier": {
                    "arms": {"a": {"base_url": "http://api.example.org/v1", "api_key": key}}
                }
            },
        )
    assert [err["loc"] for err in caught.value.errors()] == [
        ("llm", "frontier", "arms", "a", "base_url")
    ]
    assert key not in str(caught.value) and key not in repr(caught.value.errors())


def test_a_frontier_arm_with_no_key_is_not_held_to_it() -> None:
    built = Settings(
        _env_file=None,
        llm={"frontier": {"arms": {"a": {"base_url": "http://gpu.lan:8080/v1"}}}},
    )
    assert built.llm.frontier.arms["a"].base_url == "http://gpu.lan:8080/v1"


def test_a_stored_refused_address_leaves_the_console_able_to_open() -> None:
    built, refused = stored_settings(
        {"llm.openai.api_key": KEY, "llm.openai.base_url": "http://api.example.org/v1"}
    )
    assert built.llm.openai.base_url is None
    assert list(refused) == ["llm.openai.base_url"]


def test_the_rule_reads_the_host_alone() -> None:
    assert credential_in_clear_refusal(None, "x") == ""
    assert credential_in_clear_refusal("", "x") == ""
    assert credential_in_clear_refusal("https://anything.example/v1", "x") == ""
    assert credential_in_clear_refusal("http://127.0.0.1", "x") == ""
    # A single label is a compose service's name, taken as inside, as documented.
    assert credential_in_clear_refusal("http://llm/", "x") == ""
    # An IPv4-mapped address is the host it carries.
    assert credential_in_clear_refusal("http://[::ffff:10.0.0.1]/", "x") == ""
    assert "x would send" in credential_in_clear_refusal("http://example.org", "x")
    assert credential_in_clear_refusal("http:///nohost", "x")


@pytest.mark.parametrize(
    "url",
    [
        "http://[evil.example]/",  # not an address urlsplit can read
        "http://evil.example:99999/",  # a port no address has
        "https://[evil.example]/",
    ],
)
def test_an_address_that_cannot_be_read_is_refused(url: str) -> None:
    assert "cannot be read" in credential_in_clear_refusal(url, "x")


@pytest.mark.parametrize(
    "url", ["http://evil.example\\@10.0.0.1/v1", "http://evil.example\t@10.0.0.1/v1"]
)
def test_a_plain_http_address_clients_read_differently_is_refused(url: str) -> None:
    """urlsplit reads 10.0.0.1 here; an HTTP client may send to evil.example."""
    assert "read differently" in credential_in_clear_refusal(url, "x")


def test_a_frontier_arm_refusal_names_no_switch_the_arm_lacks() -> None:
    key = password(variant=7)
    with pytest.raises(ValidationError) as caught:
        Settings(
            _env_file=None,
            llm={"frontier": {"base_url": "http://api.example.org/v1", "api_key": key}},
        )
    assert "allow_plain_http" not in str(caught.value)
    assert "use https" in str(caught.value)
    # A provider has the switch, and its refusal keeps naming it.
    assert "allow_plain_http" in credential_in_clear_refusal("http://example.org", "x")
