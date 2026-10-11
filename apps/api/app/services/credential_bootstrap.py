"""Obtain a tool server's credential by the one request its declaration names.

A server may declare ``credential_bootstrap`` (``core.tool_declarations.
CredentialBootstrap``): an https URL, a JSON body, where the token sits in the
answer and the prefix it carries. ``POST /settings/servers/{key}/credential``
performs it for any server in force that declares one, and stores the token
exactly where every other tool-server credential is stored:
``SettingsService.save`` splits ``auth_token`` out of the server map into its
own encrypted row, and the map itself keeps no credential. It is deliberately
*not* written into the server's ``env`` map -- that map is part of the
non-secret JSON row and the console echoes it back. A streamable-HTTP or SSE
server sends ``auth_token`` as the bearer header, so the encrypted row is the
one place the token is of any use.

The URL comes from the declaration in force alone (a built-in's, or one an
admin saved in the server map), never from the request; the token never
reaches a log line, an audit row or the route's answer.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import httpx
from maljan.core.tool_declarations import CredentialBootstrap, first

from app.services.server_map import SERVER_MAP_KEY, TOKEN_MASK

# One call, against a host that is either up or is not. Long enough for a cold
# TLS handshake, short enough that an operator pressing a button in the console
# gets an answer rather than a spinner.
BOOTSTRAP_TIMEOUT_SECONDS = 20.0
# How much of a refusing answer the operator is shown.
ANSWER_EXCERPT_CHARS = 200


class BootstrapError(Exception):
    """The request did not yield a credential. The message is operator-facing."""


def new_client() -> httpx.AsyncClient:
    """The HTTP client one bootstrap is made with. Redirects are not followed."""
    return httpx.AsyncClient(timeout=BOOTSTRAP_TIMEOUT_SECONDS, follow_redirects=False)


def bootstrap_facts(servers: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    """Per server in force that declares a bootstrap: what the console's step shows."""
    out: dict[str, dict[str, str]] = {}
    for key, cfg in servers.items():
        declared = getattr(cfg, "credential_bootstrap", None)
        if declared is None:
            continue
        out[str(key)] = {
            "label": str(getattr(cfg, "label", "") or key),
            "family": declared.family,
            "note": declared.note,
        }
    return out


async def obtain_credential(
    declared: CredentialBootstrap, *, label: str, client: httpx.AsyncClient | None = None
) -> tuple[str, dict[str, str]]:
    """The token the declared request answers with, and the answer's declared facts."""
    owned = client is None
    http = client or new_client()
    try:
        response = await http.post(declared.url, json=declared.request_body())
    except httpx.HTTPError as exc:
        raise BootstrapError(f"{label} could not be reached ({type(exc).__name__})") from exc
    finally:
        if owned:
            await http.aclose()

    if response.status_code >= 400:
        # The body is the service's, so it is reported to the admin who pressed
        # the button, trimmed: a refusal answers with a sentence, not a document.
        # A credential a refusing answer still carries at the declared path is
        # masked in it.
        raise BootstrapError(
            f"{label} answered {response.status_code}: "
            f"{_without_token(response.text, declared)[:ANSWER_EXCERPT_CHARS]}"
        )
    try:
        body = response.json()
    except ValueError as exc:
        raise BootstrapError(f"{label}'s answer was not JSON") from exc
    if not isinstance(body, dict | list):
        raise BootstrapError(f"{label}'s answer was not an object")
    token = first(body, declared.token_json_path)
    if not isinstance(token, str) or not token or not token.startswith(declared.token_prefix):
        raise BootstrapError(f"{label}'s answer carried no credential")
    facts: dict[str, str] = {}
    for name, path in declared.facts.items():
        value = first(body, path)
        facts[name] = "" if value is None or isinstance(value, dict | list) else str(value)
    return token, facts


def _without_token(text: str, declared: CredentialBootstrap) -> str:
    """``text`` with the credential at the declared path, if it holds one, masked."""
    try:
        token = first(json.loads(text), declared.token_json_path)
    except ValueError:
        return text
    return text.replace(token, TOKEN_MASK) if isinstance(token, str) and token else text


def server_map_with_token(stored: dict[str, Any], key: str, token: str) -> dict[str, Any]:
    """The server map to save: server ``key`` enabled, carrying the new token.

    Built from whatever is stored rather than from the defaults alone, so an
    operator who has edited the tick list, the bindings or any other server
    keeps every one of those edits. A built-in the stored map does not hold
    yet is taken from its seed; ``validate_server_map`` re-seeds every other
    built-in it is not given.
    """
    from maljan.core.config import _builtin_servers

    servers: dict[str, Any] = {
        name: dict(entry) for name, entry in stored.items() if isinstance(entry, dict)
    }
    entry = servers.get(key)
    if entry is None:
        seed = _builtin_servers().get(key)
        entry = seed.model_dump(mode="json") if seed is not None else {}
    entry = dict(entry)
    entry["enabled"] = True
    entry["auth_token"] = token
    servers[key] = entry
    return servers


def masked_state(key: str, entry: dict[str, Any], facts: dict[str, str]) -> dict[str, Any]:
    """What the route answers with: the stored state, never the token."""
    return {
        "server": key,
        "enabled": True,
        "transport": str(entry.get("transport") or ""),
        "url": str(entry.get("url") or ""),
        "auth_token": TOKEN_MASK,
        "facts": dict(facts),
        "tools": entry.get("tools"),
    }


__all__ = [
    "BOOTSTRAP_TIMEOUT_SECONDS",
    "SERVER_MAP_KEY",
    "BootstrapError",
    "bootstrap_facts",
    "masked_state",
    "new_client",
    "obtain_credential",
    "server_map_with_token",
]
