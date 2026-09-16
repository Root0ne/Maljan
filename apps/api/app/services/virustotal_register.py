"""Register this deployment with VirusTotal and store the agent token.

VirusTotal's MCP server authenticates with an agent token rather than a
VirusTotal API key, and the token is issued non-interactively: one POST to
``/agents/register`` naming the agent family and version, one ``vtai_`` token
back. That is the whole ceremony, which is why it belongs in the product
instead of in a paragraph telling an operator to run curl.

The token is stored exactly where every other tool-server credential is
stored: ``SettingsService.save`` splits ``auth_token`` out of the server map
into its own encrypted row, and the map itself keeps no credential. It is
deliberately *not* written into the server's ``env`` map -- that map is part
of the non-secret JSON row and the console echoes it back, so a token there
would be readable. The seeded transport is streamable-HTTP, where the registry
sends ``auth_token`` as the bearer header, so the encrypted row is also the
one place the token is of any use.
"""

from __future__ import annotations

from typing import Any

import httpx
from maljan.core import virustotal

from app.services.server_map import SERVER_MAP_KEY, TOKEN_MASK

# One registration call, against a host that is either up or is not. Long
# enough for a cold TLS handshake, short enough that an operator pressing a
# button in the console gets an answer rather than a spinner.
REGISTER_TIMEOUT_SECONDS = 20.0

# The prefix every issued agent token carries. Checked so a response that is
# shaped like success but carries something else is reported as a failure
# rather than stored and discovered later by a job.
TOKEN_PREFIX = "vtai_"


class RegistrationError(Exception):
    """The registration did not yield a token. The message is operator-facing."""


async def register_agent(*, client: httpx.AsyncClient | None = None) -> dict[str, str]:
    """Ask VirusTotal for an agent token, and return the response's own facts.

    The caller stores the token; everything else in the answer -- the agent id,
    the public handle, the endpoint -- is what the console shows so an operator
    can recognise this deployment in VirusTotal's own listing.
    """
    payload = {
        "agent_family": virustotal.AGENT_FAMILY,
        "agent_version": virustotal.VT_MCP_VERSION,
    }
    owned = client is None
    http = client or httpx.AsyncClient(timeout=REGISTER_TIMEOUT_SECONDS)
    try:
        response = await http.post(virustotal.REGISTER_URL, json=payload)
    except httpx.HTTPError as exc:
        raise RegistrationError(f"VirusTotal could not be reached ({type(exc).__name__})") from exc
    finally:
        if owned:
            await http.aclose()

    if response.status_code >= 400:
        # The body is VirusTotal's, so it is reported in full to the admin who
        # pressed the button and trimmed: a rate-limited register answers with
        # a sentence, not a document.
        raise RegistrationError(
            f"VirusTotal answered {response.status_code}: {response.text[:200]}"
        )
    try:
        body = response.json()
    except ValueError as exc:
        raise RegistrationError("VirusTotal's answer was not JSON") from exc
    if not isinstance(body, dict):
        raise RegistrationError("VirusTotal's answer was not an object")
    token = str(body.get("agent_token") or "")
    if not token.startswith(TOKEN_PREFIX):
        raise RegistrationError("VirusTotal's answer carried no agent token")
    return {
        "agent_token": token,
        "agent_id": str(body.get("agent_id") or ""),
        "public_handle": str(body.get("public_handle") or ""),
        "mcp_endpoint": str(body.get("mcp_endpoint") or virustotal.MCP_ENDPOINT),
    }


def server_map_with_token(stored: dict[str, Any], token: str) -> dict[str, Any]:
    """The server map to save: VirusTotal enabled, carrying the new token.

    Built from whatever is stored rather than from the defaults alone, so an
    operator who has edited the tick list, the bindings or any other server
    keeps every one of those edits through a registration. A deployment that
    has never written the map has no stored entry; ``validate_server_map``
    re-seeds every built-in it is not given, so the seed supplies the rest.
    """
    from maljan.core.config import _builtin_servers

    servers: dict[str, Any] = {
        name: dict(entry) for name, entry in stored.items() if isinstance(entry, dict)
    }
    seed = _builtin_servers()[virustotal.SERVER_KEY].model_dump(mode="json")
    entry = dict(servers.get(virustotal.SERVER_KEY) or seed)
    entry["enabled"] = True
    entry["auth_token"] = token
    servers[virustotal.SERVER_KEY] = entry
    return servers


def masked_state(entry: dict[str, Any], facts: dict[str, str]) -> dict[str, Any]:
    """What the endpoint answers with: the stored state, never the token."""
    return {
        "server": virustotal.SERVER_KEY,
        "enabled": True,
        "transport": str(entry.get("transport") or ""),
        "url": str(entry.get("url") or facts.get("mcp_endpoint") or ""),
        "auth_token": TOKEN_MASK,
        "agent_id": facts.get("agent_id", ""),
        "public_handle": facts.get("public_handle", ""),
        "tools": entry.get("tools"),
    }


__all__ = [
    "REGISTER_TIMEOUT_SECONDS",
    "SERVER_MAP_KEY",
    "RegistrationError",
    "masked_state",
    "register_agent",
    "server_map_with_token",
]
