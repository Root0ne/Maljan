"""The enrichment sources in force, their credentials, and what the console is told about them.

``api.enrichment_sources`` holds the operator's declarations
(``maljan.enrichment.declared``), laid over the sources the platform ships.
A source's own credential (``api_key``) is stored in an encrypted row of its
own, like a frontier arm's key (``nested_secrets``); a source may instead name
a secret setting in ``credential``, which the catalog generates from the
shipped declarations (``maljan.enrichment.declared.credential_settings_of``).

With ``api.enrichment_reputation_servers`` on, every enabled tool server whose
roles hold ``reputation`` and that no source names is a source too
(:func:`reputation_server_sources`): asked through its indicator lookups, read
from its declarations in force, its answer read as a reputation answer. Off
(the default), a server is asked only through a source that names it: the
operator's consent to its indicators leaving the host.

Everything here reads the declarations and never names a source.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, Mapping
from typing import Any

from maljan.enrichment.declared import (
    EnrichmentSource,
    ReadySource,
    effective_sources,
)

from app.services.nested_secrets import NestedSecretMap

ENRICHMENT_SOURCES_PATH = "enrichment_sources"
ENRICHMENT_SOURCES_KEY = f"api.{ENRICHMENT_SOURCES_PATH}"
# The switch that makes every enabled reputation server a source.
REPUTATION_SERVERS_PATH = "enrichment_reputation_servers"
# The key a reputation server is asked under as a source: its declared source.
SERVER_SOURCE_PREFIX = "mcp:"
SOURCE_SECRETS = NestedSecretMap(ENRICHMENT_SOURCES_KEY, "api_key")

SecretReader = Callable[[str], Awaitable[str]]


def stored_map(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def staged_over_stored(stored: Mapping[str, Any], values: Mapping[str, Any]) -> dict[str, Any]:
    """The stored source map with each staged entry laid over its key, field by field.

    ``stored`` and ``values`` are whole settings maps (catalog key to value),
    as a probe receives them. A staged own ``api_key`` that is the mask (or
    empty) means the stored one, as it does on save.
    """
    from app.services.server_map import TOKEN_MASK

    held = {
        k: dict(v) if isinstance(v, Mapping) else v
        for k, v in stored_map(stored.get(ENRICHMENT_SOURCES_KEY)).items()
    }
    staged = values.get(ENRICHMENT_SOURCES_KEY)
    if not isinstance(staged, Mapping):
        return held
    for key, entry in staged.items():
        if not isinstance(entry, Mapping):
            continue
        entry = dict(entry)
        if entry.get("api_key") in (None, "", TOKEN_MASK):
            entry.pop("api_key", None)
        previous = held.get(key)
        held[key] = {**(previous if isinstance(previous, dict) else {}), **entry}
    return held


def credential_settings() -> frozenset[str]:
    """The settings a source's ``credential`` may name: the secrets of the enrichment group.

    A source sends its credential to the host its own declaration names, so a
    reference to any other stored secret (a model provider's key, a tool
    server's token) would hand that secret to whoever wrote the declaration.
    """
    from app.services.settings_catalog_api import catalog_index

    index = catalog_index()
    return frozenset(k for k, e in index.items() if e.secret and e.group == "enrichment")


def credential_problems(stored: Any) -> dict[str, str]:
    """Per source key, a ``credential`` reference that names a setting it may not read."""
    allowed = credential_settings()
    return {
        key: f"credential {source.credential!r} is not an enrichment secret setting "
        f"({', '.join(sorted(allowed))}); leave it empty to use the source's own api_key"
        for key, source in effective_sources(stored_map(stored)).items()
        if source.credential and source.credential not in allowed
    }


async def credential_for(key: str, source: EnrichmentSource, read_setting: SecretReader) -> str:
    """The credential ``source`` reads: the setting it names, else its own key.

    A reference to a setting outside :func:`credential_settings` reads as no
    credential, whatever a stored row says: the save refuses one, and a row
    written around the save is not trusted either.
    """
    if source.credential:
        if source.credential not in credential_settings():
            return ""
        return await read_setting(source.credential)
    return source.api_key.get_secret_value()


def slowest_shipped_pace() -> float:
    """The longest pause after a question any shipped enrichment source declares.

    What a reputation server is paced at when its block says no pace of its
    own (``reputation_service.rate_limit_seconds``): a server that relays a
    service a shipped source asks directly then never asks it faster than
    that source does, whichever service it is. Read from the declarations.
    """
    from maljan.enrichment.builtin_sources import builtin_source_entries

    paces = [
        float(entry.get("rate_limit_seconds") or 0.0)
        for entry in builtin_source_entries().values()
        if isinstance(entry, Mapping)
    ]
    return max(paces, default=0.0)


def reputation_server_sources(
    servers: Mapping[str, Any] | None, named: Iterable[str] = ()
) -> dict[str, EnrichmentSource]:
    """A source per enabled tool server whose roles hold ``reputation``, by ``mcp:<key>``.

    Each asks about domains and addresses through the server's indicator
    lookups (no tool named: ``enrichment.declared.SourceAsker``), reads the
    answer as a reputation answer and records it under the server's key. Its
    label, order, pace and thresholds are what the block says of its service
    (``reputation_service``: name, rank, rate_limit_seconds, malicious_when),
    else its label, the order a source takes by default, the slowest shipped
    pace (:func:`slowest_shipped_pace`) and no threshold, so its record
    carries no verdict and marks no indicator. A server a declared source names (``named``)
    is asked only as that source declares.
    """
    from maljan.core.reputation import REPUTATION_ROLE
    from maljan.enrichment.declared import ASKED_KINDS

    taken = set(named)
    out: dict[str, EnrichmentSource] = {}
    for key, cfg in (servers or {}).items():
        if str(key) in taken or not bool(getattr(cfg, "enabled", False)):
            continue
        if REPUTATION_ROLE not in (getattr(cfg, "roles", None) or []):
            continue
        service = getattr(cfg, "reputation_service", None)
        rank = getattr(service, "rank", None)
        pace = getattr(service, "rate_limit_seconds", None)
        fields: dict[str, Any] = {
            "label": str(getattr(service, "name", "") or getattr(cfg, "label", "") or key),
            "kinds": list(ASKED_KINDS),
            "server": str(key),
            "rate_limit_seconds": pace if isinstance(pace, int | float) else slowest_shipped_pace(),
            "malicious_when": [
                {"field": t.field, "at_least": t.at_least}
                for t in getattr(service, "malicious_when", None) or ()
            ],
        }
        if isinstance(rank, int):
            fields["order"] = rank
        try:
            out[f"{SERVER_SOURCE_PREFIX}{key}"] = EnrichmentSource.model_validate(fields)
        except ValueError:
            continue
    return out


async def ready_sources(
    stored: Any,
    read_setting: SecretReader,
    servers: Mapping[str, Any] | None = None,
    *,
    reputation_servers: bool = False,
) -> list[ReadySource]:
    """Every source in force with the credential it reads and whether its server is on.

    With ``reputation_servers``, every enabled reputation server no source
    names follows them (:func:`reputation_server_sources`).
    """
    out: list[ReadySource] = []
    declared = effective_sources(stored_map(stored))
    for key, source in declared.items():
        server_enabled = True
        if source.server:
            cfg = (servers or {}).get(source.server)
            server_enabled = bool(getattr(cfg, "enabled", False))
        out.append(
            ReadySource(
                key=key,
                source=source,
                credential=await credential_for(key, source, read_setting),
                server_enabled=server_enabled,
            )
        )
    if reputation_servers:
        named = {source.server for source in declared.values() if source.server}
        for key, source in reputation_server_sources(servers, named).items():
            out.append(ReadySource(key=key, source=source, server_enabled=True))
    return out


def asks_a_server(stored: Any, *, reputation_servers: bool = False) -> bool:
    """Whether a source in force is asked through a tool server, so the servers must be read."""
    return reputation_servers or any(
        s.server for s in effective_sources(stored_map(stored)).values()
    )


async def reputation_servers_on() -> bool:
    """Whether ``api.enrichment_reputation_servers`` is on now."""
    from app.runtime_config import runtime_config

    return bool(await runtime_config.get(REPUTATION_SERVERS_PATH))


def source_facts(stored: Any, servers: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    """What the console's guide is told about each source in force: no credential, ever.

    ``servers`` are the tool servers in force: a server source's
    ``server_enabled`` says whether its server is on, as ``ReadySource`` reads it.
    """
    out: list[dict[str, Any]] = []
    for key, source in effective_sources(stored_map(stored)).items():
        server_cfg = (servers or {}).get(source.server) if source.server else None
        out.append(
            {
                "key": key,
                "label": source.title(key),
                "kinds": list(source.kinds),
                "enabled": source.enabled,
                # The catalog key that holds its credential, or null when the
                # source holds its own (in this map) or needs none.
                "credential_key": source.credential or None,
                "own_credential": not source.credential
                and not source.server
                and source.needs_credential(),
                "server": source.server or None,
                "server_enabled": (
                    bool(getattr(server_cfg, "enabled", False)) if source.server else None
                ),
                "probe": source.probe is not None,
            }
        )
    return out


async def read_setting_secret(key: str) -> str:
    """The value of the setting ``key`` names (``api.…`` or ``core.…``), as text; "" when unset.

    Read through ``runtime_config`` so the value is the one in force now:
    an ``api.*`` leaf from the store or its default, a ``core.*`` leaf from
    the core settings a job would see.
    """
    from app.runtime_config import runtime_config
    from app.services.settings_catalog_api import API_DEFAULTS

    namespace, _, path = key.partition(".")
    if namespace == "api":
        if path not in API_DEFAULTS:
            return ""
        return await runtime_config.get_secret(path)
    if namespace == "core":
        node: Any = await runtime_config.core()
        for part in path.split("."):
            node = node.get(part) if isinstance(node, Mapping) else getattr(node, part, None)
            if node is None:
                return ""
        plain = node.get_secret_value() if hasattr(node, "get_secret_value") else node
        return str(plain) if isinstance(plain, str) else ""
    return ""


async def enrichment_reach(
    stored: Any,
    read_setting: SecretReader,
    servers: Mapping[str, Any] | None = None,
    *,
    reputation_servers: bool = False,
) -> list[dict[str, Any]]:
    """Where an enrichment job may send a report's indicators, for the run's disclosure block.

    RDAP first, which the job asks about each public address with no key,
    then every source configured to ask (enabled, holding the credential it
    needs, its server on), in its declared order: the hosts its requests name,
    or the tool server it is asked through, with the indicator kinds it
    answers (``analysis.disclosure.enrichment_source_row``); with
    ``reputation_servers``, every enabled reputation server too. Never a
    credential: the secret is read only to tell whether the source is
    configured, as the job reads it.
    """
    from maljan.analysis.disclosure import enrichment_source_row, registry_rows
    from maljan.enrichment.declared import ASKED_KINDS

    rows = registry_rows()
    ready = await ready_sources(
        stored, read_setting, servers, reputation_servers=reputation_servers
    )
    for item in sorted((s for s in ready if s.configured), key=lambda s: s.source.order):
        source = item.source
        kinds = [kind for kind in source.kinds if kind in ASKED_KINDS]
        if source.server:
            cfg = (servers or {}).get(source.server)
            rows.append(
                enrichment_source_row(
                    item.key,
                    kinds=kinds,
                    server=source.server,
                    transport=str(getattr(cfg, "transport", "") or ""),
                    server_url=str(getattr(cfg, "url", "") or ""),
                )
            )
            continue
        rows.append(
            enrichment_source_row(
                item.key,
                kinds=kinds,
                hosts=[request.host for kind, request in source.requests.items() if kind in kinds],
            )
        )
    return rows
