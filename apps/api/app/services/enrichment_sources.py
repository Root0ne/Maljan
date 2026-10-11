"""The enrichment sources in force, their credentials, and what the console is told about them.

``api.enrichment_sources`` holds the operator's declarations
(``maljan.enrichment.declared``), laid over the sources the platform ships.
A source's own credential (``api_key``) is stored in an encrypted row of its
own, like a frontier arm's key (``nested_secrets``); a source may instead name
a secret setting in ``credential``. Everything here reads the declarations and
never names a source.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from maljan.enrichment.declared import (
    EnrichmentSource,
    ReadySource,
    effective_sources,
)

from app.services.nested_secrets import NestedSecretMap

ENRICHMENT_SOURCES_PATH = "enrichment_sources"
ENRICHMENT_SOURCES_KEY = f"api.{ENRICHMENT_SOURCES_PATH}"
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


async def ready_sources(
    stored: Any,
    read_setting: SecretReader,
    servers: Mapping[str, Any] | None = None,
) -> list[ReadySource]:
    """Every source in force with the credential it reads and whether its server is on."""
    out: list[ReadySource] = []
    for key, source in effective_sources(stored_map(stored)).items():
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
    return out


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
