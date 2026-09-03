"""The API's own knobs, joined with the core catalog.

APISettings is not importable from src/, so its entries are declared here:
an explicit editable list (runtime-safe, ``applies: live``) and an explicit
read-only list (bootstrap and infrastructure, ``applies: restart``). Anything
in APISettings that is in neither list is not shown at all.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from maljan.core.settings_annotations import GROUP_ORDER
from maljan.core.settings_catalog import CatalogEntry, FieldType, core_catalog
from maljan.core.settings_overrides import redact_url
from pydantic import SecretStr

from app.config import APISettings

API_EDITABLE: dict[str, dict[str, Any]] = {
    "mock_mode_allowed": {
        "group": "api",
        "title": "Allow mock mode",
        "description": (
            "Operator gate for mock analyses. A job still has to ask for mock "
            "mode in its own config; both switches must agree."
        ),
    },
    "enrichment_enabled": {
        "group": "enrichment",
        "title": "Post-verdict enrichment",
        "description": (
            "Look up the report's domains and IPs at VirusTotal and AbuseIPDB "
            "after every analysis. Providers without a key are skipped."
        ),
    },
    "enrichment_max_lookups": {
        "group": "enrichment",
        "title": "Max lookups per kind",
        "description": "Cap on domains and on IPs sent to each provider per report.",
    },
    "virustotal_api_key": {
        "group": "enrichment",
        "title": "VirusTotal API key",
        "description": (
            "Used by enrichment and by the threat-intel MCP sidecar. Sample "
            "hashes, domains and IPs leave the host when this is set."
        ),
        "probe": "virustotal",
    },
    "abuseipdb_api_key": {
        "group": "enrichment",
        "title": "AbuseIPDB API key",
        "description": (
            "Used by enrichment and by the threat-intel MCP sidecar. IPs leave "
            "the host when this is set."
        ),
        "probe": "abuseipdb",
    },
    "upload_max_bytes": {
        "group": "api",
        "title": "Upload size limit (bytes)",
        "description": (
            "Uploads larger than this are rejected with 413 while streaming, "
            "before anything is stored."
        ),
    },
    "rate_limit_enabled": {
        "group": "api",
        "title": "Rate limiting",
        "description": (
            "Per client IP and path, counted in Redis. Fails open when Redis is unreachable."
        ),
    },
    "rate_limit_requests": {
        "group": "api",
        "title": "Rate limit: requests",
        "description": "Requests allowed per window per IP and path.",
    },
    "rate_limit_window_seconds": {
        "group": "api",
        "title": "Rate limit: window (s)",
        "description": "Length of the rate-limit window.",
    },
    "login_max_attempts": {
        "group": "api",
        "title": "Login attempts before lockout",
        "description": (
            "Failed logins per e-mail before the account is locked for the lockout period."
        ),
    },
    "login_lockout_seconds": {
        "group": "api",
        "title": "Login lockout (s)",
        "description": "How long a locked account stays locked.",
    },
    "trusted_proxy_ips": {
        "group": "api",
        "title": "Trusted proxy IPs",
        "description": (
            "Peers whose X-Forwarded-For header is believed for rate "
            "limiting. Exact IPs, one per entry."
        ),
    },
}

API_READONLY: dict[str, dict[str, Any]] = {
    "debug": {
        "title": "Debug mode",
        "description": (
            "Verbose logging and relaxed placeholder checks. Set in .env; needs a restart."
        ),
    },
    "auth_disabled": {
        "title": "Authentication bypass",
        "description": (
            "Every request is the seeded dev admin. Local development only. Set in .env."
        ),
    },
    "cors_origins": {
        "title": "CORS origins",
        "description": "Browsers allowed to call the API. Set in .env.",
    },
    "database_url": {
        "title": "Database",
        "description": "Postgres DSN; credentials are masked here.",
    },
    "redis_url": {
        "title": "Redis",
        "description": "Queue, events and rate-limit counters.",
        "probe": "redis",
    },
    "minio_endpoint": {
        "title": "Object store",
        "description": "MinIO endpoint holding uploaded samples.",
    },
    "qdrant_url": {
        "title": "Qdrant (API health probe)",
        "description": "Address the API pings on /health?deep=true.",
    },
    "jwt_access_token_expire_minutes": {
        "title": "Access token lifetime (min)",
        "description": "Set in .env.",
    },
    "jwt_refresh_token_expire_days": {
        "title": "Refresh token lifetime (days)",
        "description": "Set in .env.",
    },
    "samples_dir": {
        "title": "Samples directory",
        "description": "Host path mounted into the Ghidra MCP container; the worker mirrors "
        "each job's binary under its .work subdirectory and removes it when the job ends.",
    },
}

# Any read-only value shaped like a URL is shown with its userinfo masked
# (database, Redis, MinIO and Qdrant addresses may all carry credentials).


def _type_of(name: str, default: Any) -> tuple[FieldType, bool]:
    if isinstance(default, SecretStr):
        return "secret", True
    if isinstance(default, bool):
        return "bool", False
    if isinstance(default, int):
        return "int", False
    if isinstance(default, float):
        return "float", False
    if isinstance(default, list):
        return "list", False
    return "str", False


def _masked(name: str, value: Any) -> Any:
    if isinstance(value, str) and "://" in value:
        return redact_url(value)
    return value


def api_catalog() -> list[CatalogEntry]:
    fields = APISettings.model_fields
    entries: list[CatalogEntry] = []
    for name, ann in API_EDITABLE.items():
        default = fields[name].default
        ftype, secret = _type_of(name, default)
        entries.append(
            CatalogEntry(
                key=f"api.{name}",
                namespace="api",
                path=name,
                type=ftype,
                default=None if secret else default,
                nullable=False,
                choices=None,
                minimum=None,
                maximum=None,
                secret=secret,
                group=ann["group"],
                title=ann["title"],
                description=ann["description"],
                applies="live",
                editable=True,
                reason=None,
                probe=ann.get("probe"),
            )
        )
    for name, ann in API_READONLY.items():
        default = fields[name].default
        ftype, secret = _type_of(name, default)
        entries.append(
            CatalogEntry(
                key=f"api.{name}",
                namespace="api",
                path=name,
                type=ftype,
                default=None if secret else _masked(name, default),
                nullable=False,
                choices=None,
                minimum=None,
                maximum=None,
                secret=secret,
                group="system",
                title=ann["title"],
                description=ann["description"],
                applies="restart",
                editable=False,
                reason="set in .env; restart required",
                probe=ann.get("probe"),
            )
        )
    return entries


def full_catalog() -> list[CatalogEntry]:
    order = {g: i for i, (g, _) in enumerate(GROUP_ORDER)}
    return sorted(core_catalog() + api_catalog(), key=lambda e: (order[e.group], e.path))


@lru_cache(maxsize=1)
def catalog_index() -> dict[str, CatalogEntry]:
    return {e.key: e for e in full_catalog()}
