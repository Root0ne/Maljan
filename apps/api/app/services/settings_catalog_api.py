"""The API's own knobs, joined with the core catalog.

APISettings is not importable from src/, so its entries are declared here:
an explicit editable list (runtime-safe, ``applies: live``) and an explicit
read-only list (bootstrap and infrastructure, ``applies: restart``). Anything
in APISettings that is in neither list is not shown at all. ``API_DEFAULTS``
holds the fallback value ``runtime_config.get(name)`` returns for every
``API_EDITABLE`` entry when no store override exists, keyed by the same short
name as the entry's ``path`` (the catalog key without its ``api.`` prefix).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import replace
from functools import lru_cache
from typing import Any, get_args, get_origin

from maljan.core.settings_annotations import GROUP_ORDER
from maljan.core.settings_catalog import CatalogEntry, FieldType, _bounds, core_catalog
from maljan.core.settings_overrides import redact_url
from pydantic import SecretStr

from app.config import APISettings

# Every application-shaped setting used to live on APISettings and be
# configurable through the process environment. Task 2 of the env-free
# configuration work moved them out: the environment no longer configures
# application behaviour, only deployment/bootstrap facts (see API_READONLY
# below). Each entry's runtime value now comes from the settings store, or
# from this table when no override is stored.
API_DEFAULTS: dict[str, Any] = {
    "mock_mode_allowed": False,
    "enrichment_enabled": True,
    "enrichment_max_lookups": 25,
    "virustotal_api_key": "",
    "abuseipdb_api_key": "",
    "rate_limit_enabled": True,
    "rate_limit_requests": 100,
    "rate_limit_window_seconds": 60,
    "rate_limit_whitelist": ["/health"],
    "login_max_attempts": 10,
    "login_lockout_seconds": 300,
    "upload_max_bytes": 100 * 1024 * 1024,  # 100 MB
    "upload_allowed_mime_types": [
        # The list mirrors every analyzer package shipped by CAPEv2 under
        # ``external/CAPEv2/analyzer/{windows,linux}/modules/packages/`` so
        # any file the sandbox can detonate also clears the API gate.
        #
        # Synonym handling: ``filetype`` (magic-byte) and libmagic disagree
        # on some entries — ELF is ``x-elf`` vs ``x-executable``; PE is
        # ``x-msdownload`` vs ``vnd.microsoft.portable-executable``. Every
        # documented synonym is listed. Scripts (.vbs/.ps1/.bat/.py/.js)
        # typically come back as ``text/plain`` or ``None`` from filetype;
        # those still pass because samples.py only enforces the allow-list
        # when a MIME was actually detected.
        # ── Generic / catch-all ─────────────────────────────────
        "application/octet-stream",
        # ── Windows PE family (exe / dll / service / regsvr / msbuild) ──
        "application/x-dosexec",
        "application/x-msdownload",
        "application/vnd.microsoft.portable-executable",
        # ── Windows installers (msi / msix / nsis) ──────────────
        "application/x-ms-installer",
        "application/x-msi",
        "application/vnd.ms-msi",
        # ── *nix executables (ELF / Mach-O / shared libs) ───────
        "application/x-mach-binary",
        "application/x-elf",
        "application/x-executable",
        "application/x-sharedlib",
        "application/x-pie-executable",
        # ── Android (APK) ───────────────────────────────────────
        "application/vnd.android.package-archive",
        # ── Archives (CAPE ``zip`` / ``rar`` / ``jar`` / ``archive``) ──
        "application/zip",
        "application/x-zip-compressed",
        "application/x-7z-compressed",
        "application/x-rar-compressed",
        "application/vnd.rar",
        "application/gzip",
        "application/x-gzip",
        "application/x-bzip2",
        "application/x-xz",
        "application/x-lzma",
        "application/x-tar",
        "application/x-iso9660-image",
        "application/java-archive",
        # ── Linux package formats (CAPE Linux ``deb`` package) ──
        "application/x-deb",
        "application/vnd.debian.binary-package",
        # ── PDF (CAPE ``pdf`` package) ──────────────────────────
        "application/pdf",
        # ── Microsoft Office — legacy binary formats ────────────
        "application/msword",
        "application/vnd.ms-word",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/vnd.ms-publisher",
        "application/x-mspublisher",
        "application/vnd.ms-access",
        "application/x-msaccess",
        "application/onenote",
        "application/msonenote",
        "application/vnd.ms-xpsdocument",
        # ── Office Open XML (.docx / .xlsx / .pptx + macro variants) ──
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.ms-word.document.macroEnabled.12",
        "application/vnd.ms-excel.sheet.macroEnabled.12",
        "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
        "application/vnd.ms-word.template.macroEnabled.12",
        "application/vnd.ms-excel.template.macroEnabled.12",
        # ── Rich Text + Hangul + Ichitaro ───────────────────────
        "application/rtf",
        "text/rtf",
        "application/x-hwp",
        "application/haansofthwp",
        "application/x-ichitaro",
        # ── Mail (CAPE ``eml`` / ``msg`` / ``mht``) ─────────────
        "message/rfc822",
        "application/vnd.ms-outlook",
        "application/x-mimearchive",
        "multipart/related",
        # ── Browser / web (CAPE ``chrome`` / ``ie`` / ``crx``) ──
        "text/html",
        "application/xhtml+xml",
        "application/xml",
        "text/xml",
        "application/x-chrome-extension",
        # ── Shortcuts, HTA, registry, control panel ─────────────
        "application/x-ms-shortcut",
        "application/x-mslnk",
        "application/hta",
        "application/x-hta",
        "application/x-registry",
        "text/x-ms-regedit",
        "application/x-cpl",
        "application/x-rdp",
        # ── Help, Flash, Java applet ────────────────────────────
        "application/vnd.ms-htmlhelp",
        "application/x-chm",
        "application/x-shockwave-flash",
        "application/x-java-applet",
        # ── Scripts that DO carry a magic-byte MIME ─────────────
        # (the .vbs/.ps1/.bat/.py/.js majority come back None and
        # pass via samples.py's "detected_mime is None" branch)
        "text/x-shellscript",
        "application/x-shellscript",
        "text/x-python",
        "application/x-python",
        "text/x-perl",
        "application/x-perl",
        "application/javascript",
        "application/x-javascript",
        "text/javascript",
        "application/x-powershell",
        "text/x-powershell",
        "application/x-vbscript",
        "text/vbscript",
        "application/x-bat",
        "text/x-msdos-batch",
        "application/x-msdos-program",
    ],
    "trusted_proxy_ips": [],
    "qdrant_url": "http://127.0.0.1:6333",
    "qdrant_collection": "maljan_ltm",
    "qdrant_api_key": "",
    "jwt_access_token_expire_minutes": 30,
    "jwt_refresh_token_expire_days": 7,
}

API_EDITABLE: dict[str, dict[str, Any]] = {
    "mock_mode_allowed": {
        "type": "bool",
        "group": "api",
        "title": "Allow mock mode",
        "description": (
            "Operator gate for mock analyses. A job still has to ask for mock "
            "mode in its own config; both switches must agree."
        ),
    },
    "enrichment_enabled": {
        "type": "bool",
        "group": "enrichment",
        "title": "Post-verdict enrichment",
        "description": (
            "Look up the report's domains and IPs at VirusTotal and AbuseIPDB "
            "after every analysis. Providers without a key are skipped."
        ),
    },
    "enrichment_max_lookups": {
        "type": "int",
        "minimum": 1,
        "group": "enrichment",
        "title": "Max lookups per kind",
        "description": "Cap on domains and on IPs sent to each provider per report.",
    },
    "virustotal_api_key": {
        "type": "secret",
        "group": "enrichment",
        "title": "VirusTotal API key",
        "description": (
            "Used by enrichment and by the threat-intel MCP sidecar. Sample "
            "hashes, domains and IPs leave the host when this is set."
        ),
        "probe": "virustotal",
    },
    "abuseipdb_api_key": {
        "type": "secret",
        "group": "enrichment",
        "title": "AbuseIPDB API key",
        "description": (
            "Used by enrichment and by the threat-intel MCP sidecar. IPs leave "
            "the host when this is set."
        ),
        "probe": "abuseipdb",
    },
    "upload_max_bytes": {
        "type": "int",
        "minimum": 1024,
        "group": "api",
        "title": "Upload size limit (bytes)",
        "description": (
            "Uploads larger than this are rejected with 413 while streaming, "
            "before anything is stored."
        ),
    },
    "upload_allowed_mime_types": {
        "type": "list",
        "group": "api",
        "title": "Allowed upload MIME types",
        "description": (
            "Uploads whose detected MIME is not in this list are rejected with 415. "
            "An upload with no detected MIME (most scripts) always passes."
        ),
    },
    "rate_limit_enabled": {
        "type": "bool",
        "group": "api",
        "title": "Rate limiting",
        "description": (
            "Per client IP and path, counted in Redis. Fails open when Redis is unreachable."
        ),
    },
    "rate_limit_requests": {
        "type": "int",
        "minimum": 1,
        "group": "api",
        "title": "Rate limit: requests",
        "description": "Requests allowed per window per IP and path.",
    },
    "rate_limit_window_seconds": {
        "type": "int",
        "minimum": 1,
        "group": "api",
        "title": "Rate limit: window (s)",
        "description": "Length of the rate-limit window.",
    },
    "rate_limit_whitelist": {
        "type": "list",
        "group": "api",
        "title": "Rate limit: whitelisted paths",
        "description": "Paths that bypass rate limiting entirely (e.g. health checks).",
    },
    "login_max_attempts": {
        "type": "int",
        "minimum": 1,
        "group": "api",
        "title": "Login attempts before lockout",
        "description": (
            "Failed logins per e-mail before the account is locked for the lockout period."
        ),
    },
    "login_lockout_seconds": {
        "type": "int",
        "minimum": 1,
        "group": "api",
        "title": "Login lockout (s)",
        "description": "How long a locked account stays locked.",
    },
    "trusted_proxy_ips": {
        "type": "list",
        "group": "api",
        "title": "Trusted proxy IPs",
        "description": (
            "Peers whose X-Forwarded-For header is believed for rate "
            "limiting. CIDR networks (or single IPs), one per entry."
        ),
    },
    "qdrant_url": {
        "type": "str",
        "group": "api",
        "title": "Qdrant (API health probe)",
        "description": "Address the API pings on /health?deep=true and enrichment reads for LTM.",
    },
    "qdrant_collection": {
        "type": "str",
        "group": "api",
        "title": "Qdrant collection (API-side)",
        "description": "Collection the enrichment worker's own Qdrant client reads.",
    },
    "qdrant_api_key": {
        "type": "secret",
        "group": "api",
        "title": "Qdrant API key (API-side)",
        "description": "Sent with the API's own Qdrant health probe and enrichment reads.",
    },
    "jwt_access_token_expire_minutes": {
        "type": "int",
        "minimum": 1,
        "group": "api",
        "title": "Access token lifetime (min)",
        "description": "How long an issued access token stays valid.",
    },
    "jwt_refresh_token_expire_days": {
        "type": "int",
        "minimum": 1,
        "group": "api",
        "title": "Refresh token lifetime (days)",
        "description": "How long an issued refresh token, and its cookie, stay valid.",
    },
}

API_READONLY: dict[str, dict[str, Any]] = {
    "debug": {
        "title": "Debug mode",
        "description": (
            "Verbose logging and relaxed placeholder checks. Set in the deployment environment."
        ),
    },
    "auth_disabled": {
        "title": "Authentication bypass",
        "description": (
            "Every request is the seeded dev admin. Local development only. Set in the "
            "deployment environment."
        ),
    },
    "cors_origins": {
        "title": "CORS origins",
        "description": "Browsers allowed to call the API. Set in the deployment environment.",
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
    "cookie_secure": {
        "title": "Refresh cookie Secure flag",
        "description": (
            "Set on the HttpOnly refresh cookie; true outside debug so the cookie is "
            "sent over HTTPS only."
        ),
    },
    "samples_dir": {
        "title": "Samples directory",
        "description": "Host path mounted into the Ghidra MCP container; the worker mirrors "
        "each job's binary under its .work subdirectory and removes it when the job ends.",
    },
    "upload_temp_dir": {
        "title": "Upload staging directory",
        "description": "Defender-excluded scratch directory samples are streamed into.",
    },
}

# Any read-only value shaped like a URL is shown with its userinfo masked
# (database, Redis and MinIO addresses may all carry credentials).


def _unwrap_optional(annotation: Any) -> Any:
    """Strip a ``X | None`` / ``Optional[X]`` wrapper down to ``X``.

    A field left unset so a ``model_validator`` can fill in its real default
    later (e.g. ``cookie_secure: bool | None = None``) still has a concrete
    widget type — the ``None`` arm is just how "not yet resolved" is spelled,
    not a type of its own.
    """
    if get_origin(annotation) is type(int | None):  # UnionType, e.g. "bool | None"
        args = [a for a in get_args(annotation) if a is not type(None)]
        if len(args) == 1:
            return args[0]
    return annotation


def _type_of(name: str, annotation: Any, default: Any) -> tuple[FieldType, bool]:
    if isinstance(default, SecretStr):
        return "secret", True
    tp = _unwrap_optional(annotation)
    if tp is SecretStr:
        return "secret", True
    if tp is bool:
        return "bool", False
    if tp is int:
        return "int", False
    if tp is float:
        return "float", False
    if tp is str:
        return "str", False
    if get_origin(tp) in (list, set, tuple):
        return "list", False
    return "str", False


def _masked(name: str, value: Any) -> Any:
    if isinstance(value, str) and "://" in value:
        return redact_url(value)
    return value


def validate_editable_api_value(entry: CatalogEntry, value: Any) -> str | None:
    """Return an error message when ``value`` does not fit ``entry``, else ``None``.

    ``API_EDITABLE`` fields no longer live on ``APISettings`` (Task 2), so
    they no longer get pydantic's type/bounds checking for free when a PATCH
    lands. This is the replacement: the same numeric floors the fields used
    to declare via ``Field(ge=...)`` are carried in ``API_EDITABLE`` instead
    and enforced here.
    """
    if entry.type == "bool":
        if not isinstance(value, bool):
            return "Input should be a valid boolean"
        return None
    if entry.type in ("int", "float"):
        if isinstance(value, bool) or not isinstance(value, int | float):
            return "Input should be a valid number"
        if entry.minimum is not None and value < entry.minimum:
            return f"Input should be greater than or equal to {entry.minimum}"
        if entry.maximum is not None and value > entry.maximum:
            return f"Input should be less than or equal to {entry.maximum}"
        return None
    if entry.type == "list":
        if not isinstance(value, list):
            return "Input should be a valid list"
        for item in value:
            if not isinstance(item, str):
                return "Input should be a valid string"
        if entry.path == "trusted_proxy_ips":
            for item in value:
                try:
                    ipaddress.ip_network(item, strict=False)
                except ValueError:
                    return f"{item!r} is not an IP address or CIDR network"
        return None
    if entry.type in ("str", "secret"):
        if value is not None and not isinstance(value, str):
            return "Input should be a valid string"
        return None
    return None


def api_catalog() -> list[CatalogEntry]:
    fields = APISettings.model_fields
    entries: list[CatalogEntry] = []
    for name, ann in API_EDITABLE.items():
        ftype: FieldType = ann["type"]
        secret = ftype == "secret"
        default = API_DEFAULTS[name]
        entries.append(
            CatalogEntry(
                key=f"api.{name}",
                namespace="api",
                path=name,
                type=ftype,
                default=None if secret else default,
                nullable=False,
                choices=None,
                minimum=ann.get("minimum"),
                maximum=ann.get("maximum"),
                secret=secret,
                group=ann["group"],
                title=ann["title"],
                description=ann["description"],
                applies="live",
                editable=True,
                reason=None,
                probe=ann.get("probe"),
                applies_when=None,
                order=0,
                choices_from=None,
                editor=None,
            )
        )
    for name, ann in API_READONLY.items():
        default = fields[name].default
        ftype, secret = _type_of(name, fields[name].annotation, default)
        lo, hi = _bounds(fields[name])
        entries.append(
            CatalogEntry(
                key=f"api.{name}",
                namespace="api",
                path=name,
                type=ftype,
                default=None if secret else _masked(name, default),
                nullable=False,
                choices=None,
                minimum=lo,
                maximum=hi,
                secret=secret,
                group="system",
                title=ann["title"],
                description=ann["description"],
                applies="restart",
                editable=False,
                reason="set in the deployment environment; restart required",
                probe=ann.get("probe"),
                applies_when=None,
                order=0,
                choices_from=None,
                editor=None,
            )
        )
    return entries


def full_catalog() -> list[CatalogEntry]:
    order = {g: i for i, (g, _) in enumerate(GROUP_ORDER)}
    return sorted(core_catalog() + api_catalog(), key=lambda e: (order[e.group], e.order, e.path))


@lru_cache(maxsize=1)
def catalog_index() -> dict[str, CatalogEntry]:
    return {e.key: e for e in full_catalog()}


def _choice_sources(
    servers: Iterable[str], profiles: Iterable[str], agents: Iterable[str]
) -> dict[str, list[str]]:
    """Every ``choices_from`` source, resolved once on the way out.

    The core catalog is a pure function of the models and cannot know which
    servers, profiles or agents exist right now; the web must not decide
    either, or "what is a valid profile" has two answers.
    """
    from maljan.providers.registry import sandbox_provider_ids, static_provider_ids

    return {
        # Declared for completeness and for sub-project C's agent definitions.
        # Neither provider selector uses them today: those two are enum leaves
        # whose choices already come from the settings Literal, in its own
        # order, and re-deriving them here would only re-sort the dropdown.
        "static_providers": static_provider_ids(),
        "sandbox_providers": sandbox_provider_ids(),
        # The empty string is a real choice: it is how an operator says the
        # generic provider has no server yet.
        "mcp_servers": ["", *sorted(servers)],
        # Definition keys, not the four fixed roles: a server can be bound to
        # any agent an operator has defined (spec §2, role vocabulary).
        "agent_roles": list(agents),
        "profiles": list(profiles),
    }


def resolved_catalog(
    servers: Iterable[str],
    *,
    profiles: Iterable[str] = ("default",),
    agents: Iterable[str] = ("static", "dynamic", "network", "judge"),
) -> list[CatalogEntry]:
    """``full_catalog`` with every ``choices_from`` turned into real ``choices``.

    The core catalog is a pure function of the models and cannot know which
    servers, profiles or agents exist right now; the web must not decide
    either, or "what is a valid provider" has two answers. So it happens
    exactly here, once, on the way out.
    """
    sources = _choice_sources(servers, profiles, agents)
    out: list[CatalogEntry] = []
    for entry in full_catalog():
        if entry.choices_from and entry.choices_from in sources:
            entry = replace(entry, choices=sources[entry.choices_from])
        out.append(entry)
    return out
