"""Runtime settings: the catalog, the effective values, and the overrides."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from maljan.core.model_assignments import endpoint_label
from maljan.core.plugins import ALLOW_LIST_KEY
from maljan.core.settings_annotations import (
    GROUP_DESCRIPTIONS,
    GROUP_ORDER,
    RENAMED_SETTINGS,
    RETIRED_SETTINGS,
)
from maljan.core.settings_overrides import redact_url
from maljan.pipeline.conditions import validate_condition
from pydantic import BaseModel, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import end_read_transaction, get_db
from app.deps import require_admin
from app.logging_config import get_logger
from app.logsafe import log_safe
from app.models.user import User
from app.runtime_config import runtime_config
from app.schemas.settings import (
    AttckCheckResponse,
    AttckStatusResponse,
    AttckUpdateProgress,
    AttckUpdateStarted,
    CatalogEntryDTO,
    ConditionValidateRequest,
    ConditionValidateResponse,
    ContextWindowResponse,
    CredentialBootstrapResponse,
    EffortOptionsResponse,
    ExportResponse,
    GroupDTO,
    ImportRequest,
    MappingPreviewRequest,
    MappingPreviewResponse,
    PatchRequest,
    PatchResponse,
    PluginsResponse,
    ProbeRequest,
    ProbeResponse,
    ResetResponse,
    SchemaResponse,
    TeamFindingDTO,
    TeamGraphDTO,
    TeamLintRequest,
    TeamLintResponse,
    ValueDTO,
    ValuesResponse,
)
from app.services import attck_cache, credential_bootstrap
from app.services.audit import record as audit_record
from app.services.mapping_preview import PREVIEW_MAX_BYTES, preview_mapping
from app.services.plugins import (
    load_written_blocks,
    plugins_listing,
    stored_block_entries,
    unchanged_block_keys,
    writes_a_plugin_block,
)
from app.services.report_formats_lock import (
    report_formats_serialised,
    touches_report_formats,
)
from app.services.server_map import SERVER_MAP_KEY, TOKEN_MASK
from app.services.settings_catalog_api import catalog_index, full_catalog, resolved_catalog
from app.services.settings_probes import (
    candidate_settings,
    context_window_facts,
    known_probe,
    run_agent_probe,
    run_mcp_probe,
    run_probe,
    with_staged_sources,
)
from app.services.settings_service import (
    SettingsService,
    SettingsValidationError,
    cleared_plugin_block_keys,
    core_settings_cache,
    effective_core_settings,
    lenient_imported_declarations,
    unknown_key_reason,
)

# The settings document an export writes and an import reads. In ``/2`` a
# block's tool declarations are its changes over what the block ships, one
# tool at a time, as they are stored; an import also reads ``/1``, written
# before that, where a block's tool declarations are its whole map.
EXPORT_FORMAT = "maljan-settings/2"
WHOLE_MAP_FORMAT = "maljan-settings/1"
IMPORT_FORMATS = (EXPORT_FORMAT, WHOLE_MAP_FORMAT)

logger = get_logger("api.settings")

router = APIRouter(prefix="/settings", tags=["Settings"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def _effective_servers(db: AsyncSession) -> list[str]:
    """Server keys as they stand: the stored map if there is one, else the defaults."""
    stored = await SettingsService(db).load_overrides()
    servers = stored.get("core.mcp.servers")
    if isinstance(servers, dict) and servers:
        return list(servers)
    from maljan.core.settings_overrides import build_settings

    return list(build_settings({}).mcp.servers)


async def _effective_agents(db: AsyncSession) -> tuple[list[str], list[str]]:
    """Profile names and definition keys as they stand, for the catalog's choices."""
    from app.services.agent_map import effective_definitions, effective_profiles

    stored = await SettingsService(db).load_overrides()
    return sorted(effective_profiles(stored)), sorted(effective_definitions(stored))


@router.get("/schema", response_model=SchemaResponse)
async def get_schema(
    _: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
) -> SchemaResponse:
    from maljan.core.settings_overrides import (
        build_settings,
        pack_steps_left_out,
        refused_tool_changes,
        stored_settings,
    )

    from app.services.enrichment_sources import ENRICHMENT_SOURCES_KEY
    from app.services.settings_service import load_core_overrides

    profiles, agents = await _effective_agents(db)
    stored = await SettingsService(db).load_overrides()
    # No plugin is loaded to serve the page: a plugin block this process has
    # not read with its model is shown from its stored rows.
    extra = await stored_block_entries(db)
    core = await load_core_overrides(db)
    refused: dict[str, str] = {}
    try:
        built, refused = stored_settings(core)
        configs = built.mcp.servers
    except (ValueError, ValidationError):
        configs = build_settings({}).mcp.servers
    try:
        # Listed also where the stored settings do not build (the steps are
        # then checked against what does), never a failed schema.
        left_out = pack_steps_left_out(core)
    except (ValueError, ValidationError):
        left_out = {}
    return served_schema(
        await _effective_servers(db),
        profiles=profiles,
        agents=agents,
        enrichment_sources=stored.get(ENRICHMENT_SOURCES_KEY),
        server_configs=configs,
        tool_facts_conflicts=refused_tool_changes(core),
        pack_steps_left_out=left_out,
        stored_values_refused={f"core.{key}": reason for key, reason in refused.items()},
        plugins_allowed=stored.get(ALLOW_LIST_KEY),
        extra_entries=extra,
    )


def served_schema(
    servers: list[str],
    *,
    profiles: list[str],
    agents: list[str],
    enrichment_sources: Any = None,
    server_configs: dict[str, Any] | None = None,
    tool_facts_conflicts: dict[str, list[str]] | None = None,
    pack_steps_left_out: dict[str, str] | None = None,
    stored_values_refused: dict[str, str] | None = None,
    plugins_allowed: Any = None,
    extra_entries: list[Any] | None = None,
) -> SchemaResponse:
    """The settings schema as ``GET /settings/schema`` serves it for these choices.

    A pure function of the code and the choices, so the console's tests can
    be fed exactly what the API serves (``scripts/dev/write_console_schema.py``).
    ``enrichment_sources`` is the stored ``api.enrichment_sources`` map and
    ``server_configs`` the tool servers in force; the schema says what the
    console's guides offer for each, never a credential.
    ``tool_facts_conflicts`` names, per block, the tools whose stored change
    is refused over what ships now (``refused_tool_changes``), and
    ``pack_steps_left_out`` each stored triage pack step left out, with why
    (``pack_steps_left_out``), and ``stored_values_refused`` each stored
    value the model refuses, with why (``stored_settings``).
    ``plugins_allowed`` is the stored plugin allow-list: each provider
    selector offers the installed plugins it names, read from metadata.
    ``extra_entries`` are the stored rows of plugin blocks this process has
    not read with their models, shown as stored (``plugins.raw_block_entries``).
    """
    from app.services.credential_bootstrap import bootstrap_facts
    from app.services.enrichment_sources import source_facts

    by_group: dict[str, list[CatalogEntryDTO]] = {}
    for e in [
        *resolved_catalog(
            servers, profiles=profiles, agents=agents, plugins_allowed=plugins_allowed
        ),
        *(extra_entries or []),
    ]:
        by_group.setdefault(e.group, []).append(CatalogEntryDTO(**e.to_dict()))
    groups = [
        GroupDTO(key=g, title=t, description=GROUP_DESCRIPTIONS.get(g, ""), entries=by_group[g])
        for g, t in GROUP_ORDER
        if g in by_group
    ]
    from maljan.core.tool_declarations import declaration_fields

    from app.services.provider_facts import probe_labels

    if server_configs is None:
        from maljan.core.settings_overrides import build_settings

        server_configs = build_settings({}).mcp.servers
    return SchemaResponse(
        groups=groups,
        probe_labels=probe_labels(enrichment_sources),
        enrichment_sources=source_facts(enrichment_sources, server_configs),
        credential_servers=bootstrap_facts(server_configs),
        tool_declaration_fields=declaration_fields(),
        tool_facts_conflicts=tool_facts_conflicts or {},
        pack_steps_left_out=pack_steps_left_out or {},
        stored_values_refused=stored_values_refused or {},
    )


def default_served_schema() -> SchemaResponse:
    """The schema a deployment with nothing stored is served."""
    from maljan.core.settings_overrides import build_settings

    from app.services.agent_map import effective_definitions, effective_profiles

    return served_schema(
        list(build_settings({}).mcp.servers),
        profiles=sorted(effective_profiles({})),
        agents=sorted(effective_definitions({})),
    )


def unwritable_reason(answer: BaseModel) -> str | None:
    """Why ``answer`` cannot be written as a response body, or ``None`` when it can.

    It is written the way the response is (the model's dump, then
    ``json.dumps``), so the bound is the writers' own (pydantic-core's nesting
    guard, the interpreter's recursion limit), not a depth of ours. One more
    write of the answer: time linear in its size.
    """
    try:
        json.dumps(answer.model_dump(mode="json"))
    except (ValueError, RecursionError) as exc:
        return unwritable_reason_of(exc)
    return None


def unwritable_reason_of(exc: BaseException) -> str:
    """What :func:`unwritable_reason` says for the writer's refusal ``exc``."""
    return (
        "the stored value is not served: it is nested deeper than an answer can be "
        f"written ({type(exc).__name__}: {exc}); reset this key or save it again"
    )


def _say_unwritable(where: str, key: str, reason: str) -> None:
    logger.warning("Stored setting %s left out of %s: %s", log_safe(key), where, reason)


def served_values(vals: dict[str, Any]) -> tuple[dict[str, ValueDTO], dict[str, str]]:
    """Each value as ``GET /settings`` serves it, and the keys left unserved with why.

    A stored row an answer cannot be written with (:func:`unwritable_reason`)
    is served with no value and its reason, so one row never fails the page.
    """
    served: dict[str, ValueDTO] = {}
    unreadable: dict[str, str] = {}
    for key, info in vals.items():
        dto = ValueDTO(**vars(info))
        reason = unwritable_reason(ValuesResponse(values={key: dto}))
        if reason is not None:
            dto = ValueDTO(**{**vars(info), "value": None, "unreadable": reason})
            unreadable[key] = reason
        served[key] = dto
    return served, unreadable


@router.get("", response_model=ValuesResponse)
async def get_values(
    _: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
) -> ValuesResponse:
    vals = await SettingsService(db).values(extra=await stored_block_entries(db))
    served, unreadable = served_values(vals)
    for key, reason in unreadable.items():
        _say_unwritable("the settings answer", key, reason)
    return ValuesResponse(values=served)


@router.get("/plugins", response_model=PluginsResponse)
async def list_plugins(
    _: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
) -> PluginsResponse:
    """Every installed provider plugin per kind, read from package metadata.

    No plugin is imported to be listed, and nothing is loaded. Each names its
    package and version, whether the stored allow-list names it, what its
    metadata says of it, and the API process's own load result where the API
    loaded it for itself; the worker logs its own.
    """
    return PluginsResponse(**await plugins_listing(db))


async def _plugin_block_writes(
    db: AsyncSession, changes: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Before a save or import: ``changes`` as it writes plugin blocks, and the plain rows read.

    A key of an installed plugin's own block sent with the value stored for it
    writes nothing, so it is left out, quietly, and no plugin is loaded for it
    (``plugins.unchanged_block_keys``); a secret is never taken as sent back,
    and no stored secret is decrypted here. A plugin whose block keys the
    change does alter is loaded to read them with its own model: that plugin
    alone, and never one the same change drops from the allow-list, nor for a
    clear (``plugins.block_writes``). A change that touches no plugin block
    reads nothing and loads nothing. Answers the stored rows that are not
    secrets, ``None`` when it read none. Never fails the request: a store that
    cannot be read here is read, and said, by the save.
    """
    if not writes_a_plugin_block(changes):
        return changes, None
    try:
        rows = await SettingsService(db)._rows()
    except Exception as exc:  # noqa: BLE001 — the save reads the store itself
        logger.debug("The plugin allow-list was not read before the save (%s).", exc)
        return changes, None
    held = [(str(row.key), row.value, bool(row.is_secret)) for row in rows]
    plain = {key: value for key, value, secret in held if not secret}
    unchanged = unchanged_block_keys(changes, held)
    written = {key: value for key, value in changes.items() if key not in unchanged}
    await load_written_blocks(written, plain.get(ALLOW_LIST_KEY))
    return written, plain


@router.get("/context-window", response_model=ContextWindowResponse)
async def get_context_window(
    _: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
) -> ContextWindowResponse:
    """What the configured models serve, and what it gives one tool answer.

    Read-only, and free: the probe behind it reads a server's metadata
    endpoint and never asks a model to produce anything. The answer is cached
    per provider, endpoint and model, so the settings page pays for it once
    and a changed endpoint asks again. An endpoint that says nothing is not an
    error — the vendored table answers, then the stated fallback, and
    ``source`` says which.

    Registered ahead of ``/{key}`` on the delete side and beside the fixed
    paths here for the same reason ``/test/mcp`` is: a fixed path must win the
    match against a parameterised one.
    """
    stored = await SettingsService(db).load_overrides()
    settings = candidate_settings({}, stored)
    await end_read_transaction(db)
    return ContextWindowResponse(**await context_window_facts(settings))


@router.get("/effort-options", response_model=EffortOptionsResponse)
async def get_effort_options(
    provider: str = Query(..., min_length=1, max_length=64),
    model: str = Query("", max_length=256),
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> EffortOptionsResponse:
    """The reasoning-effort levels a per-agent entry may name for one provider and model.

    Read-only and free: the levels come from the settings' own list and, for
    an Anthropic model the window probe has described, from what the Models
    API said it takes. No request leaves the process. The console's agent
    editor draws its effort field from this answer rather than from a list
    of its own.
    """
    from maljan.llm.effort import effort_options

    stored = await SettingsService(db).load_overrides()
    settings = candidate_settings({}, stored)
    await end_read_transaction(db)
    return EffortOptionsResponse(**effort_options(settings, provider, model))


async def _agent_warnings(db: AsyncSession) -> dict[str, str]:
    """What is worth saying about the teams as they now stand.

    Read after the write rather than from the patch, because a warning is
    about the configuration that resulted: a PATCH that only changed the
    static provider is exactly the one that can turn a team's reversing stage
    tool-free, and it names no team at all.

    Never raises. The write has already succeeded and been audited by the time
    this runs, so a failure here must cost the operator an advisory note, not
    turn a saved change into a 500 that says it was not saved.
    """
    from app.services.agent_map import effective_definitions, effective_profiles, profile_warnings

    try:
        stored = await SettingsService(db).load_overrides()
        return profile_warnings(
            effective_profiles(stored),
            definitions=effective_definitions(stored),
            overrides=stored,
        )
    except Exception as exc:  # noqa: BLE001 — advisory, and the write is done
        logger.debug("Could not compute settings warnings (%s); continuing.", log_safe(str(exc)))
        return {}


async def _declared_detects(db: AsyncSession) -> dict[str, Any] | None:
    """Each declared report format's detect by name, as the settings stand; ``None`` unread.

    Read before a save that writes the report formats, so the overlap warning
    is said only for a format whose detect the save adds or changes. Never
    raises, as :func:`_agent_warnings` never does.
    """
    try:
        sandbox = (await effective_core_settings(db)).sandbox
    except Exception as exc:  # noqa: BLE001 — advisory: unread means every detect is judged
        logger.debug("Could not read the declared detects (%s); continuing.", type(exc).__name__)
        return None
    return {fmt.name: _detect_of(fmt) for fmt in sandbox.report_formats}


def _detect_of(fmt: Any) -> list[list[dict[str, Any]]]:
    return [[test.model_dump(mode="json") for test in group] for group in fmt.detect]


async def _mapping_warnings(
    db: AsyncSession, changes: dict[str, Any], detects_before: dict[str, Any] | None = None
) -> dict[str, str]:
    """A warning beside each saved report-mapping path whose reading is not linear in the report,
    and beside the detect of each format read through a mapping that a built-in's detect overlaps.

    Read from the settings as they now stand, for a save that touched the
    sandbox settings; the save itself is never refused for either
    (``core.report_mapping.costly_paths``,
    ``core.report_formats.builtin_overlapping``). The overlap is said only
    for a save that writes the report formats, and only beside a format whose
    detect the save adds or changes (``detects_before``, each declared
    format's detect by name before the save; ``None`` where it was not read,
    and then every format's detect is judged), so an unrelated save never
    repeats it. Never raises, as :func:`_agent_warnings` never does.
    """
    from maljan.core.report_formats import (
        BUILTIN_REPORT_FORMATS,
        builtin_overlapping,
        effective_formats,
        overlapping_paths,
    )
    from maljan.core.report_mapping import costly_paths
    from maljan.providers.sandbox.readers import format_reads_mapping

    if not any(str(key).startswith("core.sandbox.") for key in changes):
        return {}
    try:
        sandbox = (await effective_core_settings(db)).sandbox
    except Exception as exc:  # noqa: BLE001 — advisory, and the write is done
        logger.debug("Could not read the mapping paths (%s); continuing.", type(exc).__name__)
        return {}
    out = {
        f"core.sandbox.rest.mapping.{field}": said
        for field, said in costly_paths(sandbox.rest.mapping).items()
    }
    builtins = [
        fmt
        for fmt in effective_formats(sandbox.report_formats)
        if fmt.name in {b.name for b in BUILTIN_REPORT_FORMATS}
    ]
    formats_written = touches_report_formats(changes)
    for index, fmt in enumerate(sandbox.report_formats):
        if fmt.mapping is not None:
            for field, said in costly_paths(fmt.mapping).items():
                out[f"core.sandbox.report_formats.{index}.mapping.{field}"] = said
        changed = formats_written and (
            detects_before is None or detects_before.get(fmt.name) != _detect_of(fmt)
        )
        overlapping = (
            builtin_overlapping(fmt, builtins) if changed and format_reads_mapping(fmt) else ""
        )
        if overlapping:
            builtin = next(b for b in builtins if b.name == overlapping)
            out[f"core.sandbox.report_formats.{index}.detect"] = SHADOWED_DETECT.format(
                name=fmt.name,
                builtin=overlapping,
                places=", ".join(overlapping_paths(builtin)),
            )
    return out


SHADOWED_DETECT = (
    "{name!r} is read through a mapping, which is tried after every built-in format, and its "
    "detect overlaps the built-in format {builtin!r}: a report both recognise is read as "
    "{builtin!r}, never as {name!r}. To set them apart, add a test on a place {builtin!r} "
    "tests ({places}) that its reports cannot pass, such as another type or text they never "
    "hold; a test on a place of your own does not, since {builtin!r}'s reports may carry it "
    "too. Saved as written."
)


async def _unprobed_models_in(db: AsyncSession, changes: dict[str, Any]) -> list[str]:
    """Every per-agent model this save names that no probe has reached.

    Judged against the settings as this save would leave them, so an operator
    moving an agent to a new endpoint and a new model in one change is judged
    on the pair they are moving it to rather than the one they are leaving.

    A save that names no per-agent model is answered before the store is read:
    every PATCH goes through here, most of them carry one leaf of one group,
    and reading the overrides back and rebuilding the whole settings model to
    conclude that there was nothing to check is work on the path of every save.
    """
    from app.services.model_probes import AGENT_MODELS_KEY, unprobed_models_being_saved

    if AGENT_MODELS_KEY not in changes:
        return []
    try:
        stored = await SettingsService(db).load_overrides()
        settings = candidate_settings(changes, stored)
    except Exception as exc:  # noqa: BLE001 — a change the model rejects is refused below
        logger.debug("probe gate skipped for this save (%s).", type(exc).__name__)
        return []
    return await unprobed_models_being_saved(db, settings, changes, stored)


@router.patch("", response_model=PatchResponse)
async def patch_values(
    body: PatchRequest,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> PatchResponse | JSONResponse:
    """Save a set of staged values at once.

    A block's tool declarations (an entry's ``tool_facts`` in
    ``core.mcp.servers``, a ``core.<block>.tool_facts`` leaf) are read by
    their mark: a map holding ``"": "changes"`` is the block's changes over
    what it ships, one tool at a time (``null`` removes a shipped tool, and a
    tool it leaves out stays as shipped); a map without the mark is the whole
    map, so a shipped tool it leaves out is removed. A map sent back exactly
    as stored keeps the reading it is stored with. ``GET`` serves every
    stored map marked.
    """
    changes = _current_keys(body.changes)
    unprobed = await _unprobed_models_in(db, changes)
    if unprobed:
        from app.services.model_probes import AGENT_MODELS_KEY, refusal_sentence

        # The same refusal a job gets, on the page that can fix it: a model
        # saved here is one a run will call, and finding out at submit time
        # means finding out somewhere else.
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"errors": {AGENT_MODELS_KEY: refusal_sentence(unprobed)}},
        )
    # A plugin whose own block this save changes is loaded to read it; a block
    # key sent back unchanged is no write, and the allow-list loads nothing.
    changes, _stored = await _plugin_block_writes(db, changes)
    formats_written = touches_report_formats(changes)
    detects_before: dict[str, Any] | None = None
    try:
        # A write of the declared report formats waits for an accept that is
        # rewriting them, and an accept for it (``services.report_formats_lock``).
        async with report_formats_serialised(db, needed=formats_written):
            if formats_written:
                # Under the lock, so an accept between the read and the save
                # is never taken for this save's change.
                detects_before = await _declared_detects(db)
            res = await SettingsService(db).save(changes, user_id=user.id, ip=_client_ip(request))
    except SettingsValidationError as exc:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"errors": exc.errors}
        )
    runtime_config.invalidate()
    core_settings_cache.invalidate()
    return PatchResponse(
        applied=res.applied,
        applies=res.applies,
        warnings={
            **await _agent_warnings(db),
            **await _mapping_warnings(db, changes, detects_before),
        },
    )


@router.delete("", response_model=ResetResponse)
async def reset_group(
    request: Request,
    group: str = Query(...),
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ResetResponse | JSONResponse:
    # A plugin block's stored rows go with their group, read as stored: a
    # reset loads no plugin.
    keys = [
        e.key
        for e in [*full_catalog(), *await stored_block_entries(db)]
        if e.group == group and e.editable
    ]
    if not keys:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown group: {group}")
    try:
        async with report_formats_serialised(db, needed=touches_report_formats(keys)):
            removed = await SettingsService(db).reset(keys, user_id=user.id, ip=_client_ip(request))
    except SettingsValidationError as exc:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"errors": exc.errors}
        )
    runtime_config.invalidate()
    core_settings_cache.invalidate()
    return ResetResponse(reset=removed)


@router.delete("/{key}", response_model=ResetResponse)
async def reset_key(
    key: str,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ResetResponse | JSONResponse:
    # A row whose key left the catalog (a later deploy renamed the field) must
    # still be removable, so the catalog check only decides between 404 and
    # an empty reset when nothing is stored either.
    try:
        async with report_formats_serialised(db, needed=touches_report_formats([key])):
            removed = await SettingsService(db).reset(
                [key], user_id=user.id, ip=_client_ip(request)
            )
    except SettingsValidationError as exc:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"errors": exc.errors}
        )
    if not removed and key not in catalog_index():
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown setting: {key}")
    runtime_config.invalidate()
    core_settings_cache.invalidate()
    return ResetResponse(reset=removed)


def _strip_masks(value: Any, path: str) -> tuple[Any, list[str]]:
    """``value`` with every nested mask removed, plus the path of each one.

    ``values()`` replaces a stored credential with ``TOKEN_MASK`` wherever one
    is nested inside a composite leaf -- a server's ``auth_token``, a frontier
    arm's ``api_key`` -- so the UI never echoes a real one. Writing that mask
    into the export would configure it as the literal credential on the next
    import (the failure mode fixed for the old ``.env`` export), so it is
    dropped here instead, at any depth: a composite that grows a new secret
    leaf is covered the day it is added rather than the day someone remembers
    to extend this function.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        omitted: list[str] = []
        for name, item in value.items():
            child = f"{path}.{name}"
            if item == TOKEN_MASK:
                omitted.append(child)
                continue
            cleaned, paths = _strip_masks(item, child)
            out[name] = cleaned
            omitted.extend(paths)
        return out, omitted
    if isinstance(value, list):
        items: list[Any] = []
        omitted = []
        for i, item in enumerate(value):
            child = f"{path}.{i}"
            if item == TOKEN_MASK:
                omitted.append(child)
                continue
            cleaned, paths = _strip_masks(item, child)
            items.append(cleaned)
            omitted.extend(paths)
        return items, omitted
    return value, []


def _export_value(key: str, value: Any) -> tuple[Any, list[str]]:
    """The value as it goes into the export document, plus any paths it cost.

    Two composite leaves carry credentials inside them: ``core.mcp.servers``
    (one ``auth_token`` per server) and ``core.llm.frontier.arms`` (one
    ``api_key`` per arm). Both reach here as the mask, and both are stripped by
    ``_strip_masks`` above, together with anything else masked at any depth.
    The server map additionally carries the synthetic ``auth_token_source``
    (not an ``MCPServerConfig`` field, so it would not import back), which is
    dropped without being listed.

    The paths returned name every credential the export did not carry, e.g.
    ``core.mcp.servers.<name>.auth_token`` or
    ``core.llm.frontier.arms.<arm>.api_key``. They are informational only, not
    catalog keys: importing a document that includes one back as a top-level
    key is rejected as ``unknown key``, the same as any other stray field.
    They exist so an operator reading the export can see which servers and
    arms lost their credential, rather than silently ending up with none on
    the next import.
    """
    if key != SERVER_MAP_KEY or not isinstance(value, dict):
        return _strip_masks(value, key)
    value = {
        name: (
            {k: v for k, v in entry.items() if k != "auth_token_source"}
            if isinstance(entry, dict)
            else entry
        )
        for name, entry in value.items()
    }
    sanitized, omitted = _strip_masks(value, key)
    return _mask_server_env(sanitized, omitted)


def _mask_server_env(servers: Any, omitted: list[str]) -> tuple[Any, list[str]]:
    """Every ``env`` value masked, and its variable named in ``omitted``.

    A server's ``env`` map is the one place a credential can live without
    being typed as one, which is why
    ``public_snapshot`` masks it in run summaries. An export is a file on an
    operator's disk and the weaker of the two paths, so it masks them too. The
    variable names stay -- an operator reading the document needs to see what
    the server was handed -- and only the values go; a masked value coming
    back on import means "keep the stored one" (``split_server_secrets``).
    """
    if not isinstance(servers, dict):
        return servers, omitted
    out: dict[str, Any] = {}
    for name, entry in servers.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("env"), dict):
            out[name] = entry
            continue
        env = entry["env"]
        out[name] = {**entry, "env": {var: TOKEN_MASK for var in env}}
        omitted.extend(f"{SERVER_MAP_KEY}.{name}.env.{var}" for var in env)
    return out, omitted


@router.get("/export", response_model=ExportResponse)
async def export_values(
    response: Response,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ExportResponse:
    # A plugin block this process has not read is exported as stored; an
    # export loads no plugin.
    extra = await stored_block_entries(db)
    index = {**catalog_index(), **{entry.key: entry for entry in extra}}
    values: dict[str, Any] = {}
    secrets_omitted: list[str] = []
    unreadable: dict[str, str] = {}
    for key, info in (await SettingsService(db).values(extra=extra)).items():
        if info.source != "ui":
            continue
        entry = index[key]
        if not entry.editable:
            continue
        if entry.secret:
            secrets_omitted.append(key)
            continue
        try:
            sanitized, omitted_paths = _export_value(key, info.value)
        except RecursionError as exc:
            # Too deep for the walk that strips its masks: the same bound the
            # answer's writer has (:func:`unwritable_reason`).
            reason: str | None = unwritable_reason_of(exc)
        else:
            reason = unwritable_reason(
                ExportResponse(
                    format=EXPORT_FORMAT,
                    exported_at=datetime.now(UTC),
                    values={key: sanitized},
                    secrets_omitted=omitted_paths,
                )
            )
        if reason is not None:
            _say_unwritable("the export", key, reason)
            unreadable[key] = reason
            continue
        values[key] = sanitized
        secrets_omitted.extend(omitted_paths)
    response.headers["Content-Disposition"] = "attachment; filename=maljan-settings.json"
    return ExportResponse(
        format=EXPORT_FORMAT,
        exported_at=datetime.now(UTC),
        values=values,
        secrets_omitted=sorted(secrets_omitted),
        unreadable=unreadable,
    )


def _current_keys(values: dict[str, Any]) -> dict[str, Any]:
    """``values`` with each moved key read as the key that now holds it.

    An export written before a setting moved carries the old key; it is
    imported as the new one, and a file carrying both keeps the new one's
    value.
    """
    out = {key: value for key, value in values.items() if key not in RENAMED_SETTINGS}
    for old, new in RENAMED_SETTINGS.items():
        if old in values and new not in out:
            out[new] = values[old]
    return out


@router.post("/import", response_model=PatchResponse)
async def import_values(
    body: ImportRequest,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> PatchResponse | JSONResponse:
    if body.format not in IMPORT_FORMATS:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"errors": {"format": "unsupported format"}},
        )
    # A plugin whose own block the document changes is loaded to read it,
    # unless the document drops it from the allow-list. A block key sent back
    # as stored, as an export writes it, is no write and loads nothing, so an
    # unedited or list-edited export imports without loading a plugin.
    values, stored = await _plugin_block_writes(db, _current_keys(body.values))
    stored_allowed = stored.get(ALLOW_LIST_KEY) if stored is not None else None
    leaves = values[ALLOW_LIST_KEY] if ALLOW_LIST_KEY in values else stored_allowed
    index = catalog_index()
    # A clear of a key in an unloaded plugin's block deletes its stored row,
    # which the save does without the plugin's model.
    cleared = set(cleared_plugin_block_keys(values, index))
    errors: dict[str, str] = {}
    for key in values:
        entry = index.get(key)
        if entry is None and key in RETIRED_SETTINGS:
            errors[key] = (
                f"retired setting with no effect ({RETIRED_SETTINGS[key]}); "
                "delete this key from the file and import again"
            )
        elif entry is None and key in cleared:
            continue
        elif entry is None:
            errors[key] = unknown_key_reason(key, stored_allowed, "unknown key", leaves=leaves)
        elif not entry.editable:
            errors[key] = "read-only"
    if errors:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"errors": errors}
        )
    # A declaration another version wrote may hold what this one does not
    # read: it is left out with a warning, never a refusal of the file.
    values, left_out = lenient_imported_declarations(
        values, whole_maps=body.format == WHOLE_MAP_FORMAT
    )
    try:
        async with report_formats_serialised(db, needed=touches_report_formats(values)):
            res = await SettingsService(db).save(values, user_id=user.id, ip=_client_ip(request))
    except SettingsValidationError as exc:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"errors": exc.errors}
        )
    if res.applied:
        await audit_record(
            "settings.import",
            resource_type="settings",
            user_id=user.id,
            details={"keys": sorted(res.applied), "count": len(res.applied)},
            ip=_client_ip(request),
        )
    runtime_config.invalidate()
    core_settings_cache.invalidate()
    # An import can bring in a whole team just as a patch can, so it answers
    # with the same advisory notes.
    return PatchResponse(
        applied=res.applied,
        applies=res.applies,
        warnings={**left_out, **await _agent_warnings(db)},
    )


async def _probe_response(coro: Awaitable[Any]) -> ProbeResponse:
    """One probe's answer, as a 200 whatever happens.

    A connection test that fails is an answer, not
    an error -- an operator staging a command that turns out not to be an MCP
    server needs to read why, and a 500 (or a cancelled handler that sends
    nothing at all, which is what this endpoint did) reaches the browser as a
    bare connection failure with no CORS headers on it. ``in_probe_loop``
    already converts everything the probe itself can end with; this is the
    outer fence around the resolution work that happens before it.
    """
    try:
        result = await coro
    except (Exception, BaseExceptionGroup) as exc:  # noqa: BLE001 - reported, never raised
        logger.warning("probe failed before it ran: %s", type(exc).__name__)
        # Through ``redact_url``: what reaches this fence is a driver error —
        # arq, Redis, Qdrant — and a driver names the connection string it was
        # configured with, password and all.
        return ProbeResponse(
            ok=False, latency_ms=0, detail=redact_url(f"{type(exc).__name__}: {exc}")
        )
    return ProbeResponse(**vars(result))


# The words that mark a staged value as an address. A probe is *pointed* at
# one of these, and that is the part of a probe worth writing down.
_ADDRESS_WORDS = ("url", "endpoint", "dsn", "host")


def _endpoints_reached(values: dict[str, Any], details: dict[str, Any] | None) -> list[str]:
    """Every endpoint this probe was pointed at, as labels rather than values.

    Two sources, because two kinds of probe answer differently: the pairs an
    LLM or agent probe reports having called, and the staged values that named
    an address for every other one. Each goes through ``endpoint_label``, so
    the row names the server and never the credential in front of it.
    """
    found: list[str] = []
    for pair in (details or {}).get("completions") or []:
        if isinstance(pair, dict):
            found.append(endpoint_label(str(pair.get("endpoint") or "")))
    for key, value in (values or {}).items():
        leaf = str(key).rsplit(".", 1)[-1].lower()
        if isinstance(value, str) and any(word in leaf for word in _ADDRESS_WORDS):
            found.append(endpoint_label(value))
    return sorted({label for label in found if label})


async def _record_the_probe(
    request: Request,
    user: User,
    probe: str,
    body: ProbeRequest,
    response: ProbeResponse,
    **extra: Any,
) -> None:
    """One audit row per probe, naming what it was pointed at.

    A probe backfills every input the caller did not stage from the decrypted
    store, so a staged endpoint is sent the *stored* credential — a secret the
    console never shows in the clear. Saving that endpoint is audited and
    gated; pointing a probe at it was neither, and this is the record that
    closes it. The staged keys are named so a reader can see the endpoint did
    not come from the store; their values are not.
    """
    await audit_record(
        "settings.probe",
        resource_type="settings",
        resource_id=probe,
        user_id=user.id,
        details={
            "probe": probe,
            "endpoints": _endpoints_reached(body.values, response.details),
            "staged": sorted(body.values or {}),
            "ok": bool(response.ok),
            **extra,
        },
        ip=_client_ip(request),
    )


@router.post("/test/mcp", response_model=ProbeResponse)
async def test_mcp_server(
    body: ProbeRequest,
    request: Request,
    server: str = Query(..., description="key in mcp.servers"),
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProbeResponse:
    """Launch one configured MCP server, report the tools it offers and propose declarations.

    Takes staged values so an operator can test a server they have not saved
    yet — the same contract as every other probe, addressed to one key of one
    setting rather than to a set of settings. Registered ahead of
    ``/test/{probe}`` so the fixed path wins the match. The proposals in
    ``details`` are data for the admin to accept; nothing is saved here. A
    tool is called only when the body's ``confirmed_calls`` names it after the
    admin was shown the planned calls (``details.proposals.planned``).
    """
    stored = await SettingsService(db).load_overrides()
    # The staged values are read; what follows launches a server and waits on
    # it. Nothing below needs the transaction that read them, and a probe is
    # the longest await this API makes.
    await end_read_transaction(db)
    response = await _probe_response(
        run_mcp_probe(server, body.values, stored, confirmed_calls=body.confirmed_calls)
    )
    await _record_the_probe(
        request,
        user,
        "mcp",
        body,
        response,
        server=server,
        confirmed_calls=sorted(body.confirmed_calls),
    )
    return response


@router.post("/servers/{key}/credential", response_model=CredentialBootstrapResponse)
async def obtain_server_credential(
    key: str,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> CredentialBootstrapResponse | JSONResponse:
    """Obtain server ``key``'s credential by its declared request, store it and enable it.

    For any tool server in force that declares ``credential_bootstrap``. The
    request takes no body: the URL, the body sent and where the token sits are
    the declaration's (a built-in's, or one an admin saved in the server map),
    and the only variable part -- the token -- is what comes back. It is
    stored encrypted and never returned; the answer carries the mask and the
    facts the declaration names. A failure at the service is a 502 with its
    own sentence in it, because the fix is on its side or in the operator's
    network, not in the stored settings.
    """
    from maljan.core.settings_overrides import build_settings

    from app.services.settings_service import load_core_overrides

    service = SettingsService(db)
    try:
        servers = build_settings(await load_core_overrides(db)).mcp.servers
    except (ValueError, ValidationError):
        servers = build_settings({}).mcp.servers
    config = servers.get(key)
    if config is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such tool server")
    declared = config.credential_bootstrap
    if declared is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "this tool server declares no credential bootstrap"
        )
    label = str(config.label or key)
    # The caller was resolved from the database by the dependency above, so
    # this request is already in a transaction; the bootstrap is a call to
    # somebody else's service and must not be made inside it.
    await end_read_transaction(db)
    try:
        token, facts = await credential_bootstrap.obtain_credential(declared, label=label)
    except credential_bootstrap.BootstrapError as exc:
        # The service's own sentence goes to the admin who pressed the button,
        # not into the log.
        logger.warning("the bootstrap request failed for tool server %s", log_safe(key))
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY, content={"errors": {key: str(exc)}}
        )

    stored = await service.load_overrides()
    current = stored.get(SERVER_MAP_KEY)
    updated = credential_bootstrap.server_map_with_token(
        current if isinstance(current, dict) else {}, key, token
    )
    try:
        await service.save({SERVER_MAP_KEY: updated}, user_id=user.id, ip=_client_ip(request))
    except SettingsValidationError as exc:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"errors": exc.errors}
        )
    await audit_record(
        "settings.servers.credential",
        resource_type="settings",
        user_id=user.id,
        details={
            "server": log_safe(key),
            "facts": {log_safe(k): log_safe(v) for k, v in facts.items()},
        },
        ip=_client_ip(request),
    )
    runtime_config.invalidate()
    core_settings_cache.invalidate()
    logger.info("the bootstrap request answered for tool server %s", log_safe(key))
    entry = updated[key]
    return CredentialBootstrapResponse(
        **credential_bootstrap.masked_state(key, entry if isinstance(entry, dict) else {}, facts)
    )


async def _write_down_what_was_reached(db: AsyncSession, pairs: list[dict[str, Any]]) -> None:
    """File a row for every pair the probe actually completed a call with.

    The list comes from the probe itself (``details["completions"]``), so what
    is written down and what was called are one thing rather than two
    computations that have to agree. A pair the probe timed out on is not in
    it: nothing was learned, so nothing is recorded, and the operator is told
    to try again.

    Never raises. A probe is an operator pressing a button and reading a
    sentence; a store that could not be written is a reason to log, not a
    reason to give them an error instead of their answer.
    """
    from maljan.core.model_assignments import filed_model

    from app.services.model_probes import record_probe

    for pair in pairs:
        try:
            await record_probe(
                db,
                endpoint=str(pair.get("endpoint") or ""),
                # A pair asked at an entry's own effort is filed with it.
                model=filed_model(str(pair.get("model") or ""), pair.get("effort")),
                provider=str(pair.get("provider") or ""),
                ok=bool(pair.get("ok")),
                detail=str(pair.get("detail") or ""),
            )
        except Exception as exc:  # noqa: BLE001 — the answer still reaches the operator
            logger.warning("probe result not stored: %s", type(exc).__name__)
            continue


@router.post("/test/agent", response_model=ProbeResponse)
async def test_agent(
    body: ProbeRequest,
    request: Request,
    name: str = Query(..., description="key in agents.definitions"),
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProbeResponse:
    """Resolve one agent definition and report what it would get.

    Takes staged values so an operator can resolve a definition they have not
    saved yet — the same contract every other probe has. It ends by asking that
    agent's model for one short answer at the endpoint the agent would call,
    because the row this files is what refuses a job later and a gate has to
    rest on a call that was made.

    What it reached is written down against the endpoint and the model it
    named, so submitting a job can refuse a team whose agents name a model
    nothing has ever answered for.
    """
    stored = await SettingsService(db).load_overrides()
    # The definition is resolved; the call to the model is not this
    # transaction's business and may take the whole probe budget.
    await end_read_transaction(db)
    # The allowed model, static and sandbox plugins this agent runs on run
    # their own code here: those alone, loaded off the event loop, waited for
    # at most a connection test's budget.
    from maljan.core.settings_overrides import split_key

    from app.services.plugins import load_in_background, selected_plugins
    from app.services.settings_probes import TIMEOUT

    candidate = {
        split_key(key)[1]: value
        for key, value in {**stored, **body.values}.items()
        if key.startswith("core.")
    }
    allowed = stored.get(ALLOW_LIST_KEY)
    running = selected_plugins(candidate, allowed, ("llm", "static", "sandbox"), name)
    await load_in_background(allowed, running, TIMEOUT)
    response = await _probe_response(run_agent_probe(name, body.values, stored))
    await _write_down_what_was_reached(db, (response.details or {}).get("completions") or [])
    await _record_the_probe(request, user, "agent", body, response, agent=name)
    return response


@router.post("/test/{probe}", response_model=ProbeResponse)
async def test_probe(
    probe: str,
    body: ProbeRequest,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProbeResponse:
    stored = await SettingsService(db).load_overrides()
    if not known_probe(probe, with_staged_sources(stored, body.values)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown probe: {probe}")
    # An LLM probe is allowed five minutes at a third-party endpoint; the read
    # that prepared it ends here rather than waiting for the answer.
    await end_read_transaction(db)
    response = await _probe_response(run_probe(probe, body.values, stored))
    if probe == "llm":
        await _write_down_what_was_reached(db, (response.details or {}).get("completions") or [])
    await _record_the_probe(request, user, probe, body, response)
    return response


async def _capped_body(request: Request) -> dict[str, Any]:
    """Read the request body, refusing anything over the preview cap before it is parsed.

    ``Content-Length`` catches an honest client without reading a byte; the
    streamed guard catches a body sent without one (chunked transfer) or a
    header that understates the real size, so the cap holds either way. The
    streamed read never buffers past ``PREVIEW_MAX_BYTES + 1`` — a chunk that
    would cross the limit is sliced down to the bytes needed to prove it does,
    not appended whole, so one oversized chunk cannot balloon memory use past
    the cap it is here to enforce.
    """
    content_length = request.headers.get("content-length")
    if content_length is not None:
        with suppress(ValueError):
            if int(content_length) > PREVIEW_MAX_BYTES:
                raise HTTPException(
                    status.HTTP_413_CONTENT_TOO_LARGE,
                    f"the pasted response exceeds {PREVIEW_MAX_BYTES} bytes",
                )
    limit = PREVIEW_MAX_BYTES + 1
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        if size >= limit:
            break
        piece = chunk[: limit - size]
        chunks.append(piece)
        size += len(piece)
    if size > PREVIEW_MAX_BYTES:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            f"the pasted response exceeds {PREVIEW_MAX_BYTES} bytes",
        )
    try:
        parsed: dict[str, Any] = json.loads(b"".join(chunks) or b"{}")
        return parsed
    except json.JSONDecodeError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"invalid JSON body: {exc}") from exc


@router.post("/validate-condition", response_model=ConditionValidateResponse)
async def validate_stage_condition(
    body: ConditionValidateRequest,
    _: User = Depends(require_admin),
) -> ConditionValidateResponse:
    """Check one stage's ``when`` expression without storing anything.

    The grammar lives in ``pipeline.conditions`` and the apply path already
    refuses a bad condition, but only once the operator has finished the whole
    team and pressed apply. The editor calls this as each condition field
    loses focus, so a typo is answered next to the box it was typed into by
    the same parser that will run it.
    """
    problems = validate_condition(body.expression)
    if problems:
        logger.info(
            "Stage condition rejected: %s",
            log_safe("; ".join(problems)),
            extra={"expression": log_safe(body.expression)},
        )
    return ConditionValidateResponse(valid=not problems, problems=problems)


@router.post("/lint-teams", response_model=TeamLintResponse)
async def lint_teams_route(
    body: TeamLintRequest,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> TeamLintResponse:
    """Check every team as the editor has staged it, and lay each one out.

    Nothing is stored. The console calls this as a team is edited, debounced,
    and draws the preview and the findings from the answer. The errors are the
    team refusals the apply path makes, in the same words; a warning never
    blocks apply.

    The lint and the layout are CPU work over whatever the body holds, so they
    run in a worker thread, as the API's other blocking work does, and the
    event loop keeps serving every other request while a large team is read.
    """
    stored = await SettingsService(db).load_overrides()
    return await asyncio.to_thread(_lint_response, stored, body)


def _lint_response(stored: dict[str, Any], body: TeamLintRequest) -> TeamLintResponse:
    from app.services.agent_map import lint_team_map

    findings, graphs = lint_team_map(
        stored, profiles=body.profiles, definitions=body.definitions, active=body.profile
    )
    order = {"error": 0, "warning": 1}
    findings.sort(key=lambda f: order.get(str(f["severity"]), 2))
    return TeamLintResponse(
        findings=[TeamFindingDTO(**f) for f in findings],
        graphs={name: TeamGraphDTO(**graph) for name, graph in graphs.items()},
    )


@router.post("/sandbox-rest/preview", response_model=MappingPreviewResponse)
async def preview_sandbox_mapping(
    request: Request,
    _: User = Depends(require_admin),
) -> MappingPreviewResponse:
    """Run a mapping against a pasted response. Nothing is stored or submitted."""
    payload = await _capped_body(request)
    body = MappingPreviewRequest.model_validate(payload)
    return MappingPreviewResponse(**preview_mapping(body.sample, body.mapping))


# ── The ATT&CK cache ────────────────────────────────────────────────────────
# The cached ATT&CK bundles live on the analysis worker, which is their one
# writer; these routes ask it (``app.services.attck_cache``) and never touch
# the files. The upstream address is the platform's constant: nothing a caller
# sends names a host.


async def _attck_refresh_days(db: AsyncSession) -> int:
    """The saved ``validation.attck_refresh_days``; the read transaction ends here."""
    core = await core_settings_cache.get(db)
    await end_read_transaction(db)
    return int(core.validation.attck_refresh_days)


def _attck_caller(user: User) -> dict[str, Any]:
    """Who asked, as the worker records it and the console shows it."""
    return {"user_id": str(user.id), "name": str(getattr(user, "full_name", "") or "")}


def _worker_silent(exc: attck_cache.WorkerDidNotAnswer) -> HTTPException:
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))


@router.get("/attck", response_model=AttckStatusResponse)
async def attck_status(
    _: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
) -> AttckStatusResponse:
    """Per ATT&CK domain: the cached release, its date and age, the next automatic check."""
    days = await _attck_refresh_days(db)
    try:
        answer = await attck_cache.status(days)
    except attck_cache.WorkerDidNotAnswer as exc:
        raise _worker_silent(exc) from exc
    if answer.get("outcome") == "failed":
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=answer.get("reason"))
    return AttckStatusResponse(**answer)


@router.post("/attck/check", response_model=AttckCheckResponse)
async def attck_check(
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> AttckCheckResponse:
    """Compare the cache with MITRE's release index now. Downloads and changes nothing."""
    days = await _attck_refresh_days(db)
    try:
        answer = await attck_cache.check(_attck_caller(user), days)
    except attck_cache.WorkerDidNotAnswer as exc:
        raise _worker_silent(exc) from exc
    await audit_record(
        "settings.attck_check",
        resource_type="settings",
        resource_id="attck",
        user_id=user.id,
        details={"outcome": answer.get("outcome"), "reason": answer.get("reason") or ""},
        ip=_client_ip(request),
    )
    return AttckCheckResponse(**answer)


@router.post(
    "/attck/update", response_model=AttckUpdateStarted, status_code=status.HTTP_202_ACCEPTED
)
async def attck_update(
    request: Request,
    user: User = Depends(require_admin),
) -> AttckUpdateStarted:
    """Queue the update: download every outdated domain, check it, then swap it in.

    The worker keeps the previous files as a backup and refuses a second
    update while one runs. Poll ``/attck/update/{job_id}`` for the result.
    """
    try:
        job_id = await attck_cache.start_update(_attck_caller(user))
    except attck_cache.WorkerDidNotAnswer as exc:
        raise _worker_silent(exc) from exc
    logger.info("ATT&CK update queued by user %s as job %s", user.id, job_id)
    await audit_record(
        "settings.attck_update",
        resource_type="settings",
        resource_id="attck",
        user_id=user.id,
        details={"job_id": job_id},
        ip=_client_ip(request),
    )
    return AttckUpdateStarted(job_id=job_id)


@router.get("/attck/update/{job_id}", response_model=AttckUpdateProgress)
async def attck_update_progress(
    job_id: str,
    _: User = Depends(require_admin),
) -> AttckUpdateProgress:
    """Where one update is, and its result once it is done."""
    if not attck_cache.is_job_id(job_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such ATT&CK update.")
    try:
        progress = await attck_cache.update_progress(job_id)
    except Exception as exc:  # noqa: BLE001 — Redis down reads as no answer
        raise _worker_silent(attck_cache.WorkerDidNotAnswer(str(exc))) from exc
    return AttckUpdateProgress(**progress)
