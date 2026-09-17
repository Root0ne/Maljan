"""Runtime settings: the catalog, the effective values, and the overrides."""

from __future__ import annotations

import json
from collections.abc import Awaitable
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from maljan.core.settings_annotations import GROUP_DESCRIPTIONS, GROUP_ORDER
from maljan.core.virustotal import SERVER_KEY as VIRUSTOTAL_SERVER_KEY
from maljan.pipeline.conditions import validate_condition
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import require_admin
from app.logging_config import get_logger
from app.logsafe import log_safe
from app.models.user import User
from app.runtime_config import runtime_config
from app.schemas.settings import (
    CatalogEntryDTO,
    ConditionValidateRequest,
    ConditionValidateResponse,
    ExportResponse,
    GroupDTO,
    ImportRequest,
    MappingPreviewRequest,
    MappingPreviewResponse,
    PatchRequest,
    PatchResponse,
    ProbeRequest,
    ProbeResponse,
    ResetResponse,
    SchemaResponse,
    ValueDTO,
    ValuesResponse,
    VirustotalRegisterResponse,
)
from app.services.audit import record as audit_record
from app.services.mapping_preview import PREVIEW_MAX_BYTES, preview_mapping
from app.services.server_map import SERVER_MAP_KEY, TOKEN_MASK
from app.services.settings_catalog_api import catalog_index, full_catalog, resolved_catalog
from app.services.settings_probes import (
    PROBES,
    candidate_settings,
    models_the_llm_probe_reached,
    run_agent_probe,
    run_mcp_probe,
    run_probe,
)
from app.services.settings_service import (
    SettingsService,
    SettingsValidationError,
    core_settings_cache,
)
from app.services.virustotal_register import (
    RegistrationError,
    masked_state,
    register_agent,
    server_map_with_token,
)

EXPORT_FORMAT = "maljan-settings/1"

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
    profiles, agents = await _effective_agents(db)
    by_group: dict[str, list[CatalogEntryDTO]] = {}
    for e in resolved_catalog(await _effective_servers(db), profiles=profiles, agents=agents):
        d = e.to_dict()
        by_group.setdefault(e.group, []).append(CatalogEntryDTO(**d))
    groups = [
        GroupDTO(key=g, title=t, description=GROUP_DESCRIPTIONS.get(g, ""), entries=by_group[g])
        for g, t in GROUP_ORDER
        if g in by_group
    ]
    return SchemaResponse(groups=groups)


@router.get("", response_model=ValuesResponse)
async def get_values(
    _: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
) -> ValuesResponse:
    vals = await SettingsService(db).values()
    return ValuesResponse(values={k: ValueDTO(**vars(v)) for k, v in vals.items()})


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


@router.patch("", response_model=PatchResponse)
async def patch_values(
    body: PatchRequest,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> PatchResponse | JSONResponse:
    try:
        res = await SettingsService(db).save(body.changes, user_id=user.id, ip=_client_ip(request))
    except SettingsValidationError as exc:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"errors": exc.errors}
        )
    runtime_config.invalidate()
    core_settings_cache.invalidate()
    return PatchResponse(
        applied=res.applied, applies=res.applies, warnings=await _agent_warnings(db)
    )


@router.delete("", response_model=ResetResponse)
async def reset_group(
    request: Request,
    group: str = Query(...),
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ResetResponse:
    keys = [e.key for e in full_catalog() if e.group == group and e.editable]
    if not keys:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown group: {group}")
    removed = await SettingsService(db).reset(keys, user_id=user.id, ip=_client_ip(request))
    runtime_config.invalidate()
    core_settings_cache.invalidate()
    return ResetResponse(reset=removed)


@router.delete("/{key}", response_model=ResetResponse)
async def reset_key(
    key: str,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ResetResponse:
    # A row whose key left the catalog (a later deploy renamed the field) must
    # still be removable, so the catalog check only decides between 404 and
    # an empty reset when nothing is stored either.
    removed = await SettingsService(db).reset([key], user_id=user.id, ip=_client_ip(request))
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
    index = catalog_index()
    values: dict[str, Any] = {}
    secrets_omitted: list[str] = []
    for key, info in (await SettingsService(db).values()).items():
        if info.source != "ui":
            continue
        entry = index[key]
        if not entry.editable:
            continue
        if entry.secret:
            secrets_omitted.append(key)
            continue
        sanitized, omitted_paths = _export_value(key, info.value)
        values[key] = sanitized
        secrets_omitted.extend(omitted_paths)
    response.headers["Content-Disposition"] = "attachment; filename=maljan-settings.json"
    return ExportResponse(
        format=EXPORT_FORMAT,
        exported_at=datetime.now(UTC),
        values=values,
        secrets_omitted=sorted(secrets_omitted),
    )


@router.post("/import", response_model=PatchResponse)
async def import_values(
    body: ImportRequest,
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> PatchResponse | JSONResponse:
    if body.format != EXPORT_FORMAT:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"errors": {"format": "unsupported format"}},
        )
    index = catalog_index()
    errors: dict[str, str] = {}
    for key in body.values:
        entry = index.get(key)
        if entry is None:
            errors[key] = "unknown key"
        elif not entry.editable:
            errors[key] = "read-only"
    if errors:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"errors": errors}
        )
    try:
        res = await SettingsService(db).save(body.values, user_id=user.id, ip=_client_ip(request))
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
        applied=res.applied, applies=res.applies, warnings=await _agent_warnings(db)
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
        return ProbeResponse(ok=False, latency_ms=0, detail=f"{type(exc).__name__}: {exc}")
    return ProbeResponse(**vars(result))


@router.post("/test/mcp", response_model=ProbeResponse)
async def test_mcp_server(
    body: ProbeRequest,
    server: str = Query(..., description="key in mcp.servers"),
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProbeResponse:
    """Launch one configured MCP server and report the tools it offers.

    Takes staged values so an operator can test a server they have not saved
    yet — the same contract as every other probe, addressed to one key of one
    setting rather than to a set of settings. Registered ahead of
    ``/test/{probe}`` so the fixed path wins the match.
    """
    stored = await SettingsService(db).load_overrides()
    return await _probe_response(run_mcp_probe(server, body.values, stored))


@router.post("/virustotal/register", response_model=VirustotalRegisterResponse)
async def register_virustotal_agent(
    request: Request,
    user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> VirustotalRegisterResponse | JSONResponse:
    """Obtain a VirusTotal agent token, store it encrypted and enable the server.

    The one call in this module that reaches a third party in order to *write*
    settings. It takes no body: everything the registration says about this
    deployment is a constant of the build, and the only variable part -- the
    token -- is what comes back. A failure against VirusTotal is reported as a
    502 with their own sentence in it, because the fix is on their side or in
    the operator's network, not in the stored settings.
    """
    try:
        facts = await register_agent()
    except RegistrationError as exc:
        logger.warning("VirusTotal registration failed: %s", log_safe(str(exc)))
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={"errors": {"virustotal": str(exc)}},
        )

    service = SettingsService(db)
    stored = await service.load_overrides()
    current = stored.get(SERVER_MAP_KEY)
    servers = server_map_with_token(
        current if isinstance(current, dict) else {}, facts["agent_token"]
    )
    try:
        await service.save({SERVER_MAP_KEY: servers}, user_id=user.id, ip=_client_ip(request))
    except SettingsValidationError as exc:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"errors": exc.errors}
        )
    await audit_record(
        "settings.virustotal.register",
        resource_type="settings",
        user_id=user.id,
        details={
            "agent_id": log_safe(facts["agent_id"]),
            "public_handle": log_safe(facts["public_handle"]),
        },
        ip=_client_ip(request),
    )
    runtime_config.invalidate()
    core_settings_cache.invalidate()
    logger.info("VirusTotal agent registered: %s", log_safe(facts["public_handle"]))
    entry = servers[VIRUSTOTAL_SERVER_KEY]
    return VirustotalRegisterResponse(
        **masked_state(entry if isinstance(entry, dict) else {}, facts)
    )


async def _write_down_what_was_reached(
    db: AsyncSession, pairs: list[tuple[str, str, str]], *, ok: bool, detail: str
) -> None:
    """File this probe's answer under every model it was taken against.

    Never raises. A probe is an operator pressing a button and reading a
    sentence; a store that could not be written is a reason to log, not a
    reason to give them an error instead of their answer.
    """
    from app.services.model_probes import record_probe

    for endpoint, model, provider in pairs:
        try:
            await record_probe(
                db, endpoint=endpoint, model=model, provider=provider, ok=ok, detail=detail
            )
        except Exception as exc:  # noqa: BLE001 — the answer still reaches the operator
            logger.warning("probe result not stored: %s", type(exc).__name__)
            return


@router.post("/test/agent", response_model=ProbeResponse)
async def test_agent(
    body: ProbeRequest,
    name: str = Query(..., description="key in agents.definitions"),
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProbeResponse:
    """Resolve one agent definition and report what it would get.

    Takes staged values so an operator can resolve a definition they have not
    saved yet — the same contract every other probe has. No LLM call is made:
    this reports the model that *would* be used, never a completion.

    What it reached is written down against the endpoint and the model it
    named, so submitting a job can refuse a team whose agents name a model
    nothing has ever answered for.
    """
    stored = await SettingsService(db).load_overrides()
    response = await _probe_response(run_agent_probe(name, body.values, stored))
    named = (response.details or {}).get("llm") or {}
    endpoint, model = str(named.get("endpoint") or ""), str(named.get("model") or "")
    if endpoint and model:
        await _write_down_what_was_reached(
            db,
            [(endpoint, model, str(named.get("provider") or ""))],
            ok=response.ok,
            detail=response.detail,
        )
    return response


@router.post("/test/{probe}", response_model=ProbeResponse)
async def test_probe(
    probe: str,
    body: ProbeRequest,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProbeResponse:
    if probe not in PROBES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown probe: {probe}")
    stored = await SettingsService(db).load_overrides()
    response = await _probe_response(run_probe(probe, body.values, stored))
    if probe == "llm":
        try:
            reached = models_the_llm_probe_reached(candidate_settings(body.values, stored))
        except Exception as exc:  # noqa: BLE001 — the answer still reaches the operator
            logger.warning("probed models not derived: %s", type(exc).__name__)
            reached = []
        await _write_down_what_was_reached(db, reached, ok=response.ok, detail=response.detail)
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


@router.post("/sandbox-rest/preview", response_model=MappingPreviewResponse)
async def preview_sandbox_mapping(
    request: Request,
    _: User = Depends(require_admin),
) -> MappingPreviewResponse:
    """Run a mapping against a pasted response. Nothing is stored or submitted."""
    payload = await _capped_body(request)
    body = MappingPreviewRequest.model_validate(payload)
    return MappingPreviewResponse(**preview_mapping(body.sample, body.mapping))
