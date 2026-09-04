"""Runtime settings: the catalog, the effective values, and the overrides."""

from __future__ import annotations

import json
from contextlib import suppress
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse
from maljan.core import settings_secrets as box
from maljan.core.settings_annotations import GROUP_ORDER
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import require_admin
from app.models.user import User
from app.runtime_config import runtime_config
from app.schemas.settings import (
    CatalogEntryDTO,
    GroupDTO,
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
)
from app.services.mapping_preview import PREVIEW_MAX_BYTES, preview_mapping
from app.services.settings_catalog_api import catalog_index, full_catalog
from app.services.settings_probes import PROBES, run_probe
from app.services.settings_service import SettingsService, SettingsValidationError

router = APIRouter(prefix="/settings", tags=["Settings"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/schema", response_model=SchemaResponse)
async def get_schema(_: User = Depends(require_admin)) -> SchemaResponse:
    available = box.is_available()
    by_group: dict[str, list[CatalogEntryDTO]] = {}
    for e in full_catalog():
        d = e.to_dict()
        if e.secret and e.editable and not available:
            d["editable"] = False
            d["reason"] = "SETTINGS_ENCRYPTION_KEY is not set; secrets stay in .env"
        by_group.setdefault(e.group, []).append(CatalogEntryDTO(**d))
    groups = [
        GroupDTO(key=g, title=t, entries=by_group[g]) for g, t in GROUP_ORDER if g in by_group
    ]
    return SchemaResponse(groups=groups, secrets_available=available)


@router.get("", response_model=ValuesResponse)
async def get_values(
    _: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
) -> ValuesResponse:
    vals = await SettingsService(db).values()
    return ValuesResponse(values={k: ValueDTO(**vars(v)) for k, v in vals.items()})


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
    return PatchResponse(applied=res.applied, applies=res.applies)


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
    return ResetResponse(reset=removed)


def _env_literal(secret: bool, value: object) -> str:
    """One ``.env`` right-hand side pydantic-settings reads back unchanged.

    Lists and dicts must be JSON (a Python repr with single quotes is
    rejected); strings with whitespace or ``#`` need quoting.
    """
    if secret:
        return "***"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, dict)):
        # Quoted twice on purpose: dotenv strips the outer quotes (and would
        # otherwise cut the line at a " #" inside a list element), then
        # pydantic-settings JSON-parses the inner text.
        return json.dumps(json.dumps(value, separators=(",", ":")))
    text = str(value)
    if text == "" or any(ch in text for ch in " \t#\"'"):
        return json.dumps(text)
    return text


@router.get("/export", response_class=PlainTextResponse)
async def export_overrides(
    _: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
) -> str:
    index = catalog_index()
    lines = ["# Maljan runtime overrides (UI). Secrets are exported masked as ***."]
    for key, info in (await SettingsService(db).values()).items():
        if info.source != "ui":
            continue
        entry = index[key]
        env_name = entry.path.upper().replace(".", "__")
        lines.append(f"{env_name}={_env_literal(entry.secret, info.value)}")
    return "\n".join(lines) + "\n"


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
    result = await run_probe(probe, body.values, stored)
    return ProbeResponse(**vars(result))


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
                    status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
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
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"the pasted response exceeds {PREVIEW_MAX_BYTES} bytes",
        )
    try:
        parsed: dict[str, Any] = json.loads(b"".join(chunks) or b"{}")
        return parsed
    except json.JSONDecodeError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"invalid JSON body: {exc}") from exc


@router.post("/sandbox-rest/preview", response_model=MappingPreviewResponse)
async def preview_sandbox_mapping(
    request: Request,
    _: User = Depends(require_admin),
) -> MappingPreviewResponse:
    """Run a mapping against a pasted response. Nothing is stored or submitted."""
    payload = await _capped_body(request)
    body = MappingPreviewRequest.model_validate(payload)
    return MappingPreviewResponse(**preview_mapping(body.sample, body.mapping))
