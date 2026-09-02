"""Runtime settings: the catalog, the effective values, and the overrides."""

from __future__ import annotations

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
    PatchRequest,
    PatchResponse,
    ProbeRequest,
    ProbeResponse,
    ResetResponse,
    SchemaResponse,
    ValueDTO,
    ValuesResponse,
)
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
    if key not in catalog_index():
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown setting: {key}")
    removed = await SettingsService(db).reset([key], user_id=user.id, ip=_client_ip(request))
    runtime_config.invalidate()
    return ResetResponse(reset=removed)


@router.get("/export", response_class=PlainTextResponse)
async def export_overrides(
    _: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
) -> str:
    index = catalog_index()
    lines = ["# Maljan runtime overrides (UI). Secrets are not exported."]
    for key, info in (await SettingsService(db).values()).items():
        if info.source != "ui":
            continue
        entry = index[key]
        env_name = entry.path.upper().replace(".", "__")
        value = "***" if entry.secret else info.value
        lines.append(f"{env_name}={value}")
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
