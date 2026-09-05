"""DTOs for the runtime-settings routes.

Kept dumb by design: no logic lives here, just the wire shapes that
``app.api.v1.settings`` maps ``SettingsService`` and catalog objects onto.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CatalogEntryDTO(BaseModel):
    key: str
    namespace: str
    path: str
    type: str
    default: Any = None
    nullable: bool
    choices: list[str] | None = None
    minimum: float | None = None
    maximum: float | None = None
    secret: bool
    group: str
    title: str
    description: str
    applies: str
    editable: bool
    reason: str | None = None
    probe: str | None = None
    applies_when: dict[str, list[str]] | None = None
    order: int = 0
    choices_from: str | None = None
    editor: str | None = None


class GroupDTO(BaseModel):
    key: str
    title: str
    entries: list[CatalogEntryDTO]


class SchemaResponse(BaseModel):
    groups: list[GroupDTO]
    secrets_available: bool


class ValueDTO(BaseModel):
    value: Any = None
    is_set: bool | None = None
    hint: str | None = None
    source: str
    updated_at: datetime | None = None
    updated_by: uuid.UUID | None = None


class ValuesResponse(BaseModel):
    values: dict[str, ValueDTO]


class PatchRequest(BaseModel):
    changes: dict[str, Any] = Field(min_length=1, max_length=500)


class PatchResponse(BaseModel):
    applied: list[str]
    applies: dict[str, int]


class ResetResponse(BaseModel):
    reset: list[str]


class ProbeRequest(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)


class ProbeResponse(BaseModel):
    ok: bool
    latency_ms: int
    detail: str
    models: list[str] | None = None
    # the server's whole manifest, so the editor can render it as tick boxes
    tools: list[str] | None = None


class MappingPreviewRequest(BaseModel):
    sample: dict[str, Any]
    mapping: dict[str, Any]


class ChannelPreview(BaseModel):
    matched: int
    kept: int
    dropped: int
    truncated: bool = False
    sample_rows: list[Any]
    error: str | None = None


class MappingPreviewResponse(BaseModel):
    target_sha256: str
    channels: dict[str, ChannelPreview]
