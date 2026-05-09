"""Pydantic schemas for audit and API key endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# AuditLog schemas
# ---------------------------------------------------------------------------


class AuditLogResponse(BaseModel):
    """Single audit log entry response."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    action: str
    resource_type: str | None
    resource_id: uuid.UUID | None
    details: dict[str, Any] | None
    ip_address: str | None
    created_at: datetime


class AuditLogListResponse(BaseModel):
    """Paginated audit log list response."""

    items: list[AuditLogResponse]
    total: int
    page: int
    page_size: int


# ---------------------------------------------------------------------------
# APIKey schemas
# ---------------------------------------------------------------------------


class APIKeyCreateRequest(BaseModel):
    """Request body for creating a new API key."""

    name: str = Field(
        ..., min_length=1, max_length=255, description="Human-readable name for the key"
    )
    expires_in_days: int | None = Field(
        None, ge=1, le=365, description="Optional expiration in days"
    )


class APIKeyResponse(BaseModel):
    """API key metadata (never includes the full key after creation)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    key_prefix: str
    name: str
    expires_at: datetime | None
    last_used_at: datetime | None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class APIKeyCreateResponse(APIKeyResponse):
    """Response when creating a new API key — includes the raw key once."""

    raw_key: str = Field(..., description="The raw API key (shown only once at creation)")


class APIKeyListResponse(BaseModel):
    """Paginated API key list response."""

    items: list[APIKeyResponse]
    total: int
    page: int
    page_size: int
