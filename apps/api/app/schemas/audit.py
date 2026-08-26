"""Pydantic schemas for audit and API key endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# AuditLog schemas
# ---------------------------------------------------------------------------


class AuditLogResponse(BaseModel):
    """Single audit log entry response."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    # Nullable on purpose: security events that have no authenticated principal
    # still MUST be recorded — a failed login for an unknown e-mail, a lockout,
    # or an invalid/replayed refresh token all write ``user_id=NULL``
    # (``AuditLog.user_id`` is nullable in the model). Declaring this required
    # made the endpoint raise ResponseValidationError -> 500 as soon as such a
    # row appeared. Audit 2026-07-26 (K1).
    user_id: uuid.UUID | None
    action: str
    resource_type: str | None
    # ``AuditLog.resource_id`` is a String(255), not a UUID column (migration
    # 20250517000000 widened it deliberately). Typing it as UUID here would 500
    # the endpoint the moment a non-UUID resource id is written.
    resource_id: str | None
    details: dict[str, Any] | None
    ip_address: str | None
    created_at: datetime

    @field_validator("ip_address", mode="before")
    @classmethod
    def _coerce_ip_to_str(cls, v: Any) -> str | None:
        # The ORM maps this column to Postgres INET, so SQLAlchemy/asyncpg
        # hydrates it as an ``ipaddress.IPv4Address``/``IPv6Address`` object,
        # not a ``str``. Pydantic v2 rejects that under ``str`` and raises a
        # ResponseValidationError (500). Coerce to text before validation.
        return None if v is None else str(v)


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
