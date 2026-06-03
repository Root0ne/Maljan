"""Audit and API key management endpoints."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import get_current_user, require_admin
from app.logging_config import get_logger
from app.models.audit import APIKey, AuditLog
from app.models.user import User
from app.schemas.audit import (
    APIKeyCreateRequest,
    APIKeyCreateResponse,
    APIKeyListResponse,
    AuditLogListResponse,
    AuditLogResponse,
)

logger = get_logger("api.audit")

router = APIRouter(prefix="/audit", tags=["Audit & API Keys"])


# ---------------------------------------------------------------------------
# Audit Log endpoints (admin only)
# ---------------------------------------------------------------------------


@router.get("/logs", response_model=AuditLogListResponse)
async def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    action: str | None = Query(None, description="Filter by action type"),
    user_id: uuid.UUID | None = Query(None, description="Filter by user ID"),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List audit log entries with pagination (admin only)."""
    query = select(AuditLog).order_by(AuditLog.created_at.desc())

    if action:
        query = query.where(AuditLog.action.ilike(f"%{action}%"))
    if user_id:
        query = query.where(AuditLog.user_id == user_id)

    count_query = select(func.count()).select_from(AuditLog)
    if action:
        count_query = count_query.where(AuditLog.action.ilike(f"%{action}%"))
    if user_id:
        count_query = count_query.where(AuditLog.user_id == user_id)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    logs = result.scalars().all()

    logger.debug(
        f"Admin {admin.id} listed audit logs: page={page} count={len(logs)} total={total}",
        extra={"user_id": str(admin.id)},
    )

    return {
        "items": logs,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/logs/{log_id}", response_model=AuditLogResponse)
async def get_audit_log(
    log_id: uuid.UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> AuditLog:
    """Get a single audit log entry (admin only)."""
    result = await db.execute(select(AuditLog).where(AuditLog.id == log_id))
    log_entry = result.scalar_one_or_none()
    if not log_entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log entry not found",
        )
    return log_entry


# ---------------------------------------------------------------------------
# API Key endpoints
# ---------------------------------------------------------------------------


def _generate_api_key() -> tuple[str, str, str]:
    """Generate a raw API key, its hash, and a display prefix.

    Returns:
        (raw_key, key_hash, key_prefix)
    """
    raw = "mk_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    prefix = raw[:8]
    return raw, key_hash, prefix


@router.get("/api-keys", response_model=APIKeyListResponse)
async def list_api_keys(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List API keys for the current user."""
    query = (
        select(APIKey)
        .where(APIKey.user_id == user.id)
        .order_by(APIKey.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(query)
    keys = result.scalars().all()

    count_result = await db.execute(
        select(func.count()).select_from(APIKey).where(APIKey.user_id == user.id)
    )
    total = count_result.scalar() or 0

    return {
        "items": keys,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/api-keys", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    req: APIKeyCreateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIKey:
    """Create a new API key for the current user.

    The raw key is returned **only once** at creation time. Store it securely.
    """
    raw_key, key_hash, prefix = _generate_api_key()

    expires_at = None
    if req.expires_in_days:
        expires_at = datetime.now(UTC) + timedelta(days=req.expires_in_days)

    api_key = APIKey(
        user_id=user.id,
        key_hash=key_hash,
        key_prefix=prefix,
        name=req.name,
        expires_at=expires_at,
        is_active=True,
    )
    db.add(api_key)
    await db.flush()
    await db.refresh(api_key)

    logger.info(
        f"API key created: id={api_key.id} prefix={prefix}",
        extra={"user_id": str(user.id), "api_key_id": str(api_key.id)},
    )

    # Attach the raw key to the response object (not persisted)
    api_key.raw_key = raw_key  # type: ignore[attr-defined]
    return api_key  # type: ignore[return-value]


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Revoke (deactivate) an API key."""
    result = await db.execute(select(APIKey).where(APIKey.id == key_id, APIKey.user_id == user.id))
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    api_key.is_active = False
    await db.flush()

    logger.info(
        f"API key revoked: id={key_id}",
        extra={"user_id": str(user.id), "api_key_id": str(key_id)},
    )
