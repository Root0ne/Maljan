"""Revoking an account's credentials at once.

Two moves, both one statement in the caller's transaction:

* ``revoke_sessions`` moves ``users.token_generation`` on, which retires every
  access and refresh token minted under an earlier generation (see
  ``app.auth.jwt.is_current_generation``). Nothing is enumerated: one row is
  updated however many sessions the account has.
* ``revoke_api_keys`` deactivates every active API key of the account and
  answers how many it deactivated.

A password change does both; a replayed refresh token does the first.
"""

from __future__ import annotations

import uuid

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import APIKey
from app.models.user import User


async def revoke_sessions(db: AsyncSession, user_id: uuid.UUID) -> None:
    """Retire every access and refresh token of the account."""
    await db.execute(
        update(User)
        .where(User.id == user_id)
        .values(token_generation=User.token_generation + 1)
        .execution_options(synchronize_session=False)
    )


async def revoke_api_keys(db: AsyncSession, user_id: uuid.UUID) -> int:
    """Deactivate every active API key of the account; the number deactivated."""
    result = await db.execute(
        update(APIKey)
        .where(APIKey.user_id == user_id, APIKey.is_active.is_(True))
        .values(is_active=False)
        .returning(APIKey.id)
        .execution_options(synchronize_session=False)
    )
    return len(result.scalars().all())
