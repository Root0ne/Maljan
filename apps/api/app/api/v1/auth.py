"""Authentication endpoints — register, login, refresh, me."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import create_access_token, create_refresh_token, decode_token
from app.auth.password import hash_password, verify_password
from app.database import get_db
from app.deps import get_current_user
from app.logging_config import get_logger
from app.models.user import User
from app.schemas.auth import (
    RefreshTokenRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)

logger = get_logger("api.auth")

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(body: UserRegisterRequest, db: AsyncSession = Depends(get_db)) -> User:
    """Register a new user account."""
    logger.info(f"Registration attempt: email={body.email}")

    # Check for existing email
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        logger.warning(f"Registration failed: email already exists - {body.email}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        full_name=body.full_name,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    logger.info(
        f"User registered: id={user.id} email={user.email}",
        extra={"user_id": str(user.id)},
    )
    return user


@router.post("/login", response_model=TokenResponse)
async def login(body: UserLoginRequest, db: AsyncSession = Depends(get_db)) -> dict:
    """Authenticate and receive JWT tokens."""
    logger.info(f"Login attempt: email={body.email}")

    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.hashed_password):
        logger.warning(
            f"Login failed: invalid credentials for {body.email}",
            extra={"component": "auth"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        logger.warning(
            f"Login blocked: deactivated account {body.email}",
            extra={"user_id": str(user.id), "component": "auth"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    token_data = {"sub": str(user.id)}
    logger.info(
        f"Login successful: user={user.id}",
        extra={"user_id": str(user.id)},
    )
    return {
        "access_token": create_access_token(token_data),
        "refresh_token": create_refresh_token(token_data),
        "token_type": "bearer",
    }


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshTokenRequest, db: AsyncSession = Depends(get_db)) -> dict:
    """Exchange a refresh token for a new access + refresh token pair."""
    payload = decode_token(body.refresh_token)
    if payload is None or payload.get("type") != "refresh":
        logger.warning("Token refresh failed: invalid or expired refresh token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        logger.warning(
            f"Token refresh failed: user not found or deactivated - {user_id}",
            extra={"user_id": user_id},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or deactivated",
        )

    token_data = {"sub": str(user.id)}
    logger.info(f"Token refreshed: user={user.id}", extra={"user_id": str(user.id)})
    return {
        "access_token": create_access_token(token_data),
        "refresh_token": create_refresh_token(token_data),
        "token_type": "bearer",
    }


@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)) -> User:
    """Get the currently authenticated user's profile."""
    return user
