"""Pydantic schemas for authentication requests and responses."""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, model_validator


class UserRegisterRequest(BaseModel):
    """Request body for user registration."""

    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=255)


class UserLoginRequest(BaseModel):
    """Request body for user login."""

    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """Response with the access token. The refresh token travels as an
    HttpOnly cookie, never in the response body."""

    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    """Public user profile response."""

    id: uuid.UUID
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserUpdateRequest(BaseModel):
    """Request body for the caller updating their own profile.

    A new ``password`` needs the ``current_password`` beside it: an access
    token alone, leaked or left open, does not change the credential.
    """

    full_name: str | None = None
    password: str | None = Field(None, min_length=8, max_length=128)
    current_password: str | None = Field(None, max_length=128)

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def _password_needs_the_current_one(self) -> "UserUpdateRequest":
        if self.password is not None and not self.current_password:
            raise ValueError("current_password is required to change the password")
        return self


class UserUpdateResponse(UserResponse):
    """The updated profile. After a password change every earlier session of
    the account is revoked, and ``access_token`` carries this session's
    replacement (its refresh token is set as the cookie); otherwise it is
    ``None``."""

    access_token: str | None = None
