"""Startup bootstrap validation for the API and the worker.

Both processes must fail fast — before serving a request or taking a job —
when the process environment is missing something the deployment cannot run
without. ``require_bootstrap`` is the single entry point: it logs any
warnings and raises :class:`BootstrapProblem` naming every problem at once so
an operator does not have to restart the process repeatedly to find the next
missing variable.

This module owns *every* boot refusal. ``APISettings`` construction never
raises: a refusal raised there is a pydantic traceback from whichever import
built the singleton first, and it stops at the first offending field, which
is the opposite of the contract above.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from cryptography.fernet import Fernet
from pydantic import SecretStr

from app.config import (
    _PLACEHOLDER_JWT_SECRETS,
    _PLACEHOLDER_MINIO_KEYS,
    TEST_JWT_SECRET,
    APISettings,
    _is_test_env,
)
from app.logging_config import get_logger

logger = get_logger("bootstrap")


class BootstrapProblem(ValueError):
    """Raised when the process environment fails bootstrap validation."""


@dataclass
class BootstrapReport:
    """Result of validating an :class:`APISettings` instance at startup."""

    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _secret_value(value: SecretStr | str) -> str:
    return value.get_secret_value() if isinstance(value, SecretStr) else str(value)


def validate_bootstrap(s: APISettings) -> BootstrapReport:
    """Return the bootstrap problems and warnings for ``s``.

    Problems are hard failures (the process must not start). Warnings are
    reported but never block startup.
    """
    problems: list[str] = []
    warnings: list[str] = []

    _REQUIRED_STRING_FIELDS = (
        ("database_url", "DATABASE_URL"),
        ("redis_url", "REDIS_URL"),
        ("minio_endpoint", "MINIO_ENDPOINT"),
        ("minio_access_key", "MINIO_ACCESS_KEY"),
    )
    for attr, env_name in _REQUIRED_STRING_FIELDS:
        if not str(getattr(s, attr) or "").strip():
            problems.append(f"{env_name} is not set")

    minio_secret = _secret_value(s.minio_secret_key).strip()
    if not minio_secret:
        problems.append("MINIO_SECRET_KEY is not set")
    elif not s.debug and minio_secret in _PLACEHOLDER_MINIO_KEYS:
        problems.append("MINIO_SECRET_KEY is using the default placeholder")

    # ``auth_disabled`` makes ``get_current_user`` return the seeded dev admin
    # for every request without inspecting the token at all (deps.py), so an
    # environment carried from a dev box to a real deployment would serve an
    # unauthenticated admin API. It is a bootstrap refusal like any other.
    if s.auth_disabled and not s.debug:
        problems.append(
            "AUTH_DISABLED is set with DEBUG=False; the auth bypass serves every "
            "request as the dev admin user and is for local development only"
        )

    # Read from the environment, never from ``s.jwt_secret_key``: under pytest
    # that field carries the in-repo test secret, which is 43 characters of
    # published string and would otherwise pass every check below.
    jwt_secret = os.environ.get("JWT_SECRET_KEY", "").strip()
    if not jwt_secret and _is_test_env():
        jwt_secret = TEST_JWT_SECRET
    if not s.debug:
        if not jwt_secret:
            problems.append("JWT_SECRET_KEY is not set")
        elif jwt_secret in _PLACEHOLDER_JWT_SECRETS:
            problems.append("JWT_SECRET_KEY is a known placeholder value")
        elif len(jwt_secret) < 32:
            problems.append("JWT_SECRET_KEY is shorter than 32 characters")

    encryption_key = _secret_value(s.settings_encryption_key).strip()
    if not encryption_key:
        problems.append("SETTINGS_ENCRYPTION_KEY is not set")
    else:
        try:
            Fernet(encryption_key.encode())
        except (ValueError, TypeError):
            problems.append("SETTINGS_ENCRYPTION_KEY is not a valid Fernet key")

    if not s.debug and not s.auth_disabled and not s.cookie_secure:
        warnings.append(
            "COOKIE_SECURE is false outside debug mode; the refresh cookie will "
            "cross the wire unencrypted unless a trusted proxy terminates TLS."
        )

    return BootstrapReport(problems=problems, warnings=warnings)


def require_bootstrap(s: APISettings) -> None:
    """Validate ``s``, log any warnings, and raise on any problem.

    Raises:
        BootstrapProblem: with every problem sentence joined into one message,
            e.g. ``"bootstrap: DATABASE_URL is not set; SETTINGS_ENCRYPTION_KEY
            is not a valid Fernet key"``.
    """
    report = validate_bootstrap(s)
    for warning in report.warnings:
        logger.warning(warning)
    if report.problems:
        raise BootstrapProblem("bootstrap: " + "; ".join(report.problems))
