"""Encryption for secret settings stored in the database.

A secret set from the UI is written as ``enc:v1:<fernet token>`` under the key
in ``SETTINGS_ENCRYPTION_KEY``. The API and the worker share ``.env``, so both
can open it. Without the key, callers get ``SecretsUnavailable`` and the UI
shows secret fields read-only.
"""

from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken

PREFIX = "enc:v1:"
ENV_VAR = "SETTINGS_ENCRYPTION_KEY"


class SecretsUnavailable(RuntimeError):
    """No usable encryption key, or a token this key cannot open."""


def _fernet() -> Fernet:
    raw = os.environ.get(ENV_VAR, "").strip()
    if not raw:
        raise SecretsUnavailable(f"{ENV_VAR} is not set")
    try:
        return Fernet(raw.encode())
    except (ValueError, TypeError) as exc:
        raise SecretsUnavailable(f"{ENV_VAR} is not a valid Fernet key") from exc


def is_available() -> bool:
    try:
        _fernet()
    except SecretsUnavailable:
        return False
    return True


def encrypt(plain: str) -> str:
    return PREFIX + _fernet().encrypt(plain.encode("utf-8")).decode("ascii")


def decrypt(stored: str) -> str:
    if not is_encrypted(stored):
        raise SecretsUnavailable("value is not an encrypted secret")
    try:
        return _fernet().decrypt(stored[len(PREFIX) :].encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise SecretsUnavailable("stored secret cannot be opened with the current key") from exc


def is_encrypted(value: object) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def hint(plain: str) -> str:
    """Last four characters, or nothing for a value too short to hint safely."""
    return plain[-4:] if len(plain) >= 8 else ""
