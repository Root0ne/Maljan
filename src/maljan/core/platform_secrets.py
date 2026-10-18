"""The platform's own secrets: the bootstrap variables that open its stores.

The API and the worker are started with a small environment, the bootstrap
contract (``app.config.APISettings``; ``bootstrap.env.example`` lists all of
it). Part of it opens the platform's own stores: the database and Redis URLs
carry their passwords, the object store's keys are its root user, the settings
key decrypts every value stored encrypted, and the JWT signing keys sign a
session for any user. Those variables are marked here, on
``PlatformSecrets``, which ``APISettings`` inherits, declaring each again with
its development default; the names below are read from the marks, never kept
beside them.

No tool server's environment may carry one. A server block that names one in
``env_allow`` or as a key of ``env`` is refused where the block is validated
(``core.config.MCPServerConfig``), which is where a save, a stored row loaded
for a job and a connection test all read it; ``agents.subprocess_env`` drops
one at every spawn whatever the block says, for a block that reached a spawn
some other way.

A model provider's key an operator saves is an application setting, stored
encrypted in the settings store, and is not one of these: an operator may hand
it to a server that needs it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Annotated

from pydantic import BaseModel, SecretStr


@dataclass(frozen=True)
class PlatformSecret:
    """What a field of ``PlatformSecrets`` opens, said where a block naming it is refused.

    ``written_as`` names the variables the shipped deployment writes the same
    value under before it composes the field's own variable
    (``docker/docker-compose.yml`` builds ``DATABASE_URL`` around
    ``POSTGRES_PASSWORD``): a server handed one of those holds the same key to
    the same store, so each is refused as the field is.
    """

    opens: str
    written_as: tuple[str, ...] = ()


class PlatformSecrets(BaseModel):
    """The bootstrap variables whose values open the platform's own stores.

    No field has a default here: ``APISettings`` declares each again with its
    development default, so the bootstrap contract reads as it always did, and
    reads each from the process environment under the field's own name, case
    ignored. A field added here and not there would be one the bootstrap model
    requires, so building it would fail where it never refuses otherwise; a
    test holds every bootstrap variable shaped like a store's key to a field
    here, and every field here to a default there.
    """

    database_url: Annotated[
        str, PlatformSecret("opens the platform's database", ("POSTGRES_PASSWORD",))
    ]
    redis_url: Annotated[str, PlatformSecret("opens the platform's job queue", ("REDIS_PASSWORD",))]
    minio_access_key: Annotated[
        str, PlatformSecret("names the platform's object-store user", ("MINIO_ROOT_USER",))
    ]
    minio_secret_key: Annotated[
        SecretStr,
        PlatformSecret("opens the platform's object store", ("MINIO_ROOT_PASSWORD",)),
    ]
    settings_encryption_key: Annotated[
        SecretStr, PlatformSecret("decrypts every value the settings store keeps encrypted")
    ]
    jwt_secret_key: Annotated[
        SecretStr, PlatformSecret("signs a session for any user, an admin's included")
    ]
    jwt_previous_secret_key: Annotated[
        SecretStr, PlatformSecret("signs a session for any user until its rotation ends")
    ]


# Said of a field that carries no mark of its own: it is refused all the same,
# and a test holds every field to a mark that says what it opens.
_UNMARKED = PlatformSecret("opens one of the platform's own stores")


def _marks() -> dict[str, PlatformSecret]:
    """Every name a field of ``PlatformSecrets`` is read or written under, upper case."""
    marks: dict[str, PlatformSecret] = {}
    for field, info in PlatformSecrets.model_fields.items():
        mark = next((m for m in info.metadata if isinstance(m, PlatformSecret)), _UNMARKED)
        for name in (field, *mark.written_as):
            marks[name.upper()] = mark
    return marks


_MARKS = _marks()

# The names no tool server's environment may carry, upper case: each field's
# own name, which ``APISettings`` reads from the environment, and the names the
# shipped deployment writes the same values under.
PLATFORM_SECRET_NAMES: frozenset[str] = frozenset(_MARKS)


def is_platform_secret(name: str) -> bool:
    """Whether ``name`` is one of ``PLATFORM_SECRET_NAMES``, case ignored.

    Case is ignored because the bootstrap model reads the environment that way
    (``database_url`` is ``DATABASE_URL`` to it), and so does a Windows
    environment, where a lowercase name copies the uppercase variable's value.
    """
    return str(name).upper() in _MARKS


def platform_secrets_refusal(names: Iterable[str], field: str) -> str:
    """Why ``field`` may not name these variables, or ``""`` when it names none of them.

    It names each variable and what it opens, and never a value: a block's
    ``env`` holds the value beside the name, and this sentence travels into the
    API's answer, the console, a connection test and the worker's log.
    """
    said: list[str] = []
    for name in names:
        mark = _MARKS.get(str(name).upper())
        if mark is None:
            continue
        canonical = str(name).upper()
        label = str(name) if str(name) == canonical else f"{name}, read as {canonical},"
        said.append(f"{label} {mark.opens}")
    if not said:
        return ""
    them = "it" if len(said) == 1 else "them"
    return (
        "; ".join(said) + ". No tool server's environment may carry one of the platform's "
        f"own bootstrap variables; remove {them} from {field}."
    )
