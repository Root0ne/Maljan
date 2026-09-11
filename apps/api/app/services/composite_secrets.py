"""Keep every composite-leaf credential in its own encrypted row.

Two catalog leaves are composite: the frontier arm map
(``core.llm.frontier.arms``) and the MCP server map (``core.mcp.servers``).
Each is one plain JSONB ``runtime_settings`` row, and each entry inside it can
carry a credential -- an arm's ``api_key``, a server's ``auth_token``.

The invariant these repairs enforce: a composite row never holds a secret.
Every credential lives in its own ``runtime_settings`` row, encrypted with the
Fernet box ``SettingsService`` uses, under the per-name key
``arm_key_key``/``server_token_key``. A store written before that rule, or by
anything that bypassed the splitters, can still have a credential sitting in
the composite in clear -- or the ten-asterisk mask a JSON dump leaves in a
credential's place. Both repairs run at API start, are idempotent, and are a
no-op on a store that already satisfies the invariant.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from maljan.core import settings_secrets as box
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_config import get_logger
from app.models import RuntimeSetting
from app.services.frontier_arms import ARMS_KEY, arm_key_key
from app.services.server_map import SERVER_MAP_KEY, TOKEN_MASK, server_token_key

logger = get_logger("composite_secrets")


async def _repair_composite_secrets(
    db: AsyncSession,
    *,
    composite_key: str,
    field: str,
    row_key_of: Callable[[str], str],
    what: str,
) -> int:
    """Move every clear-text credential out of one composite row, once.

    A composite catalog leaf is one plain JSONB row, and the credential nested
    inside it -- a frontier arm's ``api_key``, an MCP server's ``auth_token``
    -- must never be stored there: in the composite it would be
    ``is_secret=false``, never through the Fernet box, sitting in the database
    beside values the UI echoes back.

    The rule this function is built around: the field is removed from the
    composite **only** when an encrypted row for that name exists -- one
    written here, in the same transaction and flushed before anything is
    stripped, or one the operator already saved. What cannot be recovered is
    left exactly where it is and named in a warning, because the alternative is
    deleting the only record that the name had a credential at all.

    This reads the *raw* stored JSON deliberately. It must not go through the
    composite's splitter: those serve the UI, where the mask means "leave the
    stored row alone" because there always is one. Here the mask is what a JSON
    dump wrote in place of a credential (``model_dump(mode="json")`` renders a
    ``SecretStr`` as ten asterisks), so "leave the stored row alone" would
    silently mean "delete the field".

    Idempotent: a composite with nothing left to move is not rewritten and not
    committed. Only counts and names are logged, never a credential.
    """
    row = (
        await db.execute(select(RuntimeSetting).where(RuntimeSetting.key == composite_key))
    ).scalar_one_or_none()
    if row is None or not isinstance(row.value, dict):
        return 0
    stored: dict[str, Any] = row.value
    present = {
        name: entry[field]
        for name, entry in stored.items()
        if isinstance(entry, dict) and field in entry
    }
    if not present:
        return 0

    existing_keys = {r[0] for r in (await db.execute(select(RuntimeSetting.key))).all()}
    to_store = {
        name: value
        for name, value in present.items()
        if isinstance(value, str)
        and value
        and value != TOKEN_MASK
        and row_key_of(name) not in existing_keys
    }
    # A mask with no row behind it names a credential this deployment no longer
    # has: it was never the credential, only what the dump left in its place.
    unrecoverable = sorted(
        name
        for name, value in present.items()
        if value == TOKEN_MASK and row_key_of(name) not in existing_keys
    )
    if unrecoverable:
        logger.warning(
            "%s for %s are masked in the stored configuration and cannot be recovered; "
            "set them again from Settings -> Configuration. The masked entries are left "
            "untouched, so nothing treats the mask as a freshly stored credential.",
            what,
            ", ".join(unrecoverable),
        )
    if to_store and not box.is_available():
        # Rewriting the composite now would destroy the only copy of a value
        # that cannot yet be encrypted; leave everything as it is and say so.
        logger.warning(
            "%s are stored in clear but SETTINGS_ENCRYPTION_KEY is unusable; the repair "
            "will run again on the next start.",
            what,
        )
        return 0

    for name, value in to_store.items():
        db.add(RuntimeSetting(key=row_key_of(name), value=box.encrypt(value), is_secret=True))
    if to_store:
        # Every row reaches the transaction before a single field leaves the
        # composite: a failing insert takes the strip down with it.
        await db.flush()

    keep = set(unrecoverable)
    cleaned = {
        name: (
            {k: v for k, v in entry.items() if k != field}
            if isinstance(entry, dict) and name in present and name not in keep
            else entry
        )
        for name, entry in stored.items()
    }
    if cleaned == stored:
        return 0
    row.value = cleaned
    await db.commit()
    logger.info("%s moved into encrypted rows: %d", what, len(to_store))
    return len(to_store)


async def repair_frontier_arm_keys(db: AsyncSession) -> int:
    """Move any clear-text frontier arm API key into its own encrypted row."""
    return await _repair_composite_secrets(
        db,
        composite_key=ARMS_KEY,
        field="api_key",
        row_key_of=arm_key_key,
        what="Frontier arm API keys",
    )


async def repair_server_auth_tokens(db: AsyncSession) -> int:
    """Move any clear-text MCP server auth token into its own encrypted row.

    The twin of the arms repair, for the only other composite catalog leaf with
    a nested ``SecretStr``. It matters more than the arms one:
    ``merge_server_secrets`` leaves a token the composite itself carries in
    place, so a masked ``auth_token`` reaches a real job as the literal bearer
    token ``**********`` -- which is why the masked entries are warned about by
    name rather than passed off as configured.
    """
    return await _repair_composite_secrets(
        db,
        composite_key=SERVER_MAP_KEY,
        field="auth_token",
        row_key_of=server_token_key,
        what="MCP server auth tokens",
    )
