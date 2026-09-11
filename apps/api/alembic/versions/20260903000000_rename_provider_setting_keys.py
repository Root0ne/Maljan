"""Rename the stored UI overrides the provider layer moved.

``runtime_settings`` is keyed by the dotted setting path, so the provider
rename (the old ``core.mcp.<name>.*`` provider blocks moving under
``core.static``/``core.sandbox``, ``core.sandbox.cape2_*`` ->
``core.sandbox.cape2.*``, …) would otherwise strand every override an
operator had set: the key would no longer match a catalog entry and the
value would be ignored in silence. The table below is frozen: a migration is
pinned to the schema of its day, so it carries its own copy of the renames
that were current on 2026-09-03 rather than following a live config table.

Idempotent by construction: a row already carrying the new key is left alone
and the stale old row is deleted, so re-running the revision changes nothing.

Revision ID: 20260903000000
Revises: 20260902000000
"""

from __future__ import annotations

import logging

import sqlalchemy as sa
from alembic import op

revision = "20260903000000"
down_revision = "20260902000000"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

# The setting renames as they stood when this revision was written, frozen here
# so later cleanups of the application's own configuration cannot change what an
# already-released migration does to an operator's database.
_GENERIC_SERVER_KEY = "custom"

_RENAMES: tuple[tuple[str, str], ...] = (
    ("mcp.ghidra", "static.ghidra"),
    ("mcp.cape", "sandbox.cape2.mcp"),
    ("sandbox.backend", "sandbox.provider"),
    ("sandbox.cape2_base_url", "sandbox.cape2.base_url"),
    ("sandbox.cape2_api_token", "sandbox.cape2.api_token"),
    ("sandbox.cape2_timeout_seconds", "sandbox.cape2.timeout_seconds"),
    ("sandbox.cape2_poll_interval_seconds", "sandbox.cape2.poll_interval_seconds"),
    ("static.generic.enabled", f"mcp.servers.{_GENERIC_SERVER_KEY}.enabled"),
    ("static.generic.transport", f"mcp.servers.{_GENERIC_SERVER_KEY}.transport"),
    ("static.generic.command", f"mcp.servers.{_GENERIC_SERVER_KEY}.command"),
    ("static.generic.args", f"mcp.servers.{_GENERIC_SERVER_KEY}.args"),
    ("static.generic.env", f"mcp.servers.{_GENERIC_SERVER_KEY}.env"),
    ("static.generic.url", f"mcp.servers.{_GENERIC_SERVER_KEY}.url"),
    ("static.generic.auth_token", f"mcp.servers.{_GENERIC_SERVER_KEY}.auth_token"),
    ("static.generic.tool_selection", f"mcp.servers.{_GENERIC_SERVER_KEY}.tool_selection"),
    ("static.generic.use_all_tools", f"mcp.servers.{_GENERIC_SERVER_KEY}.use_all_tools"),
)

# The nine leaves an MCPServerConfig block stores.
_MCP_LEAVES = (
    "enabled",
    "transport",
    "command",
    "args",
    "env",
    "url",
    "auth_token",
    "tool_selection",
    "use_all_tools",
)


def _build_renames() -> dict[str, str]:
    out: dict[str, str] = {}
    for old, new in _RENAMES:
        if old.startswith("static.generic."):
            # Sub-project B's fold of a static.generic block into the single
            # core.mcp.servers JSON document is not a rename: it is handled
            # by its own dedicated data migration, 20260905000000.
            continue
        # The two legacy aliases rooted at ``mcp`` each moved a whole
        # MCPServerConfig block (a leaf's worth of settings), not a single
        # scalar, so the stored keys are one level deeper than the alias
        # itself and need expanding over every leaf it used to carry.
        head, _, _tail = old.partition(".")
        if head == "mcp":
            for leaf in _MCP_LEAVES:
                out[f"core.{old}.{leaf}"] = f"core.{new}.{leaf}"
        else:
            out[f"core.{old}"] = f"core.{new}"
    return out


KEY_RENAMES: dict[str, str] = _build_renames()


def _move(mapping: dict[str, str]) -> None:
    conn = op.get_bind()
    for old, new in mapping.items():
        present = conn.execute(
            sa.text("SELECT key FROM runtime_settings WHERE key IN (:old, :new)"),
            {"old": old, "new": new},
        ).fetchall()
        keys = {row[0] for row in present}
        if old in keys and new in keys:
            # Both a legacy and a current row exist for the same setting. The new
            # key is the deliberate one (an operator who saved it meant to), so it
            # is kept and the stale row is dropped; only the collision is logged,
            # never either row's (possibly encrypted secret) value.
            logger.warning(
                "runtime_settings: both %r and %r are set; keeping %r, dropping %r",
                old,
                new,
                new,
                old,
            )
        conn.execute(
            sa.text(
                "UPDATE runtime_settings SET key = :new "
                "WHERE key = :old "
                "AND NOT EXISTS (SELECT 1 FROM runtime_settings r2 WHERE r2.key = :new)"
            ),
            {"old": old, "new": new},
        )
        conn.execute(sa.text("DELETE FROM runtime_settings WHERE key = :old"), {"old": old})


def upgrade() -> None:
    _move(KEY_RENAMES)


def downgrade() -> None:
    _move({new: old for old, new in KEY_RENAMES.items()})
