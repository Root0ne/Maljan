"""Point an agent tool at the agent a role key's rename moved, in the stored settings.

Revision 20261009000000 renamed an operator's own definition named
``mediator`` or ``summarizer`` to ``<key>_custom`` and moved every reference
it knew of: the teams, the ``llm.agents`` entry, the server bindings and the
two override maps. It did not know the agent tool (``{"kind": "agent",
"agent": ...}`` in a definition's ``tools``), so a lead that asked that agent
still names the old key. No definition may hold a role key, so the reference
names nothing, and the settings model refuses the document that holds it.
This revision moves such a reference to the renamed definition.

Only the role keys are repaired. The keys earlier revisions renamed for a
seed (``triage``, ``android_static``, ``reverser``, ``lead``) were renamed
before a tool could name an agent, and a reference to one of them today names
the built-in seeded there, which is a reference an operator may mean; nothing
in the store tells it from a stale one, so it is left as it is.

A reference moves only when exactly one definition is the rename's
(``<key>_custom``, or ``<key>_custom_<n>`` when that was taken): with none or
with several, which agent it meant cannot be read from the store, and it is
left for the settings model to refuse at that reference, which the console
can open past and repair. Only the definitions row is written, and only when
a reference moved; ``is_secret`` rows are never read. Running it again finds
nothing left to move.

Kept self-contained, as every revision is: the rule is restated here rather
than imported from ``maljan.core.agent_key_migration``.

Revision ID: 20261025000000
Revises: 20261024000000
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "20261025000000"
down_revision = "20261024000000"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

DEFINITIONS_KEY = "core.agents.definitions"
# Restated rather than imported, as every revision restates what it acts on.
ROLE_KEYS = ("mediator", "summarizer")
RENAME_SUFFIX = "_custom"

_UPSERT_JSON_PG = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) "
    "VALUES (:k, CAST(:v AS JSONB), false) "
    "ON CONFLICT (key) DO UPDATE SET value = CAST(:v AS JSONB)"
)
_UPSERT_JSON_OTHER = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) "
    "VALUES (:k, :v, false) "
    "ON CONFLICT (key) DO UPDATE SET value = :v"
)


def _plain_value(conn: sa.engine.Connection, key: str) -> Any:
    """The stored value for ``key``, or ``None``. A secret row is left alone."""
    row = conn.execute(
        sa.text("SELECT value, is_secret FROM runtime_settings WHERE key = :k"), {"k": key}
    ).fetchone()
    if row is None or row[1]:
        return None
    value = row[0]
    return json.loads(value) if isinstance(value, str) else value


def _store(conn: sa.engine.Connection, key: str, value: Any) -> None:
    statement = _UPSERT_JSON_PG if conn.dialect.name == "postgresql" else _UPSERT_JSON_OTHER
    conn.execute(statement, {"k": key, "v": json.dumps(value)})


def _moves(definitions: dict) -> tuple[dict, list]:
    """Each role key a reference may move from, to its one renamed definition; and the rest."""
    moves: dict = {}
    unclear: list = []
    for key in ROLE_KEYS:
        if key in definitions:
            continue
        pattern = re.compile(rf"{re.escape(key)}{RENAME_SUFFIX}(?:_\d+)?")
        found = [name for name in definitions if isinstance(name, str) and pattern.fullmatch(name)]
        if len(found) == 1:
            moves[key] = found[0]
        elif found:
            unclear.append(key)
    return moves, unclear


def _retarget(entry: Any, moves: dict) -> Any:
    """``entry`` with each agent tool naming a moved key pointed at its new one; else itself."""
    if not isinstance(entry, dict) or not isinstance(entry.get("tools"), list):
        return entry
    tools = entry["tools"]
    rewritten = [
        {**ref, "agent": moves[ref["agent"]]}
        if isinstance(ref, dict)
        and ref.get("kind") == "agent"
        and isinstance(ref.get("agent"), str)
        and ref["agent"] in moves
        else ref
        for ref in tools
    ]
    if rewritten == tools:
        return entry
    return {**entry, "tools": rewritten}


def upgrade() -> None:
    conn = op.get_bind()
    definitions = _plain_value(conn, DEFINITIONS_KEY)
    if not isinstance(definitions, dict):
        return
    moves, unclear = _moves(definitions)
    if unclear:
        logger.warning(
            "runtime_settings: an agent tool naming %s was left as it is: more than one "
            "definition could be its renamed agent. Fix it in Settings.",
            ", ".join(unclear),
        )
    if not moves:
        return
    repaired = {name: _retarget(entry, moves) for name, entry in definitions.items()}
    moved = sorted(name for name in definitions if repaired[name] is not definitions[name])
    if not moved:
        return
    _store(conn, DEFINITIONS_KEY, repaired)
    logger.warning(
        "runtime_settings: the agent tools of %s now name the renamed agent (%s).",
        ", ".join(moved),
        "; ".join(f"{old} -> {new}" for old, new in sorted(moves.items())),
    )


def downgrade() -> None:
    """Nothing to undo: the old reference named no agent the settings could hold."""
