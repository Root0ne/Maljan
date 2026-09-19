"""Move a stored per-agent budget onto the agent's own definition.

A step and time budget used to live in two maps keyed by agent name,
``core.react_agent_max_steps_overrides`` and
``core.react_agent_timeout_overrides``, away from the definition an operator
edits. They are fields of ``AgentDefinition`` now, so a clone of a team carries
the budget its agents need. An operator who raised a budget through the UI has
a row in one or both maps; without this their value would stay in a map the
code still reads but the agent card does not show, and the first edit of that
card would look as though the budget had never been set.

Only an agent the stored definition map already names is moved: a budget for an
agent that is not in that map is a budget for a built-in the operator never
edited, and the built-in seeds carry their own. The map entry is removed once
it has been copied, so the two cannot drift, and an entry whose definition
already sets that field is left alone rather than overwriting the newer value.

Only a value the new field accepts is moved. The maps are plain
``dict[str, int]`` with no per-value bound, so a zero, a negative number or a
string is storable in one today; the definition's field is ``ge=1``, and a
value it refuses would make every settings read raise after the move — an API
and a worker that cannot serve. Such a value stays in its map, where it is
still read by the deprecated-map fallback, and is named in this revision's log
line rather than raised.

Both maps are stored as one JSON document each, as ``agents.definitions`` is.
A secret row is left alone, as ``20260917000000`` leaves one alone: a
credential must not pass through a JSON rewrite, and neither of these keys has
ever been stored as one.

On a downgrade a definition's budget is written back into its map, and it wins
over whatever is there: the value that survives is the one that was in effect,
and a map entry shadowed by a definition is lost. A downgrade is a recovery
path rather than a round trip.

Idempotent by construction: a run that finds nothing to move writes nothing.

Revision ID: 20260927000000
Revises: 20260926000000
"""

from __future__ import annotations

import json
import logging

import sqlalchemy as sa
from alembic import op

revision = "20260927000000"
down_revision = "20260926000000"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

DEFINITIONS_KEY = "core.agents.definitions"
# The map each definition field is moved out of, and back into on a downgrade.
MOVES: dict[str, str] = {
    "core.react_agent_timeout_overrides": "timeout_seconds",
    "core.react_agent_max_steps_overrides": "max_steps",
}

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


def _load(conn: sa.engine.Connection, key: str) -> dict:
    """The stored map for ``key``, or ``{}``. A secret row is left alone."""
    row = conn.execute(
        sa.text("SELECT value, is_secret FROM runtime_settings WHERE key = :k"), {"k": key}
    ).fetchone()
    if row is None or row[1]:
        return {}
    value = row[0]
    loaded = json.loads(value) if isinstance(value, str) else value
    return dict(loaded) if isinstance(loaded, dict) else {}


def _is_a_budget(value: object) -> bool:
    """Whether the new field would accept this value: a whole number, at least one.

    ``True`` is an ``int`` to Python and is a budget to nobody.
    """
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _store(conn: sa.engine.Connection, key: str, value: dict) -> None:
    statement = _UPSERT_JSON_PG if conn.dialect.name == "postgresql" else _UPSERT_JSON_OTHER
    conn.execute(statement, {"k": key, "v": json.dumps(value)})


def upgrade() -> None:
    conn = op.get_bind()
    definitions = _load(conn, DEFINITIONS_KEY)
    if not definitions:
        return
    moved = 0
    refused: list[str] = []
    for map_key, field in MOVES.items():
        overrides = _load(conn, map_key)
        if not overrides:
            continue
        kept = {}
        for agent, value in overrides.items():
            entry = definitions.get(agent)
            if not isinstance(entry, dict) or entry.get(field) is not None:
                kept[agent] = value
                continue
            if not _is_a_budget(value):
                kept[agent] = value
                refused.append(f"{map_key}[{agent}]={value!r}")
                continue
            entry[field] = value
            definitions[agent] = entry
            moved += 1
        if kept != overrides:
            _store(conn, map_key, kept)
    if moved:
        _store(conn, DEFINITIONS_KEY, definitions)
    logger.info("runtime_settings: moved %d agent budget(s) onto their definitions", moved)
    if refused:
        logger.warning(
            "runtime_settings: left %d agent budget(s) in the override map, because a "
            "definition will not take them: %s",
            len(refused),
            ", ".join(sorted(refused)),
        )


def downgrade() -> None:
    """The budgets back in their maps. A definition's value wins over a map's."""
    conn = op.get_bind()
    definitions = _load(conn, DEFINITIONS_KEY)
    if not definitions:
        return
    changed = False
    for map_key, field in MOVES.items():
        overrides = _load(conn, map_key)
        before = dict(overrides)
        for agent, entry in definitions.items():
            if not isinstance(entry, dict):
                continue
            value = entry.pop(field, None)
            if value is None:
                continue
            overrides[agent] = value
            changed = True
        if overrides != before:
            _store(conn, map_key, overrides)
    if changed:
        _store(conn, DEFINITIONS_KEY, definitions)
