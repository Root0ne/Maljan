"""Move an operator's own agent or team off a key the product has now seeded.

`triage`, `android_static`, `reverser`, `mobile` and `deep_static` were all
legal names for an operator's own agent or team the day before they became
built-in seeds. The settings model refuses a stored built-in that does not
match its seed, and it refuses it on every construction — which is to say at
boot — so an operator who had named an agent `reverser` would upgrade into an
API and a worker that will not start and cannot be repaired from the console,
because the console needs the configuration to load in order to draw the page
that would fix it.

So the stored document is repaired here, once: a colliding entry that is not
the seed is renamed to `<key>_custom`, and every reference to the old name is
rewritten in the same pass — the teams that named the agent (`stages[].agents`
and the deprecated `analysts` copy), the per-agent model entry under
`core.llm.agents`, each MCP server's `agents` binding, and the two
`react_*_overrides` maps. The operator finds their agent under the new name
instead of a service that will not come up.

The settings model performs the same rename on read, so a database that never
runs this still loads. What this adds is that the rename is *written down*: the
console then shows the new name rather than renaming the same document again on
every read, and an operator who renames it to something they prefer keeps that
name.

``is_secret`` rows are never touched. No agent map was ever stored as one, and
a credential must not pass through a JSON rewrite.

Revision ID: 20260917000000
Revises: 20260916000000
"""

from __future__ import annotations

import json
import logging
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "20260917000000"
down_revision = "20260916000000"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

DEFINITIONS_KEY = "core.agents.definitions"
PROFILES_KEY = "core.agents.profiles"
ACTIVE_PROFILE_KEY = "core.agents.profile"
LLM_AGENTS_KEY = "core.llm.agents"
SERVERS_KEY = "core.mcp.servers"
TIMEOUT_OVERRIDES_KEY = "core.react_agent_timeout_overrides"
MAX_STEPS_OVERRIDES_KEY = "core.react_agent_max_steps_overrides"

# The keys this revision seeds, restated rather than imported: a migration has
# to keep doing what was correct on the day it ran, and a list that followed
# the model would rename a key a later release happened to add while an old
# database was being upgraded.
SEEDED_DEFINITIONS = ("triage", "android_static", "reverser")
SEEDED_PROFILES = ("mobile", "deep_static")

RENAME_SUFFIX = "_custom"
KEY_MAX_LENGTH = 32

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


def free_key(wanted: str, taken: set) -> str:
    """``wanted`` with the suffix, and a counter if that is taken as well."""
    stem = wanted[: KEY_MAX_LENGTH - len(RENAME_SUFFIX)]
    candidate = f"{stem}{RENAME_SUFFIX}"
    if candidate not in taken:
        return candidate
    for index in range(2, 1000):
        tail = f"{RENAME_SUFFIX}_{index}"
        candidate = f"{wanted[: KEY_MAX_LENGTH - len(tail)]}{tail}"
        if candidate not in taken:
            return candidate
    return f"{wanted[:20]}{RENAME_SUFFIX}_x"[:KEY_MAX_LENGTH]


def _rename_map(stored: Any, seeded: tuple, extra_taken: set) -> dict:
    """Old key to new key, for every seeded key this document already holds."""
    if not isinstance(stored, dict):
        return {}
    taken = set(stored) | set(seeded) | extra_taken
    renames: dict = {}
    for key in list(stored):
        if key in seeded:
            new_key = free_key(str(key), taken)
            taken.add(new_key)
            renames[key] = new_key
    return renames


def set_if_list(mapping: Any, field: str, renames: dict) -> Any:
    """``mapping`` with ``field`` rewritten, and only if it held a list.

    A copy of ``maljan.core.agent_key_migration.set_if_list`` rather than a
    call to it, for the reason every alembic revision keeps its own copies:
    alembic imports every revision file on every run, so a rename or removal in
    the application would stop the whole migration history from loading.

    The rule it enforces is the reason this revision was corrected once. Three
    optional list fields are rewritten — a team's `analysts`, a stage's
    `agents` and a server's `agents` — and none of them accepts ``None``, so
    writing the key in for a document that never had it turns a document that
    would have validated into one that will not. A debate stage has no agents,
    a team that carries stages needs no `analysts`, and a server with no agent
    restriction is the common case.

    Returns ``mapping`` itself when there is nothing to do, so a team or a
    server that references no renamed key is not rewritten at all.
    """
    if not isinstance(mapping, dict):
        return mapping
    values = mapping.get(field)
    if not isinstance(values, list):
        return mapping
    rewritten = [renames.get(v, v) if isinstance(v, str) else v for v in values]
    if rewritten == values:
        return mapping
    return {**mapping, field: rewritten}


def _rekey(mapping: Any, renames: dict) -> Any:
    if not isinstance(mapping, dict) or not renames:
        return mapping
    return {renames.get(k, k): v for k, v in mapping.items()}


def _rewrite_profiles(profiles: Any, agent_renames: dict) -> Any:
    """Every team's references to a renamed agent, under both spellings."""
    if not isinstance(profiles, dict) or not agent_renames:
        return profiles
    out = {}
    for name, entry in profiles.items():
        if not isinstance(entry, dict):
            out[name] = entry
            continue
        profile = set_if_list(entry, "analysts", agent_renames)
        stages = profile.get("stages")
        if isinstance(stages, list):
            restaged = [set_if_list(stage, "agents", agent_renames) for stage in stages]
            if restaged != stages:
                profile = {**profile, "stages": restaged}
        out[name] = profile
    return out


def _rewrite_servers(servers: Any, agent_renames: dict) -> Any:
    if not isinstance(servers, dict) or not agent_renames:
        return servers
    return {key: set_if_list(server, "agents", agent_renames) for key, server in servers.items()}


def _apply(conn: sa.engine.Connection, agent_renames: dict, profile_renames: dict) -> None:
    """Write both renames and every reference that follows them."""
    definitions = _plain_value(conn, DEFINITIONS_KEY)
    if agent_renames and isinstance(definitions, dict):
        _store(conn, DEFINITIONS_KEY, _rekey(definitions, agent_renames))

    profiles = _plain_value(conn, PROFILES_KEY)
    if isinstance(profiles, dict) and (agent_renames or profile_renames):
        _store(
            conn,
            PROFILES_KEY,
            _rekey(_rewrite_profiles(profiles, agent_renames), profile_renames),
        )

    active = _plain_value(conn, ACTIVE_PROFILE_KEY)
    if isinstance(active, str) and active in profile_renames:
        _store(conn, ACTIVE_PROFILE_KEY, profile_renames[active])

    if not agent_renames:
        return

    llm_agents = _plain_value(conn, LLM_AGENTS_KEY)
    if isinstance(llm_agents, dict):
        _store(conn, LLM_AGENTS_KEY, _rekey(llm_agents, agent_renames))

    servers = _plain_value(conn, SERVERS_KEY)
    if isinstance(servers, dict):
        _store(conn, SERVERS_KEY, _rewrite_servers(servers, agent_renames))

    for key in (TIMEOUT_OVERRIDES_KEY, MAX_STEPS_OVERRIDES_KEY):
        overrides = _plain_value(conn, key)
        if isinstance(overrides, dict):
            _store(conn, key, _rekey(overrides, agent_renames))


def upgrade() -> None:
    conn = op.get_bind()
    definitions = _plain_value(conn, DEFINITIONS_KEY)
    profiles = _plain_value(conn, PROFILES_KEY)

    agent_renames = _rename_map(definitions, SEEDED_DEFINITIONS, set())
    profile_renames = _rename_map(profiles, SEEDED_PROFILES, set())
    if not agent_renames and not profile_renames:
        return

    _apply(conn, agent_renames, profile_renames)
    described = "; ".join(
        [f"agent {old} -> {new}" for old, new in sorted(agent_renames.items())]
        + [f"team {old} -> {new}" for old, new in sorted(profile_renames.items())]
    )
    logger.warning(
        "runtime_settings: renamed off a key that is now built in: %s. "
        "Find them under the new names in Settings.",
        described,
    )


def downgrade() -> None:
    """Put a renamed key back, when nothing has since taken the old name.

    A stored `reverser_custom` on the way down is only this revision's work if
    there is no `reverser` beside it to collide with. Where there is one — the
    seed will have been written into the document by then, or the operator made
    their own — the rename stays, because undoing it would produce a document
    with two entries under one key and lose one of them.
    """
    conn = op.get_bind()
    definitions = _plain_value(conn, DEFINITIONS_KEY)
    profiles = _plain_value(conn, PROFILES_KEY)

    agent_renames = {}
    if isinstance(definitions, dict):
        for original in SEEDED_DEFINITIONS:
            renamed = f"{original}{RENAME_SUFFIX}"
            if renamed in definitions and original not in definitions:
                agent_renames[renamed] = original

    profile_renames = {}
    if isinstance(profiles, dict):
        for original in SEEDED_PROFILES:
            renamed = f"{original}{RENAME_SUFFIX}"
            if renamed in profiles and original not in profiles:
                profile_renames[renamed] = original

    if not agent_renames and not profile_renames:
        return
    _apply(conn, agent_renames, profile_renames)
