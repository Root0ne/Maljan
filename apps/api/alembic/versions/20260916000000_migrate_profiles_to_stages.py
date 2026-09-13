"""Give every stored profile the stages that say what it always did.

A profile used to be a list of analyst keys and nothing else, which meant the
shape of a run — analysts, then a debate, then a verdict, then a report — was
in the code rather than in the profile. It is in the profile now, as an ordered
list of dependent stages, and a stored document that still holds only
``analysts`` describes a team whose shape nobody wrote down.

So the document is rewritten in place: each profile without ``stages`` gets the
four that its analyst list has always meant, built with the two global keys the
conversion reads — ``core.llm.parallel_analysts`` for the analysis stage's run
mode and ``core.negotiation.max_iterations`` for the debate's round limit — so
a profile comes out of this running exactly as it ran into it.

``analysts`` is kept beside the new ``stages``. The settings model reads
``stages`` when both are present, so the copy is inert; it is what
``downgrade`` restores from, and it is what lets an operator compare the two.

Each converted profile is also marked ``derived_from_analysts``. Without the
mark the team would freeze whatever those two global keys said on the day this
ran: an operator who migrates on a hosted API and later moves back to the
single-slot local model would keep running analysts in parallel, having never
chosen to write stages at all. Marked, the settings model keeps re-deriving
them until the operator edits the team, and a migrated database and a fresh
install agree.

``is_secret`` rows are never touched — no profile was ever stored as one, and a
credential must not pass through a JSON rewrite.

Revision ID: 20260916000000
Revises: 20260915000000
"""

from __future__ import annotations

import json
import logging
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "20260916000000"
down_revision = "20260915000000"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

PROFILES_KEY = "core.agents.profiles"
PARALLEL_KEY = "core.llm.parallel_analysts"
MAX_ROUNDS_KEY = "core.negotiation.max_iterations"
CONSENSUS_KEY = "core.negotiation.consensus_threshold"

# The defaults the settings model itself declares, restated here because a
# migration must not import the application: a model that grows a field would
# then rewrite an operator's stored document from a future default during an
# upgrade of an old database.
DEFAULT_PARALLEL = False
DEFAULT_MAX_ROUNDS = 5
DEFAULT_CONSENSUS = 0.85

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


def _load_profiles(conn: sa.engine.Connection) -> dict:
    loaded = _plain_value(conn, PROFILES_KEY)
    return dict(loaded) if isinstance(loaded, dict) else {}


def _store_profiles(conn: sa.engine.Connection, profiles: dict) -> None:
    statement = _UPSERT_JSON_PG if conn.dialect.name == "postgresql" else _UPSERT_JSON_OTHER
    conn.execute(statement, {"k": PROFILES_KEY, "v": json.dumps(profiles)})


def stage_form(analysts: list, *, parallel: bool, max_rounds: int, consensus: float) -> list[dict]:
    """The four stages a list of analysts has always described.

    A copy of ``maljan.core.config.stages_from_analysts`` rather than a call to
    it, for the reason every alembic revision keeps its own constants: this has
    to keep producing the document that was correct on the day it ran, and a
    shared helper would follow the model wherever it goes next.
    """
    return [
        {
            "key": "analysis",
            "label": "Analysis",
            "kind": "analysis",
            "agents": list(analysts),
            "depends_on": [],
            "when": "",
            "mode": "parallel" if parallel else "sequential",
            "inject_upstream": "none",
            "debate": None,
            "builtin_tools": True,
        },
        {
            "key": "debate",
            "label": "Debate",
            "kind": "debate",
            "agents": [],
            "depends_on": ["analysis"],
            "when": "",
            "mode": "sequential",
            "inject_upstream": "none",
            "debate": {
                "max_rounds": int(max_rounds),
                "consensus_threshold": float(consensus),
                "sycophancy_check": True,
            },
            "builtin_tools": True,
        },
        {
            "key": "verdict",
            "label": "Verdict",
            "kind": "verdict",
            "agents": ["judge"],
            "depends_on": ["debate"],
            "when": "",
            "mode": "sequential",
            "inject_upstream": "none",
            "debate": None,
            "builtin_tools": True,
        },
        {
            "key": "report",
            "label": "Report",
            "kind": "report",
            "agents": ["reporter"],
            "depends_on": ["verdict"],
            "when": "",
            "mode": "sequential",
            "inject_upstream": "none",
            "debate": None,
            "builtin_tools": True,
        },
    ]


def upgrade() -> None:
    conn = op.get_bind()
    profiles = _load_profiles(conn)
    if not profiles:
        return

    parallel = _plain_value(conn, PARALLEL_KEY)
    max_rounds = _plain_value(conn, MAX_ROUNDS_KEY)
    consensus = _plain_value(conn, CONSENSUS_KEY)

    converted: list[str] = []
    for name, entry in profiles.items():
        if not isinstance(entry, dict) or entry.get("stages"):
            continue
        analysts = entry.get("analysts")
        if not isinstance(analysts, list) or not analysts:
            continue
        entry["stages"] = stage_form(
            analysts,
            parallel=bool(parallel) if parallel is not None else DEFAULT_PARALLEL,
            max_rounds=int(max_rounds) if max_rounds is not None else DEFAULT_MAX_ROUNDS,
            consensus=float(consensus) if consensus is not None else DEFAULT_CONSENSUS,
        )
        entry["derived_from_analysts"] = True
        converted.append(str(name))

    if not converted:
        return
    _store_profiles(conn, profiles)
    logger.info("runtime_settings: gave %s stages", ", ".join(sorted(converted)))


def downgrade() -> None:
    """Drop ``stages`` again, leaving the analyst list the profile kept."""
    conn = op.get_bind()
    profiles = _load_profiles(conn)
    if not profiles:
        return

    reverted = False
    for entry in profiles.values():
        if not isinstance(entry, dict) or "stages" not in entry:
            continue
        # A profile whose stages were written by hand has no analyst list to
        # fall back to, so its members are recovered from the analysis stages
        # rather than dropped: downgrading must not silently empty a team.
        if not entry.get("analysts"):
            members: list[str] = []
            for stage in entry.get("stages") or []:
                if isinstance(stage, dict) and stage.get("kind") == "analysis":
                    members.extend(str(a) for a in stage.get("agents") or [])
            entry["analysts"] = members
        entry.pop("stages", None)
        entry.pop("derived_from_analysts", None)
        reverted = True

    if reverted:
        _store_profiles(conn, profiles)
