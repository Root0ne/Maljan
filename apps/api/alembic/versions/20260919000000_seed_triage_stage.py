"""Put the triage pack in front of every stored team that does not have one.

A team's first step is now the pipeline itself running the deterministic
tools over the sample and writing each result to the evidence ledger, so that
the facts an analyst may or may not ask for exist before any analyst starts.
The seeded teams ship with that stage; a team already stored in an operator's
database was written without it, and the settings model refuses a stored
built-in that does not match its seed.

So the stage is inserted here, at position 0 of every stored profile that has
stages and no stage of kind ``triage``. Nothing else about the profile moves:
the builder makes a triage stage with no dependency the start of the graph and
every other root stage follow it, so no ``depends_on`` has to be rewritten. The
``derived_from_analysts`` mark is left as it is, because the settings model's
derivation now produces the same stage in the same place.

The measurement baseline is skipped by name. Its purpose is to show what the
models do with nothing established for them, and the seed it is compared
against has no triage stage.

``is_secret`` rows are never touched — no profile was ever stored as one, and a
credential must not pass through a JSON rewrite.

Revision ID: 20260919000000
Revises: 20260918000000
"""

from __future__ import annotations

import json
import logging
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "20260919000000"
down_revision = "20260918000000"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

PROFILES_KEY = "core.agents.profiles"
TRIAGE_KIND = "triage"
# The profile whose seed carries no triage stage.
MEASUREMENT_PROFILE = "measurement"

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


def triage_stage() -> dict[str, Any]:
    """The stage document, as ``maljan.core.config.triage_stage`` writes it.

    A copy rather than an import, for the reason every alembic revision keeps
    its own constants: this has to keep inserting the document that was
    correct on the day it ran.
    """
    return {
        "key": "triage_pack",
        "label": "Triage pack",
        "kind": TRIAGE_KIND,
        "agents": [],
        "depends_on": [],
        "when": "",
        "mode": "sequential",
        "inject_upstream": "none",
        "debate": None,
        "builtin_tools": True,
    }


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


def _has_triage(stages: list) -> bool:
    return any(isinstance(s, dict) and s.get("kind") == TRIAGE_KIND for s in stages)


def upgrade() -> None:
    conn = op.get_bind()
    profiles = _load_profiles(conn)
    if not profiles:
        return

    changed: list[str] = []
    for name, entry in profiles.items():
        if str(name) == MEASUREMENT_PROFILE or not isinstance(entry, dict):
            continue
        stages = entry.get("stages")
        if not isinstance(stages, list) or not stages or _has_triage(stages):
            continue
        # A stored key the stage would collide with is left alone rather than
        # made into a profile that no longer loads; the operator sees the
        # built-in identity error and clones or renames.
        if any(isinstance(s, dict) and s.get("key") == triage_stage()["key"] for s in stages):
            continue
        entry["stages"] = [triage_stage(), *stages]
        changed.append(str(name))

    if not changed:
        return
    _store_profiles(conn, profiles)
    logger.info("runtime_settings: put the triage pack in front of %s", ", ".join(sorted(changed)))


def downgrade() -> None:
    """Take every triage stage out again, wherever it sits."""
    conn = op.get_bind()
    profiles = _load_profiles(conn)
    if not profiles:
        return

    reverted = False
    for entry in profiles.values():
        if not isinstance(entry, dict):
            continue
        stages = entry.get("stages")
        if not isinstance(stages, list) or not _has_triage(stages):
            continue
        entry["stages"] = [
            s for s in stages if not (isinstance(s, dict) and s.get("kind") == TRIAGE_KIND)
        ]
        reverted = True

    if reverted:
        _store_profiles(conn, profiles)
