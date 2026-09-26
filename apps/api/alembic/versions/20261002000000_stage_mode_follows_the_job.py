"""An analysis stage that never chose a run mode follows the job's.

``StageDefinition.mode`` used to default to ``sequential``, so every stored
team wrote that word on every analysis stage whether or not anybody chose it.
The default is now unset: a stage with no mode of its own runs in the mode the
job resolves from ``llm.parallel_analysts`` (``auto`` by default — parallel on
a hosted API, one after another on a single-slot local server).

A stored ``sequential`` cannot say whether an operator chose it or the old
default wrote it, so this revision reads it by what it did:

* where ``core.llm.parallel_analysts`` is stored ``true``, a stage that says
  ``sequential`` ran one after another while the global key said parallel, so
  it is left as written;
* everywhere else the stage ran as the global key said (``false``, stored or
  by the old default), so the word is taken out and the stage follows the job.
  An explicit stored ``false`` keeps every such stage sequential.

A ``parallel`` stage is always left as written, and so is every stage of a team
still derived from its analyst list, which is rebuilt from the global key on
every load. ``is_secret`` rows are never touched.

The downgrade writes a mode back on every analysis stage without one — the
mode the old model would have run it in — and takes a stored ``auto``, which
the old model cannot read, back to the old default by deleting the row.

Revision ID: 20261002000000
Revises: 20261001000000
"""

from __future__ import annotations

import json
import logging
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "20261002000000"
down_revision = "20261001000000"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

PROFILES_KEY = "core.agents.profiles"
PARALLEL_KEY = "core.llm.parallel_analysts"

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
    try:
        return json.loads(value) if isinstance(value, str) else value
    except ValueError:
        return value


def _load_profiles(conn: sa.engine.Connection) -> dict:
    loaded = _plain_value(conn, PROFILES_KEY)
    return dict(loaded) if isinstance(loaded, dict) else {}


def _store_profiles(conn: sa.engine.Connection, profiles: dict) -> None:
    statement = _UPSERT_JSON_PG if conn.dialect.name == "postgresql" else _UPSERT_JSON_OTHER
    conn.execute(statement, {"k": PROFILES_KEY, "v": json.dumps(profiles)})


def _stored_parallel(conn: sa.engine.Connection) -> bool | None:
    """What the stored global key says: ``True``, ``False``, or ``None`` (absent or auto)."""
    value = _plain_value(conn, PARALLEL_KEY)
    if isinstance(value, bool):
        return value
    said = str(value or "").strip().lower()
    if said == "true":
        return True
    if said == "false":
        return False
    return None


def _analysis_stages(entry: Any) -> list[dict]:
    if not isinstance(entry, dict):
        return []
    return [
        stage
        for stage in entry.get("stages") or []
        if isinstance(stage, dict) and stage.get("kind", "analysis") == "analysis"
    ]


def upgrade() -> None:
    conn = op.get_bind()
    if _stored_parallel(conn) is True:
        return
    profiles = _load_profiles(conn)
    changed: list[str] = []
    for name, entry in profiles.items():
        if not isinstance(entry, dict) or entry.get("derived_from_analysts"):
            continue
        touched = False
        for stage in _analysis_stages(entry):
            if stage.get("mode") == "sequential":
                stage.pop("mode", None)
                touched = True
                # Said per stage, because an operator who had chosen
                # ``sequential`` has to know what to pin again.
                logger.warning(
                    "runtime_settings: team %r stage %r no longer says 'sequential'; it now "
                    "follows the job's analyst mode (llm.parallel_analysts). Pick "
                    "'sequential' on the stage card to pin it.",
                    str(name),
                    str(stage.get("key") or ""),
                )
        if touched:
            changed.append(str(name))
    if not changed:
        return
    _store_profiles(conn, profiles)
    logger.warning(
        "runtime_settings: the analysis stages of %s follow the job's analyst mode",
        ", ".join(sorted(changed)),
    )


def downgrade() -> None:
    conn = op.get_bind()
    parallel = _stored_parallel(conn)
    profiles = _load_profiles(conn)
    written = False
    for entry in profiles.values():
        for stage in _analysis_stages(entry):
            if stage.get("mode") not in ("parallel", "sequential"):
                stage["mode"] = "parallel" if parallel is True else "sequential"
                written = True
    if written:
        _store_profiles(conn, profiles)
    if parallel is None and _plain_value(conn, PARALLEL_KEY) is not None:
        conn.execute(sa.text("DELETE FROM runtime_settings WHERE key = :k"), {"k": PARALLEL_KEY})
