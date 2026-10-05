"""Every stored team gains the triage pack in front, and can give it back.

The revision runs on the raw stored document and never imports the
application, so what is pinned here is the document it writes: the stage at
position 0 of every profile that has stages and no triage kind, nothing else
moved, the measurement baseline and a team that already has one left alone,
running twice changing nothing, and the downgrade taking the stage out again.
The last test loads the migrated document as settings, which is the point.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20260919000000_seed_triage_stage.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("seed_triage_stage", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _engine(rows: dict[str, str]):
    engine = sa.create_engine("sqlite://")
    conn = engine.connect()
    conn.execute(
        sa.text(
            "CREATE TABLE runtime_settings "
            "(key TEXT PRIMARY KEY, value TEXT, is_secret BOOLEAN DEFAULT 0)"
        )
    )
    for key, value in rows.items():
        conn.execute(
            sa.text("INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, 0)"),
            {"k": key, "v": value},
        )
    conn.commit()
    return conn


def _profiles(conn) -> dict:
    rows = dict(conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall())
    return json.loads(rows["core.agents.profiles"])


def _stage(key: str, kind: str = "analysis", **over) -> dict:
    return {"key": key, "kind": kind, "agents": ["static"] if kind == "analysis" else [], **over}


STORED = {
    "lean": {
        "label": "Lean",
        "analysts": ["static"],
        "derived_from_analysts": True,
        "stages": [
            _stage("analysis"),
            _stage("debate", "debate", depends_on=["analysis"]),
            _stage("verdict", "verdict", agents=["judge"], depends_on=["debate"]),
        ],
    },
    "measurement": {
        "label": "Measurement baseline",
        "analysts": ["static"],
        "exclude_servers": ["*"],
        "stages": [
            _stage("analysis"),
            _stage("verdict", "verdict", agents=["judge"], depends_on=["analysis"]),
        ],
    },
    "already": {
        "label": "Already",
        "stages": [
            {"key": "facts", "kind": "triage", "agents": []},
            _stage("verdict", "verdict", agents=["judge"], depends_on=["facts"]),
        ],
    },
    "flat": {"label": "Flat", "analysts": ["network"]},
}


def test_the_revision_follows_the_qdrant_one():
    mod = _load()
    assert mod.revision == "20260919000000"
    assert mod.down_revision == "20260918000000"


def test_the_stage_it_inserts_is_the_one_the_settings_model_seeds():
    from maljan.core.config import triage_stage

    # A triage stage runs no agents side by side, so its mode means nothing:
    # the revision wrote ``sequential`` there, and the model now leaves it unset.
    assert {**_load().triage_stage(), "mode": None} == triage_stage().model_dump()


def test_the_pack_goes_in_front_of_every_team_that_lacks_it_and_nowhere_else():
    mod = _load()
    conn = _engine({mod.PROFILES_KEY: json.dumps(STORED), "core.llm.provider": '"ollama"'})
    with conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
        profiles = _profiles(conn)

        lean = profiles["lean"]
        assert [s["kind"] for s in lean["stages"]] == ["triage", "analysis", "debate", "verdict"]
        assert lean["stages"][0] == mod.triage_stage()
        # Nothing else about the team moved: the analysis stage still starts
        # nowhere, the mark is still set, the analyst list is still there.
        assert lean["stages"][1] == _stage("analysis")
        assert lean["derived_from_analysts"] is True
        assert lean["analysts"] == ["static"]

        assert profiles["measurement"] == STORED["measurement"]
        assert profiles["already"] == STORED["already"]
        assert profiles["flat"] == STORED["flat"]

        rows = dict(conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall())
        assert rows["core.llm.provider"] == '"ollama"'


def test_running_it_twice_changes_nothing():
    mod = _load()
    conn = _engine({mod.PROFILES_KEY: json.dumps(STORED)})
    with conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
        first = _profiles(conn)
        with Operations.context(ctx):
            mod.upgrade()
        assert _profiles(conn) == first


def test_the_downgrade_takes_the_stage_out_again():
    mod = _load()
    conn = _engine({mod.PROFILES_KEY: json.dumps(STORED)})
    with conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
        with Operations.context(ctx):
            mod.downgrade()
        profiles = _profiles(conn)
        assert profiles["lean"] == STORED["lean"]
        assert profiles["measurement"] == STORED["measurement"]
        # A triage stage written by hand is a triage stage: the downgrade
        # removes the kind, because the model it downgrades to has no such kind.
        assert [s["kind"] for s in profiles["already"]["stages"]] == ["verdict"]


def test_a_team_whose_key_the_stage_would_take_is_left_alone():
    mod = _load()
    stored = {
        "taken": {
            "label": "Taken",
            "stages": [
                _stage("triage_pack"),
                _stage("verdict", "verdict", agents=["judge"], depends_on=["triage_pack"]),
            ],
        }
    }
    conn = _engine({mod.PROFILES_KEY: json.dumps(stored)})
    with conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
        assert _profiles(conn) == stored


def test_a_secret_profiles_row_is_never_rewritten():
    mod = _load()
    conn = _engine({})
    with conn:
        conn.execute(
            sa.text("INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, 1)"),
            {"k": mod.PROFILES_KEY, "v": '"enc:v1:SECRET"'},
        )
        conn.commit()
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
        rows = dict(conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall())
        assert rows[mod.PROFILES_KEY] == '"enc:v1:SECRET"'


def test_the_migrated_document_loads_and_the_default_still_matches_its_seed():
    """The reason the revision exists: a stored default converted by the
    previous revision must load against a seed that now carries the pack."""
    from maljan.core.config import Settings, stages_from_analysts

    mod = _load()
    stored_default = {
        "default": {
            "label": "Default",
            "analysts": ["static", "dynamic", "network"],
            "derived_from_analysts": True,
            "stages": [
                s.model_dump()
                for s in stages_from_analysts(["static", "dynamic", "network"], triage=False)
            ],
        },
        "lean": {"label": "Lean", "analysts": ["static"], "stages": STORED["lean"]["stages"]},
    }
    conn = _engine({mod.PROFILES_KEY: json.dumps(stored_default)})
    with conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
        profiles = _profiles(conn)
    settings = Settings(_env_file=None, agents={"profiles": profiles, "profile": "lean"})
    assert [s.kind for s in settings.agents.profiles["lean"].stages][:2] == ["triage", "analysis"]
    assert settings.agents.profiles["default"].stages[0].kind == "triage"
    assert settings.agents.profiles["default"].derived_from_analysts is True
