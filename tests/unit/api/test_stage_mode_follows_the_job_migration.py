"""A stored ``sequential`` the old default wrote becomes an unset mode, and can go back.

The revision runs on the raw stored document and never imports the
application. What is pinned: an analysis stage that says ``sequential`` loses
the word unless the stored global key says ``true``; a ``parallel`` stage, a
derived team and every other kind of stage are left alone; running twice
changes nothing; the downgrade writes the mode the old model would have run
the stage in and takes a stored ``auto`` away. The last test loads the
migrated document as settings.
"""

from __future__ import annotations

import importlib.util
import json
import logging
from pathlib import Path

import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261002000000_stage_mode_follows_the_job.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("stage_mode_follows_the_job", _REV)
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


def _rows(conn) -> dict:
    return dict(conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall())


def _profiles(conn) -> dict:
    return json.loads(_rows(conn)["core.agents.profiles"])


def _run(conn, step: str) -> None:
    mod = _load()
    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        getattr(mod, step)()


def _team(mode: str | None, **over) -> dict:
    analysis = {"key": "analysis", "kind": "analysis", "agents": ["static", "network"]}
    if mode is not None:
        analysis["mode"] = mode
    return {
        "label": "Team",
        "stages": [
            {"key": "triage_pack", "kind": "triage", "agents": [], "mode": "sequential"},
            analysis,
            {
                "key": "verdict",
                "kind": "verdict",
                "agents": ["judge"],
                "depends_on": ["analysis"],
                "mode": "sequential",
            },
            {
                "key": "report",
                "kind": "report",
                "agents": ["reporter"],
                "depends_on": ["verdict"],
                "mode": "sequential",
            },
        ],
        **over,
    }


STORED = {
    "written": _team("sequential"),
    "fanned": _team("parallel"),
    "derived": _team("sequential", analysts=["static", "network"], derived_from_analysts=True),
}


def _analysis(profiles: dict, name: str) -> dict:
    return next(s for s in profiles[name]["stages"] if s["kind"] == "analysis")


def test_the_revision_follows_the_report_one():
    mod = _load()
    assert mod.revision == "20261002000000"
    assert mod.down_revision == "20261001000000"


def test_a_sequential_the_old_default_wrote_becomes_unset(caplog):
    conn = _engine({"core.agents.profiles": json.dumps(STORED)})
    with conn, caplog.at_level(logging.WARNING):
        _run(conn, "upgrade")
        profiles = _profiles(conn)
    # Each rewritten stage is named, at WARNING, so a chosen one can be pinned again.
    said = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("team 'written' stage 'analysis'" in line for line in said)
    assert not any("'fanned'" in line or "'derived'" in line for line in said)
    assert "mode" not in _analysis(profiles, "written")
    assert _analysis(profiles, "fanned")["mode"] == "parallel"
    assert _analysis(profiles, "derived")["mode"] == "sequential"
    # Only an analysis stage runs agents side by side; the others are left.
    assert profiles["written"]["stages"][0]["mode"] == "sequential"


def test_an_explicit_false_is_rewritten_and_still_runs_sequential():
    conn = _engine(
        {"core.agents.profiles": json.dumps(STORED), "core.llm.parallel_analysts": "false"}
    )
    with conn:
        _run(conn, "upgrade")
        profiles = _profiles(conn)
    assert "mode" not in _analysis(profiles, "written")


def test_a_sequential_stage_under_a_stored_true_is_left_as_written():
    conn = _engine(
        {"core.agents.profiles": json.dumps(STORED), "core.llm.parallel_analysts": "true"}
    )
    with conn:
        _run(conn, "upgrade")
        profiles = _profiles(conn)
    assert profiles == STORED


def test_running_twice_changes_nothing():
    conn = _engine({"core.agents.profiles": json.dumps(STORED)})
    with conn:
        _run(conn, "upgrade")
        once = _profiles(conn)
        _run(conn, "upgrade")
        assert _profiles(conn) == once


def test_the_downgrade_writes_the_old_mode_back_and_takes_auto_away():
    conn = _engine(
        {"core.agents.profiles": json.dumps(STORED), "core.llm.parallel_analysts": '"auto"'}
    )
    with conn:
        _run(conn, "upgrade")
        _run(conn, "downgrade")
        rows = _rows(conn)
        profiles = _profiles(conn)
    assert "core.llm.parallel_analysts" not in rows
    assert _analysis(profiles, "written")["mode"] == "sequential"
    assert _analysis(profiles, "fanned")["mode"] == "parallel"


def test_the_migrated_document_loads_with_the_stage_unset():
    from maljan.core.config import Settings

    team = _team("sequential")
    team["stages"] = [s for s in team["stages"] if s["kind"] != "report"] + [
        {
            "key": "report",
            "kind": "report",
            "agents": ["reporter"],
            "depends_on": ["verdict"],
        }
    ]
    conn = _engine({"core.agents.profiles": json.dumps({"lean": team})})
    with conn:
        _run(conn, "upgrade")
        profiles = _profiles(conn)
    settings = Settings(_env_file=None, agents={"profiles": profiles, "profile": "lean"})
    assert settings.agents.profiles["lean"].stage("analysis").mode is None
