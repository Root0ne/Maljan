"""What each tool server last declared of its tools is kept in its own table.

``app.services.served_declarations_store`` writes what a process listed or
forgot (``served_tool_declarations``, one row per source) and reads it into
another process, which reads it before any server attaches. Against an
in-memory SQLite database through the ORM, the session's calls awaited as an
``AsyncSession``'s are (no async SQLite driver is a dependency here).
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session

from app.models.served_declaration import ServedDeclaration
from app.services import served_declarations_store as store
from malspark.core import served_declarations as sd
from malspark.core.declared_reading import builtin_tools
from malspark.core.tool_declarations import ToolFacts
from malspark.providers.served_listing import unlisted as _unlisted


@compiles(postgresql.JSONB, "sqlite")
def _jsonb(element, compiler, **kw):  # noqa: ANN001, ANN202
    return "JSON"


class _Awaited:
    """An ORM ``Session``'s calls, awaited as ``AsyncSession``'s are."""

    def __init__(self, session: Session) -> None:
        self.session = session

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        return self.session.execute(statement, *args, **kwargs)

    async def get(self, *args: Any, **kwargs: Any) -> Any:
        return self.session.get(*args, **kwargs)

    def add(self, row: Any) -> None:
        self.session.add(row)

    async def delete(self, row: Any) -> None:
        self.session.delete(row)

    async def commit(self) -> None:
        self.session.commit()

    async def rollback(self) -> None:
        self.session.rollback()


@pytest.fixture
def db() -> Any:
    engine = create_engine("sqlite://")
    ServedDeclaration.__table__.create(engine)
    with Session(engine) as session:
        yield _Awaited(session)


def _rows(db: _Awaited) -> dict[str, tuple[str, Any]]:
    held = db.session.execute(select(ServedDeclaration)).scalars().all()
    return {row.source: (row.launch, row.tool_facts) for row in held}


def test_what_a_process_listed_is_kept_and_another_process_reads_it(db: _Awaited) -> None:
    sd.register_served("mcp:mine", {"t": ToolFacts(kind="strings", rows="/s/*")}, "L")
    assert asyncio.run(store.save(db)) >= 1
    assert _rows(db)["mcp:mine"] == ("L", {"t": {"kind": "strings", "rows": "/s/*"}})
    assert sd.unsaved() == []
    # Another process: nothing held, then the store read.
    sd.forget_served()
    sd._UNSAVED.clear()
    assert asyncio.run(store.load(db)) == len(_rows(db))
    assert sd.served("mcp:mine", "L")["t"].rows == "/s/*"


def test_a_listing_under_another_launch_replaces_the_row_and_a_forgotten_one_goes(
    db: _Awaited,
) -> None:
    sd.register_served("mcp:mine", {"t": ToolFacts(kind="strings")}, "L")
    asyncio.run(store.save(db))
    sd.register_served("mcp:mine", {"u": ToolFacts(kind="identity")}, "M")
    asyncio.run(store.save(db))
    assert _rows(db)["mcp:mine"] == ("M", {"u": {"kind": "identity"}})
    sd.forget_served("mcp:mine")
    asyncio.run(store.save(db))
    assert "mcp:mine" not in _rows(db)


def test_the_own_servers_saved_as_kept_read_back_as_they_were(db: _Awaited) -> None:
    before = {key: dict(builtin_tools(key)) for key in ("analysis", "die", "threatintel")}
    sd._UNSAVED.update(f"mcp:{key}" for key in before)
    asyncio.run(store.save(db))
    sd.forget_served()
    sd._UNSAVED.clear()
    assert builtin_tools("analysis") == {}
    asyncio.run(store.load(db))
    for key, facts in before.items():
        assert {t: sd._set_fields(f) for t, f in builtin_tools(key).items()} == {
            t: sd._set_fields(f) for t, f in facts.items()
        }


def test_a_store_that_cannot_be_read_leaves_what_is_held() -> None:
    engine = create_engine("sqlite://")  # no table
    with Session(engine) as session:
        held = dict(builtin_tools("analysis"))
        assert asyncio.run(store.load(_Awaited(session))) == -1
        assert builtin_tools("analysis") == held
        sd.register_served("mcp:mine", {"t": ToolFacts(kind="strings")}, "L")
        assert asyncio.run(store.save(_Awaited(session))) == -1
        # Still to be saved, and still read here.
        assert any(row[0] == "mcp:mine" for row in sd.unsaved())
        assert set(sd.served("mcp:mine")) == {"t"}


def _maker(db: _Awaited) -> Any:
    """A session maker handing out ``db``, as the application's hands out its sessions."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _session() -> Any:
        yield db

    return _session


def test_a_request_rereads_the_store_at_most_every_few_seconds(
    db: _Awaited, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []

    async def _load(session: Any) -> int:
        calls.append(session)
        return 0

    monkeypatch.setattr(store, "load", _load)
    monkeypatch.setattr(store, "_READ_AT", [float("-inf")])
    asyncio.run(store.refresh(_maker(db)))
    asyncio.run(store.refresh(_maker(db)))
    # In a session of its own, not the request's.
    assert calls == [db]

    async def _broken(session: Any) -> int:
        raise OperationalError("select", {}, Exception("gone"))

    monkeypatch.setattr(store, "load", _broken)
    monkeypatch.setattr(store, "_READ_AT", [float("-inf")])
    asyncio.run(store.refresh(_maker(db)))  # never fails the request


def test_stored_settings_that_cannot_be_read_are_said_once_and_leave_the_reading_in_force(
    db: _Awaited, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A failing settings read is said once per distinct failure, not every few seconds (T-437)."""
    import logging

    from app.services import settings_service
    from malspark.core import declared_reading

    held = object()
    monkeypatch.setattr(declared_reading, "_READ_THROUGH", [held])
    monkeypatch.setattr(store, "_REFRESH_FAILURE", [None])

    async def _load(session: Any) -> int:
        return 0

    failures: list[Exception] = [ValueError("bad"), ValueError("bad again"), KeyError("x")]

    async def _stored(session: Any) -> Any:
        if failures:
            raise failures.pop(0)
        return "the settings read"

    monkeypatch.setattr(store, "load", _load)
    monkeypatch.setattr(settings_service, "effective_core_settings", _stored)

    def _refresh() -> None:
        monkeypatch.setattr(store, "_READ_AT", [float("-inf")])
        asyncio.run(store.refresh(_maker(db)))  # never fails the request

    def _said() -> list[str]:
        return [r.getMessage() for r in caplog.records if "were not read" in r.getMessage()]

    with caplog.at_level(logging.INFO):
        _refresh()
        _refresh()
        # The same failure twice: said once, the reading before still in force.
        assert _said() == [
            "The stored settings (ValueError) were not read; the reading before stays "
            "in force until a read succeeds."
        ]
        assert declared_reading._READ_THROUGH[0] is held
        assert store.refresh_failure() == "the stored settings (ValueError)"
        # Another failure is said in its turn.
        _refresh()
        assert len(_said()) == 2
        assert store.refresh_failure() == "the stored settings (KeyError)"
        # A read that succeeds says so, ends the failure and takes over.
        _refresh()
        assert store.refresh_failure() is None
        assert declared_reading._READ_THROUGH[0] == "the settings read"
        assert any("are read again" in r.getMessage() for r in caplog.records)
        _refresh()
        assert len(_said()) == 2


def test_kept_declarations_that_cannot_be_read_are_a_failure_of_the_refresh_each_outage(
    db: _Awaited, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Load says -1 rather than raising: still a failure, said again after a recovery (T-437)."""
    import logging

    from app.services import settings_service
    from malspark.core import declared_reading

    class _Gone(_Awaited):
        """The database, unreachable while ``down`` holds."""

        down = True

        async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
            if self.down:
                raise OperationalError("select", {}, Exception("gone"))
            return await super().execute(statement, *args, **kwargs)

    gone = _Gone(db.session)
    settings_read: list[Exception | None] = [None]

    async def _stored(session: Any) -> Any:
        if settings_read[0] is not None:
            raise settings_read[0]
        return None

    monkeypatch.setattr(declared_reading, "_READ_THROUGH", [object()])
    monkeypatch.setattr(settings_service, "effective_core_settings", _stored)
    monkeypatch.setattr(store, "_SAID_UNREAD", [False])

    def _refresh() -> None:
        monkeypatch.setattr(store, "_READ_AT", [float("-inf")])
        asyncio.run(store.refresh(_maker(gone)))  # never fails the request

    def _said(text: str) -> int:
        return sum(text in r.getMessage() for r in caplog.records)

    refreshed = "were not read; the reading before stays in force"
    loaded = "The servers' kept declarations were not read (OperationalError)"
    with caplog.at_level(logging.INFO):
        assert asyncio.run(store.load(gone)) == -1
        assert _said(loaded) == 1
        _refresh()
        _refresh()
        # The outage is the refresh's failure, said once, though load raised nothing.
        assert store.refresh_failure() == "the servers' kept declarations (OperationalError)"
        assert _said(refreshed) == 1
        assert _said(loaded) == 1
        assert _said("are read again") == 0
        # Both reads succeed: said, and the failure is over.
        gone.down = False
        _refresh()
        assert store.refresh_failure() is None
        assert _said("are read again") == 1
        # A second outage after the recovery is said again, by load and by the refresh.
        gone.down = True
        _refresh()
        assert _said(loaded) == 2
        assert _said(refreshed) == 2
        # And with the settings failing as well, both reads are named.
        settings_read[0] = ValueError("bad")
        _refresh()
        assert store.refresh_failure() == (
            "the servers' kept declarations (OperationalError) and the stored settings (ValueError)"
        )
        assert _said(refreshed) == 3
        assert _said("are read again") == 1


def test_a_store_not_migrated_yet_is_said_once(caplog: pytest.LogCaptureFixture) -> None:
    import logging

    engine = create_engine("sqlite://")  # no table
    with Session(engine) as session, caplog.at_level(logging.WARNING):
        store._SAID_UNREAD[0] = False
        assert asyncio.run(store.load(_Awaited(session))) == -1
        assert asyncio.run(store.load(_Awaited(session))) == -1
    said = [r for r in caplog.records if "kept declarations were not read" in r.getMessage()]
    assert len(said) == 1


def test_a_job_s_start_forgets_a_moved_block_and_reaches_no_server(
    db: _Awaited, monkeypatch: pytest.MonkeyPatch
) -> None:
    from malspark.core.config import Settings
    from malspark.providers import served_listing

    listed: list[Any] = []

    async def _list(settings: Any, **kwargs: Any) -> list[str]:
        listed.append(settings)
        return []

    monkeypatch.setattr(served_listing, "list_unlisted", _list)
    sd.register_served("mcp:knowledge", dict(builtin_tools("knowledge")), "an earlier launch")
    asyncio.run(store.save(db))
    settings = Settings(_env_file=None)
    asyncio.run(store.prepare_job(_maker(db), settings))
    assert listed == []
    # Kept under another launch than the block's: forgotten, here and in the store.
    assert builtin_tools("knowledge") == {}
    assert "mcp:knowledge" not in _rows(db)
    # The listing is a step of its own, for a run known not to be a mock.
    asyncio.run(store.list_before_run(_maker(db), settings))
    assert listed == [settings]


def test_a_job_lists_its_servers_through_their_attach_and_keeps_what_they_serve(
    db: _Awaited, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real start of a job: each server listed through the handle a run attaches by."""
    import functools
    import json
    from pathlib import Path

    from malspark.core.config import Settings
    from malspark.core.tool_declarations import launch_identity
    from malspark.providers import served_listing, server_probe
    from malspark.providers.servers import ServerHandle
    from malspark.tools.declared_facts import FACTS_META_KEY

    captured = json.loads(
        (
            Path(__file__).resolve().parents[2] / "fixtures" / "own_server_tool_facts.json"
        ).read_text()
    )

    class _Serving(ServerHandle):
        """A server that lists its tools, each declared under ``_meta``, and nothing else."""

        async def aopen(self, job_id: str, **context: Any) -> None:
            from malspark.core.served_declarations import served_tool_facts

            listing = [
                {"name": tool, "inputSchema": {"type": "object"}, "_meta": {FACTS_META_KEY: f}}
                for tool, f in captured[self.name].items()
            ]
            toolkit = type("Kit", (), {"served_tool_facts": served_tool_facts(listing)})()
            self._note_served_declarations(toolkit)

        def all_tool_names(self) -> list[str]:
            return list(captured[self.name])

        async def aclose(self) -> None:
            return None

    real = importlib_handshake = server_probe.handshake
    monkeypatch.setattr(server_probe, "handshake", functools.partial(real, handle_factory=_Serving))
    del importlib_handshake
    monkeypatch.setattr(served_listing, "unlisted", _unlisted)
    # A fresh install: nothing kept, nothing held.
    sd.forget_served()
    sd._UNSAVED.clear()
    asyncio.run(store.save(db))
    settings = Settings(_env_file=None)
    asyncio.run(store.prepare_job(_maker(db), settings))
    asyncio.run(store.list_before_run(_maker(db), settings))
    enabled = {k for k, b in settings.mcp.servers.items() if b.enabled and k in captured}
    rows = _rows(db)
    assert set(rows) == {f"mcp:{k}" for k in enabled}
    for key in enabled:
        launch, kept = rows[f"mcp:{key}"]
        assert launch == launch_identity(settings.mcp.servers[key])
        assert kept == {
            t: sd._set_fields(ToolFacts.model_validate(f)) for t, f in captured[key].items()
        }
    # Another process reads them back as every reader reads them.
    sd.forget_served()
    sd._UNSAVED.clear()
    asyncio.run(store.load(db))
    for key in enabled:
        assert set(builtin_tools(key)) == set(captured[key])


def _staged(server: str, **fields: Any) -> dict[str, Any]:
    from malspark.core.config import Settings

    entry = Settings(_env_file=None).mcp.servers[server].model_dump(mode="json")
    entry.pop("auth_token", None)
    return {"core.mcp.servers": {server: {**entry, **fields}}}


def test_a_connection_test_keeps_only_what_the_saved_block_s_server_declared(
    db: _Awaited,
) -> None:
    from malspark.core.config import Settings
    from malspark.core.tool_declarations import launch_identity

    shipped = Settings(_env_file=None).mcp.servers["analysis"]
    stored: dict[str, Any] = {}
    # The saved block's own server, nothing staged: kept and saved.
    before = sd.snapshot_served("mcp:analysis")
    sd.register_served("mcp:analysis", {"t": ToolFacts(kind="strings")}, launch_identity(shipped))
    assert asyncio.run(store.keep_probe_listing(db, "analysis", stored, {}, before))
    assert _rows(db)["mcp:analysis"][1] == {"t": {"kind": "strings"}}
    kept = sd.snapshot_served("mcp:analysis")
    # Staged values equal to the saved block, field by field: kept too.
    sd.register_served("mcp:analysis", {"t": ToolFacts(kind="strings")}, launch_identity(shipped))
    assert asyncio.run(store.keep_probe_listing(db, "analysis", stored, _staged("analysis"), kept))
    # Staged values that reach the server otherwise: put back, never saved.
    sd.register_served("mcp:analysis", {"u": ToolFacts(kind="identity")}, "a staged launch")
    staged = _staged("analysis", url="http://elsewhere:1/mcp", transport="streamable-http")
    assert not asyncio.run(store.keep_probe_listing(db, "analysis", stored, staged, kept))
    assert sd.snapshot_served("mcp:analysis") == kept
    assert _rows(db)["mcp:analysis"][1] == {"t": {"kind": "strings"}}
    # An entry no saved block holds: put back as well.
    sd.register_served("mcp:unsaved", {"u": ToolFacts(kind="identity")}, "L")
    assert not asyncio.run(store.keep_probe_listing(db, "unsaved", stored, {}, (None, False)))
    assert sd.held_served("mcp:unsaved") is None
    assert "mcp:unsaved" not in _rows(db)


def test_a_staged_environment_is_another_entry_than_the_saved_one(db: _Awaited) -> None:
    from malspark.core.config import Settings
    from malspark.core.tool_declarations import launch_identity

    shipped = Settings(_env_file=None).mcp.servers["analysis"]
    before = sd.snapshot_served("mcp:analysis")
    # Same launch identity, another environment: what it lists may be another program's.
    sd.register_served("mcp:analysis", {"u": ToolFacts(kind="identity")}, launch_identity(shipped))
    staged = _staged("analysis", env={"PYTHONPATH": "/opt/elsewhere"})
    assert not asyncio.run(store.keep_probe_listing(db, "analysis", {}, staged, before))
    assert sd.snapshot_served("mcp:analysis") == before
    assert "mcp:analysis" not in _rows(db)


def test_a_staged_server_that_declares_nothing_never_takes_the_saved_row(db: _Awaited) -> None:
    sd._UNSAVED.add("mcp:analysis")
    asyncio.run(store.save(db))
    saved = _rows(db)["mcp:analysis"]
    # Held and unsaved before the test: so it stays.
    sd._UNSAVED.add("mcp:analysis")
    before = sd.snapshot_served("mcp:analysis")
    # The staged server listed and declared nothing: the source is forgotten here.
    sd.register_served("mcp:analysis", {}, "a staged launch")
    staged = _staged("analysis", url="http://elsewhere:1/mcp", transport="streamable-http")
    assert not asyncio.run(store.keep_probe_listing(db, "analysis", {}, staged, before))
    assert sd.snapshot_served("mcp:analysis") == before
    assert "mcp:analysis" in {row[0] for row in sd.unsaved()}
    assert _rows(db)["mcp:analysis"] == saved


def test_the_api_reads_a_moved_built_in_through_its_stored_block(
    db: _Awaited, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The API installs no settings: it reads its built-ins through the stored ones."""
    from app import database, deps
    from app.services import settings_service
    from malspark.core import declared_reading
    from malspark.core.declared_reading import shipped_by_name, ships_tool
    from malspark.core.settings_overrides import build_settings
    from malspark.core.tool_declarations import launch_identity

    stored = build_settings(
        {
            "mcp.servers": {
                "analysis": {
                    "transport": "streamable-http",
                    "url": "http://analysis-mcp:8098/mcp",
                    "trusts_served_declaration": True,
                    "enabled": True,
                }
            }
        }
    )

    async def _stored(session: Any) -> Any:
        return stored

    tools = dict(builtin_tools("analysis"))
    names = len(shipped_by_name())
    # Listed at the container by a job, and kept; nothing under the shipped launch.
    sd.forget_served("mcp:analysis")
    sd.register_served("mcp:analysis", tools, launch_identity(stored.mcp.servers["analysis"]))
    # Every own server is kept, as a deployment's store holds them, and what
    # was read of the reputation service's listing.
    sd._UNSAVED.update(sd._SERVED)
    sd._UNSAVED.update(sd._DERIVED)
    asyncio.run(store.save(db))
    sd._UNSAVED.clear()
    monkeypatch.setattr(declared_reading, "_READ_THROUGH", [None])
    assert builtin_tools("analysis") == {}
    monkeypatch.setattr(settings_service, "effective_core_settings", _stored)
    monkeypatch.setattr(database, "async_session_factory", _maker(db))
    monkeypatch.setattr(store, "_READ_AT", [float("-inf")])
    asyncio.run(deps.reads_served_declarations())
    assert set(builtin_tools("analysis")) == set(tools)
    assert ships_tool("mcp:analysis", "carve_payloads")
    assert len(shipped_by_name()) == names
