"""Every field a ledger entry carries is stored on its row and served back.

``LedgerEntry`` has 29 fields. Each one goes into the row ``_evidence_row``
builds and comes out of ``GET /jobs/{id}/evidence`` unchanged; the entry's
``id`` is the row's ``entry_id``. A row written before the seven newest
columns existed reads with those seven absent, never as false or empty, and
``structured_from_server`` is absent unless it was true.

The revision is run on a bare SQLite table and never imports the application.
"""

from __future__ import annotations

import importlib.util
import json
import uuid
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

from app.schemas.evidence import EvidenceEntryResponse
from app.worker.analysis_worker import _evidence_row
from maljan.schemas.evidence import LedgerEntry

_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261017000000_evidence_keeps_every_entry_field.py"
)

_SEVEN = (
    "source",
    "facts",
    "reputation",
    "pack_step",
    "structured_from_server",
    "agent_role",
    "agent_tab",
)


def _full_entry() -> LedgerEntry:
    """An entry where every one of the 29 fields holds a value other than its default."""
    return LedgerEntry(
        id="ev_0042",
        stage="verdict",
        agent="static",
        server="disasm",
        tool="decompile_function",
        args={"address": "0x401000"},
        symbol="sub_401000",
        ok=False,
        error="the server stopped answering",
        remediation="ask for a smaller function",
        output="int main(void) { return 0; }",
        structured={"lines": 1},
        function_ranges={"0x401000": [["0x401000", "0x401020"]]},
        truncated=True,
        chars_dropped=17,
        repeated_of="ev_0040",
        args_repaired=True,
        args_raw='{"address": "0x401000"',
        model="provider/model-a",
        started_at=1_700_000_000.25,
        duration_ms=1234,
        seq=42,
        source="mcp:disasm",
        facts={"v": 1, "kind": "decompilation", "display_name": "Decompiler"},
        reputation={"v": 1, "service": "lookup", "malicious": 3, "total": 70},
        pack_step={"v": 1, "id": "strings_custom", "label": "Strings"},
        structured_from_server=True,
        agent_role="static",
        agent_tab="static",
    )


def test_the_entry_has_the_twenty_nine_fields_the_round_trip_walks():
    assert len(LedgerEntry.model_fields) == 29
    for name in _SEVEN:
        assert name in LedgerEntry.model_fields


def test_every_field_goes_from_the_entry_through_the_row_to_the_reader():
    entry = _full_entry()
    dump = entry.model_dump(mode="json")
    assert set(dump) == set(LedgerEntry.model_fields)

    row = _evidence_row(dump, job_id=uuid.uuid4())
    row.id = uuid.uuid4()
    served = EvidenceEntryResponse.model_validate(row).model_dump(mode="json")

    for name, value in dump.items():
        key = "entry_id" if name == "id" else name
        assert served[key] == value, name


def test_the_served_page_carries_the_seven_fields_as_json():
    dump = _full_entry().model_dump(mode="json")
    row = _evidence_row(dump, job_id=uuid.uuid4())
    row.id = uuid.uuid4()
    body = json.loads(EvidenceEntryResponse.model_validate(row).model_dump_json())
    for name in _SEVEN:
        assert body[name] == dump[name], name


def test_an_entry_without_the_seven_writes_none_of_them():
    dump = LedgerEntry(id="ev_0001", tool="pe_info", seq=1).model_dump(mode="json")
    for name in _SEVEN:
        assert name not in dump

    row = _evidence_row(dump, job_id=uuid.uuid4())
    for name in _SEVEN:
        assert getattr(row, name) is None, name


def test_structured_from_server_is_stored_only_when_true():
    row = _evidence_row(
        {"id": "ev_0001", "tool": "t", "structured_from_server": False},
        job_id=uuid.uuid4(),
    )
    assert row.structured_from_server is None


def _row_as_the_database_hands_it(**columns: Any) -> Any:
    from app.models.evidence import EvidenceEntry

    base = {
        "id": uuid.uuid4(),
        "job_id": uuid.uuid4(),
        "entry_id": "ev_0001",
        "stage": "analysis",
        "agent": "static",
        "server": None,
        "tool": "pe_info",
        "ok": True,
        "duration_ms": 3,
        "seq": 1,
        "args": {},
        "output": "",
        "structured": None,
    }
    base.update(columns)
    return EvidenceEntry(**base)


def test_an_old_row_reads_with_the_seven_absent():
    old = _row_as_the_database_hands_it(**dict.fromkeys(_SEVEN))
    served = json.loads(EvidenceEntryResponse.model_validate(old).model_dump_json())
    for name in _SEVEN:
        assert name not in served, name
    # The fields the row always had are served as before.
    assert served["entry_id"] == "ev_0001"
    assert served["truncated"] is False


def test_a_stored_false_reads_as_absent_too():
    row = _row_as_the_database_hands_it(structured_from_server=False)
    served = json.loads(EvidenceEntryResponse.model_validate(row).model_dump_json())
    assert "structured_from_server" not in served


def _load():
    spec = importlib.util.spec_from_file_location("evidence_keeps_every_entry_field", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(conn, step) -> None:
    mod = _load()
    context = MigrationContext.configure(conn)
    with Operations.context(context):
        mod.op = Operations(context)
        step(mod)


def test_the_revision_follows_the_memory_plugin_one():
    mod = _load()
    assert mod.revision == "20261017000000"
    assert mod.down_revision == "20261016000000"


def test_an_older_row_holds_none_of_the_seven_and_the_downgrade_takes_them_away():
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        conn.execute(sa.text("CREATE TABLE evidence_entries (id INTEGER PRIMARY KEY, tool TEXT)"))
        conn.execute(sa.text("INSERT INTO evidence_entries (tool) VALUES ('pe_info')"))

        _run(conn, lambda mod: mod.upgrade())
        row = conn.execute(sa.text(f"SELECT {', '.join(_SEVEN)} FROM evidence_entries")).one()
        assert tuple(row) == (None,) * len(_SEVEN)

        _run(conn, lambda mod: mod.downgrade())
        columns = [c["name"] for c in sa.inspect(conn).get_columns("evidence_entries")]
        assert not set(_SEVEN) & set(columns)
