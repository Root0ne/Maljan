"""Where the pack's own readings ran is stored on the entry's row, served back and sealed when set.

``ran_on`` (T-324) names, as sources, where the platform's readings behind a
triage pack entry ran when one ran on a server of its own
(``maljan.tools.readers``). It goes into the row ``_evidence_row`` builds,
comes out of the reader as the entry carried it, and reads back into a ledger
entry unchanged. A row written before the column, or for an entry whose
readings all ran in the worker, holds none and reads as empty; the chain
digest seals it only when set, so a ledger sealed before the column existed
still verifies.

The revision is run on a bare SQLite table and never imports the application.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from importlib import util
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

from app.models.evidence import EvidenceEntry
from app.schemas.evidence import EvidenceEntryResponse
from app.services import ledger_chain
from app.worker.analysis_worker import _evidence_row
from maljan.schemas.evidence import LedgerEntry

_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261031000000_evidence_entries_name_where_readings_ran.py"
)
_WRITTEN = datetime(2026, 10, 18, 12, 0, 0, 123456, tzinfo=UTC)
# The digest of the row below as the chain computed it before the column
# existed (``test_the_nulls_a_call_left_out_are_stored_and_served``); it must
# not move.
_PINNED_DIGEST = "2cb274ce8181a1252aecfe2ff5ce13ec29dafc531e16ff3aa10bcc489cf3b306"


def _entry(seq: int, **extra: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "id": f"ev_{seq:04d}",
        "tool": "decompile_function",
        "agent": "static",
        "server": "disasm",
        "args": {"address": "0x401000"},
        "output": "int main(void) { return 0; }",
        "started_at": 1_700_000_000.0 + seq,
        "duration_ms": 12,
        "seq": seq,
    }
    fields.update(extra)
    return LedgerEntry(**fields).model_dump(mode="json")


def _served(row: Any) -> dict[str, Any]:
    row.id = uuid.uuid4()
    return json.loads(EvidenceEntryResponse.model_validate(row).model_dump_json())


def test_the_row_keeps_it_and_the_reader_serves_it_as_the_entry_had_it() -> None:
    dump = _entry(1, source="pack", ran_on=["mcp:analysis", "pack"])
    row = _evidence_row(dump, job_id=uuid.uuid4(), written_at=_WRITTEN)

    assert row.ran_on == ["mcp:analysis", "pack"]
    served = _served(row)
    assert served["ran_on"] == ["mcp:analysis", "pack"]
    back = LedgerEntry.model_validate({**served, "id": served["entry_id"]})
    assert back.ran_on == ["mcp:analysis", "pack"]


def test_an_entry_whose_readings_ran_in_the_worker_stores_none_and_reads_as_empty() -> None:
    row = _evidence_row(_entry(1, source="pack"), job_id=uuid.uuid4(), written_at=_WRITTEN)

    assert row.ran_on is None
    served = _served(row)
    assert "ran_on" not in served
    back = LedgerEntry.model_validate({**served, "id": served["entry_id"]})
    assert back.ran_on == []


def test_an_old_row_or_a_stored_empty_list_reads_as_absent() -> None:
    for value in (None, []):
        row = EvidenceEntry(
            id=uuid.uuid4(),
            job_id=uuid.uuid4(),
            entry_id="ev_0001",
            stage="analysis",
            agent="static",
            tool="pe_info",
            ok=True,
            duration_ms=3,
            seq=1,
            args={},
            output="",
            ran_on=value,
        )
        served = json.loads(EvidenceEntryResponse.model_validate(row).model_dump_json())
        assert "ran_on" not in served


def test_a_row_without_it_keeps_the_digest_it_was_sealed_with() -> None:
    row = _evidence_row(_entry(1), job_id=uuid.uuid4(), written_at=_WRITTEN)

    assert ledger_chain.entry_digest(row) == _PINNED_DIGEST


def test_it_is_sealed_when_set() -> None:
    job = uuid.uuid4()
    plain = _evidence_row(_entry(1), job_id=job, written_at=_WRITTEN)
    placed = _evidence_row(_entry(1, ran_on=["mcp:analysis"]), job_id=job, written_at=_WRITTEN)
    assert ledger_chain.entry_digest(placed) != ledger_chain.entry_digest(plain)
    assert "ran_on" in ledger_chain.DIGESTED
    assert "ran_on" in {c.name for c in EvidenceEntry.__table__.columns}


def _load() -> Any:
    spec = util.spec_from_file_location("evidence_where_readings_ran", _REV)
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_revision_follows_the_single_head() -> None:
    mod = _load()
    assert mod.revision == "20261031000000"
    assert mod.down_revision == "20261030000000"


def test_an_older_row_holds_none_and_the_downgrade_takes_it_away() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        conn.execute(sa.text("CREATE TABLE evidence_entries (id INTEGER PRIMARY KEY, tool TEXT)"))
        conn.execute(sa.text("INSERT INTO evidence_entries (tool) VALUES ('pe_info')"))
        mod = _load()
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()
            row = conn.execute(sa.text("SELECT ran_on FROM evidence_entries"))
            assert tuple(row.one()) == (None,)
            # Run twice, it changes nothing the second time.
            mod.upgrade()
            mod.downgrade()
        columns = {c["name"] for c in sa.inspect(conn).get_columns("evidence_entries")}
        assert "ran_on" not in columns
