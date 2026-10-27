"""The nulls a call left out are stored on its row, served back and sealed when set.

``args_nulls_dropped`` and ``args_nulls_withheld`` (T-330) name, by path
segments, the fields of a call whose ``null`` the tool boundary dropped or the
transport did not send. Each goes into the row ``_evidence_row`` builds, comes
out of the reader as the entry carried it, and reads back into a ledger entry
unchanged. A row written before the columns, or for a call with neither, holds
neither and reads as empty; the chain digest seals each only when set, so a
ledger sealed before the columns existed still verifies.

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
    / "apps/api/alembic/versions/20261030000000_evidence_entries_name_the_nulls_left_out.py"
)
_WRITTEN = datetime(2026, 10, 18, 12, 0, 0, 123456, tzinfo=UTC)
_COLUMNS = ("args_nulls_dropped", "args_nulls_withheld")
# The digest of the row below as the chain computed it before the columns
# existed (``test_a_call_s_wait_is_kept_beside_its_duration``); it must not move.
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


def test_the_row_keeps_both_and_the_reader_serves_them_as_the_entry_had_them() -> None:
    dump = _entry(1, args_nulls_dropped=[["limit"], ["a.b"]], args_nulls_withheld=[["depth"]])
    row = _evidence_row(dump, job_id=uuid.uuid4(), written_at=_WRITTEN)

    assert row.args_nulls_dropped == [["limit"], ["a.b"]]
    assert row.args_nulls_withheld == [["depth"]]
    served = _served(row)
    assert served["args_nulls_dropped"] == [["limit"], ["a.b"]]
    assert served["args_nulls_withheld"] == [["depth"]]
    back = LedgerEntry.model_validate({**served, "id": served["entry_id"]})
    assert back.args_nulls_dropped == [["limit"], ["a.b"]]
    assert back.args_nulls_withheld == [["depth"]]


def test_a_call_with_neither_stores_none_and_reads_as_empty() -> None:
    row = _evidence_row(_entry(1), job_id=uuid.uuid4(), written_at=_WRITTEN)

    assert row.args_nulls_dropped is None
    assert row.args_nulls_withheld is None
    served = _served(row)
    for name in _COLUMNS:
        assert name not in served
    back = LedgerEntry.model_validate({**served, "id": served["entry_id"]})
    assert back.args_nulls_dropped == []
    assert back.args_nulls_withheld == []


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
            args_nulls_dropped=value,
            args_nulls_withheld=value,
        )
        served = json.loads(EvidenceEntryResponse.model_validate(row).model_dump_json())
        for name in _COLUMNS:
            assert name not in served


def test_a_row_with_neither_keeps_the_digest_it_was_sealed_with() -> None:
    row = _evidence_row(_entry(1), job_id=uuid.uuid4(), written_at=_WRITTEN)

    assert ledger_chain.entry_digest(row) == _PINNED_DIGEST


def test_each_is_sealed_when_set() -> None:
    job = uuid.uuid4()
    plain = _evidence_row(_entry(1), job_id=job, written_at=_WRITTEN)
    for name in _COLUMNS:
        noted = _evidence_row(_entry(1, **{name: [["limit"]]}), job_id=job, written_at=_WRITTEN)
        assert ledger_chain.entry_digest(noted) != ledger_chain.entry_digest(plain), name


def test_both_are_digested_columns() -> None:
    for name in _COLUMNS:
        assert name in ledger_chain.DIGESTED
        assert name in {c.name for c in EvidenceEntry.__table__.columns}


def _load() -> Any:
    spec = util.spec_from_file_location("evidence_nulls_left_out", _REV)
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_revision_follows_the_single_head() -> None:
    mod = _load()
    assert mod.revision == "20261030000000"
    assert mod.down_revision == "20261029000000"


def test_an_older_row_holds_neither_and_the_downgrade_takes_them_away() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        conn.execute(sa.text("CREATE TABLE evidence_entries (id INTEGER PRIMARY KEY, tool TEXT)"))
        conn.execute(sa.text("INSERT INTO evidence_entries (tool) VALUES ('pe_info')"))
        mod = _load()
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()
            row = conn.execute(sa.text(f"SELECT {', '.join(_COLUMNS)} FROM evidence_entries"))
            assert tuple(row.one()) == (None, None)
            mod.downgrade()
        columns = {c["name"] for c in sa.inspect(conn).get_columns("evidence_entries")}
        assert not set(_COLUMNS) & columns
