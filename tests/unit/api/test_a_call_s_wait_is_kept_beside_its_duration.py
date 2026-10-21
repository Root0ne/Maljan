"""A call's queue wait is stored as its own column and sealed by the ledger chain when set.

``waited_ms`` is how long a call queued for a slot at its server; ``duration_ms``
runs from when it was sent. The stored row keeps both, the moment the call came
back is the start plus both, and the chain's digest seals a non-zero wait while
a row with none digests as it did, so a ledger sealed before the column existed
still verifies.
"""

from __future__ import annotations

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
from app.worker.analysis_worker import _evidence_row, _returned_at
from maljan.schemas.evidence import LedgerEntry

_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261027000000_evidence_entries_carry_their_wait.py"
)
_WRITTEN = datetime(2026, 10, 18, 12, 0, 0, 123456, tzinfo=UTC)
KEY = ledger_chain.derive_key("chain-test-material")

# The digest of the row below as the chain computed it before ``waited_ms``
# existed; it must not move.
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


def test_the_row_keeps_the_wait_and_the_reader_is_served_it() -> None:
    row = _evidence_row(_entry(1, waited_ms=700), job_id=uuid.uuid4(), written_at=_WRITTEN)
    row.id = uuid.uuid4()

    assert row.waited_ms == 700
    assert EvidenceEntryResponse.model_validate(row).waited_ms == 700
    assert _evidence_row(_entry(2), job_id=uuid.uuid4(), written_at=_WRITTEN).waited_ms == 0


def test_a_call_came_back_after_its_wait_and_its_run() -> None:
    queued = _entry(1, waited_ms=5_000, duration_ms=100)
    holder = _entry(2, started_at=queued["started_at"], waited_ms=0, duration_ms=1_000)
    plain = _entry(3, started_at=queued["started_at"], duration_ms=100)

    assert _returned_at(queued) == datetime.fromtimestamp(queued["started_at"] + 5.1, tz=UTC)
    # The call that held the slot came back before the one that queued behind it.
    assert _returned_at(holder) < _returned_at(queued)
    assert _returned_at(plain) == datetime.fromtimestamp(queued["started_at"] + 0.1, tz=UTC)


def test_a_row_with_no_wait_keeps_the_digest_it_was_sealed_with() -> None:
    plain = _evidence_row(_entry(1), job_id=uuid.uuid4(), written_at=_WRITTEN)

    assert plain.waited_ms == 0
    assert ledger_chain.entry_digest(plain) == _PINNED_DIGEST


def test_a_wait_is_sealed() -> None:
    job = uuid.uuid4()
    plain = _evidence_row(_entry(1), job_id=job, written_at=_WRITTEN)
    waited = _evidence_row(_entry(1), job_id=job, written_at=_WRITTEN)
    waited.waited_ms = 321

    assert ledger_chain.entry_digest(waited) != ledger_chain.entry_digest(plain)


def test_changing_a_sealed_rows_wait_breaks_verification() -> None:
    job = uuid.uuid4()
    rows = [
        _evidence_row(_entry(seq, waited_ms=321), job_id=job, written_at=_WRITTEN) for seq in (1, 2)
    ]
    head = ledger_chain.chain_rows(job, rows, KEY)
    assert head == rows[-1].chain
    assert rows[0].digest == ledger_chain.entry_digest(rows[0])

    rows[0].waited_ms = 0
    assert rows[0].digest != ledger_chain.entry_digest(rows[0])
    again = ledger_chain.chain_rows(job, rows, KEY)
    assert again != head


def _load() -> Any:
    spec = util.spec_from_file_location("evidence_waited_ms", _REV)
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_revision_follows_the_single_head() -> None:
    mod = _load()
    assert mod.revision == "20261027000000"
    assert mod.down_revision == "20261026000000"


def test_an_older_row_reads_zero_and_the_downgrade_takes_the_column() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        conn.execute(sa.text("CREATE TABLE evidence_entries (id INTEGER PRIMARY KEY, tool TEXT)"))
        conn.execute(sa.text("INSERT INTO evidence_entries (tool) VALUES ('pe_info')"))
        mod = _load()
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()
            assert conn.execute(sa.text("SELECT waited_ms FROM evidence_entries")).scalar() == 0
            mod.downgrade()
        columns = {c["name"] for c in sa.inspect(conn).get_columns("evidence_entries")}
        assert "waited_ms" not in columns


def test_the_model_declares_the_column() -> None:
    assert "waited_ms" in {c.name for c in EvidenceEntry.__table__.columns}
