"""Each stored ledger row carries a digest of every column it persists and its chain value.

The digest is taken over the row as the worker builds it, and the same digest
comes back from the row read out of a database and from the evidence page a
client downloads: the canonical form is what makes the three agree. The chain
runs in ``seq`` order from a genesis value bound to the job, under a key derived
from the settings encryption key (keyed HMAC), so a changed,
removed or reordered row changes every chain value after it.
"""

from __future__ import annotations

import importlib.util
import json
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.compiler import compiles
from tests.integration._session_probe import SessionFactory, fake_job, fake_sample, rows_for

from app.models.evidence import EvidenceEntry
from app.schemas.evidence import EvidenceEntryResponse
from app.services import ledger_chain
from app.worker.analysis_worker import _evidence_row, _store_the_report
from maljan.core.config import Settings
from maljan.schemas.evidence import LedgerEntry


@compiles(postgresql.JSONB, "sqlite")
def _jsonb_as_json(element, compiler, **kw):  # noqa: ANN001, ANN202
    return "JSON"


_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261020000000_evidence_entries_carry_their_chain.py"
)
_WRITTEN = datetime(2026, 10, 18, 12, 0, 0, 123456, tzinfo=UTC)
KEY = ledger_chain.derive_key("chain-test-material")


def _entry(seq: int, **extra: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "id": f"ev_{seq:04d}",
        "tool": "decompile_function",
        "agent": "static",
        "server": "disasm",
        "args": {"address": "0x401000", "depth": 2.0, "ratio": 0.1},
        "output": "int main(void) { return 0; }\r\n",
        "structured": {"lines": 1, "big": 1e20, "list": [1.5, 2.0, None, True]},
        "started_at": 1_700_000_000.25 + seq,
        "duration_ms": 12,
        "seq": seq,
        "facts": {"v": 1, "kind": "decompilation"},
        "spilled": [
            {"part": "answer", "key": "evidence/j/" + "a" * 64, "bytes": 9, "sha256": "a" * 64}
        ],
    }
    fields.update(extra)
    return LedgerEntry(**fields).model_dump(mode="json")


def _rows(job_id: uuid.UUID, count: int) -> list[Any]:
    return [
        _evidence_row(_entry(seq), job_id=job_id, written_at=_WRITTEN)
        for seq in range(1, count + 1)
    ]


def test_every_column_is_digested_or_named_as_bookkeeping():
    columns = {c.name for c in EvidenceEntry.__table__.columns}
    digested = set(ledger_chain.DIGESTED)
    bookkeeping = set(ledger_chain.BOOKKEEPING)
    assert not digested & bookkeeping
    assert digested | bookkeeping == columns


def test_a_stored_ledger_row_has_every_column_known_before_the_insert():
    unstamped = _entry(1, started_at=0.0)
    row = _evidence_row(unstamped, job_id=uuid.uuid4(), written_at=_WRITTEN)
    assert row.created_at == _WRITTEN


def test_the_chain_runs_in_seq_order_from_the_job_s_genesis():
    job_id = uuid.uuid4()
    rows = _rows(job_id, 3)
    head = ledger_chain.chain_rows(job_id, list(reversed(rows)), KEY)
    previous = ledger_chain.genesis(job_id, KEY)
    for row in rows:
        assert row.digest == ledger_chain.entry_digest(row)
        assert row.chain == ledger_chain.link(previous, row.digest, KEY)
        previous = row.chain
    assert head == rows[-1].chain
    assert ledger_chain.genesis(job_id, KEY) != ledger_chain.genesis(uuid.uuid4(), KEY)
    assert ledger_chain.chain_rows(job_id, [], KEY) == ledger_chain.genesis(job_id, KEY)


@pytest.mark.parametrize("name", ledger_chain.DIGESTED)
def test_a_change_to_any_digested_column_changes_the_digest(name: str):
    row = _rows(uuid.uuid4(), 1)[0]
    before = ledger_chain.entry_digest(row)
    value = getattr(row, name)
    if name == "created_at":
        changed: Any = datetime(2020, 1, 1, tzinfo=UTC)
    elif isinstance(value, bool):
        changed = not value
    elif isinstance(value, int | float):
        changed = value + 1
    elif isinstance(value, dict):
        changed = {**value, "x": 1}
    elif isinstance(value, list):
        changed = [*value, {"part": "output"}]
    elif value is None:
        changed = {"set": True} if name in {"reputation", "pack_step", "function_ranges"} else "x"
    else:
        changed = f"{value}x"
    setattr(row, name, changed)
    assert ledger_chain.entry_digest(row) != before


def test_numbers_read_as_jsonb_hands_them_back():
    assert ledger_chain.json_value({"a": 1.0}) == ledger_chain.json_value({"a": 1})
    assert ledger_chain.json_value(1e20) == 100000000000000000000
    assert ledger_chain.json_value(1.5e300) == 15 * 10**299
    assert ledger_chain.json_value(0.1) == 0.1
    assert ledger_chain.json_value(2**64 + 1) == 2**64 + 1
    assert ledger_chain.json_value(True) is True


def test_the_digest_survives_the_database_round_trip():
    from app.models import job as _job  # noqa: F401 — the foreign key's table

    job_id = uuid.uuid4()
    rows = _rows(job_id, 2)
    rows.append(_evidence_row(_entry(3, started_at=0.0), job_id=job_id, written_at=_WRITTEN))
    ledger_chain.chain_rows(job_id, rows, KEY)
    table = EvidenceEntry.__table__
    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        table.create(conn)
        for row in rows:
            values = {c.name: getattr(row, c.name) for c in table.columns}
            values["id"] = uuid.uuid4()
            values["updated_at"] = _WRITTEN
            conn.execute(table.insert().values(**values))
        read = conn.execute(sa.select(table).order_by(table.c.seq)).mappings().all()
    assert [ledger_chain.entry_digest(r) for r in read] == [r.digest for r in rows]
    assert [r["chain"] for r in read] == [r.chain for r in rows]


def test_the_digest_survives_the_evidence_page():
    job_id = uuid.uuid4()
    rows = _rows(job_id, 2)
    ledger_chain.chain_rows(job_id, rows, KEY)
    for row in rows:
        row.id = uuid.uuid4()
        body = json.loads(EvidenceEntryResponse.model_validate(row).model_dump_json())
        assert body["digest"] == row.digest
        assert body["chain"] == row.chain
        assert ledger_chain.entry_digest(body) == row.digest


def test_an_older_row_serves_no_digest_and_no_chain():
    row = _evidence_row(_entry(1), job_id=uuid.uuid4())
    row.id = uuid.uuid4()
    body = EvidenceEntryResponse.model_validate(row).model_dump(mode="json")
    assert "digest" not in body
    assert "chain" not in body


@pytest.mark.asyncio
async def test_the_stored_ledger_is_chained_as_it_is_inserted(monkeypatch: Any):
    monkeypatch.setattr(ledger_chain, "platform_key", lambda: KEY)
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))
    state = {
        "evidence_ledger": [_entry(2), _entry(1), _entry(3, started_at=0.0)],
        "malware_report": None,
    }
    async with factory() as db:
        await _store_the_report(
            db,
            job_uuid=job.id,
            job_id=str(job.id),
            pipeline_result=state,
            stix_bundle=None,
            run_summary={},
            transcript=[],
            core_settings=Settings(_env_file=None),
        )
    stored = [o for s in factory.sessions for o in s.added if isinstance(o, EvidenceEntry)]
    assert [r.seq for r in stored] == [1, 2, 3]
    assert all(r.created_at is not None for r in stored)
    previous = ledger_chain.genesis(job.id, KEY)
    for row in stored:
        assert row.digest == ledger_chain.entry_digest(row)
        assert row.chain == ledger_chain.link(previous, row.digest, KEY)
        previous = row.chain


def test_chaining_is_linear_in_the_ledger_s_size():
    job_id = uuid.uuid4()
    small = _rows(job_id, 300)
    large = _rows(job_id, 3000)
    started = time.perf_counter()
    ledger_chain.chain_rows(job_id, small, KEY)
    small_time = time.perf_counter() - started
    started = time.perf_counter()
    ledger_chain.chain_rows(job_id, large, KEY)
    large_time = time.perf_counter() - started
    assert large_time < max(small_time, 1e-3) * 30


def _load():
    spec = importlib.util.spec_from_file_location("evidence_entries_carry_their_chain", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_revision_follows_the_kept_parts_one():
    mod = _load()
    assert mod.revision == "20261020000000"
    assert mod.down_revision == "20261019000000"


def test_an_older_row_holds_no_chain_and_the_downgrade_takes_the_columns():
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        conn.execute(sa.text("CREATE TABLE evidence_entries (id INTEGER PRIMARY KEY, tool TEXT)"))
        conn.execute(sa.text("INSERT INTO evidence_entries (tool) VALUES ('pe_info')"))
        mod = _load()
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()
            row = conn.execute(sa.text("SELECT digest, chain FROM evidence_entries")).one()
            assert tuple(row) == (None, None)
            mod.downgrade()
        columns = {c["name"] for c in sa.inspect(conn).get_columns("evidence_entries")}
        assert not {"digest", "chain"} & columns
