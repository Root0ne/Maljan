"""Verify a job's stored ledger against its seal, from the database or a stored-run directory.

    python -m scripts.ledger.verify --job <job uuid> [--database-url URL]
    python -m scripts.ledger.verify --run <directory>
    python -m scripts.ledger.verify --audit-chain [--database-url URL]

``--job`` reads the job's ledger rows, its report row and its own chained audit
rows (with the chain value before each and the head) in one read-only
transaction (``SET TRANSACTION READ ONLY``, rolled back at the end), the way
the replay export reads a job, and checks them with
``app.services.ledger_verify``. ``--run`` reads a stored-run directory
(``evidence.json`` and ``report-byjob.json``, with ``report.json``,
``run-summary.json``, ``stix-bundle.json`` and ``stix-judge.json`` where
present) with no database; the audit log is not in such a directory, and the
answer says it was not checked. ``--audit-chain`` walks the whole audit chain
from its first row to its head, for the operator: it is the walk that finds
rows cut off the end of the chain, which a job's own verification cannot see.

The keys are the ones the platform's settings derive
(``SETTINGS_ENCRYPTION_KEY`` in the environment). The answer is printed as
JSON. Exit status: 0 verified, 1 broken, 3 not sealed, 4 sealed under a key
this environment cannot derive, 5 unverifiable, 6 deleted by its owner, 2 a
usage or read error.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from pathlib import Path
from typing import Any

EXIT = {
    "verified": 0,
    "broken": 1,
    "not_sealed": 3,
    "other_key": 4,
    "unverifiable": 5,
    "deleted": 6,
}
_MISSING = object()


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else _MISSING


def _column(byjob: dict[str, Any], name: str, file: Any) -> Any:
    """A report column from its own file where the export wrote one, else from the row."""
    return file if file is not _MISSING else byjob.get(name)


def report_row(directory: Path) -> dict[str, Any] | None:
    """The stored report row a stored-run directory holds, ``None`` when it holds none."""
    loaded = _load(directory / "report-byjob.json")
    byjob = loaded if isinstance(loaded, dict) else {}
    payload = _load(directory / "report.json")
    if not byjob.get("id") and payload is _MISSING:
        return None
    from app.services.ledger_chain import REPORT_DIGESTED

    row = {name: byjob.get(name) for name in REPORT_DIGESTED}
    row["id"] = byjob.get("id")
    row["ledger_seal"] = byjob.get("ledger_seal")
    row["malware_report"] = _column(byjob, "malware_report", payload)
    row["run_summary"] = _column(byjob, "run_summary", _load(directory / "run-summary.json"))
    row["stix_bundle"] = _column(byjob, "stix_bundle", _load(directory / "stix-bundle.json"))
    row["judge_stix_bundle"] = _column(
        byjob, "judge_stix_bundle", _load(directory / "stix-judge.json")
    )
    return row


def verify_run(directory: Path) -> dict[str, Any]:
    """The verification of a stored-run directory."""
    from app.services.ledger_verify import verify_ledger

    evidence = _load(directory / "evidence.json")
    if isinstance(evidence, dict):
        rows = evidence.get("items") or evidence.get("entries") or []
    else:
        rows = evidence if isinstance(evidence, list) else []
    byjob = _load(directory / "report-byjob.json")
    job = _load(directory / "job.json")
    job_id = (byjob.get("job_id") if isinstance(byjob, dict) else None) or (
        job.get("id") if isinstance(job, dict) else ""
    )
    return verify_ledger(job_id, list(rows), report=report_row(directory))


async def _read_only(database_url: str, work: Any) -> Any:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(database_url, pool_pre_ping=False)
    try:
        async with engine.connect() as conn:
            transaction = await conn.begin()
            try:
                await conn.execute(text("SET TRANSACTION READ ONLY"))
                return await work(conn)
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()


async def verify_database(job_id: uuid.UUID, database_url: str) -> dict[str, Any]:
    """The verification of one job, read in a read-only transaction that is rolled back."""
    from app.services.ledger_verify import verify_job

    return dict(await _read_only(database_url, lambda conn: verify_job(conn, job_id)))


async def walk_audit_chain(conn: Any) -> dict[str, Any]:
    """The whole audit chain from its first row to its head, as one verdict."""
    from sqlalchemy import select

    from app.models.audit import AuditChainHead, AuditLog
    from app.services import audit_chain, ledger_chain

    log = AuditLog.__table__
    rows = (
        (
            await conn.execute(
                select(log).where(log.c.chain_seq.is_not(None)).order_by(log.c.chain_seq)
            )
        )
        .mappings()
        .all()
    )
    heads = AuditChainHead.__table__
    head = (
        (await conn.execute(select(heads).where(heads.c.name == audit_chain.HEAD_NAME)))
        .mappings()
        .first()
    )
    current = ledger_chain.platform_key()
    check = audit_chain.verify_audit_chain(
        rows, ledger_chain.known_keys(), head, current.key_id if current is not None else None
    )
    if check.broken_at is not None:
        status = "broken"
    elif check.head_unverifiable:
        status = "unverifiable"
    else:
        status = "verified"
    return {
        "status": status,
        "reason": check.reason,
        "broken_at": check.broken_at,
        "rows": check.rows,
        "head_seq": check.head_seq,
        "rotated_at_seq": check.rotated_at_seq,
        "verified_rows": len(check.verified),
        "unverifiable": list(check.unverifiable_span or ()),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.ledger.verify",
        description="Verify a job's stored evidence ledger against its seal.",
    )
    where = parser.add_mutually_exclusive_group(required=True)
    where.add_argument("--job", type=uuid.UUID, help="a job id, read from the database")
    where.add_argument("--run", type=Path, help="a stored-run directory")
    where.add_argument(
        "--audit-chain", action="store_true", help="walk the whole audit chain to its head"
    )
    parser.add_argument(
        "--database-url", help="the database to read; DATABASE_URL or the bootstrap settings"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.run is not None:
            if not args.run.is_dir():
                print(f"not a directory: {args.run}", file=sys.stderr)
                return 2
            verdict = verify_run(args.run)
        else:
            from scripts.replay.database import _database_url

            url = _database_url(args.database_url)
            if args.audit_chain:
                verdict = asyncio.run(_read_only(url, walk_audit_chain))
            else:
                verdict = asyncio.run(verify_database(args.job, url))
    except (OSError, ValueError, LookupError) as exc:
        print(f"could not read the ledger: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(verdict, indent=1, sort_keys=True))
    return EXIT.get(str(verdict.get("status")), 2)


if __name__ == "__main__":
    sys.exit(main())
