"""Verify a job's stored ledger against its seal, from the database or a stored-run directory.

    python -m scripts.ledger.verify --job <job uuid> [--database-url URL]
    python -m scripts.ledger.verify --run <directory>

``--job`` reads the job's ledger rows, its report and the chained audit rows in
one read-only transaction (``SET TRANSACTION READ ONLY``, rolled back at the
end), the way the replay export reads a job, and checks them with
``app.services.ledger_verify``. ``--run`` reads a stored-run directory
(``evidence.json``, ``report.json``, ``run-summary.json``, ``stix-bundle.json``
and ``report-byjob.json`` where present) with no database; the audit log is not
in such a directory, and the answer says it was not checked.

The keys are the ones the platform's settings derive
(``SETTINGS_ENCRYPTION_KEY`` in the environment). The answer is printed as
JSON. Exit status: 0 verified, 1 broken, 3 not sealed, 4 sealed under a key
this environment cannot derive, 5 unverifiable (audit rows or head under a key
this environment cannot derive), 2 a usage or read error.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from pathlib import Path
from typing import Any

EXIT = {"verified": 0, "broken": 1, "not_sealed": 3, "other_key": 4, "unverifiable": 5}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def verify_run(directory: Path) -> dict[str, Any]:
    """The verification of a stored-run directory."""
    from app.services.ledger_verify import verify_ledger

    evidence = _load(directory / "evidence.json")
    if isinstance(evidence, dict):
        rows = evidence.get("items") or evidence.get("entries") or []
    else:
        rows = evidence or []
    byjob = _load(directory / "report-byjob.json") or {}
    report = _load(directory / "report.json")
    if report is None:
        report = byjob.get("malware_report")
    summary = _load(directory / "run-summary.json")
    if summary is None:
        summary = byjob.get("run_summary")
    stix = _load(directory / "stix-bundle.json")
    if stix is None:
        stix = byjob.get("stix_bundle")
    job = _load(directory / "job.json") or {}
    job_id = byjob.get("job_id") or job.get("id") or ""
    return verify_ledger(
        job_id,
        list(rows),
        report_seal=byjob.get("ledger_seal"),
        malware_report=report,
        run_summary=summary,
        stix_bundle=stix,
        report_stored=report is not None or bool(byjob.get("id")),
    )


async def verify_database(job_id: uuid.UUID, database_url: str) -> dict[str, Any]:
    """The verification of one job, read in a read-only transaction that is rolled back."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    from app.services.ledger_verify import verify_job

    engine = create_async_engine(database_url, pool_pre_ping=False)
    try:
        async with engine.connect() as conn:
            transaction = await conn.begin()
            try:
                await conn.execute(text("SET TRANSACTION READ ONLY"))
                return await verify_job(conn, job_id)
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.ledger.verify",
        description="Verify a job's stored evidence ledger against its seal.",
    )
    where = parser.add_mutually_exclusive_group(required=True)
    where.add_argument("--job", type=uuid.UUID, help="a job id, read from the database")
    where.add_argument("--run", type=Path, help="a stored-run directory")
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

            verdict = asyncio.run(verify_database(args.job, _database_url(args.database_url)))
    except (OSError, ValueError, LookupError) as exc:
        print(f"could not read the ledger: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(verdict, indent=1, sort_keys=True))
    return EXIT.get(str(verdict.get("status")), 2)


if __name__ == "__main__":
    sys.exit(main())
