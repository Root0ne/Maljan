"""A job read from the database, read-only, into the stored-run layout.

``export_jobs`` opens one read-only transaction (``SET TRANSACTION READ
ONLY``: the database itself refuses any write in it), reads each job's rows —
the job, its report, the per-agent findings, the transcript, the evidence
ledger and the job's events — and writes them into a directory per job, in
the layout :mod:`scripts.replay.stored` reads. The transaction is rolled back
when the read ends. Nothing in the database is written, locked for writing
or changed. The reader and the writer are the platform's own
(``app.services.run_export``), which the job package uses as well.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import Iterable, Sequence
from pathlib import Path

from app.services.run_export import (
    JobRows,
    jsonable,
    read_job_rows,
    run_files,
    with_sample,
    write_files,
)

__all__ = ["JobRows", "export_jobs", "jsonable", "read_jobs", "with_sample", "write_run"]


def write_run(rows: JobRows, into: Path) -> tuple[Path, list[str]]:
    """Write one job's rows into ``into`` in the stored-run layout.

    Returns ``into`` and the files of the layout an earlier export had left
    there, which are removed first: a file this job has no rows for must not
    stay from another export. No other file in ``into`` is touched.
    """
    from scripts.replay.stored import FILES

    into.mkdir(parents=True, exist_ok=True)
    cleared = sorted(name for name in FILES if (into / name).is_file())
    for name in cleared:
        (into / name).unlink()
    write_files(run_files(rows), into)
    return into, cleared


def _database_url(given: str | None) -> str:
    if given:
        return given
    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    from app.config import settings

    return str(settings.database_url)


async def read_jobs(job_ids: Sequence[str], database_url: str) -> list[JobRows]:
    """Each job's rows, read in one read-only transaction that is rolled back."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(database_url, pool_pre_ping=False)
    out: list[JobRows] = []
    try:
        async with engine.connect() as conn:
            transaction = await conn.begin()
            try:
                await conn.execute(text("SET TRANSACTION READ ONLY"))
                for raw in job_ids:
                    job_id = uuid.UUID(str(raw))
                    rows = await read_job_rows(conn, job_id)
                    if rows is None:
                        raise LookupError(f"no job {job_id}")
                    out.append(rows)
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()
    return out


def export_jobs(
    job_ids: Iterable[str], into: Path, *, database_url: str | None = None
) -> list[tuple[Path, list[str]]]:
    """Each job read from the database into ``into/<job id>``.

    Returns each directory written, with the files of an earlier export it
    removed first.
    """
    ids = [str(job_id) for job_id in job_ids]
    rows = asyncio.run(read_jobs(ids, _database_url(database_url)))
    return [write_run(job, into / str(job.job.get("id"))) for job in rows]
