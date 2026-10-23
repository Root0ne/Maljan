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

__all__ = [
    "JobRows",
    "StoredRunExists",
    "export_jobs",
    "jsonable",
    "read_jobs",
    "with_sample",
    "write_run",
]


class StoredRunExists(FileExistsError):
    """The directory an export would write holds a stored run, and no overwrite was given."""


def _held(into: Path) -> list[str]:
    """The names of the stored-run layout ``into`` already holds, a dangling link included."""
    from scripts.replay.stored import FILES

    return sorted(name for name in FILES if os.path.lexists(into / name))


def _refuse_a_held_run(into: Path) -> None:
    held = _held(into)
    if held:
        raise StoredRunExists(
            f"{into} already holds a stored run ({', '.join(held)}): it is not overwritten "
            "without --overwrite"
        )


def write_run(rows: JobRows, into: Path, *, overwrite: bool = False) -> tuple[Path, list[str]]:
    """Write one job's rows into ``into`` in the stored-run layout.

    A directory that already holds a file of the layout is a stored run, and
    is refused (:class:`StoredRunExists`) unless ``overwrite`` is given; then
    those files are removed first, since a file this job has no rows for must
    not stay from another export. Returns ``into`` and the files removed. No
    other file in ``into`` is touched.
    """
    if not overwrite:
        _refuse_a_held_run(into)
    into.mkdir(parents=True, exist_ok=True)
    cleared = _held(into)
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
    job_ids: Iterable[str],
    into: Path,
    *,
    database_url: str | None = None,
    overwrite: bool = False,
) -> list[tuple[Path, list[str]]]:
    """Each job read from the database into ``into/<job id>``.

    A ``into/<job id>`` that already holds a stored run is refused before the
    database is read, unless ``overwrite`` is given. Returns each directory
    written, with the files of an earlier export it removed first.
    """
    # Each job once: a repeated id would write its directory and then meet it.
    ids = list(dict.fromkeys(str(uuid.UUID(str(job_id))) for job_id in job_ids))
    if not overwrite:
        for raw in ids:
            _refuse_a_held_run(into / raw)
    rows = asyncio.run(read_jobs(ids, _database_url(database_url)))
    return [write_run(job, into / str(job.job.get("id")), overwrite=overwrite) for job in rows]
