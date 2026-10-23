"""The job's hash of the sample copies it hands out, at its start and at its end.

The intake digest is taken once, when the upload is streamed to the store.
Nothing read the job's copies against it afterwards: the download from the
store, each mirror written for a server's mount, and a download another job
on the same sample already holds were taken as those bytes. :class:`SampleIntegrity`
reads every copy once after the copies are made and before the pipeline
starts, and once more when the run ends, before the store and the teardown
(``maljan.analysis.sample_integrity`` holds the record and its sentences).

A changed copy is logged and recorded; the run goes on, and the report says
what changed and when it was seen.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from maljan.analysis.sample_integrity import (
    AT_END,
    AT_START,
    DOWNLOAD,
    MIRROR,
    file_sha256,
    integrity_record,
    matches,
    reading,
)

from app.logging_config import get_logger

logger = get_logger("worker.sample_integrity")


def copies_of(download: str | None, mirrors: Iterable[Path | str]) -> list[tuple[str, str, Path]]:
    """``(copy, where, path)`` for the download and each distinct mirror.

    ``where`` is a mirror's directory name, never its host path: the record is
    published with the run.
    """
    out: list[tuple[str, str, Path]] = []
    seen: set[Path] = set()
    if download:
        out.append((DOWNLOAD, "", Path(download)))
        seen.add(Path(download))
    for mirror in mirrors:
        path = Path(mirror)
        if path not in seen:
            seen.add(path)
            out.append((MIRROR, path.parent.name, path))
    return out


class SampleIntegrity:
    """The readings of one job's copies against the intake digest and size."""

    def __init__(
        self,
        expected: str,
        copies: list[tuple[str, str, Path]],
        *,
        size: Any = None,
        job_id: str = "",
    ):
        self.expected = str(expected or "")
        self.copies = list(copies)
        # The intake size: a copy of another size is a change, never read
        # (``file_sha256``), and no reading takes more than it. A size that is
        # not a count of bytes is none: the whole copy is read.
        known = isinstance(size, int) and not isinstance(size, bool) and size >= 0
        self.size = size if known else None
        self.job_id = job_id
        self.readings: list[dict[str, Any]] = []
        self._end: asyncio.Future[list[dict[str, Any]]] | None = None
        self._end_taken = False

    def _read(self, at: str) -> list[dict[str, Any]]:
        """One reading of every copy, returned whole."""
        held: list[dict[str, Any]] = []
        for copy, where, path in self.copies:
            try:
                sha256, error = file_sha256(path, self.size)
            except Exception as exc:  # noqa: BLE001 — a reading never fails the run
                # file_sha256 returns its own OS errors, so this is a fault in
                # the code: keep the traceback in the log, not in the record.
                logger.warning("Reading the sample's %s copy raised.", copy, exc_info=True)
                sha256, error = "", type(exc).__name__
            entry = reading(copy, where, at, sha256, error, datetime.now(UTC).isoformat())
            held.append(entry)
            if not matches(entry, self.expected):
                logger.warning(
                    "The sample's %s copy%s did not read as its intake SHA-256 at the %s: %s.",
                    copy,
                    f" in {where}" if where else "",
                    at,
                    sha256 or error,
                    extra={"job_id": self.job_id, "component": "sample-integrity"},
                )
        return held

    async def started(self) -> None:
        """Read every copy once, off the loop. Never raises."""
        self.readings = [*self.readings, *await asyncio.to_thread(self._read, AT_START)]

    async def ended(self) -> dict[str, Any] | None:
        """Read every copy once more, the first time only, and return the record. Never raises.

        ``None`` when the job handed out no copy. Every path that stores the
        run calls this, so a run kept after a later failure reads its copies
        once and carries the same record. The end reading is one task, shielded
        from its caller: a caller cancelled while it runs (a shutdown) leaves
        it running, a later caller waits for the same reading, and the
        readings are taken in whole or not at all.
        """
        if not self.copies:
            return None
        if self._end is None:
            self._end = asyncio.ensure_future(asyncio.to_thread(self._read, AT_END))
        ended = await asyncio.shield(self._end)
        if not self._end_taken:
            self._end_taken = True
            self.readings = [*self.readings, *ended]
        return self.record()

    def record(self) -> dict[str, Any] | None:
        """The record of the readings taken whole so far, ``None`` with none."""
        if not self.readings:
            return None
        return integrity_record(self.expected, self.readings)


async def ended_record(integrity: SampleIntegrity | None) -> dict[str, Any] | None:
    """``integrity``'s end record, ``None`` for a job that handed out no copy."""
    return await integrity.ended() if integrity is not None else None


def with_record(
    run_summary: dict[str, Any], malware_report: Any, record: Mapping[str, Any] | None
) -> None:
    """Put ``record`` on the run summary and in each disclosure's isolation part, in place."""
    if not record:
        return
    from maljan.analysis.sample_integrity import RECORD_KEY, with_integrity

    run_summary[RECORD_KEY] = dict(record)
    if "disclosure" in run_summary:
        run_summary["disclosure"] = with_integrity(run_summary["disclosure"], record)
    if not isinstance(malware_report, dict):
        return
    held = malware_report.get("run_summary")
    if isinstance(held, dict):
        malware_report["run_summary"] = {
            **held,
            RECORD_KEY: dict(record),
            **(
                {"disclosure": with_integrity(held["disclosure"], record)}
                if "disclosure" in held
                else {}
            ),
        }
