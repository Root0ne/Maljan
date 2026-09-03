"""Where the worker keeps its private copies of a sample, and how they go away.

Two directories, both created 0o700, files 0o600: the download target
(``upload_temp_dir``) and the Ghidra mirror (``<samples_dir>/.work``). The
``.work`` subdirectory is the boundary between the worker's scratch and the
operator's own corpus in ``samples_dir``: nothing here lists or deletes
outside it.
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

from app.config import settings
from app.logging_config import get_logger

logger = get_logger("worker.sample_files")

WORK_SUBDIR = ".work"


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def temp_dir() -> Path:
    return _private_dir(Path(settings.upload_temp_dir).resolve())


def work_dir() -> Path:
    return _private_dir((Path(settings.samples_dir) / WORK_SUBDIR).resolve())


def private_copy(src: Path, dest: Path) -> None:
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as out, src.open("rb") as inp:
        shutil.copyfileobj(inp, out)
    os.chmod(dest, 0o600)


def remove_quietly(path: Path | str | None, *, job_id: str | None = None) -> None:
    if not path:
        return
    p = Path(path)
    try:
        p.unlink(missing_ok=True)
        logger.debug("Removed %s", p, extra={"job_id": job_id})
    except OSError as exc:
        logger.warning("Could not remove %s: %s", p, type(exc).__name__, extra={"job_id": job_id})


def remove_for_sha(sha256: str) -> list[Path]:
    removed: list[Path] = []
    for base in (temp_dir(), work_dir()):
        for candidate in base.glob(f"{sha256}*"):
            if candidate.is_file():
                remove_quietly(candidate)
                removed.append(candidate)
    return removed


def sweep(max_age_s: float = 86_400.0, *, now: float | None = None) -> int:
    cutoff = (now if now is not None else time.time()) - max_age_s
    count = 0
    for base in (temp_dir(), work_dir()):
        for candidate in base.iterdir():
            if candidate.is_file() and candidate.stat().st_mtime < cutoff:
                remove_quietly(candidate)
                count += 1
    if count:
        logger.info("Swept %d stale sample copies from %s and %s", count, temp_dir(), work_dir())
    return count
