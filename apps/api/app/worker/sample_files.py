"""Where the worker keeps its private copies of a sample, and how they go away.

The download target (``upload_temp_dir``) plus one mirror subdirectory per
static provider that needs a copy, all created 0o700 with files 0o600. Those
subdirectories are the boundary between the worker's scratch and the operator's
own corpus in ``samples_dir``: nothing here lists or deletes outside them.

There is more than one because radare2 will not read from a hidden one. Its
own path check rejects a path carrying a ``/.`` segment, so an r2mcp handed
``<samples_dir>/.work/<sha>.exe`` answers "Failed to open file." to every tool
call — the whole of BUG 10, live on 2026-09-07. ``.work`` stays for Ghidra,
whose container mount is written against it; r2 gets ``r2-work``, and
``WORK_SUBDIRS`` is what keeps the cleanup and the sweep covering both.
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

from app.config import settings
from app.logging_config import get_logger

logger = get_logger("worker.sample_files")

# The Ghidra mirror, and the default for anything that does not ask otherwise.
# Hidden on purpose: it is the worker's scratch, not part of the corpus.
WORK_SUBDIR = ".work"

# radare2's, which may not be hidden — see the module docstring. Named here
# rather than derived from settings so the sweep can find it without loading
# the analysis config.
R2_WORK_SUBDIR = "r2-work"

# Every mirror subdirectory the cleanup paths must reach. A provider that
# introduces another one adds it here, or its copies outlive their job.
WORK_SUBDIRS = (WORK_SUBDIR, R2_WORK_SUBDIR)


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions — 0o700 is intentional: owner-only access to a private working directory that holds uploaded sample bytes  # noqa: E501
    os.chmod(path, 0o700)
    return path


def temp_dir() -> Path:
    return _private_dir(Path(settings.upload_temp_dir).resolve())


def work_dir(subdir: str = WORK_SUBDIR) -> Path:
    """The private mirror directory ``subdir`` names, created 0o700.

    ``subdir`` is a provider's ``MirrorSpec.work_subdir``. Only the name is
    used, so a spec built from a configured path cannot escape ``samples_dir``.
    """
    name = Path(subdir).name or WORK_SUBDIR
    return _private_dir((Path(settings.samples_dir) / name).resolve())


def work_dirs() -> list[Path]:
    """Every mirror directory, for the paths that sweep or clean up."""
    return [work_dir(name) for name in WORK_SUBDIRS]


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
    for base in [temp_dir(), *work_dirs()]:
        for candidate in base.glob(f"{sha256}*"):
            if candidate.is_file():
                remove_quietly(candidate)
                removed.append(candidate)
    return removed


def sweep(max_age_s: float = 86_400.0, *, now: float | None = None) -> int:
    """Remove mirrored sample copies older than ``max_age_s``.

    API-2 (dev audit 2026-09-06): the cutoff is the whole of the coordination
    there is, and it is deliberate. Several workers may share these directories
    and run this sweep at once, with no lock between them; what makes that safe
    is the age, not a lock. A file in flight for a live job was written when
    that job started, so a 24 h cutoff only ever reaches copies whose job has
    been over for a day -- a job that ran longer than the cutoff would have to
    exist for a sweep to take a file out from under it, and the pipeline's own
    budgets are an order of magnitude below it. Two sweeps racing on the same
    stale file is not a problem either: the loser gets an OSError from a file
    that is already gone and skips it.

    So the assumption to keep in mind when changing either number: ``max_age_s``
    must stay comfortably longer than the longest job a worker can run. Lower it
    towards that and this needs real coordination (a lock, or a per-file owner)
    rather than an age.
    """
    cutoff = (now if now is not None else time.time()) - max_age_s
    count = 0
    for base in [temp_dir(), *work_dirs()]:
        for candidate in base.iterdir():
            try:
                if candidate.is_file() and candidate.stat().st_mtime < cutoff:
                    remove_quietly(candidate)
                    count += 1
            except OSError:
                # Vanished or became unreadable between ``iterdir`` and
                # ``stat``/unlink (another sweep, a concurrent cleanup) —
                # skip it rather than aborting the rest of the sweep.
                continue
    if count:
        logger.info(
            "Swept %d stale sample copies from %s",
            count,
            ", ".join(str(base) for base in [temp_dir(), *work_dirs()]),
        )
    return count
