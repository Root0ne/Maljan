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

    ``subdir`` is a provider's ``MirrorSpec.work_subdir``, which for r2 comes
    from an operator-set path. Taking the last segment is not on its own enough
    to keep this inside ``samples_dir``: ``Path("data/samples/..").name`` is
    ``".."``, which resolves to the *parent* of ``samples_dir`` — a directory
    this would then chmod 0o700 and ``sweep`` would delete stale files in.
    ``""`` and ``"."`` were quieter and no better: they fell back to the hidden
    ``WORK_SUBDIR``, silently putting r2's sample back where radare2 refuses to
    open it (BUG 10).

    So the three names that do not denote a child are refused outright rather
    than corrected into something plausible. ``StaticR2Config`` rejects them at
    settings validation too; this is the fence for every other caller.
    """
    name = Path(subdir).name
    if name in ("", ".", ".."):
        raise ValueError(
            f"invalid sample mirror directory {subdir!r}: its last segment is {name!r}, "
            f"which names a directory itself or its parent rather than a private "
            f"subdirectory of the samples directory"
        )
    return _private_dir((Path(settings.samples_dir) / name).resolve())


def _configured_mirror_subdirs(mirror_dir: str | None) -> tuple[str, ...]:
    """``mirror_dir``, on top of the built-ins, as a one-entry tuple or none.

    ``WORK_SUBDIRS`` alone left a custom ``static.r2.mirror_dir`` — which the
    validator accepts — cleaned per job through the explicit ``host_mirrors``
    list but never reached by ``sweep`` or ``remove_for_sha``, so a crashed
    worker's copies stayed forever in a directory that holds live malware.

    Takes the effective ``static.r2.mirror_dir`` value as a parameter rather
    than reading it itself: this module is imported by both the API and the
    worker, and neither may build core ``Settings`` bare (the environment is
    not a layer for the application) or reach for the process-wide
    ``get_settings()`` singleton on a request path that never installed it.
    Each caller resolves the value the way appropriate to where it runs (the
    store, for a request handler; a caller inside a job, from the settings
    already installed for that job) and passes it in. ``None`` (the settings
    load failed, or the caller has no settings to offer) means "built-ins
    only" — the same as before this took a parameter.
    """
    if not mirror_dir:
        return ()
    configured = Path(mirror_dir).name
    return (configured,) if configured and configured not in ("", ".", "..") else ()


def work_dirs(mirror_dir: str | None = None) -> list[Path]:
    """Every mirror directory, for the paths that sweep or clean up.

    ``mirror_dir`` is the effective ``static.r2.mirror_dir``, if the caller
    has one to offer -- see ``_configured_mirror_subdirs``.
    """
    seen: dict[str, None] = {}
    for name in (*WORK_SUBDIRS, *_configured_mirror_subdirs(mirror_dir)):
        seen.setdefault(name, None)
    return [work_dir(name) for name in seen]


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


def remove_for_sha(sha256: str, *, mirror_dir: str | None = None) -> list[Path]:
    removed: list[Path] = []
    for base in [temp_dir(), *work_dirs(mirror_dir)]:
        for candidate in base.glob(f"{sha256}*"):
            if candidate.is_file():
                remove_quietly(candidate)
                removed.append(candidate)
    return removed


def sweep(
    max_age_s: float = 86_400.0, *, now: float | None = None, mirror_dir: str | None = None
) -> int:
    """Remove mirrored sample copies older than ``max_age_s``.

    The cutoff is the whole of the coordination
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
    for base in [temp_dir(), *work_dirs(mirror_dir)]:
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
            ", ".join(str(base) for base in [temp_dir(), *work_dirs(mirror_dir)]),
        )
    return count
