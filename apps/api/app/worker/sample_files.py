"""Where the worker keeps its private copies of a sample, and how they go away.

The download target (``upload_temp_dir``) plus one mirror subdirectory per
server that needs a copy, all created 0o700 with files 0o600. Those
subdirectories are the boundary between the worker's scratch and the operator's
own corpus in ``samples_dir``: nothing here lists or deletes outside them.

Which subdirectories there are is not written here. Each static provider says
where it mirrors (``mirror_spec()``) and each server declares its own
``work_dir``; ``maljan.providers.registry.mirror_work_dirs`` is their union for
a settings object, and every path that sweeps, removes or exports a root takes
that union from its caller. There is more than one because a tool may refuse a
directory another accepts: radare2 rejects a path carrying a ``/.`` segment, so
its copies cannot go in the hidden shared one (BUG 10, live on 2026-09-07).
"""

from __future__ import annotations

import os
import re
import shutil
import time
from collections.abc import Iterable
from pathlib import Path

from app.config import settings
from app.logging_config import get_logger

logger = get_logger("worker.sample_files")

# The characters a sample file's suffix keeps in the platform's own copy of it.
_SAFE_SUFFIX = re.compile(r"\.[A-Za-z0-9._-]+")


def safe_suffix(filename: str) -> str:
    """The suffix of an uploaded ``filename`` the platform's copies keep, or ``""``.

    Every copy of a sample the platform writes (the download, each provider's
    mirror) is named by its SHA-256 plus the upload's suffix, so a sandbox
    can pick its profile from ``.elf`` or ``.exe``. The suffix is the
    uploader's text: one with a percent sign, a backslash, a control character
    or any other character outside ``[A-Za-z0-9._-]`` is dropped, so every
    path the platform hands a tool is plain and reads the same everywhere.
    """
    suffix = Path(str(filename or "")).suffix
    return suffix if _SAFE_SUFFIX.fullmatch(suffix) else ""


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions — 0o700 is intentional: owner-only access to a private working directory that holds uploaded sample bytes  # noqa: E501
    os.chmod(path, 0o700)
    return path


def temp_dir() -> Path:
    return _private_dir(Path(settings.upload_temp_dir).resolve())


def work_dir(subdir: str) -> Path:
    """The private mirror directory ``subdir`` names, created 0o700.

    ``subdir`` is a provider's ``MirrorSpec.work_subdir``, which for r2 comes
    from an operator-set path. Taking the last segment is not on its own enough
    to keep this inside ``samples_dir``: ``Path("data/samples/..").name`` is
    ``".."``, which resolves to the *parent* of ``samples_dir`` — a directory
    this would then chmod 0o700 and ``sweep`` would delete stale files in.
    ``""`` and ``"."`` were quieter and no better: they fell back to the hidden
    shared directory, silently putting r2's sample back where radare2 refuses
    to open it (BUG 10).

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


def configured_subdirs() -> tuple[str, ...]:
    """The mirror subdirectories the shipped settings name, for a caller with none of its own.

    Built from the model defaults only (``build_settings({})``): a caller that
    has the effective settings (the store, for a request handler; the job's
    own, inside a job) passes their ``mirror_work_dirs`` instead.
    """
    from maljan.core.settings_overrides import build_settings
    from maljan.providers.registry import mirror_work_dirs

    return mirror_work_dirs(build_settings({}))


def work_dirs(subdirs: Iterable[str] | None = None) -> list[Path]:
    """Every mirror directory, for the paths that sweep or clean up.

    ``subdirs`` is ``mirror_work_dirs`` of the caller's effective settings;
    ``None`` reads the shipped settings' (``configured_subdirs``). A name that
    does not denote a child of the samples directory is skipped here, so one
    bad declaration never stops the sweep of the others.
    """
    seen: dict[str, None] = {}
    for name in configured_subdirs() if subdirs is None else subdirs:
        last = Path(str(name)).name
        if last and last not in (".", ".."):
            seen.setdefault(last, None)
    return [work_dir(name) for name in seen]


def export_sample_roots(subdirs: Iterable[str] | None = None) -> list[Path]:
    """Tell the tool sidecars which directories this worker's samples live in.

    A sidecar reads a path argument only inside the roots it was given (see
    ``maljan.tools.roots``), and the ones this worker uses are its own: the
    download target every sample lands in and the mirror subdirectories a
    static provider reads from. Nothing here comes from a model, and none of
    it is a secret — the variable says where a sample is, not what is in it.

    Called at worker startup, before any job can start a sidecar, and again
    per job for a worker whose settings named another mirror directory.
    ``subdirs`` is as for ``work_dirs``.
    Returns the roots it exported, for the caller that wants to log them.
    """
    from maljan.tools.roots import add_sample_root

    roots = [temp_dir(), *work_dirs(subdirs)]
    for root in roots:
        add_sample_root(root)
    return roots


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


def remove_for_sha(sha256: str, *, subdirs: Iterable[str] | None = None) -> list[Path]:
    removed: list[Path] = []
    for base in [temp_dir(), *work_dirs(subdirs)]:
        for candidate in base.glob(f"{sha256}*"):
            if candidate.is_file():
                remove_quietly(candidate)
                removed.append(candidate)
    return removed


def sweep(
    max_age_s: float = 86_400.0,
    *,
    now: float | None = None,
    subdirs: Iterable[str] | None = None,
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
    bases = [temp_dir(), *work_dirs(subdirs)]
    for base in bases:
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
            ", ".join(str(base) for base in bases),
        )
    return count
