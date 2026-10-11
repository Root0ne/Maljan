"""Where the worker keeps its private copies of a sample, and how they go away.

The download target (``upload_temp_dir``) plus one mirror subdirectory per
server that needs a copy, all created 0o700 with files 0o600. Those
subdirectories are the boundary between the worker's scratch and the operator's
own corpus in ``samples_dir``: nothing here lists or deletes outside them.

Which subdirectories there are is not written here. Each static provider says
where it mirrors (``mirror_spec()``, from its server's declared ``work_dir``);
``maljan.providers.registry.mirror_work_dirs`` is the union for the providers
a settings object selects and switches on, and every path that sweeps,
removes or exports a root takes that union from its caller, beside the
shipped mirror directories. A name is used only when it is a plain child of
``samples_dir`` (never a link) that the worker created and marked
(``MIRROR_MARKER``) or a shipped mirror directory, so a server naming the
operator's own folder changes nothing in it; and only files named as the
worker names a copy (a SHA-256 and a plain suffix) are ever removed.

There is more than one because a tool may refuse a
directory another accepts: radare2 rejects a path carrying a ``/.`` segment, so
its copies cannot go in the hidden shared one (BUG 10, live on 2026-09-07).
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import stat
import time
from collections.abc import Iterable
from pathlib import Path

from maljan.providers.base import DEFAULT_WORK_DIR

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


# The file the worker writes into each mirror directory it creates. A
# directory under the samples directory that holds none, and is not one of the
# shipped mirror directories, is the operator's and is never written to,
# chmodded, swept, cleared or exported.
MIRROR_MARKER = ".maljan-mirror"

# The SHA-256 every copy the worker writes is named by.
_SHA256 = re.compile(r"[0-9a-f]{64}")


class NotAMirrorDirectory(ValueError):
    """A named directory the worker may not use as a mirror directory."""


@functools.cache
def shipped_mirror_dirs() -> tuple[str, ...]:
    """The mirror directories the shipped settings' providers copy into.

    These are the worker's own by allow-list, so a directory a release before
    the marker created is adopted (and marked) rather than left unswept.
    """
    from maljan.core.settings_overrides import build_settings
    from maljan.providers.registry import mirror_work_dirs

    return mirror_work_dirs(build_settings({}), selected_only=False)


def _child_name(subdir: str) -> str:
    name = Path(str(subdir)).name
    if name in ("", ".", ".."):
        raise NotAMirrorDirectory(
            f"invalid sample mirror directory {subdir!r}: its last segment is {name!r}, "
            f"which names a directory itself or its parent rather than a private "
            f"subdirectory of the samples directory"
        )
    return name


def work_dir(subdir: str = DEFAULT_WORK_DIR) -> Path:
    """The private mirror directory ``subdir`` names, created 0o700 and marked.

    ``subdir`` is a provider's ``MirrorSpec.work_subdir`` (the shared default
    when none is named); only its last segment is used. ``..``, ``.`` and the
    empty name are refused: ``Path("data/samples/..").name`` is ``..``, the
    parent of ``samples_dir``, and an empty name once fell back to the hidden
    shared directory, putting r2's sample where radare2 refuses to open it
    (BUG 10).

    The directory must be a direct child of ``samples_dir`` that is not a
    symbolic link (read with ``lstat``, never followed). One that does not
    exist is created and gets ``MIRROR_MARKER``. One that exists is the
    worker's only when it holds the marker, or is a shipped mirror directory
    (which is then marked); any other is the operator's, such as a corpus
    folder a server's declaration happens to name, and is refused with
    ``NotAMirrorDirectory`` before anything is changed in it.
    """
    name = _child_name(subdir)
    base = Path(settings.samples_dir).resolve()
    path = base / name
    created = False
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        base.mkdir(parents=True, exist_ok=True)
        try:
            path.mkdir(mode=0o700)
            created = True
        except FileExistsError:
            pass
        st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise NotAMirrorDirectory(
            f"sample mirror directory {name!r} is not a plain directory under the samples "
            "directory (a link or a file); the worker leaves it as it is"
        )
    if path.resolve().parent != base:
        raise NotAMirrorDirectory(
            f"sample mirror directory {name!r} does not resolve to a child of the samples directory"
        )
    marker = path / MIRROR_MARKER
    if not os.path.lexists(marker):
        if not created and name not in shipped_mirror_dirs():
            raise NotAMirrorDirectory(
                f"{name!r} under the samples directory was not created by the worker (it holds "
                f"no {MIRROR_MARKER}); it is left untouched and not used as a mirror directory"
            )
        _write_marker(marker)
    elif not stat.S_ISREG(os.lstat(marker).st_mode):
        raise NotAMirrorDirectory(f"the marker in {name!r} is not a plain file")
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions — 0o700 is intentional: owner-only access to a private working directory that holds uploaded sample bytes  # noqa: E501
    os.chmod(path, 0o700)
    return path


def _write_marker(marker: Path) -> None:
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return
    with os.fdopen(fd, "w") as out:
        out.write("A sample mirror directory of the Maljan worker.\n")


def work_dirs(subdirs: Iterable[str] | None = None) -> list[Path]:
    """Every mirror directory of the worker's own, for the paths that sweep or clean up.

    The shipped mirror directories (``shipped_mirror_dirs``) and ``subdirs``,
    ``mirror_work_dirs`` of the caller's effective settings when it has them.
    A name the worker may not use (no child, a link, the operator's own
    directory) is skipped and logged, so one bad name never stops the others.
    """
    seen: dict[str, None] = {}
    for name in (*shipped_mirror_dirs(), *(subdirs or ())):
        last = Path(str(name)).name
        if last and last not in (".", ".."):
            seen.setdefault(last, None)
    dirs: list[Path] = []
    for name in seen:
        try:
            dirs.append(work_dir(name))
        except NotAMirrorDirectory as exc:
            logger.warning("Skipped a sample mirror directory: %s", exc)
    return dirs


def _is_sample_copy(name: str, sha256: str | None = None) -> bool:
    """Whether ``name`` is a copy the worker writes: a SHA-256 and a plain suffix."""
    digest, rest = name[:64], name[64:]
    if not _SHA256.fullmatch(digest) or (sha256 is not None and digest != sha256):
        return False
    return rest == "" or bool(_SAFE_SUFFIX.fullmatch(rest))


def _regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


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
    """Remove the copies the worker wrote of ``sha256``: its download and its mirrors.

    Only in the worker's own directories, and only files named as the worker
    names a copy (the SHA-256 and a plain suffix), never a link.
    """
    removed: list[Path] = []
    if not _SHA256.fullmatch(str(sha256)):
        return removed
    for base in [temp_dir(), *work_dirs(subdirs)]:
        for candidate in base.iterdir():
            if _is_sample_copy(candidate.name, sha256) and _regular_file(candidate):
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
            if not _is_sample_copy(candidate.name):
                continue
            try:
                st = os.lstat(candidate)
                if stat.S_ISREG(st.st_mode) and st.st_mtime < cutoff:
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
