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

import contextlib
import fcntl
import functools
import os
import re
import shutil
import stat
import time
from collections.abc import Callable, Iterable, Iterator
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


# The file the worker writes into each mirror directory it creates, and the
# text it holds. A directory under the samples directory that holds no such
# file (a regular file the worker's own user owns, holding exactly this text),
# and is not one of the shipped mirror directories, is the operator's and is
# never written to, chmodded, swept, cleared or exported.
MIRROR_MARKER = ".maljan-mirror"
MIRROR_MARKER_TEXT = "A sample mirror directory of the Maljan worker.\n"

# The SHA-256 every copy the worker writes is named by.
_SHA256 = re.compile(r"[0-9a-f]{64}")

# A directory opened for acting on its entries: never through a link.
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


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


def _marker_is_the_workers(dir_fd: int) -> bool | None:
    """``True`` for the worker's own marker, ``False`` for any other, ``None`` for none.

    The worker's own is a regular file, never a link, owned by this process's
    user and holding exactly ``MIRROR_MARKER_TEXT``.
    """
    try:
        fd = os.open(MIRROR_MARKER, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError:
        return False
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
            return False
        return os.read(fd, len(MIRROR_MARKER_TEXT) + 1) == MIRROR_MARKER_TEXT.encode()
    finally:
        os.close(fd)


def _write_marker(dir_fd: int) -> None:
    try:
        fd = os.open(
            MIRROR_MARKER,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=dir_fd,
        )
    except FileExistsError:
        return
    with os.fdopen(fd, "w") as out:
        out.write(MIRROR_MARKER_TEXT)


def _open_mirror(subdir: str) -> tuple[Path, int]:
    """Open the mirror directory ``subdir`` names; its path and an fd every action goes through.

    ``subdir`` is a provider's ``MirrorSpec.work_subdir``; only its last
    segment is used. ``..``, ``.`` and the empty name are refused:
    ``Path("data/samples/..").name`` is ``..``, the parent of ``samples_dir``,
    and an empty name once fell back to the hidden shared directory, putting
    r2's sample where radare2 refuses to open it (BUG 10).

    The directory is opened relative to ``samples_dir`` with ``O_NOFOLLOW``,
    so a link in its place is refused, and every check after that reads the
    open directory, not a path. One that did not exist is created and gets
    ``MIRROR_MARKER``. One that exists is the worker's only when it holds the
    worker's own marker, or is a shipped mirror directory with no marker
    (which is then marked); any other is the operator's, such as a corpus
    folder a server's declaration happens to name, and is refused with
    ``NotAMirrorDirectory`` before anything is changed in it. The caller
    closes the fd.
    """
    name = _child_name(subdir)
    base = Path(settings.samples_dir).resolve()
    base.mkdir(parents=True, exist_ok=True)
    base_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    try:
        created = False
        try:
            os.mkdir(name, 0o700, dir_fd=base_fd)
            created = True
        except FileExistsError:
            pass
        try:
            fd = os.open(name, _DIR_FLAGS, dir_fd=base_fd)
        except OSError as exc:
            raise NotAMirrorDirectory(
                f"sample mirror directory {name!r} is not a plain directory under the samples "
                "directory (a link or a file); the worker leaves it as it is"
            ) from exc
    finally:
        os.close(base_fd)
    try:
        held = _marker_is_the_workers(fd)
        if held is False:
            raise NotAMirrorDirectory(
                f"the {MIRROR_MARKER} in {name!r} is not the worker's own; the directory is "
                "left untouched and not used as a mirror directory"
            )
        if held is None:
            if not created and name not in shipped_mirror_dirs():
                raise NotAMirrorDirectory(
                    f"{name!r} under the samples directory was not created by the worker (it "
                    f"holds no {MIRROR_MARKER}); it is left untouched and not used as a mirror "
                    "directory"
                )
            _write_marker(fd)
        # A directory only the worker may list and enter: 0o700 is owner-only, x is the entering.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions — owner-only directory  # noqa: E501
        os.fchmod(fd, 0o700)
    except BaseException:
        os.close(fd)
        raise
    return base / name, fd


def work_dir(subdir: str = DEFAULT_WORK_DIR) -> Path:
    """The private mirror directory ``subdir`` names, created 0o700 and marked.

    See ``_open_mirror`` for what is refused; this returns the path for a
    caller that writes through ``private_copy``.
    """
    path, fd = _open_mirror(subdir)
    os.close(fd)
    return path


def _mirror_fds(subdirs: Iterable[str] | None) -> list[tuple[Path, int]]:
    """Every mirror directory of the worker's own, each opened; the caller closes the fds.

    The shipped mirror directories (``shipped_mirror_dirs``) and ``subdirs``,
    ``mirror_work_dirs`` of the caller's effective settings when it has them.
    A name the worker may not use (no child, a link, the operator's own
    directory) or cannot open (another user's) is skipped and logged, so one
    bad name never stops the others.
    """
    seen: dict[str, None] = {}
    for name in (*shipped_mirror_dirs(), *(subdirs or ())):
        last = Path(str(name)).name
        if last and last not in (".", ".."):
            seen.setdefault(last, None)
    opened: list[tuple[Path, int]] = []
    for name in seen:
        try:
            opened.append(_open_mirror(name))
        except NotAMirrorDirectory as exc:
            logger.warning("Skipped a sample mirror directory: %s", exc)
        except OSError as exc:
            logger.warning("Skipped the sample mirror directory %r: %s", name, type(exc).__name__)
    return opened


def work_dirs(subdirs: Iterable[str] | None = None) -> list[Path]:
    """Every mirror directory of the worker's own (see ``_mirror_fds``), as paths."""
    paths: list[Path] = []
    for path, fd in _mirror_fds(subdirs):
        os.close(fd)
        paths.append(path)
    return paths


def _is_sample_copy(name: str, sha256: str | None = None) -> bool:
    """Whether ``name`` is a copy the worker writes: a SHA-256 and a plain suffix."""
    digest, rest = name[:64], name[64:]
    if not _SHA256.fullmatch(digest) or (sha256 is not None and digest != sha256):
        return False
    return rest == "" or bool(_SAFE_SUFFIX.fullmatch(rest))


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
    """Copy ``src`` to ``dest`` as a new 0o600 file, never through a link.

    ``dest``'s directory is opened with ``O_DIRECTORY | O_NOFOLLOW`` and every
    step after goes through that fd: a name already there (a stale copy, or a
    link planted in its place) is unlinked, never followed, and the copy is
    created with ``O_CREAT | O_EXCL | O_NOFOLLOW``, so nothing outside the
    directory is ever written.
    """
    dir_fd = os.open(dest.parent, _DIR_FLAGS)
    try:
        try:
            os.unlink(dest.name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        fd = os.open(
            dest.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=dir_fd,
        )
        with os.fdopen(fd, "wb") as out, src.open("rb") as inp:
            shutil.copyfileobj(inp, out)
            os.fchmod(out.fileno(), 0o600)
    finally:
        os.close(dir_fd)


# A job's hold on a copy it shares: an empty file beside the copy, named for the
# copy and the job. Its name reads as a copy's (a SHA-256 and a plain suffix),
# so the age sweep and a sample's delete take a hold a crashed job left behind
# together with the copies.
_HOLD_INFIX = ".held-by-"
# A copy a job is still writing, beside the name it will take, read as a copy too.
_STAGING_INFIX = ".part-"
_HOLD_TAG = re.compile(r"[A-Za-z0-9-]{1,64}")


def copy_name(sha256: str, extension: str, job_id: str = "") -> str:
    """The name of one job's mirror copy: the SHA-256, the job's id, the upload's suffix.

    A server that names a program by the file it was handed (Ghidra) would
    otherwise see two jobs on one sample as one program, and one job's
    re-import would replace the other's analysed program on a shared server.
    A job with no usable id keeps the plain name. The digest stays the first
    dot-separated part and the suffix the last, so every reader of a copy's
    name (:func:`_is_sample_copy`, a sandbox's profile choice) reads it as before.
    """
    tag = str(job_id or "")
    return f"{sha256}.{tag}{extension}" if _HOLD_TAG.fullmatch(tag) else f"{sha256}{extension}"


def _hold_name(copy_name: str, job_id: str) -> str | None:
    tag = str(job_id or "")
    return f"{copy_name}{_HOLD_INFIX}{tag}" if _HOLD_TAG.fullmatch(tag) else None


def _holders(dir_fd: int, copy_name: str) -> set[str]:
    prefix = f"{copy_name}{_HOLD_INFIX}"
    with os.scandir(dir_fd) as entries:
        return {
            entry.name[len(prefix) :]
            for entry in entries
            if entry.name.startswith(prefix) and entry.is_file(follow_symlinks=False)
        }


def hold_copy(dest: Path, job_id: str, make: Callable[[Path], None]) -> None:
    """Hold ``dest`` for ``job_id``, making it unless another job holding it already did.

    The copies are named by the sample's SHA-256, so two jobs on one sample —
    two workers sharing these directories — reach the same name. Each job
    writes a hold beside the copy before it uses it, and :func:`release_copy`
    removes the copy only with the last hold. A copy another job holds is not
    written again (it holds the same bytes) and has its time renewed, so the
    age sweep measures it from its latest use.

    ``make(target)`` writes the copy to ``target``. It writes a staging file of
    this job's own beside ``dest``, outside any lock, so a slow download never
    holds the directory; the staging file is then renamed over ``dest`` in one
    step, so no reader of ``dest`` ever sees half a file. The hold and the
    rename run under an exclusive lock on the directory, so a release never
    interleaves with either. A job with no usable id makes ``dest`` in place,
    unheld, as before.
    """
    hold = _hold_name(dest.name, job_id)
    if hold is None:
        make(dest)
        return
    staging = dest.with_name(f"{dest.name}{_STAGING_INFIX}{job_id}")
    dir_fd = os.open(dest.parent, _DIR_FLAGS)
    try:
        with _locked(dir_fd):
            others = _holders(dir_fd, dest.name) - {str(job_id)}
            fd = os.open(hold, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
            os.close(fd)
            if others and _is_regular(dir_fd, dest.name):
                os.utime(dest.name, dir_fd=dir_fd, follow_symlinks=False)
                return
        try:
            make(staging)
            with _locked(dir_fd):
                others = _holders(dir_fd, dest.name) - {str(job_id)}
                if others and _is_regular(dir_fd, dest.name):
                    # Another job finished the same copy first; its bytes are these.
                    os.unlink(staging.name, dir_fd=dir_fd)
                else:
                    os.rename(staging.name, dest.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except BaseException:
            # A copy this job could not make is not one it holds.
            with _locked(dir_fd):
                for name in (staging.name, hold):
                    with contextlib.suppress(OSError):
                        os.unlink(name, dir_fd=dir_fd)
            raise
    finally:
        os.close(dir_fd)


@contextlib.contextmanager
def _locked(dir_fd: int) -> Iterator[None]:
    """An exclusive lock on the open directory, for the length of the block."""
    fcntl.flock(dir_fd, fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(dir_fd, fcntl.LOCK_UN)


def held_copy(src: Path, dest: Path, *, job_id: str) -> None:
    """:func:`private_copy` of ``src`` to ``dest`` under ``job_id``'s hold (:func:`hold_copy`)."""
    hold_copy(dest, job_id, lambda target: private_copy(src, target))


def release_copy(path: Path | str | None, *, job_id: str) -> bool:
    """Drop ``job_id``'s hold on ``path``, and remove the copy when no other job holds it.

    Never raises; returns whether the copy was removed. A copy another job
    still holds is left for that job's own release; one a crashed job's hold
    keeps goes with the age sweep. A job with no usable id removes the copy as
    before (:func:`remove_quietly`).
    """
    if not path:
        return False
    p = Path(path)
    hold = _hold_name(p.name, job_id)
    if hold is None:
        remove_quietly(p, job_id=job_id)
        return True
    try:
        dir_fd = os.open(p.parent, _DIR_FLAGS)
    except OSError as exc:
        logger.warning(
            "Could not open %s: %s", p.parent, type(exc).__name__, extra={"job_id": job_id}
        )
        return False
    try:
        with _locked(dir_fd):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(hold, dir_fd=dir_fd)
            others = _holders(dir_fd, p.name)
            if others:
                logger.debug(
                    "Left %s for the %d other job(s) holding it.",
                    p,
                    len(others),
                    extra={"job_id": job_id},
                )
                return False
            if _is_regular(dir_fd, p.name):
                os.unlink(p.name, dir_fd=dir_fd)
        logger.debug("Removed %s", p, extra={"job_id": job_id})
        return True
    except OSError as exc:
        logger.warning("Could not remove %s: %s", p, type(exc).__name__, extra={"job_id": job_id})
        return False
    finally:
        os.close(dir_fd)


def _is_regular(dir_fd: int, name: str) -> bool:
    try:
        return stat.S_ISREG(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
    except FileNotFoundError:
        return False


def remove_quietly(path: Path | str | None, *, job_id: str | None = None) -> None:
    if not path:
        return
    p = Path(path)
    try:
        p.unlink(missing_ok=True)
        logger.debug("Removed %s", p, extra={"job_id": job_id})
    except OSError as exc:
        logger.warning("Could not remove %s: %s", p, type(exc).__name__, extra={"job_id": job_id})


def _remove_in(base: Path, dir_fd: int, keep: Callable[[os.DirEntry[str]], bool]) -> list[Path]:
    """Unlink each regular file in the open directory ``keep`` picks, through its fd.

    A link is never followed: an entry is read with ``follow_symlinks=False``
    and unlinked by name relative to the directory. An entry that vanishes or
    cannot be read is skipped.
    """
    removed: list[Path] = []
    with os.scandir(dir_fd) as entries:
        for entry in entries:
            try:
                if not entry.is_file(follow_symlinks=False) or not keep(entry):
                    continue
                os.unlink(entry.name, dir_fd=dir_fd)
            except OSError:
                continue
            removed.append(base / entry.name)
    return removed


def _each_directory(
    subdirs: Iterable[str] | None, act: Callable[[Path, int, bool], list[Path]]
) -> list[Path]:
    """``act(path, fd, is_upload_dir)`` on the upload directory and each mirror directory.

    A directory that cannot be opened or listed (another user's, a
    ``PermissionError``) is logged and skipped; the others still are acted on.
    """
    done: list[Path] = []
    try:
        upload = temp_dir()
        upload_fd = os.open(upload, _DIR_FLAGS)
        opened = [(upload, upload_fd, True)]
    except OSError as exc:
        logger.warning("Skipped the upload staging directory: %s", type(exc).__name__)
        opened = []
    opened += [(path, fd, False) for path, fd in _mirror_fds(subdirs)]
    for path, fd, is_upload in opened:
        try:
            done += act(path, fd, is_upload)
        except OSError as exc:
            logger.warning("Skipped the directory %s: %s", path, type(exc).__name__)
        finally:
            os.close(fd)
    return done


def remove_for_sha(sha256: str, *, subdirs: Iterable[str] | None = None) -> list[Path]:
    """Remove the copies the worker wrote of ``sha256``: its download and its mirrors.

    Only in the worker's own directories, and only files named as the worker
    names a copy (the SHA-256 and a plain suffix), never a link.
    """
    if not _SHA256.fullmatch(str(sha256)):
        return []
    return _each_directory(
        subdirs,
        lambda path, fd, _upload: _remove_in(
            path, fd, lambda entry: _is_sample_copy(entry.name, sha256)
        ),
    )


def sweep(
    max_age_s: float = 86_400.0,
    *,
    now: float | None = None,
    subdirs: Iterable[str] | None = None,
) -> int:
    """Remove stale sample copies older than ``max_age_s``.

    In the upload staging directory, the worker's and the API's own private
    scratch, every regular file goes: an upload the API was staging when it
    died (``maljan-upload-*``) holds live malware as surely as a copy. In a
    mirror directory only the files named as the worker names a copy go.

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

    def stale(entry: os.DirEntry[str], is_upload: bool) -> bool:
        if not is_upload and not _is_sample_copy(entry.name):
            return False
        return entry.stat(follow_symlinks=False).st_mtime < cutoff

    swept = _each_directory(
        subdirs,
        lambda path, fd, is_upload: _remove_in(path, fd, lambda e: stale(e, is_upload)),
    )
    if swept:
        logger.info(
            "Swept %d stale sample copies from %s",
            len(swept),
            ", ".join(sorted({str(p.parent) for p in swept})),
        )
    return len(swept)
