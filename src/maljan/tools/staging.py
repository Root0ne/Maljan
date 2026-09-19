"""Where one job's staged bytes live, and who takes them away again.

A tool sidecar writes two kinds of file: the uploads ``put_sample`` receives
and the payloads ``carve_payloads`` writes out of a sample. Both used to land
in one directory per server *process*, which is one directory for every job the
host ever ran — so an operator's uploaded document stayed readable by the next
job the moment any read surface widened, and a stale tree from an old run of
the same sample was reachable until the TTL took it.

The boundary is the job's own directory:

* ``MALJAN_STAGING_DIR`` is the **base**, and it stays what the operator set.
  A server nobody configured uses ``default_base()``.
* ``MALJAN_STAGING_JOB`` is the **leaf**, one directory name composed by
  whoever spawns the sidecar and never read from the parent environment. The
  sidecar joins the two itself, which is why the spawn does not have to know
  the base a sidecar would have defaulted to.

Two variables rather than one because the spawn cannot compose one:
``agents.subprocess_env.child_env`` applies the server's own ``mcp.<server>.env``
mapping last, so a composed absolute path written before it would be overridden
by an operator's value, and one written after it would overwrite theirs.

Who creates what, and who removes it:

* the sidecar creates ``<base>/<leaf>`` 0o700, on its first write, and nothing
  else creates it — a job that stages nothing has no directory;
* the spawn composes the name and records it here, so the process that started
  the sidecars knows exactly which directories that job may have created;
* the job's owner removes them on every way out of the run, beside the owner
  heartbeat it drops in the same place;
* whatever a removal missed — a worker that was killed, a directory another
  user's process holds open — is left to the sidecar's own TTL sweep, which
  prunes a whole job directory by the newest mtime inside it.
"""

from __future__ import annotations

import os
import re
import stat
import tempfile
import threading
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path

# The base directory, the per-job leaf inside it, and how long anything in
# either is kept. Named here so the sidecars, the spawn and the worker read
# one spelling of each.
STAGING_DIR_ENV = "MALJAN_STAGING_DIR"
STAGING_JOB_ENV = "MALJAN_STAGING_JOB"
STAGING_TTL_ENV = "MALJAN_STAGING_TTL_HOURS"

# The base a sidecar uses when nothing configured one. Shared rather than
# written out in each server, because the remover has to reach the same
# directory the writer did.
DEFAULT_BASE_NAME = "maljan-analysis-mcp"

# What a job directory is called. The prefix is what tells the sweep which
# entries under the base are job directories and which are the flat files of
# an older release, and it keeps the name away from ``carved``.
JOB_DIRECTORY_PREFIX = "job-"

# The child of a job directory a sandbox capture is fetched into. A capture is
# the one file the platform writes into staging without going through
# ``put_sample``, and until it moved here it went to a directory shared by
# every job on the host, named as a permanent sample root, and removed by
# nothing — so a sample carrying one instruction could have a later job read
# an earlier job's whole network capture.
CAPTURES_DIRECTORY = "captures"

# Where the release before this fetched captures. Written by nothing now; the
# sweep still reaches it, because it is this project's directory and what is
# in it is somebody's traffic.
LEGACY_CAPTURE_DIR_NAME = "maljan-cape-pcap"

# A job id is a uuid in every deployment, but it arrives as a string and a
# directory name is not a place to find out otherwise. Anything outside this
# set becomes a hyphen and the original is named by a digest suffix, so two ids
# that differ only in what was replaced still get two directories.
_UNSAFE_IN_A_NAME = re.compile(r"[^A-Za-z0-9._-]")
_MAX_ID_CHARS = 64
_DIGEST_CHARS = 12

# The job directories this process composed a name for, by job id. The spawn
# writes here and the job's teardown reads it: the exact paths, rather than a
# base re-derived at removal time from settings that may since have been
# reloaded. Reached from the agent loop's thread and the graph loop's thread.
_COMPOSED: dict[str, set[Path]] = {}
_COMPOSED_LOCK = threading.Lock()


def default_base() -> Path:
    """The staging base a sidecar uses when ``MALJAN_STAGING_DIR`` is unset."""
    return Path(tempfile.gettempdir()) / DEFAULT_BASE_NAME


def staging_base(environ: Mapping[str, str] | None = None) -> Path:
    """The configured base, created or not. Never the per-job directory.

    Made absolute here, at the one place both sides read it. A relative
    ``MALJAN_STAGING_DIR`` otherwise means two directories: the worker resolves
    it against its own working directory and a built-in sidecar against
    ``services/<name>-mcp``, which is the cwd it is spawned with — so the
    remover would look somewhere the writer never wrote.
    """
    source = os.environ if environ is None else environ
    configured = str(source.get(STAGING_DIR_ENV, "")).strip()
    base = Path(configured) if configured else default_base()
    return base if base.is_absolute() else Path(os.path.abspath(base))


def job_directory_name(job_id: str) -> str:
    """The one directory name that stands for ``job_id``.

    Deterministic, so the spawn, the sidecar and the remover name the same
    directory without passing a path between them, and a single path segment
    whatever the id was: a value carrying a separator or a ``..`` is replaced
    character by character and then distinguished by a digest of the original.

    Written in lower case, because a staging base may sit on a mount that does
    not distinguish case (macOS, CIFS) and two ids differing only in case would
    then be one directory. A job id is a uuid in every deployment here, so this
    changes nothing in practice and closes the case that is not a deployment
    here. The digest suffix keeps two ids apart when the folding — or the
    character replacement — made them equal.
    """
    raw = str(job_id or "")
    safe = _UNSAFE_IN_A_NAME.sub("-", raw)[:_MAX_ID_CHARS].lower()
    if safe != raw:
        digest = sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:_DIGEST_CHARS]
        safe = f"{safe}-{digest}" if safe else digest
    return f"{JOB_DIRECTORY_PREFIX}{safe}"


def is_job_directory_name(name: str) -> bool:
    """Whether ``name`` is one segment this module would have composed.

    Asked of the leaf a sidecar is handed before it is joined to the base: the
    value comes from the process that spawned the server rather than from a
    model, and it is still not joined to a path unchecked.
    """
    return (
        bool(name)
        and name.startswith(JOB_DIRECTORY_PREFIX)
        and "/" not in name
        and os.sep not in name
        and name not in (".", "..")
        and Path(name).name == name
    )


def job_staging_dir(base: Path, job_id: str) -> Path:
    """Where everything ``job_id`` stages lands, under ``base``."""
    return base / job_directory_name(job_id)


def job_capture_dir(job_id: str, environ: Mapping[str, str] | None = None) -> Path:
    """Where this job's sandbox captures land, created or not.

    A child of the job's own staging directory, which is what makes a capture
    obey every rule the rest of this job's bytes obey: removed with the job,
    swept by the same TTL, and refused to another job by ``confined_to_this_job``
    without a rule of its own.
    """
    return job_staging_dir(staging_base(environ), job_id) / CAPTURES_DIRECTORY


def open_capture_dir(job_id: str) -> Path:
    """This job's capture directory, created 0o700, readable by this job's sidecars.

    The directory is named as a sample root because a capture is not staged
    through ``put_sample`` — the sandbox provider writes it and the network
    analyst is told the path — and a root is how a sidecar learns it may read
    a directory the platform filled. The root is this job's own and is dropped
    when the job ends, so no later job inherits it; the shared, permanent root
    of the release before this is what let one job read another's capture.
    """
    from maljan.tools.roots import add_sample_root

    captures = job_capture_dir(job_id)
    for directory in (captures.parent.parent, captures.parent, captures):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeError(f"capture path {directory} is not a directory")
        if directory.lstat().st_mode & 0o077:
            directory.chmod(0o700)
    note_job_directory(job_id, captures.parent)
    add_sample_root(captures)
    return captures


def staging_root(environ: Mapping[str, str] | None = None) -> Path:
    """The directory the server reading ``environ`` may write and read.

    The job directory when a leaf was composed for this child, and the base
    itself when none was — a sidecar started by hand, a settings probe, or a
    deployment that runs the server outside a job.
    """
    source = os.environ if environ is None else environ
    base = staging_base(source)
    leaf = str(source.get(STAGING_JOB_ENV, "")).strip()
    return base / leaf if is_job_directory_name(leaf) else base


def touch_job_staging(job_id: str) -> bool:
    """Say this job is still running, where another process's sweep can read it.

    The sweep prunes a job directory whole once the newest mtime inside it is
    past the TTL, and it runs inside a sidecar — a child with no database, no
    queue and no way to ask whether a job is alive. So the job says so on disk,
    by keeping its own directory's mtime current: the owner that refreshes the
    heartbeat refreshes this beside it, twice inside the claim's own TTL.

    Without it, a job that has been running longer than
    ``MALJAN_STAGING_TTL_HOURS`` without staging anything new — a long static
    pass, a slow sandbox — could have its directory, carved payloads and all,
    removed under it by a *second* worker's sidecar sharing the base.

    Returns whether there was a directory to touch.
    """
    directory = job_staging_dir(staging_base(), job_id)
    try:
        os.utime(directory, None, follow_symlinks=False)
    except OSError:  # nothing staged yet, or a directory somebody else owns
        return False
    return True


def make_private(path: Path) -> None:
    """Take everyone but this user off a file the platform just wrote.

    For a file a provider streamed in rather than one this project opened:
    ``put_sample`` creates its own at 0o600 with ``O_NOFOLLOW``, while a
    capture arrives through an HTTP client that writes at the process umask —
    0o664 on this host, which on a shared machine is every local user.
    """
    try:
        if not path.is_symlink() and path.is_file():
            path.chmod(0o600)
    except OSError:  # a file the provider removed again, or a foreign mount
        pass


def confined_to_this_job(resolved: Path, environ: Mapping[str, str] | None = None) -> Path:
    """``resolved``, unless it is staged bytes belonging to a different job.

    A sample root is a deployment's own directory and a staging base may be
    configured inside one — and then a path argument that lands in a sibling
    job's directory answers the roots question truthfully and would be read.
    The job directory is the boundary whatever the roots are, so the staging
    base is the one place where being inside a root is not enough.

    Raises:
        PathOutsideRoots: for anything staged that this job did not stage.
    """
    from maljan.tools.roots import PathOutsideRoots

    source = os.environ if environ is None else environ
    base = staging_base(source)
    root = staging_root(source)
    if root == base:
        return resolved
    real_base = Path(os.path.realpath(base))
    real_root = Path(os.path.realpath(root))
    if real_base in resolved.parents and not (
        resolved == real_root or real_root in resolved.parents
    ):
        raise PathOutsideRoots()
    return resolved


def note_job_directory(job_id: str, path: Path) -> None:
    """Record that ``job_id``'s sidecars were pointed at ``path``."""
    with _COMPOSED_LOCK:
        _COMPOSED.setdefault(str(job_id), set()).add(Path(path))


def job_directories(job_id: str) -> list[Path]:
    """Every directory this process composed for ``job_id``, in a stable order."""
    with _COMPOSED_LOCK:
        return sorted(_COMPOSED.get(str(job_id), ()))


def forget_job_directories(job_id: str) -> list[Path]:
    """Drop what was recorded for ``job_id`` and hand it back."""
    with _COMPOSED_LOCK:
        return sorted(_COMPOSED.pop(str(job_id), ()))


def remove_job_staging(job_id: str) -> list[Path]:
    """Remove every staging directory this process composed for ``job_id``.

    Returns the ones that were there and are gone. A directory that was never
    created — a job whose sidecars staged nothing — is not in that list and is
    not a failure either; the caller tells the two apart by asking what is left
    on disk rather than by counting. Never raises: a removal that fails is the
    caller's to log, and what is left behind is swept by the sidecar's TTL.

    The tree holds live malware, so it is walked rather than handed to a
    library: nothing is followed through a symlink, and each directory is made
    private again before it is descended into, so a partial removal cannot
    leave a readable directory behind.

    The job's capture directory goes with it, and so does the sample root that
    named it: a root left behind would be inherited by every sidecar this
    process starts afterwards, which is the shape of the leak this replaces.
    """
    from maljan.tools.roots import remove_sample_root

    remove_sample_root(job_capture_dir(job_id))
    removed: list[Path] = []
    for path in forget_job_directories(job_id):
        if not path.exists() and not path.is_symlink():
            continue
        if remove_tree(path):
            removed.append(path)
    return removed


def remove_tree(root: Path) -> bool:
    """Delete ``root`` and everything under it. True when nothing is there.

    A symlink at ``root`` is unlinked rather than followed, and so is every
    link inside it: a directory of staged malware is exactly the place a link
    planted into it must not turn a cleanup into a delete somewhere else.
    """
    try:
        info = root.lstat()
    except OSError:
        return True  # nothing there, which is the state this asks for
    if not stat.S_ISDIR(info.st_mode):
        try:
            root.unlink()
        except OSError:
            return False
        return True
    ok = True
    for directory, subdirectories, files in os.walk(root, topdown=False, followlinks=False):
        here = Path(directory)
        try:
            here.chmod(0o700)
        except OSError:
            ok = False
        for name in files:
            try:
                (here / name).unlink()
            except OSError:
                ok = False
        # ``os.walk`` reports a symlink to a directory among the directories
        # and never descends into it, so it is unlinked here rather than
        # rmdir'd — the target is somebody else's.
        for name in subdirectories:
            entry = here / name
            if entry.is_symlink():
                try:
                    entry.unlink()
                except OSError:
                    ok = False
        try:
            here.rmdir()
        except OSError:
            ok = False
    return ok and not root.exists()
