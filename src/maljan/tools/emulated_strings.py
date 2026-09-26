"""Strings a sample only builds at run time, recovered by emulating its code.

A sample that keeps its strings encrypted shows a plain ``strings`` pass
nothing but noise: the mutex name, the file paths, the User-Agent and the
command words exist only after the sample's own decoding routine has run. An
analyst recovers them with an emulating string decoder, and this is that tool.

FLOSS does the work. It loads the file into a vivisect workspace, scores every
function for how much it looks like a decoder, and emulates the candidates and
the functions that build strings on the stack. Nothing is executed natively —
the instructions run on vivisect's emulator, over a copy of the image in the
emulator's own memory — so this is static analysis in the sense that matters
here: the sample never gets a CPU, a file system or a network.

What comes back is what FLOSS found, row by row, with the function that
decoded or built each string and the address FLOSS gives for it. Nothing is
concluded from the strings here; which of them matter is the reader's call.

FLOSS runs as FLARE's standalone Linux build, a pinned executable outside this
project's Python environment, so its dependency bounds never reach the
product's lockfile. It is found at ``MALJAN_FLOSS_PATH``, in the user tools
directory ``scripts/install_floss.sh`` writes to, or on ``PATH`` (where the
backend image puts it), and is run only when its sha256 is the pinned build's.
The child has a hard wall clock and an address-space limit, runs in a session
of its own so an overrun takes the whole process group, and is given a home and
a temporary directory inside this job's staging directory and no other
environment. What is parsed is FLOSS's JSON result document. The document is
kept for the sample while its size and mtime are unchanged, and one emulation
of a sample runs at a time, so paging through the answer or asking twice at
once costs one emulation.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import resource
import shutil
import signal
import subprocess
import tempfile
import threading
from collections.abc import Callable, Mapping, Sequence
from functools import partial
from pathlib import Path
from typing import Any

from maljan.tools import staging
from maljan.tools.errors import MISSING_DEPENDENCY, tool_error
from maljan.tools.strings import DEFAULT_STRINGS_LIMIT, _matcher

# The pinned build: FLARE's ``floss-v3.1.1-linux.zip`` release asset. The
# release publishes no digest, so both were computed from the asset when it was
# pinned. The install script and the image build check the zip; this module
# checks the executable it is about to run.
FLOSS_VERSION = "3.1.1"
FLOSS_ZIP_SHA256 = "40c05a869f34f7e2417b17ca290cc54bd3671ee1f0a2d9bd5103284c01a54666"
FLOSS_BINARY_SHA256 = "d71b9ea4fe3b2de974dc1ae3c5d0f67569921bc118dcb02ed72e905a662411cb"

# Where an operator names the executable, set in the analysis server's ``env``.
FLOSS_PATH_ENV = "MALJAN_FLOSS_PATH"

# What a caller is told to do when no usable executable is found.
FLOSS_REMEDIATION = (
    "install the pinned FLOSS build on the host that runs this server with "
    "scripts/install_floss.sh, put it on PATH, or name it in MALJAN_FLOSS_PATH in the "
    "analysis server's env"
)

# The wall clock one emulation may take when its caller names none: none. A
# 60 KB DLL was measured at under forty seconds on a laptop and a large one
# takes many minutes; how many grows with the sample's code, so a fixed number
# stopped large samples half-way. A caller that wants a bound passes
# ``timeout_s`` (the triage pack passes what is left of its budget), and past
# it FLOSS is stopped and the caller told so; the address-space limit below
# bounds its memory either way, and the job's timeout its time.
FLOSS_TIMEOUT_S: int | None = None

# The address space the child may map. On a 60 KB DLL with 150 functions the
# standalone build peaked at 814 MB resident and 836 MB of address space (the
# Python package measured 893 MB resident on the same file); vivisect's
# workspace grows with the function count, so a large or hostile PE could
# otherwise hold many gigabytes for the whole wall clock. About five times the
# measured peak leaves room for a sample several times larger. Past it the
# child's allocations fail, and that is reported the way an overrun of the wall
# clock is.
FLOSS_ADDRESS_SPACE_BYTES = 4 * 1024 * 1024 * 1024

# The three kinds FLOSS recovers by emulation. Its fourth, the static strings,
# is what the ``strings`` tool already answers, and asking FLOSS for them again
# would put a second copy of the same noise in front of the model.
KINDS = ("decoded", "stack", "tight")

# FLOSS's own default. Shorter than the ``strings`` tool's six because a
# decoded string is already known to be a string: a four-character mutex or
# path fragment is exactly the kind of thing worth seeing.
DEFAULT_MIN_LENGTH = 4
_MIN_REQUESTABLE_LENGTH = 3

# The largest page one call answers, as ``strings`` bounds its own.
_MAX_LIMIT = 2000

# How many result documents are remembered at once. One per sample a sidecar
# sees, and a document for a small sample is a few kilobytes: the bound is
# against a process that lives for weeks.
_MAX_REMEMBERED = 8
_REMEMBERED: dict[tuple[str, int, int, int], dict[str, Any]] = {}
_LOCK = threading.Lock()
# One lock per sample being emulated, so a second caller waits for the first
# result rather than starting a second emulation of the same file.
_IN_FLIGHT: dict[tuple[str, int, int, int], threading.Lock] = {}

# The executables whose digest has been checked, keyed by path and by the
# file's size, mtime, inode and ctime, so any write, replacement or rename onto
# the path is checked again.
_VERIFIED: dict[tuple[str, int, int, int, int], bool] = {}

# The name the verified copy of the build is written under, inside the run's
# own directory.
_RUN_COPY = "floss"

# The last line of FLOSS's stderr is what an error answer quotes, bounded.
_ERROR_TAIL_CHARS = 400

# The directory under this job's staging directory that holds each run's own
# directory, the child's home and temporary directory: the standalone build
# unpacks itself into ``TMPDIR`` and vivisect creates ``~/.envi`` under ``HOME``.
_SCRATCH_DIRECTORY = "floss"

# How a child that ran out of address space ends: Python's MemoryError, or a
# signal from a native allocation that failed (SIGABRT, SIGSEGV) or from the
# kernel (SIGKILL).
_KILLED_BY = frozenset({-signal.SIGABRT, -signal.SIGSEGV, -signal.SIGKILL})
_OUT_OF_MEMORY_WORDS = ("MemoryError", "Cannot allocate memory", "std::bad_alloc")

Runner = Callable[[Sequence[str], float | None], "subprocess.CompletedProcess[str]"]


def user_tools_dir() -> Path:
    """Where ``scripts/install_floss.sh`` puts the build for this user.

    Under ``HOME`` alone: the sidecar is started with ``HOME`` and not with the
    XDG variables, so a directory chosen by them in the installer's shell could
    be one the server never looks in.
    """
    return Path.home() / ".local" / "share" / "maljan" / "tools"


def default_install_path() -> Path:
    """The executable ``scripts/install_floss.sh`` writes for the pinned version."""
    return user_tools_dir() / f"floss-{FLOSS_VERSION}" / "floss"


def _is_pinned_build(path: Path) -> bool:
    """Whether ``path`` is the pinned build, by its sha256.

    This choice of candidate is what the manifest reports; it is not what makes
    a run safe. The bytes that run are the copy ``_verified_copy`` writes and
    hashes as it writes them, so a file swapped in after this check is refused
    rather than run. The verdict is remembered per size, mtime, inode and
    ctime, and anything that changes the file changes one of those.
    """
    try:
        info = path.stat()
    except OSError:
        return False
    key = (str(path), info.st_size, info.st_mtime_ns, info.st_ino, info.st_ctime_ns)
    known = _VERIFIED.get(key)
    if known is not None:
        return known
    hasher = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(block)
    except OSError:
        return False
    _VERIFIED[key] = hasher.hexdigest() == FLOSS_BINARY_SHA256
    return _VERIFIED[key]


def find_floss(environ: Mapping[str, str] | None = None) -> tuple[Path | None, str]:
    """The pinned FLOSS executable, or ``None`` and the reason there is none.

    ``MALJAN_FLOSS_PATH`` when it is set, and nothing else then; otherwise the
    user tools directory, then ``PATH``. The reason names where the tool looked
    and never a host path, because it travels to the capability manifest, the
    console and the judge's prompt. ``environ`` is the environment to read the
    two variables from, this process's when it is not given: the triage pack
    passes the analysis server's, so the pack and the server find one build.
    """
    source = os.environ if environ is None else environ
    configured = str(source.get(FLOSS_PATH_ENV, "")).strip()
    if configured:
        candidates = [configured]
    else:
        candidates = [
            str(default_install_path()),
            shutil.which("floss", path=source.get("PATH")) or "",
        ]
    found = [Path(c) for c in candidates if c and Path(c).is_file() and os.access(c, os.X_OK)]
    if not found:
        where = (
            f"{FLOSS_PATH_ENV} names no executable file"
            if configured
            else "no floss executable in the user tools directory or on PATH"
        )
        return None, f"floss is not installed: {where}"
    for path in found:
        if _is_pinned_build(path):
            return path, ""
    return None, (
        f"floss is not installed: the executable found is not the pinned FLOSS "
        f"{FLOSS_VERSION} build (sha256 mismatch)"
    )


def floss_unavailable(environ: Mapping[str, str] | None = None) -> str | None:
    """The capability manifest's probe: ``None`` when the pinned build is here."""
    path, reason = find_floss(environ)
    return None if path is not None else reason


def _scratch(directory: Path | None = None) -> Path:
    """This job's directory for the child's home and temporary files, created private.

    ``directory`` is one a caller outside the sidecar opened for its job; the
    sidecar itself joins the staging base and the job leaf its spawn named.
    """
    if directory is not None:
        return staging.private_dir(Path(directory))
    base = staging.private_dir(staging.staging_base())
    root = staging.staging_root()
    if root != base:
        staging.private_dir(root)
    return staging.private_dir(root / _SCRATCH_DIRECTORY)


def _limit_address_space() -> None:
    """Run in the child before FLOSS starts: cap the address space it may map."""
    resource.setrlimit(resource.RLIMIT_AS, (FLOSS_ADDRESS_SPACE_BYTES, FLOSS_ADDRESS_SPACE_BYTES))


class NotThePinnedBuild(OSError):
    """The executable's bytes, read to be run, are not the pinned build's."""


def _verified_copy(source: Path, directory: Path) -> Path:
    """``source`` copied into ``directory`` and hashed as it is read, or refused.

    What this protects against: an executable at the configured path or on
    ``PATH`` that is not the pinned build, or that was changed or replaced
    after the manifest checked it. The copy is the file that runs, it is
    written by this process into a directory only this user may enter, and its
    digest is of exactly the bytes written, so no check-then-run gap remains.
    The copy is refused and removed when the digest is not the pinned one.
    """
    target = directory / _RUN_COPY
    hasher = hashlib.sha256()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(target, flags, 0o700)
    try:
        with source.open("rb") as handle, os.fdopen(fd, "wb") as out:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(block)
                out.write(block)
    except OSError:
        target.unlink(missing_ok=True)
        raise
    if hasher.hexdigest() != FLOSS_BINARY_SHA256:
        target.unlink(missing_ok=True)
        raise NotThePinnedBuild(
            f"the floss executable is not the pinned FLOSS {FLOSS_VERSION} build "
            "(sha256 mismatch when read to run); nothing was run"
        )
    return target


def _seconds(timeout_s: int | None) -> int | None:
    """A caller's wall clock as whole seconds of at least one, or ``None`` for none."""
    return None if timeout_s is None else max(1, int(timeout_s))


def _run(
    argv: Sequence[str],
    timeout: float | None,
    pinned: Path | None = None,
    scratch: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """FLOSS's command line, bounded in time and memory, its whole group killed on overrun.

    Each run has a directory of its own inside this job's scratch directory:
    the child's home, temporary directory and working directory, where the
    standalone build unpacks itself (about 63 MB). It is removed when the run
    ends, however it ends — an answer, a timeout, the memory limit. With
    ``pinned``, that executable is copied into the run's directory through
    ``_verified_copy`` and the copy is what ``argv`` runs. ``scratch`` is the
    job directory the run's own directory goes in, when the caller opened one.

    The environment is built rather than inherited: a search path, a locale,
    the run's directory as home and temporary directory, and the switch that
    keeps FLOSS from saving a vivisect workspace beside the sample. Nothing of
    the server's own environment reaches the child.
    """
    run = Path(tempfile.mkdtemp(prefix="run-", dir=_scratch(scratch)))
    try:
        command = list(argv)
        if pinned is not None:
            command[0] = str(_verified_copy(pinned, run))
        return _spawn(command, timeout, str(run))
    finally:
        shutil.rmtree(run, ignore_errors=True)


def _spawn(
    command: list[str], timeout: float | None, workdir: str
) -> subprocess.CompletedProcess[str]:
    """One child in its own session, in ``workdir``, its group killed if it overruns."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "HOME": workdir,
        "TMPDIR": workdir,
        "FLOSS_SAVE_WORKSPACE": "0",
    }
    process = subprocess.Popen(  # noqa: S603 - a fixed argv naming the verified build
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=workdir,
        start_new_session=True,
        preexec_fn=_limit_address_space,  # noqa: PLW1509 - one setrlimit call
    )
    # Its own session, so its group is what the server kills when every caller
    # of this run has gone (``tools.children``).
    from maljan.tools import children

    # Only while it runs: a reaped child's pid can be another session's.
    children.register(
        lambda: children.kill_process_group(process.pid) if process.poll() is None else None
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # The standalone build is a bootloader and the interpreter it starts;
        # the group is what holds both.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _floss_argv(executable: str, path: Path, min_len: int) -> list[str]:
    """The command FLOSS is run as: JSON out, no prompt, no static strings.

    The sample's path is absolute because the child runs in a directory of its
    own, where a relative path names nothing.
    """
    return [
        executable,
        "--json",
        "--quiet",
        "--disable-progress",
        "--minimum-length",
        str(min_len),
        "--only",
        *KINDS,
        "--",
        str(path.resolve()),
    ]


def _hex(value: Any) -> str | None:
    """An address as the hexadecimal a disassembler shows, or ``None``."""
    return hex(value) if isinstance(value, int) and not isinstance(value, bool) else None


def _rva(value: Any, imagebase: Any) -> str | None:
    """An address inside the image as an offset from its base, or ``None``.

    vivisect may load a DLL at a base of its own choosing rather than the one
    the header asks for, so a virtual address FLOSS reports is only meaningful
    against the base it reports with it. The difference is the one number a
    disassembler opened on the same file agrees with.
    """
    if not isinstance(value, int) or not isinstance(imagebase, int) or not imagebase:
        return None
    offset = value - imagebase
    return hex(offset) if offset >= 0 else None


def _rows(document: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per recovered string, decoded first, in FLOSS's order.

    ``function`` is the routine that produced the string in every row, so a
    reader can take any of them to a disassembler — ``function_rva`` is the
    same address as an offset from the image base, which is what a
    disassembler that loaded the file elsewhere agrees with. A decoded string also
    carries ``called_at``, the call site the emulation started from, and
    ``address``, where in memory the decoded text was written, with FLOSS's
    word for which memory that was. A stack or tight string carries the
    instruction it was read at and its offset in the function's frame.
    """
    found = document.get("strings") or {}
    base = (document.get("metadata") or {}).get("imagebase")
    rows: list[dict[str, Any]] = []
    for entry in found.get("decoded_strings") or []:
        rows.append(
            {
                "kind": "decoded",
                "string": str(entry.get("string") or ""),
                "encoding": str(entry.get("encoding") or ""),
                "function": _hex(entry.get("decoding_routine")),
                "function_rva": _rva(entry.get("decoding_routine"), base),
                "called_at": _hex(entry.get("decoded_at")),
                "called_at_rva": _rva(entry.get("decoded_at"), base),
                "address": _hex(entry.get("address")),
                "address_type": str(entry.get("address_type") or ""),
            }
        )
    for kind, key in (("stack", "stack_strings"), ("tight", "tight_strings")):
        for entry in found.get(key) or []:
            rows.append(
                {
                    "kind": kind,
                    "string": str(entry.get("string") or ""),
                    "encoding": str(entry.get("encoding") or ""),
                    "function": _hex(entry.get("function")),
                    "function_rva": _rva(entry.get("function"), base),
                    "program_counter": _hex(entry.get("program_counter")),
                    "frame_offset": entry.get("frame_offset"),
                }
            )
    return rows


def _meta(document: dict[str, Any]) -> dict[str, Any]:
    """What FLOSS says about its own run: version, image base, how much it looked at."""
    meta = document.get("metadata") or {}
    functions = (document.get("analysis") or {}).get("functions") or {}
    runtime = meta.get("runtime") or {}
    return {
        "floss_version": str(meta.get("version") or ""),
        "imagebase": _hex(meta.get("imagebase")),
        "language": str(meta.get("language") or ""),
        "functions_discovered": functions.get("discovered"),
        "functions_emulated_for_decoding": functions.get("analyzed_decoded_strings"),
        "runtime_s": runtime.get("total"),
    }


def _error(message: str) -> dict[str, Any]:
    return {"error": message, "tool": "floss"}


def _tail(text: str) -> str:
    lines = [line for line in (text or "").strip().splitlines() if line.strip()]
    last = lines[-1] if lines else ""
    return last[-_ERROR_TAIL_CHARS:]


def _ran_out_of_memory(finished: subprocess.CompletedProcess[str]) -> bool:
    """Whether a failed child ended the way one past its address-space limit does."""
    if finished.returncode in _KILLED_BY:
        return True
    return any(word in (finished.stderr or "") for word in _OUT_OF_MEMORY_WORDS)


def _emulate(
    executable: str, target: Path, min_len: int, timeout_s: int | None, runner: Runner
) -> dict[str, Any] | str:
    """One FLOSS run over ``target``: its result document, or the sentence saying why not."""
    try:
        finished = runner(
            _floss_argv(executable, target, min_len),
            None if timeout_s is None else float(timeout_s),
        )
    except subprocess.TimeoutExpired:
        return f"FLOSS produced no result within its budget ({timeout_s} s) and was stopped"
    except OSError as exc:
        return f"FLOSS could not be started: {exc}"
    if finished.returncode != 0:
        if _ran_out_of_memory(finished):
            limit_mib = FLOSS_ADDRESS_SPACE_BYTES // (1024 * 1024)
            return (
                f"FLOSS produced no result within its budget ({limit_mib} MiB of address "
                "space) and was stopped"
            )
        return f"FLOSS exited with status {finished.returncode}: {_tail(finished.stderr)}"
    output = (finished.stdout or "").strip()
    if not output:
        # FLOSS prints nothing at all for a file with no printable run in it,
        # which is an answer: there was nothing to start from.
        return {}
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        return f"FLOSS answered with something other than its JSON document: {_tail(output)}"
    if not isinstance(parsed, dict):
        return "FLOSS answered with something other than its JSON document"
    return parsed


def _document(
    executable: str, target: Path, min_len: int, timeout_s: int | None, runner: Runner
) -> dict[str, Any] | str:
    """FLOSS's result document for this file, emulated once however many ask."""
    info = target.stat()
    key = (str(target), info.st_size, info.st_mtime_ns, min_len)
    with _LOCK:
        remembered = _REMEMBERED.get(key)
        if remembered is not None:
            return remembered
        in_flight = _IN_FLIGHT.setdefault(key, threading.Lock())
    with in_flight:
        with _LOCK:
            remembered = _REMEMBERED.get(key)
        if remembered is not None:
            return remembered
        document = _emulate(executable, target, min_len, timeout_s, runner)
        with _LOCK:
            _IN_FLIGHT.pop(key, None)
            if isinstance(document, dict):
                if len(_REMEMBERED) >= _MAX_REMEMBERED:
                    _REMEMBERED.clear()
                _REMEMBERED[key] = document
        return document


def forget_documents() -> None:
    """Drop every remembered result document and checked digest. For tests."""
    with _LOCK:
        _REMEMBERED.clear()
        _IN_FLIGHT.clear()
    _VERIFIED.clear()


def floss(
    path: str,
    min_len: int = DEFAULT_MIN_LENGTH,
    kinds: Sequence[str] | None = None,
    limit: int = DEFAULT_STRINGS_LIMIT,
    offset: int = 0,
    pattern: str | None = None,
    timeout_s: int | None = FLOSS_TIMEOUT_S,
    runner: Runner | None = None,
    environ: Mapping[str, str] | None = None,
    scratch: str | Path | None = None,
) -> dict[str, Any]:
    """The decoded, stack and tight strings FLOSS recovers from a PE by emulation.

    Paged the way ``strings`` is: ``total`` is every row FLOSS recovered,
    ``total_matched`` the rows ``kinds`` and ``pattern`` kept, and
    ``next_offset`` where the following page starts, ``None`` on the last one.
    ``counts`` says how many of each kind FLOSS found before any filter.
    ``runner`` stands in for the child process in tests; with it, the
    executable is not looked for. ``environ`` is where the executable is
    looked for (``find_floss``) and ``scratch`` the job directory the run's
    own directory is made in; the sidecar passes neither, the triage pack
    passes both.
    """
    target = Path(path)
    if not target.is_file():
        return _error(f"no such file: {path}")
    minimum = max(_MIN_REQUESTABLE_LENGTH, int(min_len))
    limit = max(0, min(int(limit), _MAX_LIMIT))
    offset = max(0, int(offset))
    wanted = tuple(KINDS) if not kinds else tuple(str(k).strip().lower() for k in kinds)
    unknown = [kind for kind in wanted if kind not in KINDS]
    if unknown:
        return _error(f"unknown kinds {unknown}; known: {', '.join(KINDS)}")
    try:
        matches = _matcher(pattern)
    except Exception as exc:  # noqa: BLE001 - re.error, reported as the caller's to fix
        return _error(f"bad pattern {pattern!r}: {exc}")
    with target.open("rb") as handle:
        if handle.read(2) != b"MZ":
            return _error(
                "FLOSS emulates Windows PE code only; this file is not a PE (no MZ header)"
            )
    # vivisect loads a saved workspace beside the file in place of the file,
    # and a saved workspace is a pickle: reading one runs whatever it holds.
    if Path(f"{target}.viv").exists():
        return _error(
            "a saved vivisect workspace sits beside this file; FLOSS would load it in place "
            "of the file, so the call is refused"
        )

    if runner is None:
        executable, reason = find_floss(environ)
        if executable is None:
            return tool_error(
                MISSING_DEPENDENCY, reason, tool="floss", remediation=FLOSS_REMEDIATION
            )
        pinned = partial(_run, pinned=executable, scratch=Path(scratch) if scratch else None)
        document = _document(str(executable), target, minimum, _seconds(timeout_s), pinned)
    else:
        document = _document("floss", target, minimum, _seconds(timeout_s), runner)
    if isinstance(document, str):
        return _error(document)

    rows = _rows(document)
    counts = {kind: sum(1 for row in rows if row["kind"] == kind) for kind in KINDS}
    kept = [row for row in rows if row["kind"] in wanted and matches(row["string"])]
    page = kept[offset : offset + limit]
    more = len(kept) > offset + len(page) and bool(page)
    return {
        "strings": page,
        "counts": counts,
        "total": len(rows),
        "total_matched": len(kept),
        "page_offset": offset,
        "page_limit": limit,
        "kinds": list(wanted),
        "pattern": pattern,
        "next_offset": offset + len(page) if more else None,
        "truncated": more,
        "meta": _meta(document),
    }


def remembered_rows(path: str | Path) -> list[dict[str, Any]]:
    """FLOSS's rows for this file when a result document is remembered for it, else none.

    Never runs FLOSS: a tool that compares its own findings with FLOSS's asks
    what an earlier call in this process already recovered, and a file FLOSS
    has not been run on has nothing to compare with. Any length the document
    was made with will do; the rows are the same strings above it.
    """
    target = Path(path)
    try:
        info = target.stat()
    except OSError:
        return []
    with _LOCK:
        documents = [
            document
            for (name, size, mtime, _min_len), document in _REMEMBERED.items()
            if name == str(target) and size == info.st_size and mtime == info.st_mtime_ns
        ]
    return _rows(documents[0]) if documents else []
