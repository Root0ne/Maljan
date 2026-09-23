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
import threading
from collections.abc import Callable, Sequence
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

# The wall clock one emulation may take. A 60 KB DLL was measured at under
# forty seconds on a laptop; a large one takes many minutes, and past this
# FLOSS is stopped and the caller told so rather than left waiting on a stage
# budget.
FLOSS_TIMEOUT_S = 600

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

# The executables whose digest has been checked, keyed by path, size and mtime.
_VERIFIED: dict[tuple[str, int, int], bool] = {}

# The last line of FLOSS's stderr is what an error answer quotes, bounded.
_ERROR_TAIL_CHARS = 400

# The directory under this job's staging directory the child uses as its home
# and its temporary directory: the standalone build unpacks itself into
# ``TMPDIR`` and vivisect creates ``~/.envi`` under ``HOME``.
_SCRATCH_DIRECTORY = "floss"

# How a child that ran out of address space ends: Python's MemoryError, or a
# signal from a native allocation that failed (SIGABRT, SIGSEGV) or from the
# kernel (SIGKILL).
_KILLED_BY = frozenset({-signal.SIGABRT, -signal.SIGSEGV, -signal.SIGKILL})
_OUT_OF_MEMORY_WORDS = ("MemoryError", "Cannot allocate memory", "std::bad_alloc")

Runner = Callable[[Sequence[str], float], "subprocess.CompletedProcess[str]"]


def user_tools_dir() -> Path:
    """Where ``scripts/install_floss.sh`` puts the build for this user."""
    data = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(data) / "maljan" / "tools"


def default_install_path() -> Path:
    """The executable ``scripts/install_floss.sh`` writes for the pinned version."""
    return user_tools_dir() / f"floss-{FLOSS_VERSION}" / "floss"


def _is_pinned_build(path: Path) -> bool:
    """Whether ``path`` is the pinned build, by its sha256, remembered per size and mtime."""
    try:
        info = path.stat()
    except OSError:
        return False
    key = (str(path), info.st_size, info.st_mtime_ns)
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


def find_floss() -> tuple[Path | None, str]:
    """The pinned FLOSS executable, or ``None`` and the reason there is none.

    ``MALJAN_FLOSS_PATH`` when it is set, and nothing else then; otherwise the
    user tools directory, then ``PATH``. The reason names where the tool looked
    and never a host path, because it travels to the capability manifest, the
    console and the judge's prompt.
    """
    configured = os.environ.get(FLOSS_PATH_ENV, "").strip()
    if configured:
        candidates = [configured]
    else:
        candidates = [str(default_install_path()), shutil.which("floss") or ""]
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


def floss_unavailable() -> str | None:
    """The capability manifest's probe: ``None`` when the pinned build is here."""
    path, reason = find_floss()
    return None if path is not None else reason


def _scratch() -> Path:
    """This job's directory for the child's home and temporary files, created private."""
    base = staging.private_dir(staging.staging_base())
    root = staging.staging_root()
    if root != base:
        staging.private_dir(root)
    return staging.private_dir(root / _SCRATCH_DIRECTORY)


def _limit_address_space() -> None:
    """Run in the child before FLOSS starts: cap the address space it may map."""
    resource.setrlimit(resource.RLIMIT_AS, (FLOSS_ADDRESS_SPACE_BYTES, FLOSS_ADDRESS_SPACE_BYTES))


def _run(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    """FLOSS's command line, bounded in time and memory, its whole group killed on overrun.

    The environment is built rather than inherited: a search path, a locale, a
    home and a temporary directory inside this job's staging directory, and
    the switch that keeps FLOSS from saving a vivisect workspace beside the
    sample. Nothing of the server's own environment reaches the child.
    """
    scratch = str(_scratch())
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "HOME": scratch,
        "TMPDIR": scratch,
        "FLOSS_SAVE_WORKSPACE": "0",
    }
    process = subprocess.Popen(  # noqa: S603 - a fixed argv naming the verified build
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=scratch,
        start_new_session=True,
        preexec_fn=_limit_address_space,  # noqa: PLW1509 - one setrlimit call
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
    return subprocess.CompletedProcess(list(argv), process.returncode, stdout, stderr)


def _floss_argv(executable: str, path: Path, min_len: int) -> list[str]:
    """The command FLOSS is run as: JSON out, no prompt, no static strings."""
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
        str(path),
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
    executable: str, target: Path, min_len: int, timeout_s: int, runner: Runner
) -> dict[str, Any] | str:
    """One FLOSS run over ``target``: its result document, or the sentence saying why not."""
    try:
        finished = runner(_floss_argv(executable, target, min_len), float(timeout_s))
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
    executable: str, target: Path, min_len: int, timeout_s: int, runner: Runner
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
    timeout_s: int = FLOSS_TIMEOUT_S,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """The decoded, stack and tight strings FLOSS recovers from a PE by emulation.

    Paged the way ``strings`` is: ``total`` is every row FLOSS recovered,
    ``total_matched`` the rows ``kinds`` and ``pattern`` kept, and
    ``next_offset`` where the following page starts, ``None`` on the last one.
    ``counts`` says how many of each kind FLOSS found before any filter.
    ``runner`` stands in for the child process in tests; with it, the
    executable is not looked for.
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
        executable, reason = find_floss()
        if executable is None:
            return tool_error(
                MISSING_DEPENDENCY, reason, tool="floss", remediation=FLOSS_REMEDIATION
            )
        document = _document(str(executable), target, minimum, max(1, int(timeout_s)), _run)
    else:
        document = _document("floss", target, minimum, max(1, int(timeout_s)), runner)
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
