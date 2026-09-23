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

FLOSS runs as a child process with a hard wall clock, for the reason capa
does: vivisect's analysis loop has no point at which it can be cancelled, and
a child can be killed where a thread cannot. The child is FLOSS's own command
line with its JSON output, so what is parsed is FLOSS's result document rather
than objects inside its package. The document is kept for the sample while its
size and mtime are unchanged, so paging through the answer costs one
emulation, not one per page.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from maljan.tools.strings import DEFAULT_STRINGS_LIMIT, _matcher

# The wall clock one emulation may take. A 60 KB DLL was measured at under
# forty seconds on a laptop; a large one takes many minutes, and past this
# FLOSS is stopped and the caller told so rather than left waiting on a stage
# budget.
FLOSS_TIMEOUT_S = 600

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

# The last line of FLOSS's stderr is what an error answer quotes, bounded.
_ERROR_TAIL_CHARS = 400

# What the child is started as. FLOSS's CLI saves a vivisect workspace beside
# the sample when this variable asks it to, and a workspace written next to a
# sample in a shared directory is a file this tool had no business creating.
_NO_WORKSPACE = {"FLOSS_SAVE_WORKSPACE": "0"}

Runner = Callable[[Sequence[str], float], "subprocess.CompletedProcess[str]"]


def _run(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    """FLOSS's command line, killed if it overruns ``timeout``."""
    env = {**os.environ, **_NO_WORKSPACE}
    return subprocess.run(  # noqa: S603 - a fixed argv built from our own interpreter
        list(argv),
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )


def _floss_argv(path: Path, min_len: int) -> list[str]:
    """The command FLOSS is run as: JSON out, no prompt, no static strings."""
    return [
        sys.executable,
        "-m",
        "floss",
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


def _document(target: Path, min_len: int, timeout_s: int, runner: Runner) -> dict[str, Any] | str:
    """FLOSS's result document for this file, or the sentence saying why there is none."""
    info = target.stat()
    key = (str(target), info.st_size, info.st_mtime_ns, min_len)
    with _LOCK:
        remembered = _REMEMBERED.get(key)
    if remembered is not None:
        return remembered
    try:
        finished = runner(_floss_argv(target, min_len), float(timeout_s))
    except subprocess.TimeoutExpired:
        return f"FLOSS produced no result within its budget ({timeout_s} s) and was stopped"
    except OSError as exc:
        return f"FLOSS could not be started: {exc}"
    if finished.returncode != 0:
        return f"FLOSS exited with status {finished.returncode}: {_tail(finished.stderr)}"
    output = (finished.stdout or "").strip()
    if not output:
        # FLOSS prints nothing at all for a file with no printable run in it,
        # which is an answer: there was nothing to start from.
        document: dict[str, Any] = {}
    else:
        try:
            parsed = json.loads(output)
        except json.JSONDecodeError:
            return f"FLOSS answered with something other than its JSON document: {_tail(output)}"
        if not isinstance(parsed, dict):
            return "FLOSS answered with something other than its JSON document"
        document = parsed
    with _LOCK:
        if len(_REMEMBERED) >= _MAX_REMEMBERED:
            _REMEMBERED.clear()
        _REMEMBERED[key] = document
    return document


def forget_documents() -> None:
    """Drop every remembered result document. For tests."""
    with _LOCK:
        _REMEMBERED.clear()


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

    if runner is None and importlib.util.find_spec("floss") is None:
        return _error("flare-floss is not installed; it comes with the floss extra")
    document = _document(target, minimum, max(1, int(timeout_s)), runner or _run)
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
