"""unblob over MCP: the files a container or firmware image holds, carved and extracted.

Tools around ``unblob`` (its command-line program), in an image of its own
with the extractors it calls (``Dockerfile``); see ``README.md``. unblob reads
the file it is given, finds each chunk of a format it knows (archives,
compressed streams, file systems, firmware containers) by its own bytes, and
unpacks each one with that format's extractor; nothing it unpacks is run.

Where the files go. Never beside the sample: the sample directory is mounted
read-only, and every extraction is written into a directory of its own under
this server's carve root (``UNBLOB_CARVE_ROOT``, in the container's tmpfs),
named by a fresh id. unblob confines its own writes to that directory
(Landlock, where the kernel offers it) and refuses an archive member whose
path or link leaves it and a device or other special file; the listing here
is made by walking the directory by its bytes without following any link, so
a link is listed by what it names and never read through, and only a regular
file is hashed or handed on. A name that is not UTF-8 is shown with its bytes
escaped (``\\xe9``) and handed on percent-encoded, so it is read back by its
own bytes. A file is handed to another server only through the platform's
artefact store: a pack step that declares this tool's ``outputs`` reads each
one back over ``get_artefact``, which opens it beneath the carve root
component by component with no link followed. A file of several names is
handed on once, and only when every one of its names is inside the same
extraction. An extraction directory is removed ``CARVED_KEEP_SECONDS`` after
it was written (an hour unless set), at once when it holds no file, and
earlier, oldest first, when the carve root has no room for another run.

How much is written. Machine-safety bounds, each the operator's to set, as the
container's memory ceiling is: a run stops once the files it wrote pass the
larger of the sample's own size and the platform's sample upload bound
(``UPLOAD_MAX_BYTES``, the console's ``upload_max_bytes``, 100 MiB unless set),
or once it made more than ``UNBLOB_MAX_ENTRIES`` entries (100,000 unless set),
counted at once and then twice a second; no one file it writes may pass that
byte bound (the run's file size limit, so a write past it fails at once); and
the carve root is the container's own sized tmpfs (``UNBLOB_TMPFS_SIZE``), so
what a run writes past the last check ends in a full file system, never in
the host's memory. A stopped run lists only the files that fit under the bound
and says it stopped.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import re
import resource
import shutil
import stat
import sys
import tempfile
import threading
import time
import uuid
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote_to_bytes

from mcp.server.fastmcp import FastMCP

try:  # The image copies the shared module beside this file.
    import cli_sidecar as sidecar
except ModuleNotFoundError:  # A checkout keeps it in a directory of its own.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli-sidecar"))
    import cli_sidecar as sidecar

SERVER = "unblob"
# The release the image pins (``requirements.txt``); the install hint names it.
UNBLOB_VERSION = "26.6.4"
PROGRAM = sidecar.Program(
    name="unblob",
    command=("unblob",),
    install=(
        f"install unblob {UNBLOB_VERSION} (pip install unblob=={UNBLOB_VERSION}) and the "
        "extractors it calls (unblob --show-external-dependencies lists them), or run the "
        "unblob-mcp image, which carries both"
    ),
)
SCAN_TOOL = "container_scan"
EXTRACT_TOOL = "container_extract"
FETCH_TOOL = "get_artefact"
TOOLS = (SCAN_TOOL, EXTRACT_TOOL)

# Where each extraction's directory is made, and how long it is kept.
CARVE_ROOT_ENV = "UNBLOB_CARVE_ROOT"
KEEP_ENV = "CARVED_KEEP_SECONDS"
KEEP_SECONDS = 3600.0
# The platform's sample upload bound (``maljan.core.delivery_limits``), which
# every decompression it does stops at; ``UPLOAD_MAX_BYTES`` holds the
# console's ``upload_max_bytes`` where an operator changed it.
UPLOAD_BOUND_ENV = "UPLOAD_MAX_BYTES"
SAMPLE_UPLOAD_MAX_BYTES = 100 * 1024 * 1024
# How many entries (files, directories, links) one run may make.
MAX_ENTRIES_ENV = "UNBLOB_MAX_ENTRIES"
MAX_ENTRIES = 100_000
# How recently written or read an extraction must not be to be removed to make
# room for a new run.
IN_USE_SECONDS = 60.0
# How often the files an extraction wrote are counted while it runs, after a
# first count at once.
WATCH_SECONDS = 0.5
# unblob's own recursion depth (``unblob.processing.DEFAULT_DEPTH``).
DEFAULT_DEPTH = 10
# The most one ``get_artefact`` call answers: the platform's own chunk
# (``maljan.pipeline.artefacts.FETCH_CHUNK_BYTES``).
FETCH_CHUNK_BYTES = 4 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024

# What the answer says when extraction stopped at a bound.
EXTRACTION_STOPPED = (
    "extraction stopped once {what}; the files listed are those written by then that fit "
    "under {bound} bytes, the larger of the file's size and the platform's sample upload "
    "bound ({env})"
)
NO_REPORT_WRITTEN = "; unblob's report of the chunks was not written"
STOPPED_BYTES = "the files written passed {bound} bytes"
STOPPED_ENTRIES = "it made more than {entries} entries ({env})"
# What the answer says when unblob ended without writing its report.
NO_REPORT = "unblob wrote no report: {said}"
# Why a regular file is not handed on.
NAMED_OUTSIDE = "it has {links} names and only {inside} of them are inside this extraction"
UNREADABLE = "it cannot be read ({error})"
PAST_THE_BOUND = "the run stopped, and it is past the bound"
CUT_AT_THE_BOUND = "it reached {bound} bytes, the most one file may hold, and was cut there"
STOPPED_A_FILE = "a file reached {bound} bytes, the most one file may hold, and was cut there"

# The reports of unblob's that say something was refused or failed, kept on
# ``problems``; each with the fields that name what and where.
_PROBLEM_FIELDS = (
    "problem",
    "resolution",
    "path",
    "extraction_path",
    "link_path",
    "link",
    "target",
    "command",
    "exit_code",
    "dependencies",
    "handler",
    "start_offset",
    "cmd",
    "timeout",
    "severity",
)
_RUN_ID_RE = re.compile(r"[0-9a-f]{32}")

mcp = FastMCP("UnblobMCP", stateless_http=True)

# What each tool declares of itself (``cli_sidecar.reading_tool``).
# unblob carves and extracts into a directory of its own, never beside the
# sample, and runs nothing it extracts; a written file reaches another server
# only through the job's artefact store, which reads it back over
# ``get_artefact`` (a delivery primitive, never a model's).
_DECLARED: dict[str, dict[str, Any]] = {
    SCAN_TOOL: sidecar.reading_tool(
        "Container chunks",
        {
            "kind": "embedded_chunks",
            "rows": "/chunks/*",
            "places": {"offset": "/start_offset"},
            "values": {"handler": "/handler"},
            "arguments": {"path": "path"},
            "display_name": "unblob",
            "shows": (
                "each chunk of a known format inside the file (archives, compressed streams, "
                "file systems, firmware containers, a payload appended to another file), found "
                "by its own bytes, with its byte range, and the ranges no format claims with "
                "their entropy"
            ),
            "does_not_show": (
                "what a chunk holds (nothing is unpacked), or a format unblob has no handler "
                "for; nothing is run"
            ),
        },
    ),
    EXTRACT_TOOL: sidecar.reading_tool(
        "Extract a container",
        {
            "kind": "extracted_files",
            "long_running": True,
            "rows": "/files/*",
            "values": {"name": "/name", "sha256": "/sha256", "magic": "/magic"},
            "arguments": {"path": "path"},
            "display_name": "unblob",
            "shows": (
                "every file the container's chunks hold, extracted recursively, each with its "
                "place in the container, size, sha256 and file type; links by what they name, "
                "and what unblob refused (a member whose path or link leaves the extraction, a "
                "device file)"
            ),
            "does_not_show": (
                "what an extracted file does: nothing extracted is run or opened beyond its "
                "type; a format unblob has no handler for, an encrypted chunk's contents, or "
                "anything past the sample upload bound the extraction stops at"
            ),
        },
    ),
    FETCH_TOOL: sidecar.reading_tool("Fetch an extracted file", {"kind": "artefact_delivery"}),
    "capabilities": sidecar.reading_tool("Tool availability", sidecar.CAPABILITIES_FACTS),
}


def carve_root() -> Path:
    """The directory each extraction's own directory is made under."""
    raw = os.environ.get(CARVE_ROOT_ENV, "").strip()
    return Path(raw) if raw else Path(tempfile.gettempdir()) / "unblob-carved"


def _number(env: str, default: float) -> float:
    raw = os.environ.get(env, "").strip()
    try:
        value = float(raw) if raw else default
    except ValueError:
        sidecar.logger.warning("%s=%r is not a number; the default holds.", env, raw)
        return default
    return value if value > 0 else default


def keep_seconds() -> float:
    """How long an extraction's directory is kept, from ``CARVED_KEEP_SECONDS``."""
    return _number(KEEP_ENV, KEEP_SECONDS)


def upload_bound() -> int:
    """The platform's sample upload bound, from ``UPLOAD_MAX_BYTES`` where it is set."""
    return int(_number(UPLOAD_BOUND_ENV, SAMPLE_UPLOAD_MAX_BYTES))


def max_entries() -> int:
    """How many entries one run may make, from ``UNBLOB_MAX_ENTRIES``."""
    return int(_number(MAX_ENTRIES_ENV, MAX_ENTRIES))


def written_bound(sample: str) -> int:
    """How many bytes one extraction may write: the larger of the file's size and the bound."""
    return max(os.path.getsize(sample), upload_bound())


def file_size_limit(bound: int) -> dict[int, int]:
    """The run's limits: no one file it writes may pass ``bound`` bytes."""
    return {resource.RLIMIT_FSIZE: bound}


def clean(text: str) -> str:
    """``text`` as UTF-8 can carry it: a byte a name held that is not UTF-8 shown escaped."""
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        pass
    try:
        raw = text.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
    return raw.decode("utf-8", "backslashreplace")


def _cleaned(value: Any) -> Any:
    """Every text in a JSON document cleaned (:func:`clean`), in one pass."""
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, list):
        return [_cleaned(item) for item in value]
    if isinstance(value, dict):
        return {clean(str(key)): _cleaned(item) for key, item in value.items()}
    return value


def shown(raw: bytes) -> str:
    """A name's bytes as the answer shows it: UTF-8, with any other byte escaped."""
    return raw.decode("utf-8", "backslashreplace")


def handed(run_id: str, raw: bytes) -> str:
    """How ``get_artefact`` is asked for a file: the run's id and its bytes, percent-encoded."""
    return f"{run_id}/{quote(raw, safe='/')}"


# ---------------------------------------------------------------------------
# The carve root
# ---------------------------------------------------------------------------

_sweep_lock = threading.Lock()
# The extraction directories a call is still writing, which no sweep removes.
_writing: set[str] = set()
# Each run's count of names per file it holds (device, inode), once counted.
_names: dict[str, dict[tuple[int, int], int]] = {}


def _runs(root: Path) -> list[tuple[float, str]]:
    """Each finished extraction directory under ``root``, oldest first, by when it was written."""
    found: list[tuple[float, str]] = []
    for entry in os.scandir(root):
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode) and entry.name not in _writing:
            found.append((info.st_mtime, entry.name))
    return sorted(found)


def _remove(root: Path, run_id: str) -> None:
    shutil.rmtree(root / run_id, ignore_errors=True)
    _names.pop(run_id, None)


def _room(root: Path) -> tuple[int, int]:
    """The bytes the carve root's file system has free, and all it holds."""
    held = os.statvfs(root)
    return held.f_bavail * held.f_frsize, held.f_blocks * held.f_frsize


def sweep(now: float | None = None, room_for: int = 0) -> None:
    """Remove each extraction older than ``CARVED_KEEP_SECONDS``, and make room for a run.

    Then, while the carve root has less room than ``room_for`` bytes (the next
    run's bound, at most all the file system holds), the oldest finished
    extraction goes, so a new run starts with room for what it may write. A
    directory a call is writing is never removed, nor, to make room, one
    written or read in the last ``IN_USE_SECONDS`` (``get_artefact`` marks a
    run it reads as newest).
    """
    root = carve_root()
    if not root.is_dir():
        return
    at = time.time() if now is None else now
    oldest = at - keep_seconds()
    with _sweep_lock:
        runs = _runs(root)
        for when, run_id in runs:
            if when < oldest:
                _remove(root, run_id)
        for when, run_id in runs:
            if when < oldest or when >= at - IN_USE_SECONDS:
                continue
            free, total = _room(root)
            if free >= min(room_for, total):
                break
            _remove(root, run_id)


def mark_in_use(run_id: str) -> None:
    """Mark the run ``run_id`` as newest: one being read is the last to go."""
    with _sweep_lock, contextlib.suppress(OSError):
        os.utime(carve_root() / run_id)


def new_run_directory() -> tuple[str, Path]:
    """A fresh extraction directory under the carve root, 0o700, and its id."""
    root = carve_root()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex
    where = root / run_id
    with _sweep_lock:
        where.mkdir(mode=0o700)
        _writing.add(run_id)
    return run_id, where


def _walk(top: bytes) -> Iterator[tuple[bytes, os.stat_result]]:
    """Every entry under ``top``, as its bytes relative to ``top`` and its own ``lstat``.

    By bytes, so a name that is not UTF-8 is walked as it is. No link is
    followed: a link is yielded as a link, and a directory is gone into only
    when ``lstat`` says it is one.
    """
    pending = [b""]
    while pending:
        relative = pending.pop()
        try:
            entries = sorted(os.scandir(os.path.join(top, relative)), key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            name = os.path.join(relative, entry.name) if relative else entry.name
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            yield name, info
            if stat.S_ISDIR(info.st_mode):
                pending.append(name)


def written(top: Path) -> tuple[int, int]:
    """The bytes the regular files under ``top`` hold and how many entries it has."""
    size = entries = 0
    for _name, info in _walk(os.fsencode(top)):
        entries += 1
        if stat.S_ISREG(info.st_mode):
            size += info.st_size
    return size, entries


def written_bytes(top: Path) -> int:
    """The bytes the regular files under ``top`` hold."""
    return written(top)[0]


def name_counts(top: Path) -> dict[tuple[int, int], int]:
    """How many names under ``top`` each regular file of several names has."""
    counts: dict[tuple[int, int], int] = {}
    for _name, info in _walk(os.fsencode(top)):
        if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
            key = (info.st_dev, info.st_ino)
            counts[key] = counts.get(key, 0) + 1
    return counts


def _sha256(fd: int) -> str:
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as handle:
        while chunk := handle.read(HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


_SPECIAL_KINDS = (
    (stat.S_ISFIFO, "fifo"),
    (stat.S_ISSOCK, "socket"),
    (stat.S_ISCHR, "character device"),
    (stat.S_ISBLK, "block device"),
)


@dataclass
class Listing:
    """What one extraction directory holds: files handed on, files not, links, the rest."""

    files: list[dict[str, Any]] = field(default_factory=list)
    not_handed_on: list[dict[str, str]] = field(default_factory=list)
    links: list[dict[str, str]] = field(default_factory=list)
    special: list[dict[str, str]] = field(default_factory=list)
    # Whether a file reached the most one file may hold, and was cut there.
    cut: bool = False


def listing(
    run_id: str, top: Path, *, within: int | None = None, file_bound: int | None = None
) -> Listing:
    """Each entry under ``top``: a regular file with its size and digest, a link by its target.

    A regular file's ``path`` is what ``get_artefact`` reads it by (the run's
    id and its place's bytes, percent-encoded); ``name`` is its place, shown.
    A file of several names is one row, its other names under ``also_named``,
    when every name is inside this extraction, and is not handed on
    otherwise. A link is never read through: its row says what it names.
    Anything that is neither (a FIFO, a socket, a device, which unblob refuses
    to make) is named with its kind and never opened. ``within`` (a stopped
    run's bound) lists only the files that fit under it, in the walk's order;
    a file that reached ``file_bound`` (the most one file may hold) was cut
    there by the run's limit, and is not handed on.
    """
    held = Listing()
    raw_top = os.fsencode(top)
    counts = name_counts(top)
    _names[run_id] = counts
    rows: dict[tuple[int, int], dict[str, Any]] = {}
    total = 0
    for name, info in _walk(raw_top):
        mode = info.st_mode
        if stat.S_ISREG(mode):
            key = (info.st_dev, info.st_ino)
            if info.st_nlink > 1:
                if key in rows:
                    rows[key].setdefault("also_named", []).append(shown(name))
                    continue
                inside = counts.get(key, 0)
                if inside != info.st_nlink:
                    why = NAMED_OUTSIDE.format(links=info.st_nlink, inside=inside)
                    held.not_handed_on.append({"name": shown(name), "reason": why})
                    continue
            if file_bound is not None and info.st_size >= file_bound:
                why = CUT_AT_THE_BOUND.format(bound=file_bound)
                held.not_handed_on.append({"name": shown(name), "reason": why})
                held.cut = True
                continue
            if within is not None and total + info.st_size > within:
                held.not_handed_on.append({"name": shown(name), "reason": PAST_THE_BOUND})
                continue
            try:
                fd = os.open(os.path.join(raw_top, name), _OPEN_FLAGS | _NONBLOCK)
                digest = _sha256(fd)
            except OSError as exc:
                why = UNREADABLE.format(error=type(exc).__name__)
                held.not_handed_on.append({"name": shown(name), "reason": why})
                continue
            total += info.st_size
            row: dict[str, Any] = {
                "path": handed(run_id, name),
                "name": shown(name),
                "size": info.st_size,
                "sha256": digest,
            }
            rows[key] = row
            held.files.append(row)
        elif stat.S_ISLNK(mode):
            try:
                target = shown(os.readlink(os.path.join(raw_top, name)))
            except OSError:
                target = ""
            held.links.append({"name": shown(name), "target": target})
        elif not stat.S_ISDIR(mode):
            kind = next((word for test, word in _SPECIAL_KINDS if test(mode)), "special file")
            held.special.append({"name": shown(name), "kind": kind})
    return held


# ---------------------------------------------------------------------------
# unblob's report
# ---------------------------------------------------------------------------


def _place(raw: Any, sample: str, top: Path | None) -> str:
    """A path of unblob's report as the answer names it: ``""`` for the sample, else its place."""
    text = str(raw or "")
    if not text or text == sample:
        return ""
    if not Path(text).is_absolute():
        # An archive member's own path, as the archive wrote it.
        return text
    if top is not None:
        # unblob names its extraction directory resolved; either spelling is it.
        for spelling in dict.fromkeys((str(top), os.path.realpath(top))):
            with contextlib.suppress(ValueError):
                return Path(text).relative_to(spelling).as_posix()
    return Path(text).name


def _next(pending: deque[tuple[str, Any]], where: str, report: dict[str, Any]) -> None:
    """Put a report's own reports next in line, in their order, so each is read where it stands."""
    inner = report.get("extraction_reports") or ()
    pending.extendleft((where, held) for held in reversed(list(inner)))


def _report_rows(document: Any, sample: str, top: Path | None) -> dict[str, Any]:
    """The chunks, file types and problems unblob's ``--report`` document holds.

    One pass over the document: each task (the sample, then each file it
    unpacked) with its chunks (each known chunk's handler and byte range, each
    unknown range with its entropy), the type libmagic gives it, and every
    report that says something was refused or failed.
    """
    if not isinstance(document, list):
        raise sidecar.ToolFailure(sidecar.TOOL_FAILED, "unblob's report is not a list of tasks")
    sample = clean(sample)
    chunks: list[dict[str, Any]] = []
    types: dict[str, dict[str, str]] = {}
    problems: list[dict[str, Any]] = []
    pending: deque[tuple[str, Any]] = deque()
    for result in document:
        if not isinstance(result, dict):
            continue
        task = result.get("task")
        where = _place(task.get("path") if isinstance(task, dict) else "", sample, top)
        pending.extend((where, report) for report in result.get("reports") or ())
    while pending:
        where, report = pending.popleft()
        if not isinstance(report, dict):
            continue
        kind = str(report.get("__typename__") or "")
        if kind == "ChunkReport":
            chunks.append(
                {
                    "file": where,
                    "handler": str(report.get("handler_name") or ""),
                    "start_offset": report.get("start_offset"),
                    "end_offset": report.get("end_offset"),
                    "size": report.get("size"),
                    "encrypted": bool(report.get("is_encrypted")),
                }
            )
            _next(pending, where, report)
        elif kind == "UnknownChunkReport":
            row = {
                "file": where,
                "handler": "unknown",
                "start_offset": report.get("start_offset"),
                "end_offset": report.get("end_offset"),
                "size": report.get("size"),
            }
            randomness = report.get("randomness")
            shannon = randomness.get("shannon") if isinstance(randomness, dict) else None
            if isinstance(shannon, dict) and "mean" in shannon:
                row["entropy"] = shannon["mean"]
            chunks.append(row)
        elif kind == "MultiFileReport":
            _next(pending, where, report)
        elif kind == "FileMagicReport":
            types[where] = {
                "magic": str(report.get("magic") or ""),
                "mime_type": str(report.get("mime_type") or ""),
            }
        elif "severity" in report or "problem" in report:
            row = {"report": kind, "file": where}
            for name in _PROBLEM_FIELDS:
                value = report.get(name)
                if value is None or value == "":
                    continue
                if name in ("path", "extraction_path", "link_path"):
                    value = _place(value, sample, top)
                row[name] = value
            problems.append(row)
    return {"chunks": chunks, "types": types, "problems": problems}


def _read_report(report: Path, ran: sidecar.Ran) -> Any:
    try:
        text = report.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        said = ran.said or f"exit status {ran.returncode}"
        raise sidecar.ToolFailure(sidecar.TOOL_FAILED, NO_REPORT.format(said=said)) from exc
    try:
        # A name that was not UTF-8 is in the report as a lone surrogate:
        # shown escaped, as the listing shows it.
        return _cleaned(json.loads(text))
    except ValueError as exc:
        raise sidecar.ToolFailure(
            sidecar.TOOL_FAILED, f"unblob's report does not parse: {exc}"
        ) from exc


def _depth(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise sidecar.ToolFailure(sidecar.BAD_ARGUMENT, "depth must be a whole number of 1 or more")
    return value


def _arguments(extract_dir: Path, scratch: Path, depth: int, *, skip_extraction: bool) -> list[str]:
    arguments = [
        "--extract-dir",
        str(extract_dir),
        "--report",
        str(scratch / "report.json"),
        "--log",
        str(scratch / "unblob.log"),
        # One worker: a call reads one file, and a container's pids limit
        # always has room for one.
        "--process-num",
        "1",
        "--depth",
        str(depth),
    ]
    if skip_extraction:
        arguments.append("--skip-extraction")
    return arguments


async def _extract_within(
    arguments: list[str], sample: str, top: Path, bound: int, scratch: str
) -> tuple[sidecar.Ran | None, str]:
    """Run unblob, counting what it writes under ``top``; stop it past either bound.

    Counted at once and then every ``WATCH_SECONDS``. Answers the run
    (``None`` when it was stopped) and why it was stopped (``""`` when it was
    not). A cancelled call still kills the run, as every run's does.
    """
    entries = max_entries()
    # ``--`` ends the options: a sample path is a path, never a flag.
    work = asyncio.ensure_future(
        sidecar.run(
            PROGRAM,
            [*arguments, "--", sample],
            workdir=scratch,
            limits=file_size_limit(bound),
        )
    )
    try:
        while True:
            size, made = await asyncio.to_thread(written, top)
            why = ""
            if size > bound:
                why = STOPPED_BYTES.format(bound=bound)
            elif made > entries:
                why = STOPPED_ENTRIES.format(entries=entries, env=MAX_ENTRIES_ENV)
            if why:
                work.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await work
                return None, why
            done, _ = await asyncio.wait({work}, timeout=WATCH_SECONDS)
            if done:
                return work.result(), ""
    except asyncio.CancelledError:
        work.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await work
        raise


@mcp.tool(**_DECLARED["container_scan"])
async def container_scan(path: str) -> dict[str, Any]:
    """Find the chunks of known formats inside a file, by their own bytes, without unpacking them.

    Each row of ``chunks`` is one chunk: the ``handler`` (the format unblob
    found: zip, gzip, squashfs, uimage, cab, iso9660 …), its byte range in
    the file (``start_offset``, ``end_offset``, ``size``) and whether it is
    encrypted; a range no format claims is ``unknown``, with its entropy.
    Nothing is kept: the chunks are carved into a scratch directory that goes
    with the call.
    """

    async def work() -> dict[str, Any]:
        sample = sidecar.sample_file(path)
        bound = written_bound(sample)
        with tempfile.TemporaryDirectory(prefix="unblob-scan-") as scratch:
            where = Path(scratch)
            out = where / "carved"
            arguments = _arguments(out, where, 1, skip_extraction=True)
            ran = await sidecar.run(
                PROGRAM,
                [*arguments, "--", sample],
                workdir=scratch,
                limits=file_size_limit(bound),
            )
            document = _read_report(where / "report.json", ran)
            rows = _report_rows(document, sample, out)
        chunks = [row for row in rows["chunks"] if row["file"] == ""]
        return {
            "tool": SCAN_TOOL,
            "engine": "unblob",
            "engine_version": UNBLOB_VERSION,
            "file_type": rows["types"].get("", {}),
            "chunks": chunks,
            "chunk_count": len(chunks),
            "problems": rows["problems"],
        }

    return await sidecar.answering(SCAN_TOOL, work)


@mcp.tool(**_DECLARED["container_extract"])
async def container_extract(path: str, depth: int = DEFAULT_DEPTH) -> dict[str, Any]:
    """Carve and extract every file a container or firmware image holds, recursively.

    unblob unpacks each chunk it finds (archives, compressed streams, file
    systems, firmware containers) and what those hold, ``depth`` levels deep
    (unblob's own 10 unless asked). Each row of ``files`` is one regular file
    written: its place under the extraction (``name``, any byte that is not
    UTF-8 escaped), ``size``, ``sha256``, its other names (``also_named``)
    and, from libmagic, ``magic`` and ``mime_type``; ``path`` is how the
    platform's artefact store reads it back. ``not_handed_on`` names a
    regular file that is not, and why; ``links`` lists each link by what it
    names (never followed), ``special`` anything else, ``chunks`` every chunk
    found and in which file, ``problems`` what unblob refused or could not
    unpack (a member whose path or link leaves the extraction, a special
    file, a failed extractor). Nothing extracted is run.
    """

    async def work() -> dict[str, Any]:
        sample = sidecar.sample_file(path)
        levels = _depth(depth)
        bound = written_bound(sample)
        await asyncio.to_thread(sweep, None, bound)
        run_id, top = new_run_directory()
        try:
            with tempfile.TemporaryDirectory(prefix="unblob-run-") as scratch:
                where = Path(scratch)
                arguments = _arguments(top, where, levels, skip_extraction=False)
                ran, stopped = await _extract_within(arguments, sample, top, bound, scratch)
                rows: dict[str, Any] = {"chunks": [], "types": {}, "problems": []}
                if ran is not None:
                    rows = _report_rows(_read_report(where / "report.json", ran), sample, top)
            held = await asyncio.to_thread(
                partial(listing, within=bound if stopped else None, file_bound=bound), run_id, top
            )
            if held.cut and not stopped:
                stopped = STOPPED_A_FILE.format(bound=bound)
        except BaseException:
            _remove(carve_root(), run_id)
            raise
        finally:
            with _sweep_lock:
                # Kept from when it was written to the end, not from its start.
                with contextlib.suppress(OSError):
                    os.utime(top)
                _writing.discard(run_id)
        if not held.files:
            _remove(carve_root(), run_id)
        for row in held.files:
            row.update(rows["types"].get(row["name"], {}))
        answer: dict[str, Any] = {
            "tool": EXTRACT_TOOL,
            "engine": "unblob",
            "engine_version": UNBLOB_VERSION,
            "depth": levels,
            "file_type": rows["types"].get("", {}),
            "files": held.files,
            "file_count": len(held.files),
            "bytes_written": sum(row["size"] for row in held.files),
            "not_handed_on": held.not_handed_on,
            "links": held.links,
            "special": held.special,
            "chunks": rows["chunks"],
            "problems": rows["problems"],
        }
        if stopped:
            answer["stopped"] = EXTRACTION_STOPPED.format(
                what=stopped, bound=bound, env=UPLOAD_BOUND_ENV
            ) + (NO_REPORT_WRITTEN if ran is None else "")
        return answer

    return await sidecar.answering(EXTRACT_TOOL, work)


# ---------------------------------------------------------------------------
# Handing a file over
# ---------------------------------------------------------------------------

_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
NOT_BENEATH = "the path names no file this server extracted"


def _parts(name: str) -> tuple[str, list[bytes]]:
    """``name`` as its run's id and the bytes of each part of its place under the run."""
    if not isinstance(name, str) or not name.strip() or "\0" in name:
        raise sidecar.ToolFailure(sidecar.BAD_ARGUMENT, "path names no file")
    run_id, _, rest = name.partition("/")
    parts = [unquote_to_bytes(part) for part in rest.split("/")]
    if (
        not _RUN_ID_RE.fullmatch(run_id)
        or not rest
        or any(part in (b"", b".", b"..") or b"/" in part or b"\0" in part for part in parts)
    ):
        raise sidecar.ToolFailure(sidecar.PATH_OUTSIDE_ROOTS, NOT_BENEATH)
    return run_id, parts


def _inside(run_id: str, key: tuple[int, int]) -> int:
    """How many names inside the run ``run_id`` the file ``key`` has (counted once per run)."""
    counts = _names.get(run_id)
    if counts is None:
        counts = _names[run_id] = name_counts(carve_root() / run_id)
    return counts.get(key, 0)


def open_extracted(name: str) -> int:
    """A read-only descriptor of the extracted regular file ``name``; else a failure.

    ``name`` is a ``path`` of a ``container_extract`` answer: the run's id and
    the file's place under it, percent-encoded. Opened from the carve root
    component by component, by bytes, each with ``O_NOFOLLOW`` relative to the
    one before, so no link is followed anywhere and nothing can be swapped
    between a check and the open; refused unless ``fstat`` says it is a
    regular file every name of which is inside the same extraction.
    """
    run_id, parts = _parts(name)
    try:
        current = os.open(carve_root(), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise sidecar.ToolFailure(sidecar.NO_SUCH_FILE, NOT_BENEATH) from exc
    try:
        for part in [run_id.encode("ascii"), *parts[:-1]]:
            try:
                below = os.open(part, _OPEN_FLAGS | os.O_DIRECTORY, dir_fd=current)
            except OSError as exc:
                raise sidecar.ToolFailure(sidecar.NO_SUCH_FILE, NOT_BENEATH) from exc
            os.close(current)
            current = below
        try:
            fd = os.open(parts[-1], _OPEN_FLAGS | _NONBLOCK, dir_fd=current)
        except OSError as exc:
            raise sidecar.ToolFailure(sidecar.NO_SUCH_FILE, NOT_BENEATH) from exc
    finally:
        os.close(current)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise sidecar.ToolFailure(
            sidecar.UNSUPPORTED_FORMAT, "the path names a link, a directory or a special file"
        )
    if info.st_nlink > 1:
        inside = _inside(run_id, (info.st_dev, info.st_ino))
        if inside != info.st_nlink:
            os.close(fd)
            raise sidecar.ToolFailure(
                sidecar.PATH_OUTSIDE_ROOTS,
                "the file is not read: " + NAMED_OUTSIDE.format(links=info.st_nlink, inside=inside),
            )
    return fd


def _read_chunk(name: str, offset: int, length: int) -> dict[str, Any]:
    fd = open_extracted(name)
    mark_in_use(_parts(name)[0])
    with os.fdopen(fd, "rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        handle.seek(offset)
        data = handle.read(min(length, FETCH_CHUNK_BYTES))
        answer: dict[str, Any] = {
            "path": name,
            "offset": offset,
            "size": size,
            "content_b64": base64.b64encode(data).decode("ascii"),
        }
        if offset == 0:
            # The whole file's digest, stated with the first chunk.
            handle.seek(0)
            digest = hashlib.sha256()
            while chunk := handle.read(HASH_CHUNK_BYTES):
                digest.update(chunk)
            answer["sha256"] = digest.hexdigest()
    return answer


@mcp.tool(**_DECLARED["get_artefact"])
async def get_artefact(
    path: str, offset: int = 0, length: int = FETCH_CHUNK_BYTES
) -> dict[str, Any]:
    """Read back a file ``container_extract`` wrote, ``length`` bytes from ``offset``.

    For the platform's artefact store, never an analysis step: ``path`` is a
    ``path`` of a ``container_extract`` answer. Answers ``content_b64`` (at
    most 4 MiB a call), the whole file's ``size`` and, with the first chunk,
    its ``sha256``.
    """

    async def work() -> dict[str, Any]:
        for name, value in (("offset", offset), ("length", length)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise sidecar.ToolFailure(sidecar.BAD_ARGUMENT, f"{name} must be 0 or more")
        if length == 0:
            raise sidecar.ToolFailure(sidecar.BAD_ARGUMENT, "length must be at least 1")
        return await asyncio.to_thread(_read_chunk, path, offset, length)

    return await sidecar.answering(FETCH_TOOL, work)


@mcp.tool(**_DECLARED["capabilities"])
def capabilities() -> dict[str, Any]:
    """Which of this server's tools this host can run, and how to install what is missing."""
    return sidecar.capabilities(SERVER, PROGRAM, (*TOOLS, FETCH_TOOL), version=UNBLOB_VERSION)


if __name__ == "__main__":
    sidecar.serve(mcp)
