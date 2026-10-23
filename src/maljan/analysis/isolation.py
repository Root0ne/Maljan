"""Where a run read the sample's bytes, and what kept each reader from the worker's secrets.

The **isolation** part of the run's disclosure record
(``run_summary["disclosure"]["isolation"]``), printed in Appendix B under its
own lead sentence. Built from the run's own records, never from a tool's name:

* **Which sources read the sample.** A ledger entry whose stored facts give an
  argument the role ``path`` or ``carved`` (:data:`SAMPLE_ARGUMENT_ROLES`), any
  call through a settings block that declares where its server sees the sample
  (``sample_mount``, ``work_dir``, ``sample_open.open_tool``), and the reads in
  the worker that write no entry, noted when they happen
  (:func:`note_in_process`).
* **What each was measured as.** A tool server started over stdio is measured
  by the worker right after its ``initialize`` and before its first tool call
  (``providers.servers.ServerHandle``). Its process status gives its user, its
  effective capabilities and the no-new-privileges flag, and its namespace links
  are compared with the worker's own. The platform variables in its environment
  are read off the environment the platform built and handed to it, so they are
  known exactly, by name, never by value (:func:`measure_process`). A read in
  the worker process is the worker's own, by construction.

**Right or absent.** A row is isolated only when it was measured and every
check passed. A field that could not be read is ``None``, and never counts as
passing. A server reached at an address is not measured by this run and is
said to be "not verified". The whole part is isolated only when at least one
row exists and every row is isolated. A run that recorded no read of the
sample says so and claims nothing. Where the worker hashed the copies it
handed out at the job's start and end, the part also says whether each stayed
the intake bytes (``analysis.sample_integrity``).

What is measured is the process the worker started and every process under it
(:func:`measure_tree`): a launcher starts the real server as its own child, and
which process of the tree reads the sample cannot be told, so every one is held
to the checks.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from maljan.core.platform_secrets import is_platform_secret

# The argument roles whose value is the sample, or bytes carved from it, that
# the tool opens (``ToolFacts.arguments``; ``builtin_declarations._PATH``).
SAMPLE_ARGUMENT_ROLES = ("path", "carved")

# The block fields that declare where a server sees the job's sample: every
# call through such a block works on the sample it was handed.
SAMPLE_BLOCK_FIELDS = ("sample_mount", "work_dir", "sample_open.open_tool")

# Where a reader ran.
IN_PROCESS = "in_process"
CHILD = "child"
LOCAL_SERVICE = "local_service"
REMOTE_SERVICE = "remote"
UNPLACED = ""

# The platform's own readers in the worker that write no ledger entry, noted
# when the sample's routing reads it (``MaljanApp._infer_sample_platform``),
# which every run with a readable sample does before any tool is called.
WORKER_SOURCE = "worker"
WORKER_LABEL = "the platform's own readers in the worker"

# The report step's own read of the sample: its drafted YARA rule checked
# against the file the run analysed (``reporting.detection_signatures``). It
# writes no ledger entry, so it is noted when it opens the file.
REPORT_SOURCE = "report"
REPORT_LABEL = "the report step"

_ORDER = {IN_PROCESS: 0, CHILD: 1, LOCAL_SERVICE: 2, REMOTE_SERVICE: 3, UNPLACED: 4}

# The namespaces compared with the worker's: its process table, its network
# and its mount namespace.
_NAMESPACES = {"pid": "own_pid_namespace", "net": "own_net_namespace", "mnt": "own_mount_namespace"}

# The measured fields of a process, in the order a row stores them.
MEASURED_FIELDS = (
    "uid",
    "same_uid_as_worker",
    "shares_group_with_worker",
    "own_pid_namespace",
    "own_net_namespace",
    "own_mount_namespace",
    "cap_eff_zero",
    "cap_prm_zero",
    "cap_amb_zero",
    "no_new_privs",
    "platform_names_in_env",
)


# ---------------------------------------------------------------------------
# Measuring a process
# ---------------------------------------------------------------------------


def _status(pid: int | str) -> dict[str, str] | None:
    """``/proc/<pid>/status`` as ``{field: value}``, ``None`` where it cannot be read."""
    try:
        with open(f"/proc/{pid}/status", encoding="ascii", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            out[key.strip()] = value.strip()
    return out


def _ids(status: Mapping[str, str] | None, key: str) -> tuple[int, ...] | None:
    """The four ids of a ``Uid`` or ``Gid`` line (real, effective, saved, filesystem), or ``None``.

    ``None`` unless all four are there and read as numbers.
    """
    parts = str((status or {}).get(key) or "").split()
    try:
        ids = tuple(int(part) for part in parts)
    except ValueError:
        return None
    return ids if len(ids) == 4 else None


def _effective_uid(status: Mapping[str, str] | None) -> int | None:
    """The effective user id: the second of the four ``Uid`` fields."""
    ids = _ids(status, "Uid")
    return ids[1] if ids else None


def _groups(status: Mapping[str, str] | None) -> frozenset[int] | None:
    """The supplementary groups of a ``Groups`` line, or ``None`` where the line is absent."""
    if status is None or "Groups" not in status:
        return None
    try:
        return frozenset(int(part) for part in str(status["Groups"]).split())
    except ValueError:
        return None


def _shares(theirs: Iterable[int] | None, ours: Iterable[int]) -> bool | None:
    """Whether any of ``theirs`` is one of ``ours``; ``None`` where ``theirs`` was not read."""
    if theirs is None:
        return None
    return bool(set(theirs) & set(ours))


def _worker_groups() -> frozenset[int]:
    """The worker's effective group and supplementary groups."""
    return frozenset({os.getegid(), *os.getgroups()})


def _cap_zero(status: Mapping[str, str] | None, key: str) -> bool | None:
    """Whether a capability set (``CapEff``, ``CapPrm``, ``CapAmb``) is empty; ``None`` unread."""
    text = str((status or {}).get(key) or "")
    try:
        return int(text, 16) == 0 if text else None
    except ValueError:
        return None


def _cap_eff_zero(status: Mapping[str, str] | None) -> bool | None:
    return _cap_zero(status, "CapEff")


def _no_new_privs(status: Mapping[str, str] | None) -> bool | None:
    text = str((status or {}).get("NoNewPrivs") or "")
    return {"0": False, "1": True}.get(text)


def _namespace(pid: int | str, name: str) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/ns/{name}")
    except OSError:
        return None


def platform_names(names: Iterable[str]) -> list[str]:
    """The platform's own bootstrap variables among ``names`` (``core.platform_secrets``)."""
    return sorted({str(name) for name in names if is_platform_secret(str(name))})


def measure_process(pid: int, env_names: Iterable[str]) -> dict[str, Any]:
    """What separates process ``pid`` from this one, each field ``None`` where it cannot be read.

    ``env_names`` are the names of the environment the platform built and
    handed to the process.
    """
    status = _status(pid)
    uids, gids, groups = _ids(status, "Uid"), _ids(status, "Gid"), _groups(status)
    out: dict[str, Any] = {
        "uid": uids[1] if uids else None,
        # Any of the four user ids (real, effective, saved, filesystem) that is
        # the worker's effective one: a saved or real id can be taken back.
        "same_uid_as_worker": _shares(uids, {os.geteuid()}),
        # Any of the four group ids, or a supplementary group, that is one of
        # the worker's groups: a group opens what is group-readable.
        "shares_group_with_worker": (
            None if gids is None or groups is None else _shares({*gids, *groups}, _worker_groups())
        ),
    }
    for name, key in _NAMESPACES.items():
        theirs, ours = _namespace(pid, name), _namespace("self", name)
        out[key] = None if theirs is None or ours is None else theirs != ours
    out["cap_eff_zero"] = _cap_eff_zero(status)
    # The permitted set can be raised into the effective one, and the ambient
    # set is handed to what the process executes: both must be empty too.
    out["cap_prm_zero"] = _cap_zero(status, "CapPrm")
    out["cap_amb_zero"] = _cap_zero(status, "CapAmb")
    out["no_new_privs"] = _no_new_privs(status)
    out["platform_names_in_env"] = platform_names(env_names)
    return out


# The most processes one started server's tree is measured over: a server is its
# launcher and a few helpers, and a wider tree is said to be cut, never judged.
MAX_TREE_PROCESSES = 64


def _children(pid: int) -> list[int] | None:
    """The children of ``pid`` across its threads, or ``None`` where they cannot be read."""
    try:
        tasks = os.listdir(f"/proc/{pid}/task")
    except OSError:
        return None
    found: list[int] = []
    for task in tasks:
        try:
            with open(f"/proc/{pid}/task/{task}/children", encoding="ascii") as fh:
                found.extend(int(child) for child in fh.read().split())
        except FileNotFoundError:
            # The thread ended between the listing and the read.
            continue
        except (OSError, ValueError):
            return None
    return found


def environ_names(pid: int) -> list[str] | None:
    """The variable names in ``/proc/<pid>/environ``, ``None`` where it cannot be read.

    Only the part of each entry before ``=`` is kept; the bytes read are
    dropped here and no value leaves this function.
    """
    try:
        with open(f"/proc/{pid}/environ", "rb") as fh:
            blob = fh.read()
    except OSError:
        return None
    names = [
        entry.split(b"=", 1)[0].decode("ascii", "replace") for entry in blob.split(b"\0") if entry
    ]
    del blob
    return names


def _gone(pid: int) -> bool:
    return not os.path.exists(f"/proc/{pid}")


def measure_tree(pid: int, env_names: Iterable[str]) -> dict[str, Any]:
    """The process the worker started (:func:`measure_process`), and each of its descendants.

    A launcher (a sandbox's monitor, ``uv run``, a container client) starts the
    real server as its own child, so the whole tree under the started process
    is walked, breadth first, through ``/proc/<pid>/task/*/children``, up to
    :data:`MAX_TREE_PROCESSES`. Which process of the tree reads the sample
    cannot be told from outside, so every one is held to the checks. A process
    that ended during the walk is left out. A tree that could not be read
    whole, or is wider than the bound, is ``descendants_judged: False``, with
    why.

    A descendant's platform variables are read from its own
    ``/proc/<pid>/environ``, names only (:func:`environ_names`): a launcher
    can add variables to what it hands the server. Where that file cannot be
    read they are ``None``, unknown, which fails like any unread fact.

    Each descendant records its ``depth`` below the started process (its
    children are depth 1), which a block's declared launcher is read against
    (``launcher_depth``, :func:`isolation_part`).
    """
    started = measure_process(pid, env_names)
    descendants: list[dict[str, Any]] = []
    judged, why = True, ""
    seen, queue = {pid}, [(pid, 0)]
    while queue and judged:
        current, depth = queue.pop(0)
        children = _children(current)
        if children is None:
            if not _gone(current):
                judged, why = False, "the children of a process in its tree could not be read"
            continue
        for child in children:
            if child in seen:
                continue
            if len(seen) >= MAX_TREE_PROCESSES:
                judged = False
                why = f"its tree holds more than {MAX_TREE_PROCESSES} processes, which is "
                why += "as many as one start is measured over"
                break
            seen.add(child)
            measured = measure_process(child, ())
            if measured["uid"] is None and _gone(child):
                continue
            names = environ_names(child)
            measured["platform_names_in_env"] = None if names is None else platform_names(names)
            measured["depth"] = depth + 1
            descendants.append(measured)
            queue.append((child, depth + 1))
    return {
        **started,
        "descendants": descendants,
        "descendants_judged": judged,
        "descendants_why": why,
    }


def worker_facts() -> dict[str, Any]:
    """The worker process itself: its user, capabilities, flag and platform variables by name."""
    status = _status("self")
    uid = _effective_uid(status)
    return {
        "uid": os.geteuid() if uid is None else uid,
        "cap_eff_zero": _cap_eff_zero(status),
        "cap_prm_zero": _cap_zero(status, "CapPrm"),
        "cap_amb_zero": _cap_zero(status, "CapAmb"),
        "no_new_privs": _no_new_privs(status),
        "platform_names_in_env": platform_names(os.environ),
    }


# ---------------------------------------------------------------------------
# The job's notes
# ---------------------------------------------------------------------------

# Per job key, per source, what was noted: the measurement of each process a
# server was started as, and each read in the worker that writes no entry.
# Kept by job key because a server handle knows its job's key and nothing else
# of the job; read by the disclosure builder and dropped at teardown.
_NOTES: dict[str, dict[str, list[dict[str, Any]]]] = {}
_NOTES_LOCK = threading.Lock()


def note_process(job_key: str, source: str, measured: Mapping[str, Any]) -> None:
    """Record the measurement of one process ``source``'s server was started as."""
    if not job_key or not source:
        return
    with _NOTES_LOCK:
        _NOTES.setdefault(str(job_key), {}).setdefault(str(source), []).append(
            {"where": CHILD, **dict(measured)}
        )


def note_in_process(job_key: str, source: str, label: str = "") -> None:
    """Record that ``source`` read the sample in the worker process, once per source."""
    if not job_key or not source:
        return
    with _NOTES_LOCK:
        held = _NOTES.setdefault(str(job_key), {}).setdefault(str(source), [])
        if not any(note.get("where") == IN_PROCESS for note in held):
            held.append({"where": IN_PROCESS, "label": str(label)})


def note_read_in_worker(container: Any, source: str, label: str = "") -> None:
    """:func:`note_in_process` under ``container``'s job key; nothing for one without a key."""
    job_key = getattr(container, "job_key", None)
    if callable(job_key):
        note_in_process(str(job_key()), source, label)


def noted(job_key: str) -> dict[str, list[dict[str, Any]]]:
    """A copy of what was noted for ``job_key``."""
    with _NOTES_LOCK:
        held = _NOTES.get(str(job_key), {})
        return {source: [dict(note) for note in notes] for source, notes in held.items()}


def forget(job_key: str) -> None:
    """Drop what was noted for ``job_key``."""
    with _NOTES_LOCK:
        _NOTES.pop(str(job_key), None)


# ---------------------------------------------------------------------------
# Which sources read the sample
# ---------------------------------------------------------------------------


def _field(entry: Any, name: str) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def _block_opens(snapshot: Mapping[str, Any], path: str | None) -> bool:
    return bool(path) and any(snapshot.get(f"{path}.{leaf}") for leaf in SAMPLE_BLOCK_FIELDS)


def _normal_paths(paths: Iterable[Any]) -> frozenset[str]:
    return frozenset(os.path.normpath(str(p)) for p in paths if isinstance(p, str) and p.strip())


def _names_a_sample_path(entry: Any, paths: frozenset[str]) -> bool:
    """Whether a top-level argument of the call is one of the job's sample paths, as given."""
    args = _field(entry, "args")
    if not paths or not isinstance(args, Mapping):
        return False
    return any(
        isinstance(value, str) and value.strip() and os.path.normpath(value) in paths
        for value in args.values()
    )


def sample_readers(
    snapshot: Mapping[str, Any],
    entries: Iterable[Any],
    block_path: Callable[[str], str | None],
    sample_paths: Iterable[str] = (),
) -> tuple[dict[str, int], int]:
    """``({source: calls that read the sample}, calls that read it but record no source)``.

    A call reads the sample when its block declares where it sees it, when its
    tool declares an argument as the sample, or, read from the data, when it
    was handed one of the job's paths to the sample (``sample_paths``: the
    worker's copy, the paths servers that declare a mount see it at, the static
    providers' mirrors), so a tool that declares nothing is counted too.
    Linear in the entries and their arguments: each source's block is looked up
    once.
    """
    from maljan.core.declared_reading import kind_free_facts

    paths = _normal_paths(sample_paths)
    blocks: dict[str, bool] = {}
    readers: dict[str, int] = {}
    unsourced = 0
    for entry in entries:
        if _field(entry, "repeated_of"):
            continue
        source = str(_field(entry, "source") or "")
        if source and source not in blocks:
            blocks[source] = _block_opens(snapshot, block_path(source))
        reads = bool(source) and blocks[source]
        if not reads:
            arguments = kind_free_facts(entry).arguments
            reads = any(role in arguments for role in SAMPLE_ARGUMENT_ROLES)
        if not reads:
            reads = _names_a_sample_path(entry, paths)
        if not reads:
            continue
        if source:
            readers[source] = readers.get(source, 0) + 1
        else:
            unsourced += 1
    return readers, unsourced


# ---------------------------------------------------------------------------
# The part
# ---------------------------------------------------------------------------


def _merged(measurements: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], bool]:
    """Each field as every measurement gave it, ``None`` where two disagree; and whether any did."""
    out: dict[str, Any] = {}
    disagreed = False
    for key in MEASURED_FIELDS:
        values = [m.get(key) for m in measurements]
        first = values[0] if values else None
        agreed = all(v == first for v in values)
        disagreed = disagreed or not agreed
        out[key] = first if agreed else None
    return out, disagreed


def _passes(row: Mapping[str, Any]) -> bool:
    """Whether a measured row passes: every check read, and every one held."""
    checks = [
        row.get("same_uid_as_worker") is False,
        row.get("shares_group_with_worker") is False,
        row.get("own_pid_namespace") is True,
        row.get("own_mount_namespace") is True,
        row.get("cap_eff_zero") is True,
        row.get("cap_prm_zero") is True,
        row.get("cap_amb_zero") is True,
        row.get("no_new_privs") is True,
        row.get("platform_names_in_env") == [],
        row.get("needs_network") is True or row.get("own_net_namespace") is True,
    ]
    return all(checks)


def _launcher_passes(process: Mapping[str, Any]) -> bool:
    """Whether a process of a declared launcher passes: its environment held no platform variable.

    A launcher its block declares (``launcher_depth``) starts the server and
    reads no sample, so the checks that keep a reader from the worker are not
    its to pass: a launcher that separates its child runs as the worker's user,
    in the worker's namespaces, by its nature. What it still hands down is its
    environment, so that is held to the check every process is.
    """
    return process.get("platform_names_in_env") == []


# Why a start's descendants were not judged when its note says nothing of them.
DESCENDANTS_UNRECORDED = "the run recorded no walk of the processes under it"
# Why, under a declared launcher, they were not: the walk recorded no depth, so
# which process is the launcher's cannot be told.
DEPTH_UNRECORDED = "the run recorded no depth of the processes under it"


def _descendant_fields(
    notes: Sequence[Mapping[str, Any]], needs_network: bool, launcher_depth: int = 0
) -> dict[str, Any]:
    """Every start's descendants together: how many, how many failed, and whether all were judged.

    A note that records no walk judged nothing: never isolated by default.
    Under a declared launcher of ``launcher_depth`` levels, a descendant above
    that depth is the launcher's (:func:`_launcher_passes`) and one at or below
    it is held to every check; ``under_launcher`` counts the latter.
    """
    count = failing = under = 0
    judged, why = True, ""
    for note in notes:
        if "descendants_judged" not in note:
            judged, why = False, why or DESCENDANTS_UNRECORDED
            continue
        if not note.get("descendants_judged"):
            judged = False
            why = why or str(note.get("descendants_why") or DESCENDANTS_UNRECORDED)
        for process in note.get("descendants") or []:
            count += 1
            depth = process.get("depth")
            if launcher_depth and not isinstance(depth, int):
                judged, why = False, why or DEPTH_UNRECORDED
                failing += 1
                continue
            if launcher_depth and depth < launcher_depth:
                failing += 0 if _launcher_passes(process) else 1
                continue
            under += 1
            failing += 0 if _passes({**process, "needs_network": needs_network}) else 1
    return {
        "descendants": count,
        "descendants_failing": failing,
        "descendants_judged": judged,
        "descendants_why": why,
        "under_launcher": under if launcher_depth else 0,
    }


def _row(source: str, where: str, calls: int, **over: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "source": source,
        "label": "",
        "where": where,
        "transport": "",
        "host": "",
        "calls": calls,
        "measured_by": "",
        "attaches": 0,
        **dict.fromkeys(MEASURED_FIELDS),
        "descendants": 0,
        "descendants_failing": 0,
        "descendants_judged": False,
        "descendants_why": "",
        "needs_network": False,
        "launcher_depth": 0,
        "under_launcher": 0,
        "isolated": False,
        "isolated_by": "",
        "why_not_measured": "",
    }
    row.update(over)
    return row


# What an isolated row, or the whole part, rests on: every check measured, or
# a check that rests on a block's declared launcher (``launcher_depth``). The
# whole part rests on a declaration when any of its rows does.
BY_MEASUREMENT = "measurement"
BY_DECLARATION = "declaration"

# Why a row's isolation cannot be told.
NOT_MEASURED_CHILD = "the run holds no measurement of the process it was started as"
NOT_MEASURED_SERVICE = "it is a server reached at a local address, which this run does not measure"
NOT_MEASURED_REMOTE = "it runs outside this machine, which this run cannot measure"
NOT_MEASURED_DISAGREE = "its processes were measured differently from one start to the next"


def isolation_part(
    readers: Mapping[str, int],
    unsourced: int,
    notes: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    worker: Mapping[str, Any],
    in_process: Mapping[str, str],
    route: Callable[[str], tuple[str, str, str, str]],
    needs_network: Callable[[str], bool],
    launcher_depth: Callable[[str], int] = lambda _source: 0,
) -> dict[str, Any]:
    """The isolation part of the disclosure record.

    ``readers`` are the sources that read the sample, with their calls, and
    ``unsourced`` the calls that read it with no source recorded
    (:func:`sample_readers`); ``notes`` what was noted for the job;
    ``worker`` the worker's own facts (:func:`worker_facts`); ``in_process``
    the platform's declared in-process sources with their labels; ``route``
    answers a source's ``(transport, host, locality, why)`` from its settings
    block, and ``needs_network`` whether that block declares it needs one;
    ``launcher_depth`` how many levels at the top of the process tree the
    worker starts for a source its block declares a launcher's (``0``: none).

    **A declared launcher.** A launcher that separates the real server from the
    worker (a sandbox's monitor, a namespace or user switch) runs as the
    worker's user and would keep the row "not isolated" however well its child
    is kept. A block that declares one has its top ``launcher_depth`` levels
    held only to carrying no platform variable, every process under them to
    every check, and is isolated only when at least one process under them was
    measured: a launcher whose server runs where this run cannot see it (a
    container client) proves nothing and stays "not isolated". The declaration
    is the block's word, and the report says so.
    """
    from maljan.core.host_locality import LOCAL, REMOTE

    sources = dict(readers)
    for source, held in notes.items():
        if any(note.get("where") == IN_PROCESS for note in held):
            sources.setdefault(source, 0)
    rows: list[dict[str, Any]] = []
    for source, calls in sources.items():
        held = list(notes.get(source) or [])
        in_worker = [note for note in held if note.get("where") == IN_PROCESS]
        if source in in_process or in_worker:
            label = in_process.get(source) or str((in_worker or [{}])[0].get("label") or "")
            rows.append(
                _row(
                    source,
                    IN_PROCESS,
                    calls,
                    label=label,
                    measured_by="worker",
                    uid=worker.get("uid"),
                    same_uid_as_worker=True,
                    shares_group_with_worker=True,
                    own_pid_namespace=False,
                    own_net_namespace=False,
                    own_mount_namespace=False,
                    cap_eff_zero=worker.get("cap_eff_zero"),
                    cap_prm_zero=worker.get("cap_prm_zero"),
                    cap_amb_zero=worker.get("cap_amb_zero"),
                    no_new_privs=worker.get("no_new_privs"),
                    platform_names_in_env=list(worker.get("platform_names_in_env") or []),
                )
            )
            continue
        transport, host, locality, why = route(source)
        network = bool(needs_network(source))
        if transport == "stdio":
            levels = max(0, int(launcher_depth(source) or 0))
            measured = [note for note in held if note.get("where") == CHILD]
            if not measured:
                rows.append(
                    _row(
                        source,
                        CHILD,
                        calls,
                        transport=transport,
                        needs_network=network,
                        launcher_depth=levels,
                        why_not_measured=NOT_MEASURED_CHILD,
                    )
                )
                continue
            fields, disagreed = _merged(measured)
            row = _row(
                source,
                CHILD,
                calls,
                transport=transport,
                measured_by="worker",
                attaches=len(measured),
                needs_network=network,
                launcher_depth=levels,
                why_not_measured=NOT_MEASURED_DISAGREE if disagreed else "",
                **fields,
                **_descendant_fields(measured, network, levels),
            )
            row["isolated"] = (
                (_launcher_passes(row) if levels else _passes(row))
                and row["descendants_judged"]
                and not row["descendants_failing"]
                and (not levels or row["under_launcher"] > 0)
            )
            if row["isolated"]:
                row["isolated_by"] = BY_DECLARATION if levels else BY_MEASUREMENT
            rows.append(row)
            continue
        if transport and locality == LOCAL:
            rows.append(
                _row(
                    source,
                    LOCAL_SERVICE,
                    calls,
                    transport=transport,
                    host=host,
                    needs_network=network,
                    why_not_measured=NOT_MEASURED_SERVICE,
                )
            )
        elif transport and locality == REMOTE:
            rows.append(
                _row(
                    source,
                    REMOTE_SERVICE,
                    calls,
                    transport=transport,
                    host=host,
                    needs_network=network,
                    why_not_measured=NOT_MEASURED_REMOTE,
                )
            )
        else:
            rows.append(
                _row(
                    source,
                    UNPLACED,
                    calls,
                    transport=transport,
                    host=host,
                    needs_network=network,
                    why_not_measured=why or "the settings do not say where it ran",
                )
            )
    rows.sort(key=lambda r: (_ORDER[r["where"]], r["source"]))
    isolated = bool(rows) and not unsourced and all(row["isolated"] for row in rows)
    declared = any(row["isolated_by"] == BY_DECLARATION for row in rows)
    return {
        "worker": dict(worker),
        "rows": rows,
        "unsourced_reads": max(0, int(unsourced or 0)),
        "isolated": isolated,
        "isolated_by": (BY_DECLARATION if declared else BY_MEASUREMENT) if isolated else "",
    }


# ---------------------------------------------------------------------------
# The sentences
# ---------------------------------------------------------------------------

INTRO_SENTENCE = (
    "**Isolation:** where this run read the sample's bytes, and what kept each reader from "
    "the worker, as measured when each started; never assumed."
)


def _code(text: str) -> str:
    return f"`{text}`"


def _who(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    source = str(row.get("source") or "")
    label = str(row.get("label") or "")
    if row.get("where") == IN_PROCESS:
        return f"{label} ({code(source)})" if label else f"the in-process source {code(source)}"
    kind, _, key = source.partition(":")
    if kind == "mcp" and key:
        return f"tool server {code(key)}"
    if kind == "provider" and key:
        return f"the {code(key)} provider's tool server"
    return f"source {code(source)}"


def _names(names: Any, code: Callable[[str], str]) -> str:
    return ", ".join(code(str(name)) for name in names or [])


def _env_clause(names: Any, code: Callable[[str], str], whose: str) -> str:
    if names is None:
        return f"{whose} environment could not be read"
    if not names:
        return f"{whose} environment held none of the platform's own variables"
    return f"{whose} environment held the platform's own variables {_names(names, code)}"


def _yes_no(value: Any, yes: str, no: str, unread: str) -> str:
    if value is True:
        return yes
    if value is False:
        return no
    return unread


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:]


def _user(uid: Any, same: Any) -> str:
    who = "a user that could not be read" if uid is None else f"user {uid}"
    whose = _yes_no(
        same,
        " (one of its real, effective, saved or filesystem user ids is the worker's)",
        " (none of its real, effective, saved or filesystem user ids is the worker's)",
        " (its user ids could not all be read)",
    )
    return f"{who}{whose}"


_CAPABILITY_SETS = (
    ("cap_eff_zero", "effective"),
    ("cap_prm_zero", "permitted"),
    ("cap_amb_zero", "ambient"),
)


def _capabilities(row: Mapping[str, Any]) -> str:
    """The three capability sets, said together."""
    held = [name for key, name in _CAPABILITY_SETS if row.get(key) is False]
    unread = [name for key, name in _CAPABILITY_SETS if row.get(key) is None]
    if held:
        return f"{_joined_names(held)} capabilities"
    if unread:
        return f"{_joined_names(unread)} capabilities that could not be read"
    return "no effective, permitted or ambient capabilities"


def _joined_names(names: list[str]) -> str:
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def _worker_line(worker: Mapping[str, Any], code: Callable[[str], str]) -> str:
    uid = worker.get("uid")
    who = f"user {uid}" if uid is not None else "a user that could not be read"
    names = worker.get("platform_names_in_env")
    if names is None:
        clause = "its environment could not be read"
    elif not names:
        clause = "its environment holds none of the platform's own variables"
    else:
        clause = f"its environment holds the platform's own variables {_names(names, code)}"
    return f"The worker process runs as {who}; {clause}."


def _in_process_line(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    return (
        f"{_cap(_who(row, code))} read the sample in the worker process itself: not "
        "isolated, since it shares the worker's memory, environment, files and network."
    )


def _child_line(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    who = _cap(_who(row, code))
    why = str(row.get("why_not_measured") or "")
    if row.get("measured_by") != "worker":
        return (
            f"{who} (stdio, run on this machine) read the sample in a process the worker "
            f"started; {why}, so its isolation cannot be told."
        )
    parts = [
        f"it ran as {_user(row.get('uid'), row.get('same_uid_as_worker'))}",
        _yes_no(
            row.get("shares_group_with_worker"),
            "in a group of the worker's",
            "in none of the worker's groups",
            "in groups that could not all be read",
        ),
        _yes_no(
            row.get("own_pid_namespace"),
            "with a process table of its own",
            "sharing the worker's process table",
            "its process table could not be compared",
        ),
        _yes_no(
            row.get("own_mount_namespace"),
            "a mount namespace of its own",
            "the worker's mount namespace",
            "its mount namespace could not be compared",
        ),
        _yes_no(
            row.get("own_net_namespace"),
            "a network of its own",
            "the worker's network",
            "its network could not be compared",
        ),
        _capabilities(row),
        _yes_no(
            row.get("no_new_privs"),
            "no way to gain privileges",
            "no bar on gaining privileges",
            "a privilege flag that could not be read",
        ),
        _env_clause(row.get("platform_names_in_env"), code, "its"),
    ]
    starts = int(row.get("attaches") or 0)
    measured = (
        "measured at its start" if starts == 1 else f"measured at each of its {starts} starts"
    )
    verdict = "isolated" if row.get("isolated") else "not isolated"
    if row.get("isolated") and row.get("isolated_by") == BY_DECLARATION:
        verdict = "isolated by its block's declaration"
    need = " Its block declares that it needs the network." if row.get("needs_network") else ""
    tail = f" {_cap(why)}." if why else ""
    levels = int(row.get("launcher_depth") or 0)
    tree = _launcher_sentence(row, levels) if levels else _tree_sentence(row)
    return (
        f"{who} (stdio, run on this machine) read the sample. The process the worker started "
        f"for it was {measured}: " + "; ".join(parts) + f". {tree} "
        f"So: {verdict}.{need}{tail}"
    )


def _launcher_sentence(row: Mapping[str, Any], levels: int) -> str:
    """What was judged of a tree whose top ``levels`` its block declares a launcher's."""
    top = f"the top {levels} levels of its tree"
    if levels == 1:
        top = "the process the worker started"
    declared = (
        f"Its block declares {top} a launcher that does not read the sample (the block's word, "
        "not measured), so the launcher is held only to carrying none of the platform's own "
        "variables, and every process under it to every check."
    )
    if not row.get("descendants_judged"):
        return (
            f"{declared} Its descendant processes were not judged "
            f"({row.get('descendants_why')}), so they cannot be shown to be kept from the worker."
        )
    under, failing = int(row.get("under_launcher") or 0), int(row.get("descendants_failing") or 0)
    if not under:
        return (
            f"{declared} No process under the launcher was measured, so what read the sample "
            "cannot be shown to be kept from the worker."
        )
    noun = "process under the launcher was" if under == 1 else "processes under the launcher were"
    if not failing:
        return f"{declared} {under} {noun} measured, and every process of the tree passed."
    return f"{declared} {under} {noun} measured, and {failing} of the tree did not pass."


def _tree_sentence(row: Mapping[str, Any]) -> str:
    """What was judged of the processes under the one the worker started."""
    if not row.get("descendants_judged"):
        return (
            f"Its descendant processes were not judged ({row.get('descendants_why')}), so they "
            "cannot be shown to be kept from the worker."
        )
    count, failing = int(row.get("descendants") or 0), int(row.get("descendants_failing") or 0)
    if not count:
        return "It had no descendant process when it was measured."
    which = "Which process of its tree reads the sample cannot be told, so every one is held to "
    which += "the checks."
    noun = "process was" if count == 1 else "processes were"
    if not failing:
        return f"Its {count} descendant {noun} measured too, and every one passed. {which}"
    return (
        f"Its {count} descendant {noun} measured too, and {failing} did not pass every "
        f"check. {which}"
    )


def _service_line(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    at = f" at {code(str(row['host']))}" if row.get("host") else ""
    transport = str(row.get("transport") or "transport not recorded")
    if row.get("where") == LOCAL_SERVICE:
        tail = "not verified by this run"
    elif row.get("where") == REMOTE_SERVICE:
        tail = "this run cannot tell what isolation it had"
    else:
        tail = "its isolation cannot be told"
    return (
        f"{_cap(_who(row, code))} ({transport}){at} read the sample; "
        f"{row.get('why_not_measured')}, so {tail}."
    )


def isolation_lines(part: Any, code: Callable[[str], str] = _code) -> list[str]:
    """The part's sentences, one per line; ``[]`` for a record without the part."""
    if not isinstance(part, Mapping) or "rows" not in part:
        return []
    rows = [row for row in part.get("rows") or [] if isinstance(row, Mapping)]
    unsourced = int(part.get("unsourced_reads") or 0)
    lines: list[str] = []
    if not rows and not unsourced:
        lines.append("This run recorded no read of the sample's bytes, so nothing is said of it.")
    elif part.get("isolated") and part.get("isolated_by") == BY_DECLARATION:
        declared = [row for row in rows if row.get("isolated_by") == BY_DECLARATION]
        names = ", ".join(_who(row, code) for row in declared)
        lines.append(
            "Every source that read the sample's bytes was kept from the worker as measured, "
            f"but for {names} that rests on its block's declaration of a launcher."
        )
    elif part.get("isolated"):
        lines.append(
            "Every source that read the sample's bytes was measured as kept from the worker."
        )
    else:
        lines.append(
            "Not every source that read the sample's bytes was kept from the worker; each is "
            "listed with what was measured."
        )
    worker = part.get("worker")
    if isinstance(worker, Mapping) and rows:
        lines.append(_worker_line(worker, code))
    for row in rows:
        where = row.get("where")
        if where == IN_PROCESS:
            lines.append(_in_process_line(row, code))
        elif where == CHILD:
            lines.append(_child_line(row, code))
        else:
            lines.append(_service_line(row, code))
    if unsourced:
        calls = "call" if unsourced == 1 else "calls"
        lines.append(
            f"{unsourced} {calls} that read the sample recorded no source, so where "
            f"{'it' if unsourced == 1 else 'they'} ran cannot be told."
        )
    # Whether the copies handed out stayed the intake bytes, where the worker
    # recorded it (``analysis.sample_integrity``); a part stored without it says none.
    from maljan.analysis.sample_integrity import RECORD_KEY, integrity_lines

    lines.extend(integrity_lines(part.get(RECORD_KEY), code))
    return lines
