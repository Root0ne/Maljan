"""The platform's own readings of the sample, and where each one runs.

Every step of the triage pack that opens the sample's bytes — or the bytes of
a file a reading wrote out of it, or of the job's packet capture — goes
through one of the readers named here (:data:`READERS`): the format readers,
the rule matchers, the emulator, the unpacker, the byte scans. Each stands in
for a tool a server declares (``stands_for``), the tool of the same function
the analysis or network server offers a model.

**Where it runs.** In this process by default, exactly as before. When the
server declaring the tool a reader stands in for is reached at an address — a
container of its own, on an internal network, with the samples mounted
read-only and no platform secret (X2) — the reading runs there instead, over
that server's ``run_reader`` delivery primitive (:data:`RUN_READER`), and the
worker reads only its answer (:class:`SampleReaders`). Which server that is,
and whether it is reached at an address, is read from the run's settings by
the caller; nothing here names a tool server.

**The same reading either way.** Each reader is one function of JSON values
(and of the environment its side reads: the worker's with the declaring
server's ``env`` over it, or the server's own), so the server runs the very
code the worker would. Its answer crosses as JSON and is read as JSON only,
never as code: the server's process opened hostile bytes, so what it says is
data. A reader that raised is raised again here under its own class name, so
the entry a reader cites says what it would have said in process.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import re
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "READERS",
    "RELEASE_JOB",
    "RUN_READER",
    "Place",
    "Reader",
    "ReaderRefused",
    "SampleNotPlaced",
    "SampleReaders",
    "groups_state",
    "merge_groups_state",
    "serve_release",
    "serve_reader",
]

# The delivery primitive a server offers for the platform to run one of its
# readings there (``agents.tool_pinning.DELIVERY_TOOLS``): ``reader`` (a name
# of :data:`READERS`), ``arguments`` (its JSON arguments) and ``job`` (the
# job's id, whose staging directory a reading that writes writes in). It
# answers ``value`` (the reading's answer) or ``raised`` (the class name and
# words of what the reading raised). Never shown to a model.
RUN_READER = "run_reader"

# The delivery primitive a server that runs readings offers for the job's end:
# ``job`` (the job's id), whose staging directory there (``<staging>/<job>``:
# capa's and FLOSS's scratch, the unpacker's carves) it removes, that job's
# alone. It answers ``released`` (whether nothing of the job's is left there)
# or an ``error``. Never shown to a model.
RELEASE_JOB = "release_job"


class ReaderRefused(RuntimeError):
    """The server did not run the reading: it refused the call, or its answer was not one."""


class SampleNotPlaced(RuntimeError):
    """The reading runs on a server that was handed no copy of the sample to open."""


Environ = Mapping[str, str] | None


@dataclass(frozen=True)
class Reader:
    """One reading: its function, the tool it stands in for, and its file arguments.

    ``fn`` is called with the environment of the side that runs it and the
    reading's arguments. ``files`` are the arguments that name a file:
    the sample, a file a reading on the same server wrote, or (``worker_files``)
    a file only this worker holds, handed to the server through the job's
    artefact store first. ``local_only`` are arguments that exist only in
    process (an object the reading writes into) and are never sent.
    ``data_dirs`` are arguments that name a directory of the platform's own
    data (a rule corpus), which a server holds to its data root, and
    ``optional_dirs`` those of them an empty value leaves out (capa's
    signatures: no library identification); ``choices`` answers, for an
    argument that names one of a fixed set, the values a server takes.
    """

    fn: Callable[..., Any]
    stands_for: str
    files: tuple[str, ...] = ("path",)
    worker_files: tuple[str, ...] = ()
    local_only: tuple[str, ...] = ()
    data_dirs: tuple[str, ...] = ()
    optional_dirs: tuple[str, ...] = ()
    choices: Callable[[], Mapping[str, Iterable[str]]] | None = None


# ---------------------------------------------------------------------------
# The readings
# ---------------------------------------------------------------------------


def _identify_file(environ: Environ, path: str) -> Any:
    from maljan.tools import identify

    return identify.identify_file(path)


def _hashes(environ: Environ, path: str) -> Any:
    from maljan.tools import identify

    return identify.hashes(path)


def _signing_info(environ: Environ, path: str, file_type: str | None = None) -> Any:
    from maljan.tools import identify

    return identify.signing_info(path, file_type=file_type)


def _format_reader(name: str) -> Callable[..., Any]:
    def read(environ: Environ, path: str) -> Any:
        from maljan.tools import binary

        return getattr(binary, name)(path)

    read.__name__ = f"_{name}"
    return read


def _strings(environ: Environ, path: str, min_len: int, limit: int) -> Any:
    from maljan.tools import strings

    return strings.strings(path, min_len=min_len, limit=limit)


def _iocs_from_file(environ: Environ, path: str) -> Any:
    from maljan.tools import strings

    return strings.iocs_from_file(path)


def _yara_scan(environ: Environ, path: str, timeout_s: int | None = None) -> Any:
    from maljan.tools import rules

    if timeout_s is None:
        return rules.yara_scan(path=path)
    return rules.yara_scan(path=path, timeout_s=timeout_s)


def _capa(
    environ: Environ,
    path: str,
    timeout_s: int | None,
    backend: str,
    rules_dir: str,
    signatures_dir: str,
    job: str = "",
) -> Any:
    from maljan.tools import rules, staging

    scratch = staging.open_job_directory(job, staging.CAPA_DIRECTORY, environ) if job else None
    return rules.capa(
        path,
        timeout_s=timeout_s,
        backend=backend,
        rules_dir=rules_dir,
        signatures_dir=signatures_dir,
        scratch=scratch,
    )


def _capa_choices() -> Mapping[str, Iterable[str]]:
    """The backends capa's reading takes: the names the capa provider maps."""
    from maljan.providers.static.capa_yara import _BACKEND_NAMES

    return {"backend": tuple(_BACKEND_NAMES)}


def _floss_unavailable(environ: Environ) -> Any:
    from maljan.tools import emulated_strings

    return emulated_strings.floss_unavailable(environ)


def _floss(environ: Environ, path: str, limit: int, timeout_s: int | None, job: str = "") -> Any:
    """The emulator's whole result first, then the entry's page of it.

    ``found`` (the whole result, when it is an error) or ``answer`` (the page)
    with ``rows`` (every row the page was cut from): the page and the rows the
    pack's readers compare with are one result, never a second read of the
    emulator's process-wide memory.
    """
    from maljan.tools import emulated_strings, staging

    scratch = staging.open_job_directory(job, "floss", environ) if job else None
    found = emulated_strings.recovered(path, timeout_s=timeout_s, environ=environ, scratch=scratch)
    if "error" in found:
        return {"found": found}
    answer = emulated_strings.floss(
        path,
        limit=limit,
        timeout_s=timeout_s,
        environ=environ,
        scratch=scratch,
        found=found,
    )
    return {"answer": answer, "rows": list(found["rows"])}


def _resolve_api_hashes(
    environ: Environ, path: str, function_starts: list[Any], function_source: str
) -> Any:
    from maljan.tools import api_hashes

    return api_hashes.resolve_api_hashes(
        path, function_starts=function_starts, function_source=function_source
    )


def _decode_string_blobs(
    environ: Environ,
    path: str,
    function_starts: list[Any],
    function_source: str,
    recovered: list[Any],
    decoder: str,
    recovered_partial: str,
) -> Any:
    from maljan.tools import string_blobs

    return string_blobs.decode_string_blobs(
        path,
        function_starts=function_starts,
        function_source=function_source,
        recovered=recovered,
        decoder=decoder,
        recovered_partial=recovered_partial,
    )


def _find_crypto_constants(
    environ: Environ, path: str, function_starts: list[Any], function_source: str
) -> Any:
    from maljan.tools import crypto_constants

    return crypto_constants.find_crypto_constants(
        path, function_starts=function_starts, function_source=function_source
    )


def _function_index(environ: Environ, path: str, **joined: Any) -> Any:
    """The function index and the exception directory's ranges it read, side by side."""
    from maljan.tools import artefact_index

    ranges: dict[str, list[list[str]]] = {}
    answer = artefact_index.function_index(path, ranges_into=ranges, **joined)
    return {"answer": answer, "ranges": ranges}


def _upx_header(environ: Environ, path: str) -> Any:
    from maljan.tools import upx

    return upx.has_pack_header_at(path)


def _file_digest(path: str) -> str:
    """The SHA-256 of the file at ``path``, read in pieces: the name of its carved tree."""
    hasher = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _unpack_upx(environ: Environ, path: str, job: str) -> Any:
    """Unpack a UPX image into ``<staging>/<job>/carved/<sha256>/`` of the side that runs it."""
    from maljan.tools import staging, upx

    carved = staging.open_job_directory(job, staging.CARVED_DIRECTORY, environ)
    destination = staging.private_dir(carved / _file_digest(path))
    return upx.unpack_upx(path, destination)


def _pcap_summary(environ: Environ, path: str) -> Any:
    from maljan.tools import pcap

    return pcap.pcap_summary(path)


def _toolchain(environ: Environ, path: str, prefix_bytes: int) -> Any:
    """The language or compiler a bounded prefix of the file names, ``""`` for none."""
    from maljan.extractors.sample_identity import _detect_language_or_compiler

    with Path(path).open("rb") as handle:
        return _detect_language_or_compiler(handle.read(prefix_bytes)) or ""


def _directed_scan(
    environ: Environ,
    path: str,
    source: str,
    regions: list[Any] | None = None,
    extra: Mapping[str, str] | None = None,
    seconds: float | None = None,
    room: int | None = None,
    into: Any = None,
    opened: Callable[[int], None] | None = None,
    deadline_at: float | None = None,
) -> Any:
    """The directed-text phrases in one file's bytes.

    Into ``into`` (the pass's own groups) when run in process, ``opened``
    told how many bytes the file held before any match and ``deadline_at``
    the pass's own deadline on this process's clock; otherwise into groups
    of its own, by a deadline ``seconds`` from now, handed back as their
    state (:func:`groups_state`) for the caller to merge, with ``spent``
    where the deadline stopped it. ``bytes`` is how many the file held.
    """
    import time

    from maljan.analysis import directed_text

    deadline = deadline_at
    if into is None and seconds is not None:
        deadline = time.monotonic() + float(seconds)
    blob = Path(path).read_bytes()
    held = [
        region
        if isinstance(region, directed_text.Region)
        else directed_text.Region(str(region["name"]), int(region["start"]), region.get("end"))
        for region in regions or ()
    ]
    if into is not None:
        if opened is not None:
            opened(len(blob))
        directed_text.scan_bytes_into(into, blob, source, held, deadline, extra)
        return {"bytes": len(blob)}
    groups = directed_text.Groups(room=room)
    out: dict[str, Any] = {"bytes": len(blob)}
    try:
        directed_text.scan_bytes_into(groups, blob, source, held, deadline, extra)
    except directed_text.Spent as spent:
        out["spent"] = spent.at
    out["groups"] = groups_state(groups)
    return out


READERS: dict[str, Reader] = {
    "identify_file": Reader(_identify_file, "identify_file"),
    "hashes": Reader(_hashes, "hashes"),
    "signing_info": Reader(_signing_info, "signing_info"),
    **{
        name: Reader(_format_reader(name), name)
        for name in (
            "pe_info",
            "elf_info",
            "macho_info",
            "apk_info",
            "document_info",
            "archive_list",
        )
    },
    "strings": Reader(_strings, "strings"),
    "iocs_from_file": Reader(_iocs_from_file, "iocs_from_file"),
    "yara_scan": Reader(_yara_scan, "yara_scan"),
    "capa": Reader(
        _capa,
        "capa",
        data_dirs=("rules_dir", "signatures_dir"),
        optional_dirs=("signatures_dir",),
        choices=_capa_choices,
    ),
    "floss": Reader(_floss, "floss"),
    "floss_unavailable": Reader(_floss_unavailable, "floss", files=()),
    "resolve_api_hashes": Reader(_resolve_api_hashes, "resolve_api_hashes"),
    "decode_string_blobs": Reader(_decode_string_blobs, "decode_string_blobs"),
    "find_crypto_constants": Reader(_find_crypto_constants, "find_crypto_constants"),
    "function_index": Reader(_function_index, "function_index"),
    "upx_header": Reader(_upx_header, "unpack_upx"),
    "unpack_upx": Reader(_unpack_upx, "unpack_upx"),
    "pcap_summary": Reader(_pcap_summary, "pcap_summary", files=(), worker_files=("path",)),
    # The two readings that are no tool of their own: the toolchain a prefix
    # names stands in for the identity reading, a file's directed-text phrases
    # for the reading of its text.
    "toolchain": Reader(_toolchain, "identify_file"),
    "directed_scan": Reader(
        _directed_scan, "strings", local_only=("into", "opened", "deadline_at")
    ),
}


# ---------------------------------------------------------------------------
# The directed-text groups across the boundary
# ---------------------------------------------------------------------------


def groups_state(groups: Any) -> dict[str, Any]:
    """``directed_text.Groups`` as JSON values, every group in the order it was first held."""
    return {
        "total": groups.total,
        "counts": dict(groups.counts),
        "held": [
            {
                "family": group.family,
                "phrase": group.phrase,
                "first": group.first,
                "last": group.last,
                "count": group.count,
                "sources": dict(group.sources),
                "disguises": sorted(group.disguises),
                "inside_template": group.inside_template,
                "names": dict(group.names),
            }
            for group in groups.held.values()
        ],
    }


def merge_groups_state(groups: Any, state: Mapping[str, Any]) -> None:
    """Fold a state :func:`groups_state` gave into ``groups``, as adding its matches would.

    A group ``groups`` does not hold is taken as it is, after every group it
    holds; one it holds keeps its first place and takes the other's last
    place, counts, sources, disguises and names it lacks — the same groups,
    in the same order, that adding the matches one by one gives.
    """
    from maljan.analysis import directed_text

    groups.total += int(state.get("total") or 0)
    for family, count in dict(state.get("counts") or {}).items():
        groups.counts[str(family)] = groups.counts.get(str(family), 0) + int(count)
    for row in state.get("held") or []:
        key = (str(row["family"]), str(row["phrase"]))
        group = groups.held.get(key)
        if group is None:
            group = groups.held[key] = directed_text._Group(
                key[0], key[1], first=dict(row["first"])
            )
        group.count += int(row["count"])
        group.last = dict(row["last"])
        for source, count in dict(row["sources"]).items():
            group.sources[str(source)] = group.sources.get(str(source), 0) + int(count)
        group.disguises.update(str(d) for d in row["disguises"])
        group.inside_template += int(row["inside_template"])
        for name_key, text in dict(row["names"]).items():
            group.names.setdefault(str(name_key), text)


# ---------------------------------------------------------------------------
# The server's side
# ---------------------------------------------------------------------------


def _json(value: Any) -> Any:
    """``value`` as the JSON it crosses as."""
    return json.loads(json.dumps(value, allow_nan=False))


def _in_data_root(value: str) -> str:
    """A data directory a reading names, resolved, if it lands inside the platform's data root.

    Read as the platform reads a configured data path (``core.paths.resolve_data``:
    a relative one against the project root), then held to ``<project>/data``
    with every link followed, so neither a ``..`` climb nor an absolute path
    reaches outside it.

    Raises:
        PathOutsideRoots: for any directory outside the data root.
    """
    from maljan.core.paths import get_project_root, resolve_data
    from maljan.tools.roots import resolve_under

    return str(resolve_under(resolve_data(value), (get_project_root() / "data",)))


def _text_argument(name: str, value: Any) -> str:
    """A path argument as the string it must be.

    Raises:
        TypeError: for any other value (a number would name a file descriptor).
    """
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, not {type(value).__name__}")
    return value


def serve_release(job: Any, environ: Environ = None) -> dict[str, Any]:
    """Remove job ``job``'s staging directory on the server's side: ``released``, or an ``error``.

    The directory is ``<staging base>/<the job's directory name>``
    (``tools.staging.release_job_directory``): one path segment composed from
    the id, so no id names anything outside the base, and a link standing
    there is removed rather than followed. A server started for one job
    releases only that one. Never raises.
    """
    from maljan.tools import staging

    if not isinstance(job, str) or not job.strip():
        return {"error": f"{RELEASE_JOB} needs the id of the job to release"}
    try:
        return {"released": staging.release_job_directory(job, environ)}
    except staging.NotThisJob as exc:
        return {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001 — a release that failed is answered, not raised
        return {"error": f"{type(exc).__name__}: the job's staging was not removed"}


def serve_reader(
    reader: str,
    arguments: Mapping[str, Any] | None,
    job: str,
    *,
    offered: frozenset[str] | set[str],
    confine: Callable[[str, str], str],
) -> dict[str, Any]:
    """Run one reading on the server's side: ``value``, ``raised``, or an ``error``.

    Only a reading that stands in for a tool this server offers (``offered``)
    is run. Each file argument is held to what this server may read for this
    job (``confine``, given the path and the job's id), each data directory
    to the platform's data root (:func:`_in_data_root`) and each argument of
    a fixed set to that set; an argument only an in-process call passes is
    refused. A file argument or a data directory given at all is a string,
    or the reading raises ``TypeError``: no other value reaches a path or a
    file descriptor unchecked. An empty data directory is refused (it would
    name the project root, outside the data root) unless the reading declares
    it optional (``Reader.optional_dirs``). The environment read is the
    server's own. Never raises.
    """
    spec = READERS.get(str(reader or ""))
    if spec is None or spec.stands_for not in offered:
        return {"error": f"this server runs no reading named {str(reader)[:64]!r}"}
    given = dict(arguments or {})
    if any(name in given for name in spec.local_only):
        return {"error": f"{reader} takes {', '.join(spec.local_only)} only in process"}
    try:
        for name in (*spec.files, *spec.worker_files):
            if name in given:
                given[name] = confine(_text_argument(name, given[name]), str(job or ""))
        for name in spec.data_dirs:
            if name not in given:
                continue
            value = _text_argument(name, given[name])
            if value:
                given[name] = _in_data_root(value)
            elif name not in spec.optional_dirs:
                raise ValueError(f"{name} names no directory, and {reader} needs one")
        for name, allowed in (spec.choices() if spec.choices else {}).items():
            if name in given and given[name] not in tuple(allowed):
                raise ValueError(
                    f"{name} {str(given[name])[:64]!r} is none of {', '.join(map(str, allowed))}"
                )
        if "job" in given:
            given["job"] = str(job or "")
        return {"value": _json(spec.fn(os.environ, **given))}
    except Exception as exc:  # noqa: BLE001 — a reading that raised is answered, not raised
        return {"raised": {"type": type(exc).__name__, "message": str(exc)}}


# ---------------------------------------------------------------------------
# The worker's side
# ---------------------------------------------------------------------------

_CLASS_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _raised(said: Any) -> Exception:
    """What a reading on the server raised, as an exception of its class name here.

    A built-in exception's own class where the name is one (so ``except
    OSError`` reads a missing file as it would in process); otherwise a class
    of that name made here, holding only the words. The name is the server's
    text and is checked as an identifier before it names anything.
    """
    said = said if isinstance(said, Mapping) else {}
    name = str(said.get("type") or "")
    message = str(said.get("message") or "")
    if not _CLASS_NAME.match(name):
        return ReaderRefused(message or "the server's reading raised")
    known = getattr(builtins, name, None)
    if isinstance(known, type) and issubclass(known, Exception):
        try:
            return known(message)
        except Exception:  # noqa: BLE001 — a class that will not take one argument
            pass
    # Made for this raise and not kept: the names are the server's, and a
    # server that names a new one each time grows nothing here.
    made: type[Exception] = type(name, (Exception,), {})
    return made(message)


@dataclass(frozen=True)
class Place:
    """A server a reading runs on, as this job reaches it.

    ``sample_path`` is the path that server opens the job's sample at (``""``:
    it was handed none). ``call`` sends one ``run_reader`` call and answers
    its JSON object; ``hand`` puts a file only this worker holds where the
    server opens it and answers that path.
    """

    server: str
    sample_path: str
    job: str
    call: Callable[[dict[str, Any], float | None], Any]
    hand: Callable[[str], str] | None = None


# What a reading's call on a server waits beyond the reading's own clock: the
# crossing both ways and the answer's encoding, so a reading that used all of
# its clock there is still answered here.
CALL_MARGIN_SECONDS = 30.0


@dataclass
class SampleReaders:
    """Where this job's readings run: here, or on the place of the tool each stands in for.

    ``places`` holds a place by the tool it is the server of; a reading whose
    tool has none runs here. ``sample_path`` is the worker's own path of the
    sample, the one argument value a place is handed its own path for.
    ``clock`` answers the wall clock a reading on a place is given when its
    caller names none (the pack: what is left of its budget; ``None``: none).
    Where each reading ran is told to every :meth:`noting` open on the
    thread that ran it.
    """

    sample_path: str = ""
    places: Mapping[str, Place] = field(default_factory=dict)
    clock: Callable[[], float | None] | None = None
    # The lists :meth:`noting` opened on each thread, innermost last.
    _noting: threading.local = field(
        default_factory=threading.local, init=False, repr=False, compare=False
    )

    @contextmanager
    def noting(self) -> Iterator[list[str | None]]:
        """Where each reading run on this thread inside the block ran, in order.

        A place's server for a reading sent there, ``None`` for one run in
        this process; noted when the reading starts, so a reading that raised
        is noted too. Blocks nest: a reading is noted in each one open.
        """
        stack: list[list[str | None]] | None = getattr(self._noting, "stack", None)
        if stack is None:
            stack = self._noting.stack = []
        ran: list[str | None] = []
        stack.append(ran)
        try:
            yield ran
        finally:
            # By identity: two blocks' lists may hold the same places.
            del stack[next(at for at, held in enumerate(stack) if held is ran)]

    def _ran(self, where: str | None) -> None:
        for ran in getattr(self._noting, "stack", None) or ():
            ran.append(where)

    def place_of(self, reader: str) -> Place | None:
        """The place ``reader`` runs on, ``None`` for this process."""
        return self.places.get(READERS[reader].stands_for)

    def read(
        self,
        reader: str,
        environ: Environ = None,
        *,
        timeout: float | None = None,
        **arguments: Any,
    ) -> Any:
        """Run ``reader`` where it runs and answer what it answered, raising what it raised.

        On a place, the call waits the reading's own clock (``timeout``, else
        ``clock``'s) and :data:`CALL_MARGIN_SECONDS` beyond it; with neither,
        it waits as long as the reading takes, as it would in process.
        """
        spec = READERS[reader]
        place = self.place_of(reader)
        if place is None:
            self._ran(None)
            return spec.fn(environ, **arguments)
        sent = {k: v for k, v in arguments.items() if k not in spec.local_only}
        for name in spec.files:
            value = sent.get(name)
            if isinstance(value, str) and value and value == self.sample_path:
                if not place.sample_path:
                    raise SampleNotPlaced(
                        f"{reader} runs on {place.server}, which was handed no copy of the "
                        "sample (its block declares no sample_mount)"
                    )
                sent[name] = place.sample_path
        for name in spec.worker_files:
            value = sent.get(name)
            if isinstance(value, str) and value:
                if place.hand is None:
                    raise SampleNotPlaced(f"{reader} runs on {place.server}; no file reaches it")
                sent[name] = place.hand(value)
        if timeout is None and self.clock is not None:
            timeout = self.clock()
        wait = None if timeout is None else float(timeout) + CALL_MARGIN_SECONDS
        self._ran(place.server)
        answer = place.call({"reader": reader, "arguments": sent, "job": place.job}, wait)
        if not isinstance(answer, Mapping):
            raise ReaderRefused(f"{place.server} answered {RUN_READER} with no object")
        if "raised" in answer:
            raise _raised(answer["raised"])
        if "value" not in answer:
            said = answer.get("error")
            if isinstance(said, Mapping):
                said = said.get("message") or said.get("code")
            raise ReaderRefused(str(said or f"{place.server} did not run {reader}"))
        return answer["value"]
