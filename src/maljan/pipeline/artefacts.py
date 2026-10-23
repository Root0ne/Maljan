"""The job's artefact store: a file one tool server wrote, handed to another server's tool.

A tool that writes a file (a payload carved out of the sample, an archive
member unpacked, a script decoded) names it in its answer, in its own
server's namespace, and no other server can open that name. The store is the
one way such a file reaches another server's tool, whatever either tool is:

* **Taken in.** A pack step that declares ``outputs`` (``core.pack_steps``)
  names the path of its answer that lists the files its tool wrote. Each is
  copied into the store, under the job's own staging directory
  (``<staging base>/<job>/artefacts/<sha256>/<name>``, every level 0o700 and
  the file 0o600, removed with the job's staging), and given a stable id, its
  digest (``art_<sha256>``). The bytes come over the producing server's own
  ``get_artefact`` tool where it offers one, whatever its transport, and
  otherwise, for a server on this host's filesystem (stdio, no
  ``sample_mount``), from inside that server's own job staging directory and
  nowhere else, opened beneath it with no link followed (:func:`open_beneath`).
  A file that cannot be taken in is named with why.
* **Recorded.** The producing entry's ``pack_step`` names what was taken in
  (``wrote``: each id, digest, size and name) and what was not
  (``not_taken``), and the entry of a step that read one names its id
  (``read``), so the ledger says which file went from which call to which.
* **Handed over.** A step names a file of the store by placeholder:
  ``{artefact_path}`` on a step that ``reads`` a producing step (it runs once
  per file), ``{capture_path}`` and ``{sandbox_report_path}`` for the job's
  sandbox capture and report, which the pack takes into the store the first
  time a step names them; the capture only from the directory the worker
  fetched this job's captures into, whatever path the report names. The
  receiving server is handed the path it opens the file at, exactly as it is
  handed the sample: a server on this host's
  filesystem a copy under its own job staging directory (the store's own file
  where that is the same directory); a server that declares a
  ``sample_mount`` a copy the worker places under its read-only mount, as it
  places the sample (``ServiceContainer.place_for_server``); a server across a
  network an upload over its ``put_sample`` tools, written to the job's
  record of uploads. A server none of these reaches is not called, and its
  step says why. Never a path only this host can open.

Nothing here opens a file as anything but bytes: nothing is run, unpacked or
parsed, and no file's own name decides where it lands (:func:`safe_name`).
There is no size limit; each file is streamed through once.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.tools import staging

__all__ = [
    "ARTEFACT_ID_PREFIX",
    "FETCH_TOOL",
    "Artefact",
    "ArtefactStore",
    "answer_data",
    "artefact_id",
    "open_beneath",
    "safe_name",
    "shares_the_worker_filesystem",
    "hand_over",
    "reason_for",
    "take_in_outputs",
    "written_names",
]

# What an artefact's id is: this prefix and the file's SHA-256, so one file has
# one id in every run and a stored run's ids read the same on replay.
ARTEFACT_ID_PREFIX = "art_"

# The tool a server offers for the platform to read a file it wrote, as
# ``put_sample`` is the one it offers to be handed one: ``path`` (the name its
# answer gave the file), ``offset`` and ``length`` in bytes; it answers
# ``content_b64`` (those bytes), ``size`` (the whole file's) and, where it
# knows it, ``sha256`` (the whole file's). A delivery primitive, never shown to
# a model (``agents.tool_pinning.DELIVERY_TOOLS``).
FETCH_TOOL = "get_artefact"

# How much one ``get_artefact`` call asks for, and how much of a local file is
# read at a time: the size an upload chunk is, so neither side holds more.
FETCH_CHUNK_BYTES = 4 * 1024 * 1024

# A file's name as the store keeps it: these characters, the rest replaced.
_UNSAFE_IN_A_NAME = re.compile(r"[^A-Za-z0-9._-]")
_NAME_CHARS = 128
_SUFFIX_CHARS = 16
_FALLBACK_NAME = "artefact"


@dataclass(frozen=True)
class Artefact:
    """One file of the store: its stable id, digest, size, name and where the worker keeps it.

    ``path`` is the worker's own and is never published: an entry names the
    artefact by its id (:meth:`record`).
    """

    id: str
    sha256: str
    size: int
    name: str
    path: Path
    # What the file is, as a staging record names it when it is uploaded
    # (``analysis.disclosure.staging_record``): ``artefact`` (a file a tool
    # wrote), ``capture`` or ``sandbox_report``.
    kind: str = "artefact"

    def record(self) -> dict[str, Any]:
        """The artefact as an entry names it: id, digest, size and name, never its path."""
        return {"id": self.id, "sha256": self.sha256, "size": self.size, "name": self.name}


def artefact_id(sha256: str) -> str:
    """The id of the file whose SHA-256 is ``sha256``."""
    return f"{ARTEFACT_ID_PREFIX}{sha256}"


def safe_name(raw: Any) -> str:
    """The name the store keeps a file under: its last part, in safe characters, bounded.

    The name came from a tool's answer about the sample, so the sample's author
    may have written it: only its last path part is kept, every character
    outside letters, digits, ``.``, ``_`` and ``-`` is replaced, no leading dot
    is kept (no hidden file, no ``..``) and a long name keeps its suffix, so a
    tool that reads a file by its extension still can.
    """
    text = str(raw or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = _UNSAFE_IN_A_NAME.sub("_", text).lstrip(".")
    if len(name) > _NAME_CHARS:
        _stem, dot, suffix = name.rpartition(".")
        kept = f".{suffix}" if dot and 0 < len(suffix) <= _SUFFIX_CHARS else ""
        name = name[: _NAME_CHARS - len(kept)] + kept
    return name or _FALLBACK_NAME


def answer_data(output: Any, structured: Any = None) -> Any:
    """A tool's answer as data: ``structured`` where given, else its text read as JSON."""
    if structured is not None:
        return structured
    if isinstance(output, (dict, list)):
        return output
    try:
        return json.loads(str(output))
    except (TypeError, ValueError):
        return None


def written_names(data: Any, path: str) -> list[str]:
    """The file names ``path`` (a declared field path) gives in ``data``, each once, in order.

    A value that is a list is read item by item; anything but a non-blank text
    names no file.
    """
    from maljan.core.tool_declarations import select

    names: dict[str, None] = {}
    for value in select(data, path) if path else ():
        for item in value if isinstance(value, list) else (value,):
            if isinstance(item, str) and item.strip():
                names.setdefault(item, None)
    return list(names)


def shares_the_worker_filesystem(config: Any) -> bool:
    """Whether a server opens this host's filesystem as it is: stdio, and no ``sample_mount``."""
    from maljan.agents.sample_staging import REMOTE_TRANSPORTS

    transport = str(getattr(config, "transport", "stdio") or "stdio").lower()
    return transport not in REMOTE_TRANSPORTS and not str(getattr(config, "sample_mount", "") or "")


def server_environ(config: Any) -> dict[str, str]:
    """This process's environment with the server's own ``env`` map over it, as it is spawned."""
    environ = dict(os.environ)
    environ.update({str(k): str(v) for k, v in dict(getattr(config, "env", None) or {}).items()})
    return environ


# Why a name is refused beneath its root, said in the store's own words.
NOT_BENEATH = "it is not inside {where}"

_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _parts_beneath(root: Path, name: str, where: str) -> list[str]:
    """``name`` as the parts of a path under ``root``: relative, or absolute under it as spelt.

    Read as text only, nothing resolved: a ``..``, an empty part or an
    absolute name under no spelling of ``root`` is refused.
    """
    given = Path(name)
    if given.is_absolute():
        for spelling in dict.fromkeys((str(root), os.path.realpath(root))):
            try:
                given = given.relative_to(spelling)
                break
            except ValueError:
                continue
        else:
            raise ValueError(NOT_BENEATH.format(where=where))
    parts = [part for part in given.parts if part != "."]
    if not parts or any(part in ("", "..") for part in parts):
        raise ValueError(NOT_BENEATH.format(where=where))
    return parts


def open_beneath(root: Path, name: str, where: str) -> int:
    """A read-only descriptor of the regular file ``name`` beneath ``root``; else ``ValueError``.

    Opened component by component from a descriptor of ``root``, each
    directory with ``O_DIRECTORY`` and every component with ``O_NOFOLLOW``
    relative to the one before (``openat``), so no link is followed anywhere
    below ``root`` and nothing can be swapped between a check and the open:
    what is read is what was opened, and the open itself is the check. The
    file is opened without blocking (a FIFO planted there never holds the
    worker) and is refused unless ``fstat`` says it is a regular file.
    ``root`` itself is the deployment's own directory and is opened as it is.
    ``where`` names ``root`` in a refusal.
    """
    parts = _parts_beneath(root, name, where)
    try:
        current = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise ValueError(NOT_BENEATH.format(where=where)) from exc
    try:
        for part in parts[:-1]:
            try:
                below = os.open(part, _OPEN_FLAGS | os.O_DIRECTORY, dir_fd=current)
            except OSError as exc:
                raise ValueError(NOT_BENEATH.format(where=where)) from exc
            os.close(current)
            current = below
        try:
            fd = os.open(parts[-1], _OPEN_FLAGS | getattr(os, "O_NONBLOCK", 0), dir_fd=current)
        except OSError as exc:
            raise ValueError(f"it cannot be opened as a file inside {where}") from exc
    finally:
        os.close(current)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise ValueError("it is not a regular file")
    if info.st_nlink != 1:
        # A hard link names the same file as a path outside the root may: what
        # the root holds is then not the root's alone, and it is not read.
        os.close(fd)
        raise ValueError(f"it has {info.st_nlink} hard links, so it may be a file outside {where}")
    return fd


class _Fetched:
    """The chunks of a file read over a server's ``get_artefact`` tool, and the digest stated."""

    def __init__(self, call: Callable[[int], Any]) -> None:
        self._call = call
        self.sha256 = ""

    def __iter__(self) -> Iterator[bytes]:
        """Each chunk in order, until the size the first answer stated is read.

        No limit of the platform's own: the read ends where the server said
        the file ends, and the server is held to it. The size is fixed by the
        first answer, which must state one (a read with no stated end is
        refused), and a later answer that states another, a chunk that would
        pass it, an empty chunk before it and a digest that changes are each
        refused, so the read always ends.
        """
        from maljan.agents.sample_staging import _check

        offset, size = 0, -1
        while size < 0 or offset < size:
            answer = self._call(offset)
            _check(answer)
            data = answer_data(answer)
            if not isinstance(data, Mapping):
                raise ValueError(f"{FETCH_TOOL} answered no object")
            try:
                chunk = base64.b64decode(str(data.get("content_b64") or ""), validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError(f"{FETCH_TOOL} answered content that is not base64") from exc
            stated = data.get("size")
            if not (isinstance(stated, int) and not isinstance(stated, bool) and stated >= 0):
                raise ValueError(
                    f"{FETCH_TOOL} stated no size for the file, so its read has no end; refused"
                )
            if size < 0:
                size = stated
            elif stated != size:
                raise ValueError(f"{FETCH_TOOL} changed the file's size from {size} to {stated}")
            digest = str(data.get("sha256") or "")
            if digest and self.sha256 and digest != self.sha256:
                raise ValueError(f"{FETCH_TOOL} changed the file's stated sha256")
            self.sha256 = self.sha256 or digest
            if not chunk:
                if offset < size:
                    raise ValueError(f"{FETCH_TOOL} answered no bytes at offset {offset} of {size}")
                return
            if offset + len(chunk) > size:
                raise ValueError(f"{FETCH_TOOL} answered past the file's stated size of {size}")
            offset += len(chunk)
            yield chunk


def _same_directory(left: Path, right: Path) -> bool:
    return os.path.realpath(left) == os.path.realpath(right)


class ArtefactStore:
    """One job's artefact store (module docstring). Safe to use from the pack's threads."""

    def __init__(self, job_id: str, environ: Mapping[str, str] | None = None) -> None:
        self.job_id = str(job_id or "")
        self._environ = dict(environ) if environ is not None else None
        self._held: dict[str, Artefact] = {}
        self._delivered: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()

    @property
    def directory(self) -> Path:
        """Where the store keeps its files, created or not."""
        base = staging.staging_base(self._environ)
        return staging.job_staging_dir(base, self.job_id) / staging.ARTEFACTS_DIRECTORY

    def get(self, artefact_id: str) -> Artefact | None:
        """The artefact of ``artefact_id``, or ``None`` for one this store does not hold."""
        with self._lock:
            return self._held.get(str(artefact_id or ""))

    # -- taking a file in ---------------------------------------------------

    def take_in_bytes(self, blob: bytes, name: str, *, kind: str = "artefact") -> Artefact:
        """``blob`` as a file of the store, named ``name``, of ``kind`` (``Artefact.kind``)."""
        return self.take_in_chunks((blob,), name, kind=kind)

    def take_in_beneath(
        self, root: Path, name: str, where: str, *, kind: str = "artefact"
    ) -> Artefact:
        """The regular file ``name`` beneath ``root`` as a file of the store (``open_beneath``)."""
        fd = open_beneath(root, name, where)
        with os.fdopen(fd, "rb") as handle:
            chunks = iter(lambda: handle.read(FETCH_CHUNK_BYTES), b"")
            return self.take_in_chunks(chunks, name, kind=kind)

    def take_in_capture(self, name: str) -> Artefact:
        """The sandbox capture ``name`` as a file of the store, from the job's capture directory.

        The name is read out of the sandbox report, which a provider, a REST
        sandbox or an operator's upload wrote, so it is never trusted as a
        path: the file is opened beneath the directory the worker fetches this
        job's captures into (``tools.staging.job_capture_dir``), and a name
        anywhere else is refused, never read.
        """
        root = staging.job_capture_dir(self.job_id, self._environ)
        return self.take_in_beneath(root, name, "this job's capture directory", kind="capture")

    def take_in_chunks(
        self,
        chunks: Iterable[bytes],
        name: str,
        *,
        sha256: str | Callable[[], str] = "",
        kind: str = "artefact",
    ) -> Artefact:
        """The bytes of ``chunks`` as a file of the store, streamed once; ``sha256`` is checked.

        ``sha256`` is the digest stated for the bytes, or what states it once
        they are all read (a server answers it with its chunks). A file the
        store already holds is the artefact it is already, under its first
        name.
        """
        directory = staging.open_job_directory(
            self.job_id, staging.ARTEFACTS_DIRECTORY, self._environ
        )
        digest, size = hashlib.sha256(), 0
        # Created 0o600 and exclusively, under a name no file's own name can take.
        fd, incoming = tempfile.mkstemp(dir=directory, prefix=".incoming-")
        try:
            with os.fdopen(fd, "wb") as out:
                for chunk in chunks:
                    out.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
            found = digest.hexdigest()
            stated = sha256() if callable(sha256) else str(sha256 or "").strip().lower()
            if stated and stated != found:
                raise ValueError(f"its bytes hash to {found}, not to the {stated} stated for it")
            with self._lock:
                held = self._held.get(artefact_id(found))
                if held is not None:
                    return held
                home = staging.private_dir(directory / found, what="artefact directory")
                target = home / safe_name(name)
                os.replace(incoming, target)
                incoming = ""
                artefact = Artefact(artefact_id(found), found, size, target.name, target, kind)
                self._held[artefact.id] = artefact
            logger.info("artefact store: took in %s (%d bytes).", artefact.id, size)
            return artefact
        finally:
            if incoming:
                try:
                    os.unlink(incoming)
                except OSError:
                    pass

    def take_in_written(
        self,
        server_key: str,
        config: Any,
        names: Iterable[str],
        *,
        handle: Any = None,
        run_blocking: Callable[[Any], Any] | None = None,
    ) -> tuple[list[Artefact], list[dict[str, str]]]:
        """Each file ``server_key`` named as written, taken in; and each one not, with why.

        Over the server's ``get_artefact`` tool where ``handle`` (its open
        handle) offers it and ``run_blocking`` runs a coroutine; else, for a
        server on this host's filesystem, from inside its own job staging
        directory. Never raises.
        """
        taken: list[Artefact] = []
        missed: list[dict[str, str]] = []
        offered: set[str] = set()
        if handle is not None:
            try:
                offered = set(handle.all_tool_names())
            except Exception:  # noqa: BLE001 — a handle that cannot list offers nothing
                offered = set()
        local = shares_the_worker_filesystem(config)
        root = staging.job_staging_dir(staging.staging_base(server_environ(config)), self.job_id)
        for name in names:
            try:
                if FETCH_TOOL in offered and run_blocking is not None:
                    taken.append(self._fetch(handle, name, run_blocking))
                elif local:
                    taken.append(
                        self.take_in_beneath(
                            root, name, "that server's own staging directory for this job"
                        )
                    )
                else:
                    missed.append(
                        {
                            "name": safe_name(name),
                            "reason": f"{server_key} offers no {FETCH_TOOL} and does not share "
                            "this host's filesystem",
                        }
                    )
            except Exception as exc:  # noqa: BLE001 — a file not taken in is said, not raised
                missed.append({"name": safe_name(name), "reason": reason_for(exc)})
        return taken, missed

    def _fetch(self, handle: Any, name: str, run_blocking: Callable[[Any], Any]) -> Artefact:
        from maljan.agents.sample_staging import _call

        def call(offset: int) -> Any:
            return run_blocking(
                _call(handle, FETCH_TOOL, path=name, offset=offset, length=FETCH_CHUNK_BYTES)
            )

        fetched = _Fetched(call)
        return self.take_in_chunks(fetched, name, sha256=lambda: fetched.sha256)

    # -- handing a file over ------------------------------------------------

    def path_for(
        self,
        artefact: Artefact,
        server_key: str,
        config: Any,
        *,
        place: Callable[[str, Path, str, str], str | None] | None = None,
        handle: Any = None,
        run_blocking: Callable[[Any], Any] | None = None,
        stagings: list[dict[str, Any]] | None = None,
    ) -> tuple[str, str]:
        """The path ``server_key`` opens ``artefact`` at, and ``""``; or ``""`` and why it cannot.

        As the sample reaches that server (module docstring): a copy under its
        own job staging directory for a server on this host's filesystem, the
        worker's copy under its ``sample_mount`` (``place``), an upload over
        its ``put_sample`` tools for one across a network (``handle``,
        ``run_blocking``, the upload written to ``stagings``). Each server is
        handed a file once. Never raises.
        """
        key = (str(server_key), artefact.id)
        with self._lock:
            done = self._delivered.get(key)
        if done:
            return done, ""
        try:
            path, why = self._deliver(
                artefact,
                server_key,
                config,
                place=place,
                handle=handle,
                run_blocking=run_blocking,
                stagings=stagings,
            )
        except Exception as exc:  # noqa: BLE001 — a file not handed over is said, not raised
            path, why = "", reason_for(exc)
        if path:
            with self._lock:
                self._delivered[key] = path
        return path, why

    def _deliver(
        self,
        artefact: Artefact,
        server_key: str,
        config: Any,
        *,
        place: Callable[[str, Path, str, str], str | None] | None,
        handle: Any,
        run_blocking: Callable[[Any], Any] | None,
        stagings: list[dict[str, Any]] | None,
    ) -> tuple[str, str]:
        from maljan.agents.sample_staging import REMOTE_TRANSPORTS, put_file, supports_staging

        transport = str(getattr(config, "transport", "stdio") or "stdio").lower()
        if str(getattr(config, "sample_mount", "") or ""):
            if place is None:
                return "", f"this run places no file under {server_key}'s sample_mount"
            placed = place(server_key, artefact.path, artefact.sha256, artefact.name)
            return (placed, "") if placed else ("", f"it could not be placed for {server_key}")
        if transport in REMOTE_TRANSPORTS:
            offered = set(handle.all_tool_names()) if handle is not None else set()
            if not supports_staging(offered) or run_blocking is None:
                return "", (
                    f"{server_key} is reached over {transport}, offers no put_sample and "
                    "declares no sample_mount"
                )
            path = run_blocking(
                put_file(
                    handle,
                    server_key,
                    artefact.name,
                    artefact.path,
                    artefact.sha256,
                    stagings=stagings,
                    what=artefact.kind,
                )
            )
            return str(path), ""
        return str(self._local_copy(artefact, config)), ""

    def _local_copy(self, artefact: Artefact, config: Any) -> Path:
        """``artefact`` under the job staging directory of a server on this host's filesystem.

        The store's own file where the server's staging base is this
        process's; a private copy under the server's own base otherwise, its
        job directory recorded for the job's teardown.
        """
        environ = server_environ(config)
        job_dir = staging.job_staging_dir(staging.staging_base(environ), self.job_id)
        home = job_dir / staging.ARTEFACTS_DIRECTORY / artefact.sha256
        if _same_directory(home, artefact.path.parent):
            return artefact.path
        for directory in (job_dir.parent, job_dir, home.parent, home):
            staging.private_dir(directory, what="artefact directory")
        staging.note_job_directory(self.job_id, job_dir)
        target = home / artefact.name
        if not target.is_file():
            fd, incoming = tempfile.mkstemp(dir=home, prefix=".incoming-")
            try:
                with os.fdopen(fd, "wb") as out, artefact.path.open("rb") as source:
                    shutil.copyfileobj(source, out, FETCH_CHUNK_BYTES)
                os.replace(incoming, target)
                incoming = ""
            finally:
                if incoming:
                    try:
                        os.unlink(incoming)
                    except OSError:
                        pass
        return target


# Why a file a step's answer named as written was not taken in, where the run
# keeps no store (a pack run handed none).
NO_STORE = "this run keeps no artefact store"


def _blocking(label: str, budget: float | None) -> Callable[[Any], Any]:
    """Run a coroutine on the shared agent loop, where the server handles' transports live.

    Each call waits at most ``budget`` seconds: the step's declared budget, as
    the step's own call does (``nodes._server_step_call``); ``None`` where the
    step declares none and the pack has no budget left to give.
    """
    from maljan.agents.base_agent import run_coro_blocking

    wait = float(budget) if budget else None
    return lambda coroutine: run_coro_blocking(coroutine, wait, label=label)


def _open_handle(container: Any, server_key: str) -> Any:
    """The job's open handle of ``server_key``, or ``None``."""
    try:
        handle = container.get_server_registry().get(server_key)
    except Exception:  # noqa: BLE001 — a server the registry does not hold has no handle
        return None
    return handle if getattr(handle, "is_open", False) else None


def hand_over(
    store: ArtefactStore | None,
    container: Any,
    server_key: str,
    config: Any,
    values: dict[str, str],
    budget: float | None = None,
) -> str:
    """Put in ``values`` the path ``server_key`` opens each named file at; ``""``, or why not.

    ``values`` holds, under each file placeholder a step names
    (``core.pack_steps.FILE_PLACEHOLDERS``), the artefact's id; each becomes
    the path the server opens the file at (:meth:`ArtefactStore.path_for`),
    each call of an upload waiting at most ``budget`` seconds. Every path
    handed over is noted on the container (``artefact_paths``), so the run's
    isolation part counts a call handed one as a read of what came out of
    the sample. The first file that cannot reach the server is why the step
    is not run.
    """
    from maljan.core.pack_steps import FILE_PLACEHOLDERS

    named = [name for name in FILE_PLACEHOLDERS if values.get(name)]
    if not named:
        return ""
    if store is None:
        return NO_STORE
    place = getattr(container, "place_for_server", None)
    stagings = getattr(container, "sample_stagings", None)
    for name in named:
        artefact = store.get(values[name])
        if artefact is None:
            return f"{values[name]} is no file of this job's artefact store"
        path, why = store.path_for(
            artefact,
            server_key,
            config,
            place=place if callable(place) else None,
            handle=_open_handle(container, server_key),
            run_blocking=_blocking(f"artefact:{server_key}", budget),
            stagings=stagings if isinstance(stagings, list) else None,
        )
        if not path:
            return f"{artefact.id} could not reach {server_key}: {why}"
        values[name] = path
        handed = getattr(container, "artefact_paths", None)
        if isinstance(handed, list) and path not in handed:
            handed.append(path)
    return ""


def take_in_outputs(
    store: ArtefactStore | None,
    container: Any,
    server_key: str,
    config: Any,
    outputs: str,
    output: Any,
    budget: float | None = None,
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, str], ...]]:
    """The files a step's answer names at ``outputs``, taken in: each as recorded, and each not.

    Each ``get_artefact`` call waits at most ``budget`` seconds (the step's
    declared budget). Nothing for a step that declares no ``outputs``. Never
    raises.
    """
    names = written_names(answer_data(output), outputs) if outputs else []
    if not names:
        return (), ()
    if store is None:
        return (), tuple({"name": safe_name(name), "reason": NO_STORE} for name in names)
    taken, missed = store.take_in_written(
        server_key,
        config,
        names,
        handle=_open_handle(container, server_key),
        run_blocking=_blocking(f"artefact:{server_key}", budget),
    )
    return tuple(artefact.record() for artefact in taken), tuple(missed)


def reason_for(exc: BaseException) -> str:
    """What a published reason says of a failure: a server's or the store's words, else its kind.

    A refusal a server answered, and a store check (a link, a name outside the
    staging directory, a digest that does not match), say their own words;
    anything else is named by its kind and remedy, never by a message that can
    name a host path.
    """
    from maljan.agents.sample_staging import StagingRefused, reason_of
    from maljan.pipeline.events import describe_exception

    if isinstance(exc, StagingRefused):
        return reason_of(exc)
    if type(exc) is ValueError:
        return str(exc)
    return describe_exception(exc)
