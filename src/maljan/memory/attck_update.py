"""What the console asks about the cached ATT&CK bundles, and the one way they are replaced.

Three questions and one action, each answered from the cache directory
``attck_loader`` reads (``ATTCK_CACHE_DIR``), on the process that owns it:

* ``status`` — per domain, the cached release, its date, the cache's age and
  when the next automatic check is due; and the last check and update. An
  update record whose process is gone (the lock is free) is reported as an
  update that did not finish, never as one still running.
* ``check`` — read MITRE's release index and compare it with the cache. It
  downloads no bundle and leaves the cache files as they are; the only thing
  written is the record of the check itself, so the console can show it.
* ``update`` — download each outdated domain's release, read it back whole
  (it parses, it is the release the index named, it carries techniques), and
  only then move it over the cached file in one rename, after keeping the
  previous file beside it as ``<name>.bak``. A swap that fails part way puts
  the domains already replaced back from those backups.
* ``scheduled_update`` — the same update, run when the cache is older than
  ``validation.attck_refresh_days``; 0 never runs it. After a failure it
  waits before trying again, twice as long after each failure in a row, never
  longer than the interval.

One writer at a time: every write of a bundle — this module's update and the
loader's own refresh — takes the cache directory's lock first, and an update
that finds it held says who holds it instead of waiting or writing alongside.
A reader needs no lock: a bundle is only ever replaced by a rename, so a
reader holds the old file or the new one, never half of either.

A whole bundle is parsed in a short-lived child process, one at a time per
process (``_PARSE_LOCK``): the half gigabyte a parse costs leaves with the
child instead of staying in the analysis worker, and the worker's event loop
is not held by a parse that keeps the interpreter lock for seconds.

The release index and the bundles are fetched from the loader's constant base
URL; nothing here takes an address from a caller.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.memory import attck_loader

try:  # POSIX; the lock falls back to one per process elsewhere
    import fcntl
except ImportError:  # pragma: no cover - not reached on the platforms the worker runs on
    fcntl = None  # type: ignore[assignment]

# MITRE's own list of every release of every domain, with dates. A few tens of
# kilobytes, on the same host as the bundles.
ATTCK_INDEX_URL = f"{attck_loader._BUNDLE_BASE_URL}/index.json"
INDEX_TIMEOUT_SECONDS = 20.0
BUNDLE_TIMEOUT_SECONDS = 300.0

# How often the worker's cron asks whether the automatic check is due
# (``app.worker.attck_worker``: every hour). The first wait after a failed
# automatic check is one period; each failure in a row doubles it, up to the
# interval itself.
SCHEDULE_PERIOD_SECONDS = 3600.0

DOMAIN_LABELS: dict[str, str] = {"enterprise": "Enterprise", "mobile": "Mobile", "ics": "ICS"}

# A release number as MITRE writes them (``19.2``, ``20.0``). The only part of
# a download address that comes from the index, so it is held to digits.
_VERSION_RE = re.compile(r"\A\d{1,4}(?:\.\d{1,4}){0,3}\Z")

LOCK_NAME = ".update.lock"
HOLDER_NAME = ".update.holder.json"
STATE_LOCK_NAME = ".state.lock"
STATE_NAME = "update-state.json"

_THREAD_LOCKS: dict[str, threading.Lock] = {}

# One whole-bundle parse at a time in this process (see the module docstring).
_PARSE_LOCK = threading.Lock()


class ReleaseIndexError(RuntimeError):
    """The release index was read but says nothing this module can use."""


class BundleRejected(RuntimeError):
    """A downloaded bundle failed its check and was not moved into the cache."""


class UpdateStopped(RuntimeError):
    """The update was told to stop, or ran past its deadline, before the swap."""


# ── small helpers ────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


def _iso_ts(timestamp: float) -> str:
    return _iso(datetime.fromtimestamp(timestamp, UTC))


def cache_dir() -> Path:
    """The directory the loader reads, looked up when asked (tests redirect it)."""
    return Path(attck_loader.ATTCK_CACHE_DIR)


def cache_file(domain: str) -> Path:
    return Path(attck_loader.ATTCK_CACHE_FILES[domain])


def meta_file(bundle: Path) -> Path:
    """Where the facts read out of a cached bundle are kept, beside it."""
    return attck_loader.meta_path(bundle)


def backup_file(bundle: Path) -> Path:
    return bundle.with_name(f"{bundle.name}.bak")


def version_key(version: str) -> tuple[int, ...] | None:
    """``"19.2"`` as ``(19, 2)``; ``None`` for anything that is not a release number."""
    text = str(version or "").strip()
    if not _VERSION_RE.match(text):
        return None
    return tuple(int(part) for part in text.split("."))


def release_url(domain: str, version: str) -> str:
    """The address of one domain's release, built from the platform's constant."""
    if domain not in attck_loader.DOMAINS:
        raise ValueError(f"Unknown ATT&CK domain {domain!r}")
    if version_key(version) is None:
        raise ValueError(f"Not an ATT&CK release number: {version!r}")
    base = attck_loader._BUNDLE_BASE_URL
    return f"{base}/{domain}-attack/{domain}-attack-{version}.json"


def _write_atomically(target: Path, text: str) -> None:
    """Write ``text`` beside ``target`` and rename it over ``target``."""
    target.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115 - closed below, before the rename
        "w",
        encoding="utf-8",
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".part",
        delete=False,
    )
    part = Path(handle.name)
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(part, target)
    except BaseException:
        part.unlink(missing_ok=True)
        raise


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


@contextmanager
def _locked(
    path: Path, *, blocking: bool, holder: Mapping[str, Any] | None = None
) -> Iterator[bool]:
    """An exclusive lock on ``path``, shared by every process on this host.

    Yields whether it was taken. ``flock`` locks an open file description, so
    two threads of one process that each open the file exclude each other as
    two processes do. ``holder``, when given, is written beside the lock once
    it is taken, so a caller that finds the lock held can say who holds it.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if fcntl is None:  # pragma: no cover - see the import
        lock = _THREAD_LOCKS.setdefault(str(path), threading.Lock())
        taken = lock.acquire(blocking)
        try:
            if taken and holder is not None:
                _note_holder(path, holder)
            yield taken
        finally:
            if taken:
                lock.release()
        return
    with path.open("a+") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            yield False
            return
        try:
            if holder is not None:
                _note_holder(path, holder)
            yield True
        finally:
            if holder is not None:
                with suppress(OSError):
                    path.with_name(HOLDER_NAME).unlink()
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _note_holder(lock: Path, holder: Mapping[str, Any]) -> None:
    with suppress(OSError):
        _write_atomically(
            lock.with_name(HOLDER_NAME), json.dumps({**holder, "since": _iso(_now())})
        )


def _holder_of(directory: Path) -> dict[str, Any]:
    raw = _read_json(directory / HOLDER_NAME)
    return raw if isinstance(raw, dict) else {}


ANSWER_PREFIX = ".attck-parse."


def _settled_age() -> float:
    """How old a file written without a cross-process lock must be to be dead.

    The facts files and a child's answer file are written right after a parse,
    and a parse is killed past its own limit (:func:`parse_timeout`), so one
    older than the longest limit any cached bundle gives is no write in
    progress, in this process or another sharing the volume.
    """
    limits = [parse_timeout(cache_file(domain)) for domain in attck_loader.DOMAINS]
    return max(limits) if limits else PARSE_START_SECONDS


def clear_leftovers_at_start() -> list[Path]:
    """Remove every temporary file a killed process left in the cache directory.

    The bundles' and the holder's are written under the update lock and the
    state's under the state lock, so both locks are held while they are
    removed: another worker sharing the volume cannot be writing one. The
    facts files and the child parses' answer files are written under neither,
    so only those older than :func:`_settled_age` go. Nothing is removed while
    another process holds the update lock.
    """
    directory = cache_dir()
    removed: list[Path] = []
    if not directory.is_dir():
        return removed

    def remove(leftover: Path) -> None:
        with suppress(OSError):
            leftover.unlink()
            removed.append(leftover)

    with _locked(directory / LOCK_NAME, blocking=False) as held:
        if not held:
            return removed
        with _locked(directory / STATE_LOCK_NAME, blocking=True):
            locked_names = [STATE_NAME, HOLDER_NAME]
            unlocked_names = []
            for domain in attck_loader.DOMAINS:
                bundle = cache_file(domain)
                locked_names.append(bundle.name)
                unlocked_names.append(meta_file(bundle).name)
            for name in locked_names:
                for pattern in (f".{name}.*.part", f".{name}.*.bak"):
                    for leftover in directory.glob(pattern):
                        remove(leftover)
            settled_before = time.time() - _settled_age()
            unlocked = [
                leftover
                for name in unlocked_names
                for leftover in directory.glob(f".{name}.*.part")
            ] + list(directory.glob(f"{ANSWER_PREFIX}*.json"))
            for leftover in unlocked:
                with suppress(OSError):
                    if leftover.stat().st_mtime < settled_before:
                        remove(leftover)
    if removed:
        logger.info("Removed %d leftover temporary file(s) from the ATT&CK cache.", len(removed))
    return removed


def _who(triggered_by: Mapping[str, Any] | None) -> str:
    if not triggered_by:
        return "unknown"
    return str(triggered_by.get("user_id") or triggered_by.get("name") or "unknown")


def _busy_reason(directory: Path) -> str:
    """Why the cache lock is held, in the holder's own words."""
    holder = _holder_of(directory)
    since = holder.get("since")
    when = f" (since {since})" if since else ""
    kind = holder.get("holder")
    if kind == "update":
        by = (holder.get("triggered_by") or {}).get("name") or _who(holder.get("triggered_by"))
        return f"another ATT&CK update is running{when}, started by {by}"
    if kind == "loader refresh":
        return f"the cache is being written by the loader's own refresh{when}; try again shortly"
    if kind == "status read":
        return f"the cache's status is being read{when}; try again shortly"
    return "the cache is being written; try again shortly"


# ── the record of checks and updates ─────────────────────────────────────


def read_state() -> dict[str, Any]:
    raw = _read_json(cache_dir() / STATE_NAME)
    return raw if isinstance(raw, dict) else {}


def _record(**changes: Any) -> None:
    """Merge ``changes`` into the state file; a key set to ``None`` is removed."""
    directory = cache_dir()
    try:
        with _locked(directory / STATE_LOCK_NAME, blocking=True):
            state = read_state()
            for key, value in changes.items():
                if value is None:
                    state.pop(key, None)
                else:
                    state[key] = value
            _write_atomically(directory / STATE_NAME, json.dumps(state, indent=1, sort_keys=True))
    except OSError as exc:
        logger.warning("Could not record the ATT&CK check or update: %s", exc)


# ── what a bundle is ─────────────────────────────────────────────────────


def bundle_facts(raw: Mapping[str, Any]) -> dict[str, Any]:
    """The release a bundle is, its date, and how many techniques it carries."""
    version = ""
    released = ""
    for obj in raw.get("objects") or []:
        if isinstance(obj, dict) and obj.get("type") == "x-mitre-collection":
            version = str(obj.get("x_mitre_version") or "")
            released = str(obj.get("modified") or "")
            break
    return {
        "version": version,
        "released": released,
        "techniques": len(attck_loader._parse_bundle(dict(raw))),
    }


def read_facts(path: str) -> dict[str, Any]:
    """Parse one bundle file and say what it is: ``{"facts"}`` or ``{"kind", "error"}``.

    What the child process runs (``_child_main``); callable in process too.
    """
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        return {"kind": "unreadable", "error": f"the file cannot be read ({exc})"}
    except ValueError as exc:
        return {"kind": "json", "error": f"does not parse as JSON ({exc})"}
    if not isinstance(raw, dict) or not isinstance(raw.get("objects"), list):
        return {"kind": "shape", "error": "is not a STIX bundle (no object list)"}
    return {"facts": bundle_facts(raw)}


def _child_main() -> None:
    """``python -P -c '…_child_main()' <bundle> <answer file>``: write one bundle's facts.

    The answer goes to a file of its own, never stdout, so nothing a module
    prints on import can be mistaken for it.
    """
    import logging

    logging.disable(logging.CRITICAL)
    Path(sys.argv[2]).write_text(json.dumps(read_facts(sys.argv[1])), encoding="utf-8")


# How long a child parse may take: a start-up allowance plus a rate far below
# what ``json.loads`` does on this kind of file (tens of megabytes a second),
# so a slow disk is never cut short and a hung one is.
PARSE_START_SECONDS = 30.0
PARSE_SECONDS_PER_MB = 2.0

# What the child is handed of the environment: enough to find the interpreter's
# packages, nothing of the worker's credentials.
_CHILD_ENV_NAMES = ("PATH", "PYTHONPATH", "HOME")


def parse_timeout(path: Path) -> float:
    """The seconds a child parse of ``path`` may take, from its size."""
    try:
        size_mb = path.stat().st_size / 1_000_000
    except OSError:
        size_mb = 0.0
    return PARSE_START_SECONDS + PARSE_SECONDS_PER_MB * size_mb


def _not_known(error: str) -> dict[str, Any]:
    return {"kind": "child", "error": error}


def _parse_in_child(path: Path) -> dict[str, Any]:
    """``read_facts`` in a short-lived child process, so its memory leaves with it.

    The child gets a timeout derived from the file's size and is killed when it
    runs past it, a minimal environment, ``-P`` (the working directory is not
    on its path) and an answer file of its own. A child that dies, runs out of
    time or cannot be started answers ``kind: "child"``: what the file holds
    is then not known, which is not the same as the file being unreadable.
    """
    timeout = parse_timeout(path)
    logger.debug("ATT&CK parse of %s in a child, at most %.0f s.", path.name, timeout)
    # In the cache directory, so a child a killed worker left behind leaves its
    # answer where the start-up sweep finds it.
    cache_dir().mkdir(parents=True, exist_ok=True)
    handle, answer_name = tempfile.mkstemp(prefix=ANSWER_PREFIX, suffix=".json", dir=cache_dir())
    os.close(handle)
    answer_file = Path(answer_name)
    command = [
        sys.executable,
        "-P",
        "-c",
        "from maljan.memory.attck_update import _child_main; _child_main()",
        str(path),
        str(answer_file),
    ]
    env = {name: os.environ[name] for name in _CHILD_ENV_NAMES if name in os.environ}
    try:
        try:
            child = subprocess.Popen(  # noqa: S603 - our own interpreter and module, our paths
                command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
            )
        except OSError as exc:
            logger.warning("ATT&CK parse of %s could not be started: %s", path.name, exc)
            return _not_known(f"the parse could not be started ({exc})")
        try:
            _, stderr = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate()
            logger.warning(
                "ATT&CK parse of %s passed its %.0f s limit and was stopped.", path.name, timeout
            )
            return _not_known(f"the parse did not finish within {timeout:.0f} s and was stopped")
        if child.returncode < 0:
            return _not_known(f"the parse did not finish (signal {-child.returncode})")
        try:
            answer = json.loads(answer_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            tail = (stderr or "").strip().splitlines()[-1:] or [f"exit status {child.returncode}"]
            return _not_known(f"the parse did not finish ({tail[0]})")
        return answer if isinstance(answer, dict) else _not_known("the parse gave no answer")
    finally:
        answer_file.unlink(missing_ok=True)


# The parse runner. A test may hand ``read_facts`` in its place to stay in
# process; the shipped one is always the child.
_run_parse: Callable[[Path], dict[str, Any]] = _parse_in_child


def _facts_of_file(path: Path) -> dict[str, Any]:
    """One whole-bundle parse, never two at once in this process."""
    with _PARSE_LOCK:
        return _run_parse(path)


def validate_bundle_file(path: Path, expected_version: str) -> dict[str, Any]:
    """Read a downloaded bundle back whole and say what it is, or refuse it.

    It has to parse, be a STIX bundle, be the release the index named and
    carry at least one technique.
    """
    answer = _facts_of_file(path)
    if answer.get("kind") == "child":
        raise BundleRejected(f"the download could not be checked: {answer.get('error')}")
    if "facts" not in answer:
        raise BundleRejected(f"the download {answer.get('error') or 'cannot be read'}")
    facts: dict[str, Any] = answer["facts"]
    if facts["version"] != expected_version:
        raise BundleRejected(
            f"the download is release {facts['version'] or 'with no version'}, "
            f"not {expected_version}"
        )
    if facts["techniques"] <= 0:
        raise BundleRejected("the download carries no techniques")
    return facts


def _write_meta(bundle: Path, facts: Mapping[str, Any], written_by: str) -> None:
    try:
        stat = bundle.stat()
        meta = {
            **facts,
            "inode": stat.st_ino,
            "size": stat.st_size,
            "written_by": written_by,
            "written_at": _iso(_now()),
        }
        _write_atomically(meta_file(bundle), json.dumps(meta, sort_keys=True))
    except OSError as exc:
        logger.warning("Could not write the facts of %s: %s", bundle.name, exc)


def _kept_meta(bundle: Path) -> tuple[os.stat_result, dict[str, Any] | None]:
    """The bundle's stat and its kept facts, when they still describe this file."""
    stat = bundle.stat()
    meta = _read_json(meta_file(bundle))
    fresh = (
        isinstance(meta, dict)
        and meta.get("inode") == stat.st_ino
        and meta.get("size") == stat.st_size
    )
    return stat, (meta if fresh else None)


def cached_facts(domain: str) -> dict[str, Any]:
    """What the cache holds for one domain, without a network.

    The release and its date are read once out of the bundle and kept beside
    it; a bundle replaced since (a new file, so a new inode) is read again,
    once: a caller that waited for another's parse finds the facts it kept.
    """
    bundle = cache_file(domain)
    try:
        stat, meta = _kept_meta(bundle)
    except FileNotFoundError:
        return {"present": False}
    if meta is None:
        with _PARSE_LOCK:
            try:
                stat, meta = _kept_meta(bundle)
            except FileNotFoundError:
                return {"present": False}
            if meta is None:
                answer = _run_parse(bundle)
                if answer.get("kind") == "child":
                    # Not known right now, which is not unreadable: nothing is
                    # written, and the next read tries again.
                    return {
                        "present": True,
                        "readable": None,
                        "reason": (
                            "the release the cache holds is not known right now: "
                            f"{answer.get('error')}"
                        ),
                        "cached_at": _iso_ts(stat.st_mtime),
                        "age_days": round(max(0.0, (time.time() - stat.st_mtime) / 86400.0), 2),
                    }
                if "facts" not in answer:
                    return {
                        "present": True,
                        "readable": False,
                        "reason": f"the cached file {answer.get('error') or 'cannot be read'}",
                        "cached_at": _iso_ts(stat.st_mtime),
                    }
                old = _read_json(meta_file(bundle))
                written_by = str((old or {}).get("written_by") or "unknown")
                _write_meta(bundle, answer["facts"], written_by)
                meta = {**answer["facts"], "written_by": written_by}
    age_days = max(0.0, (time.time() - stat.st_mtime) / 86400.0)
    return {
        "present": True,
        "readable": True,
        "version": str(meta.get("version") or ""),
        "released": str(meta.get("released") or ""),
        "techniques": int(meta.get("techniques") or 0),
        "cached_at": _iso_ts(stat.st_mtime),
        "age_days": round(age_days, 2),
        "written_by": str(meta.get("written_by") or "unknown"),
    }


def cache_signature() -> tuple[tuple[str, int, int] | None, ...]:
    """Which files the cache holds right now: a replaced bundle changes it."""
    out: list[tuple[str, int, int] | None] = []
    for domain in attck_loader.DOMAINS:
        try:
            stat = cache_file(domain).stat()
        except OSError:
            out.append(None)
            continue
        out.append((domain, stat.st_ino, stat.st_size))
    return tuple(out)


# ── the release index ────────────────────────────────────────────────────


def _domain_of_collection(collection: Mapping[str, Any]) -> str | None:
    words = str(collection.get("name") or "").lower().split()
    if words and words[0] in attck_loader.DOMAINS:
        return words[0]
    for row in collection.get("versions") or []:
        url = str(row.get("url") or "") if isinstance(row, dict) else ""
        for domain in attck_loader.DOMAINS:
            if f"/{domain}-attack/" in url:
                return domain
    return None


def latest_releases(index: Any) -> dict[str, dict[str, str]]:
    """``{domain: {"version", "released"}}`` for the newest release the index lists."""
    collections = index.get("collections") if isinstance(index, dict) else None
    if not isinstance(collections, list):
        raise ReleaseIndexError("the release index has no collection list")
    latest: dict[str, dict[str, str]] = {}
    for collection in collections:
        if not isinstance(collection, dict):
            continue
        domain = _domain_of_collection(collection)
        if domain is None or domain in latest:
            continue
        best: tuple[tuple[int, ...], str, str] | None = None
        for row in collection.get("versions") or []:
            if not isinstance(row, dict):
                continue
            version = str(row.get("version") or "").strip()
            key = version_key(version)
            if key is not None and (best is None or key > best[0]):
                best = (key, version, str(row.get("modified") or ""))
        if best is not None:
            latest[domain] = {"version": best[1], "released": best[2]}
    if not latest:
        raise ReleaseIndexError("the release index lists none of the ATT&CK domains")
    return latest


def fetch_latest_releases() -> dict[str, dict[str, str]]:
    raw = attck_loader._fetch_bundle(
        ATTCK_INDEX_URL,
        timeout=INDEX_TIMEOUT_SECONDS,
        deadline=time.monotonic() + INDEX_TIMEOUT_SECONDS,
    )
    return latest_releases(raw)


def compare(cached: Mapping[str, Any], latest: Mapping[str, str] | None) -> str:
    """``current``, ``outdated``, ``missing`` (nothing cached) or ``unlisted`` (not upstream)."""
    if latest is None:
        return "unlisted"
    if cached.get("present") and cached.get("readable", True) is None:
        return "unknown"
    if not cached.get("present") or not cached.get("readable", True):
        return "missing"
    have = version_key(str(cached.get("version") or ""))
    want = version_key(str(latest.get("version") or ""))
    if have is None or want is None:
        return "outdated"
    return "current" if have >= want else "outdated"


_NEEDS_UPDATE = ("outdated", "missing")


# ── status and check ─────────────────────────────────────────────────────


def _next_check(cached: Mapping[str, Any], refresh_days: int | None) -> str | None:
    """When the interval makes this domain due; ``None`` off, uncached or past any date."""
    if refresh_days is None or refresh_days <= 0:
        return None
    if not cached.get("present"):
        return None
    try:
        stamp = datetime.fromisoformat(str(cached["cached_at"])).timestamp()
        return _iso_ts(stamp + refresh_days * 86400)
    except (KeyError, OverflowError, OSError, ValueError):
        return None


def _schedule_line(domains: Sequence[Mapping[str, Any]], refresh_days: int | None) -> str | None:
    """The overall next automatic check: the earliest due domain, or the back-off's end."""
    if refresh_days is None or refresh_days <= 0:
        return None
    due = [str(d["next_check_at"]) for d in domains if d.get("next_check_at")]
    earliest = min(due) if due else None
    retry_after = (read_state().get("schedule_failures") or {}).get("retry_after")
    if retry_after and (earliest is None or str(retry_after) > earliest):
        return str(retry_after)
    return earliest


def _running_now() -> dict[str, Any] | None:
    """The running update's record, only while its lock is really held.

    A record whose lock is free belongs to a process that stopped mid-update
    (killed, recycled, restarted): it is turned, once, into the last update's
    record, saying it did not finish, when it started and who started it.
    """
    directory = cache_dir()
    running = read_state().get("running")
    if not running:
        return None
    with _locked(directory / LOCK_NAME, blocking=False, holder={"holder": "status read"}) as held:
        if not held:
            return dict(running)
        stale = read_state().get("running")
        if stale:
            by = (stale.get("triggered_by") or {}).get("name") or _who(stale.get("triggered_by"))
            _record(
                running=None,
                last_update={
                    "ok": False,
                    "outcome": "interrupted",
                    "reason": (
                        f"the update started {stale.get('started_at') or 'at an unknown time'} "
                        f"by {by} did not finish: the process running it stopped"
                    ),
                    "started_at": stale.get("started_at"),
                    "finished_at": None,
                    "trigger": stale.get("trigger"),
                    "triggered_by": stale.get("triggered_by") or {},
                    "changes": [],
                    "kept_previous": None,
                },
            )
            logger.warning("ATT&CK update record without a running update: marked as interrupted.")
    return None


def status(refresh_days: int) -> dict[str, Any]:
    """Everything the console shows about the cache, read from disk."""
    domains: list[dict[str, Any]] = []
    for domain in attck_loader.DOMAINS:
        cached = cached_facts(domain)
        domains.append(
            {
                "domain": domain,
                "label": DOMAIN_LABELS[domain],
                **cached,
                "next_check_at": _next_check(cached, refresh_days),
            }
        )
    running = _running_now()
    state = read_state()
    return {
        "refresh_days": refresh_days,
        "next_check_at": _schedule_line(domains, refresh_days),
        "domains": domains,
        "last_check": state.get("last_check"),
        "last_update": state.get("last_update"),
        "running": running,
    }


def check(
    triggered_by: Mapping[str, Any] | None = None, refresh_days: int | None = None
) -> dict[str, Any]:
    """Compare the cache with MITRE's release index. Downloads no bundle.

    A failure to read the index is an outcome of its own, ``failed``, with the
    reason: it is never reported as up to date. ``refresh_days``, when given,
    puts the next automatic check on the answer, for the console's choice to
    wait for it.
    """
    checked_at = _iso(_now())
    cached = {domain: cached_facts(domain) for domain in attck_loader.DOMAINS}
    rows_for_schedule = [{"next_check_at": _next_check(c, refresh_days)} for c in cached.values()]
    schedule = {
        "refresh_days": refresh_days,
        "next_check_at": _schedule_line(rows_for_schedule, refresh_days),
    }
    try:
        latest = fetch_latest_releases()
    except (RuntimeError, ReleaseIndexError) as exc:
        result: dict[str, Any] = {
            "ok": False,
            "outcome": "failed",
            "reason": f"the ATT&CK release index could not be read: {exc}",
            "checked_at": checked_at,
            "triggered_by": dict(triggered_by or {}),
            "domains": [
                {"domain": d, "label": DOMAIN_LABELS[d], "cached": cached[d], "latest": None}
                for d in attck_loader.DOMAINS
            ],
            **schedule,
        }
        logger.warning("ATT&CK check failed: %s", result["reason"])
    else:
        rows = []
        for domain in attck_loader.DOMAINS:
            rows.append(
                {
                    "domain": domain,
                    "label": DOMAIN_LABELS[domain],
                    "cached": cached[domain],
                    "latest": latest.get(domain),
                    "state": compare(cached[domain], latest.get(domain)),
                }
            )
        outdated = any(row["state"] in _NEEDS_UPDATE for row in rows)
        unknown = [row for row in rows if row["state"] == "unknown"]
        result = {
            "ok": not unknown or outdated,
            "outcome": "outdated" if outdated else ("failed" if unknown else "up_to_date"),
            "reason": "; ".join(
                f"{row['label']}: {cached[str(row['domain'])].get('reason')}" for row in unknown
            ),
            "checked_at": checked_at,
            "triggered_by": dict(triggered_by or {}),
            "domains": rows,
            **schedule,
        }
        logger.info("ATT&CK check: %s.", result["outcome"])
    _record(last_check=result)
    return result


# ── update ───────────────────────────────────────────────────────────────


def _keep_backup(bundle: Path) -> None:
    """Keep the file about to be replaced as ``<name>.bak``.

    A hard link when the filesystem allows one: the cached file is about to be
    renamed over, never written into, so the link keeps the old contents.
    """
    backup = backup_file(bundle)
    staging = bundle.with_name(f".{bundle.name}.{uuid.uuid4().hex}.bak")
    try:
        os.link(bundle, staging)
    except OSError:
        shutil.copy2(bundle, staging)
    os.replace(staging, backup)


def _restore_backup(bundle: Path, had_previous: bool) -> None:
    """Put the file a swap replaced back, from its ``.bak`` (the backup is kept)."""
    if not had_previous:
        bundle.unlink(missing_ok=True)
        return
    staging = bundle.with_name(f".{bundle.name}.{uuid.uuid4().hex}.part")
    try:
        os.link(backup_file(bundle), staging)
    except OSError:
        shutil.copy2(backup_file(bundle), staging)
    os.replace(staging, bundle)


def _clear_leftovers(directory: Path) -> None:
    """Remove the partial files of an update a stopped process left behind.

    Called with the update lock held, so no update in progress owns one. Only
    a bundle's own partial files: the state and facts files are written
    without that lock, and theirs are not touched.
    """
    for domain in attck_loader.DOMAINS:
        name = cache_file(domain).name
        for pattern in (f".{name}.*.part", f".{name}.*.bak"):
            for leftover in directory.glob(pattern):
                with suppress(OSError):
                    leftover.unlink()


def update(
    triggered_by: Mapping[str, Any] | None = None,
    *,
    trigger: str = "console",
    deadline: float | None = None,
    stop: threading.Event | None = None,
) -> dict[str, Any]:
    """Bring every outdated domain to MITRE's latest release, all or none.

    Every outdated domain is downloaded and checked before any cached file is
    touched; one that fails leaves the whole cache as it was, and says which
    domain and why. An update that finds the cache lock held says who holds it
    and writes nothing. ``deadline`` (a ``time.monotonic`` instant) bounds the
    downloads as a whole, and ``stop`` is set by a caller that gave up on the
    update: either way it ends before the swap, with nothing replaced.
    """
    directory = cache_dir()
    started_at = _iso(_now())
    who = dict(triggered_by or {})
    holder = {"holder": "update", "trigger": trigger, "triggered_by": who}
    with _locked(directory / LOCK_NAME, blocking=False, holder=holder) as held:
        if not held:
            reason = _busy_reason(directory)
            logger.info("ATT&CK update by %s not started: %s.", _who(who), reason)
            return {
                "ok": False,
                "outcome": "busy",
                "reason": reason,
                "started_at": started_at,
                "finished_at": _iso(_now()),
                "trigger": trigger,
                "triggered_by": who,
                "changes": [],
                "kept_previous": True,
            }
        logger.info("ATT&CK update started by %s (%s).", _who(who), trigger)
        _record(running={"started_at": started_at, "trigger": trigger, "triggered_by": who})
        result: dict[str, Any] = {}
        try:
            result = _update_held(directory, started_at, trigger, who, deadline, stop)
        finally:
            if not result:
                result = {
                    "ok": False,
                    "outcome": "failed",
                    "reason": "the update stopped before it finished",
                    "started_at": started_at,
                    "finished_at": _iso(_now()),
                    "trigger": trigger,
                    "triggered_by": who,
                    "changes": [],
                    "kept_previous": None,
                }
            changes: dict[str, Any] = {"running": None, "last_update": result}
            if result.get("ok"):
                changes["schedule_failures"] = None
            _record(**changes)
        if result.get("ok"):
            logger.info(
                "ATT&CK update by %s finished: %s.",
                _who(who),
                ", ".join(
                    f"{c['label']} {c['from'] or 'none'} -> {c['to']}" for c in result["changes"]
                )
                or "already current",
            )
        else:
            logger.warning("ATT&CK update by %s failed: %s", _who(who), result.get("reason"))
        return result


def _update_held(
    directory: Path,
    started_at: str,
    trigger: str,
    who: dict[str, Any],
    deadline: float | None,
    stop: threading.Event | None,
) -> dict[str, Any]:
    def finished(
        ok: bool,
        outcome: str,
        reason: str,
        changes: list[dict[str, Any]],
        kept_previous: bool | None = None,
    ) -> dict[str, Any]:
        return {
            "ok": ok,
            "outcome": outcome,
            "reason": reason,
            "started_at": started_at,
            "finished_at": _iso(_now()),
            "trigger": trigger,
            "triggered_by": who,
            "changes": changes,
            "kept_previous": (not changes) if kept_previous is None else kept_previous,
        }

    def go_on() -> None:
        if stop is not None and stop.is_set():
            raise UpdateStopped("the update was stopped before anything was replaced")
        if deadline is not None and time.monotonic() > deadline:
            raise UpdateStopped("the update ran past its time limit before anything was replaced")

    try:
        latest = fetch_latest_releases()
    except (RuntimeError, ReleaseIndexError) as exc:
        return finished(False, "failed", f"the ATT&CK release index could not be read: {exc}", [])

    _clear_leftovers(directory)
    try:
        cached = {domain: cached_facts(domain) for domain in attck_loader.DOMAINS}
    except OSError as exc:
        return finished(False, "failed", f"the cache could not be read: {exc}", [])
    unknown = [d for d in attck_loader.DOMAINS if compare(cached[d], latest.get(d)) == "unknown"]
    if unknown:
        return finished(
            False,
            "failed",
            "; ".join(f"{DOMAIN_LABELS[d]}: {cached[d].get('reason')}" for d in unknown)
            + "; nothing was downloaded",
            [],
        )
    plan = [
        domain
        for domain in attck_loader.DOMAINS
        if compare(cached[domain], latest.get(domain)) in _NEEDS_UPDATE
    ]

    staged: dict[str, tuple[Path, dict[str, Any]]] = {}
    current = ""
    part: Path | None = None
    try:
        for domain in plan:
            go_on()
            current = domain
            version = latest[domain]["version"]
            part = directory / f".{domain}-attack.json.{uuid.uuid4().hex}.part"
            attck_loader._download_bundle_file(
                release_url(domain, version),
                part,
                timeout=BUNDLE_TIMEOUT_SECONDS,
                deadline=deadline,
            )
            staged[domain] = (part, validate_bundle_file(part, version))
            part = None
        go_on()
    except UpdateStopped as exc:
        for leftover in [p for p, _ in staged.values()] + ([part] if part else []):
            leftover.unlink(missing_ok=True)
        return finished(False, "stopped", str(exc), [])
    except (RuntimeError, OSError, ValueError) as exc:
        for leftover in [p for p, _ in staged.values()] + ([part] if part else []):
            leftover.unlink(missing_ok=True)
        label = DOMAIN_LABELS.get(current, current)
        return finished(False, "failed", f"{label}: {exc}", [])

    changes: list[dict[str, Any]] = []
    swapped: list[tuple[str, bool]] = []
    for domain, (path, facts) in staged.items():
        target = cache_file(domain)
        had_previous = target.exists()
        try:
            if had_previous:
                _keep_backup(target)
            os.replace(path, target)
        except OSError as exc:
            return _undo_swap(finished, staged, swapped, changes, domain, exc)
        swapped.append((domain, had_previous))
        _write_meta(target, facts, trigger)
        changes.append(
            {
                "domain": domain,
                "label": DOMAIN_LABELS[domain],
                "from": str(cached[domain].get("version") or ""),
                "to": facts["version"],
                "released": facts["released"],
                "techniques": facts["techniques"],
            }
        )

    # The domains that were already current were checked just now, so their
    # age counts from here: the automatic check is about how long ago the
    # cache was last compared with MITRE, not when the file was written.
    now = time.time()
    for domain in attck_loader.DOMAINS:
        if domain not in staged and cached[domain].get("present"):
            if compare(cached[domain], latest.get(domain)) == "current":
                with suppress(OSError):
                    os.utime(cache_file(domain), (now, now))

    return finished(True, "updated" if changes else "up_to_date", "", changes)


def _undo_swap(
    finished: Callable[..., dict[str, Any]],
    staged: Mapping[str, tuple[Path, dict[str, Any]]],
    swapped: list[tuple[str, bool]],
    changes: list[dict[str, Any]],
    failed: str,
    exc: OSError,
) -> dict[str, Any]:
    """A swap that failed part way: put back what it replaced, and say exactly what holds."""
    for leftover, _ in staged.values():
        leftover.unlink(missing_ok=True)
    restored: list[str] = []
    still_new: list[dict[str, Any]] = []
    for domain, had_previous in swapped:
        try:
            _restore_backup(cache_file(domain), had_previous)
            restored.append(DOMAIN_LABELS[domain])
        except OSError as restore_exc:
            logger.warning(
                "ATT&CK %s could not be restored from its backup: %s", domain, restore_exc
            )
            still_new.extend(c for c in changes if c["domain"] == domain)
    reason = f"{DOMAIN_LABELS[failed]}: the new file could not be moved into place ({exc})"
    if still_new:
        unchanged = [
            DOMAIN_LABELS[d]
            for d in attck_loader.DOMAINS
            if d not in {c["domain"] for c in still_new}
        ]
        reason += (
            f"; replaced and not restored: {', '.join(c['label'] for c in still_new)}"
            f"; unchanged: {', '.join(unchanged)}"
        )
        return finished(False, "failed", reason, still_new, kept_previous=False)
    if restored:
        reason += f"; nothing is replaced: {', '.join(restored)} restored from the backup"
    return finished(False, "failed", reason, [], kept_previous=True)


# ── the automatic check ──────────────────────────────────────────────────


def scheduled_update_due(refresh_days: int) -> bool:
    """Whether the cache is older than the interval (or has no Enterprise bundle)."""
    if refresh_days <= 0:
        return False
    limit = refresh_days * 86400
    now = time.time()
    for domain in attck_loader.DOMAINS:
        try:
            age = now - cache_file(domain).stat().st_mtime
        except FileNotFoundError:
            if domain == "enterprise":
                return True
            continue
        if age >= limit:
            return True
    return False


def backoff_seconds(failures: int, refresh_days: int) -> float:
    """How long to wait after ``failures`` failed automatic checks in a row.

    One cron period after the first, doubling with each one after it, never
    longer than the interval: an unreachable MITRE costs one attempt per
    interval at worst, and a host that comes back online is checked soon.
    """
    interval = refresh_days * 86400.0
    exponent = min(max(failures - 1, 0), 64)
    return min(interval, SCHEDULE_PERIOD_SECONDS * (2.0**exponent))


def scheduled_update(refresh_days: int) -> dict[str, Any] | None:
    """Run the update when the interval says it is due; ``None`` when it is not."""
    if not scheduled_update_due(refresh_days):
        return None
    failures = read_state().get("schedule_failures") or {}
    retry_after = failures.get("retry_after")
    if retry_after and _iso(_now()) < str(retry_after):
        return {
            "ok": True,
            "outcome": "backing_off",
            "reason": f"waiting after {failures.get('count')} failed automatic check(s)",
            "retry_after": retry_after,
        }
    result = update({"name": "automatic check"}, trigger="schedule")
    if result.get("outcome") in ("failed", "stopped"):
        count = int(failures.get("count") or 0) + 1
        wait = backoff_seconds(count, refresh_days)
        retry_at = _iso_ts(time.time() + wait)
        _record(schedule_failures={"count": count, "retry_after": retry_at})
        logger.warning(
            "ATT&CK automatic check failed (%d in a row): %s. Next attempt not before %s "
            "(back-off %.1f h, doubling per failure up to the %d-day interval).",
            count,
            result.get("reason"),
            retry_at,
            wait / 3600.0,
            refresh_days,
        )
    return result


# ── the loader's own refresh ─────────────────────────────────────────────


def _technique_objects(bundle: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Every attack-pattern object of a bundle, revoked and deprecated ones included."""
    return [
        obj
        for obj in bundle.get("objects") or []
        if isinstance(obj, Mapping) and obj.get("type") == "attack-pattern"
    ]


def _domains(objects: list[Mapping[str, Any]]) -> set[str]:
    """The ATT&CK domains a bundle's techniques name (``x_mitre_domains``)."""
    found: set[str] = set()
    for obj in objects:
        named = obj.get("x_mitre_domains")
        if isinstance(named, list):
            found.update(str(d) for d in named if d)
    return found


def refresh_refusal(bundle: Any, cached: Any = None) -> str | None:
    """Why a bundle the loader downloaded may not replace the cache, or ``None``.

    The checks the console's update makes of its download
    (``validate_bundle_file``), made on the bundle already in memory: it is a
    STIX bundle, and it carries at least one technique. There is no index
    naming the release the loader expects, so the release is not compared.
    Against the ``cached`` bundle it would replace: it names the same ATT&CK
    domain, and it carries no fewer technique objects, revoked and deprecated
    ones counted (a release retires techniques by marking them, never by
    leaving them out).
    """
    if not isinstance(bundle, Mapping) or not isinstance(bundle.get("objects"), list):
        return "is not a STIX bundle (no object list)"
    try:
        techniques = int(bundle_facts(bundle)["techniques"])
    except Exception as exc:  # noqa: BLE001 — a bundle that cannot be read is refused
        return f"cannot be read ({type(exc).__name__})"
    if techniques <= 0:
        return "carries no techniques"
    if not isinstance(cached, Mapping) or not isinstance(cached.get("objects"), list):
        return None
    fresh, kept = _technique_objects(bundle), _technique_objects(cached)
    fresh_domains, kept_domains = _domains(fresh), _domains(kept)
    if kept_domains and fresh_domains != kept_domains:
        return (
            f"names the domain {', '.join(sorted(fresh_domains)) or 'none'}, not the cached "
            f"{', '.join(sorted(kept_domains))}"
        )
    if len(fresh) < len(kept):
        return f"carries {len(fresh)} technique objects, fewer than the cached {len(kept)}"
    return None


def save_refreshed_bundle(bundle: Mapping[str, Any], target: Path) -> bool:
    """Write a bundle the loader just downloaded, in one rename, under the lock.

    Returns whether it was written. While an update holds the lock it is not:
    that update is replacing the same files with a checked copy. A bundle
    ``refresh_refusal`` refuses is never written. The facts the console shows
    are written beside it from the bundle already in memory, so no later
    status read has to parse the file again.
    """
    refused = refresh_refusal(bundle)
    if refused is not None:
        logger.warning("The refreshed %s is not written: the download %s.", target.name, refused)
        return False
    with _locked(
        target.parent / LOCK_NAME, blocking=False, holder={"holder": "loader refresh"}
    ) as held:
        if not held:
            logger.info(
                "The ATT&CK cache is busy (%s); the refreshed %s is not written.",
                _busy_reason(target.parent),
                target.name,
            )
            return False
        _write_atomically(target, json.dumps(bundle))
        _write_meta(target, bundle_facts(bundle), "loader refresh")
        logger.info("ATT&CK bundle cached at: %s", target)
        return True
