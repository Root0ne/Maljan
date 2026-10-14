"""What the console asks about the cached ATT&CK bundles, and the one way they are replaced.

Three questions and one action, each answered from the cache directory
``attck_loader`` reads (``ATTCK_CACHE_DIR``), on the process that owns it:

* ``status`` — per domain, the cached release, its date, the cache's age and
  when the next automatic check is due; and the last check and update.
* ``check`` — read MITRE's release index and compare it with the cache. It
  downloads no bundle and leaves the cache files as they are; the only thing
  written is the record of the check itself, so the console can show it.
* ``update`` — download each outdated domain's release, read it back whole
  (it parses, it is the release the index named, it carries techniques), and
  only then move it over the cached file in one rename, after keeping the
  previous file beside it as ``<name>.bak``.
* ``scheduled_update`` — the same update, run when the cache is older than
  ``validation.attck_refresh_days``; 0 never runs it.

One writer at a time: every write of a bundle — this module's update and the
loader's own refresh — takes the cache directory's lock first, and an update
that finds it held says so instead of waiting or writing alongside. A reader
needs no lock: a bundle is only ever replaced by a rename, so a reader holds
the old file or the new one, never half of either.

The release index and the bundles are fetched from the loader's constant base
URL; nothing here takes an address from a caller.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator, Mapping
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

DOMAIN_LABELS: dict[str, str] = {"enterprise": "Enterprise", "mobile": "Mobile", "ics": "ICS"}

# A release number as MITRE writes them (``19.2``, ``20.0``). The only part of
# a download address that comes from the index, so it is held to digits.
_VERSION_RE = re.compile(r"\A\d{1,4}(?:\.\d{1,4}){0,3}\Z")

LOCK_NAME = ".update.lock"
STATE_LOCK_NAME = ".state.lock"
STATE_NAME = "update-state.json"

_THREAD_LOCKS: dict[str, threading.Lock] = {}


class ReleaseIndexError(RuntimeError):
    """The release index was read but says nothing this module can use."""


class BundleRejected(RuntimeError):
    """A downloaded bundle failed its check and was not moved into the cache."""


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
    return bundle.with_name(f"{bundle.stem}.meta.json")


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


@contextmanager
def _locked(path: Path, *, blocking: bool) -> Iterator[bool]:
    """An exclusive lock on ``path``, shared by every process on this host.

    Yields whether it was taken. ``flock`` locks an open file description, so
    two threads of one process that each open the file exclude each other as
    two processes do.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if fcntl is None:  # pragma: no cover - see the import
        lock = _THREAD_LOCKS.setdefault(str(path), threading.Lock())
        taken = lock.acquire(blocking)
        try:
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
            yield True
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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


def validate_bundle_file(path: Path, expected_version: str) -> dict[str, Any]:
    """Read a downloaded bundle back whole and say what it is, or refuse it.

    It has to parse, be a STIX bundle, be the release the index named and
    carry at least one technique.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BundleRejected(f"the download does not parse as JSON ({exc})") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("objects"), list):
        raise BundleRejected("the download is not a STIX bundle (no object list)")
    facts = bundle_facts(raw)
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


def cached_facts(domain: str) -> dict[str, Any]:
    """What the cache holds for one domain, without a network.

    The release and its date are read once out of the bundle and kept beside
    it; a bundle replaced since (a new file, so a new inode) is read again.
    """
    bundle = cache_file(domain)
    try:
        stat = bundle.stat()
    except FileNotFoundError:
        return {"present": False}
    meta = _read_json(meta_file(bundle))
    if not (
        isinstance(meta, dict)
        and meta.get("inode") == stat.st_ino
        and meta.get("size") == stat.st_size
    ):
        try:
            raw = attck_loader._read_cache(bundle)
        except (OSError, ValueError) as exc:
            return {
                "present": True,
                "readable": False,
                "reason": f"the cached file does not parse ({exc})",
                "cached_at": _iso_ts(stat.st_mtime),
            }
        facts = bundle_facts(raw)
        written_by = meta.get("written_by") if isinstance(meta, dict) else None
        _write_meta(bundle, facts, str(written_by or "unknown"))
        meta = {**facts, "written_by": written_by or "unknown"}
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
    raw = attck_loader._fetch_bundle(ATTCK_INDEX_URL, timeout=INDEX_TIMEOUT_SECONDS)
    return latest_releases(raw)


def compare(cached: Mapping[str, Any], latest: Mapping[str, str] | None) -> str:
    """``current``, ``outdated``, ``missing`` (nothing cached) or ``unlisted`` (not upstream)."""
    if latest is None:
        return "unlisted"
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
    if refresh_days is None or refresh_days <= 0:
        return None
    if not cached.get("present"):
        return None
    stamp = datetime.fromisoformat(str(cached["cached_at"])).timestamp()
    return _iso_ts(stamp + refresh_days * 86400)


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
    state = read_state()
    due = [d["next_check_at"] for d in domains if d.get("next_check_at")]
    return {
        "refresh_days": refresh_days,
        "next_check_at": min(due) if due else None,
        "domains": domains,
        "last_check": state.get("last_check"),
        "last_update": state.get("last_update"),
        "running": state.get("running"),
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
    due = [
        stamp
        for stamp in (_next_check(c, refresh_days) for c in cached.values())
        if refresh_days is not None and stamp
    ]
    schedule = {
        "refresh_days": refresh_days,
        "next_check_at": min(due) if due else None,
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
        result = {
            "ok": True,
            "outcome": "outdated" if outdated else "up_to_date",
            "reason": "",
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


def _who(triggered_by: Mapping[str, Any] | None) -> str:
    if not triggered_by:
        return "unknown"
    return str(triggered_by.get("user_id") or triggered_by.get("name") or "unknown")


def update(
    triggered_by: Mapping[str, Any] | None = None, *, trigger: str = "console"
) -> dict[str, Any]:
    """Bring every outdated domain to MITRE's latest release, all or none.

    Every outdated domain is downloaded and checked before any cached file is
    touched; one that fails leaves the whole cache as it was, and says which
    domain and why. An update that finds another one running says so and
    writes nothing.
    """
    directory = cache_dir()
    started_at = _iso(_now())
    who = dict(triggered_by or {})
    with _locked(directory / LOCK_NAME, blocking=False) as held:
        if not held:
            running = read_state().get("running") or {}
            since = running.get("started_at")
            reason = "another ATT&CK update is running" + (f" (started {since})" if since else "")
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
            result = _update_held(directory, started_at, trigger, who)
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
                    "kept_previous": True,
                }
            _record(running=None, last_update=result)
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
            logger.warning(
                "ATT&CK update by %s failed: %s; the previous cache is kept.",
                _who(who),
                result.get("reason"),
            )
        return result


def _update_held(
    directory: Path, started_at: str, trigger: str, who: dict[str, Any]
) -> dict[str, Any]:
    def finished(
        ok: bool, outcome: str, reason: str, changes: list[dict[str, Any]]
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
            "kept_previous": not ok,
        }

    try:
        latest = fetch_latest_releases()
    except (RuntimeError, ReleaseIndexError) as exc:
        return finished(False, "failed", f"the ATT&CK release index could not be read: {exc}", [])

    _clear_leftovers(directory)
    cached = {domain: cached_facts(domain) for domain in attck_loader.DOMAINS}
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
            current = domain
            version = latest[domain]["version"]
            part = directory / f".{domain}-attack.json.{uuid.uuid4().hex}.part"
            attck_loader._download_bundle_file(
                release_url(domain, version), part, timeout=BUNDLE_TIMEOUT_SECONDS
            )
            staged[domain] = (part, validate_bundle_file(part, version))
            part = None
    except (RuntimeError, OSError, ValueError) as exc:
        for leftover in [p for p, _ in staged.values()] + ([part] if part else []):
            leftover.unlink(missing_ok=True)
        label = DOMAIN_LABELS.get(current, current)
        return finished(False, "failed", f"{label}: {exc}", [])

    changes: list[dict[str, Any]] = []
    for domain, (path, facts) in staged.items():
        target = cache_file(domain)
        try:
            if target.exists():
                _keep_backup(target)
            os.replace(path, target)
        except OSError as exc:
            for leftover, _ in staged.values():
                leftover.unlink(missing_ok=True)
            done = ", ".join(c["label"] for c in changes)
            return finished(
                False,
                "failed",
                f"{DOMAIN_LABELS[domain]}: the new file could not be moved into place ({exc})"
                + (f"; already replaced: {done}" if done else ""),
                changes,
            )
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
                try:
                    os.utime(cache_file(domain), (now, now))
                except OSError:
                    pass

    return finished(True, "updated" if changes else "up_to_date", "", changes)


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


def scheduled_update(refresh_days: int) -> dict[str, Any] | None:
    """Run the update when the interval says it is due; ``None`` when it is not."""
    if not scheduled_update_due(refresh_days):
        return None
    return update({"name": "automatic check"}, trigger="schedule")


# ── the loader's own refresh ─────────────────────────────────────────────


def save_refreshed_bundle(bundle: Mapping[str, Any], target: Path) -> bool:
    """Write a bundle the loader just downloaded, in one rename, under the lock.

    Returns whether it was written. While an update holds the lock it is not:
    that update is replacing the same files with a checked copy.
    """
    with _locked(target.parent / LOCK_NAME, blocking=False) as held:
        if not held:
            logger.info(
                "An ATT&CK update holds the cache; the refreshed %s is not written.", target.name
            )
            return False
        _write_atomically(target, json.dumps(bundle))
        logger.info("ATT&CK bundle cached at: %s", target)
        return True
