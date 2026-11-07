"""Resident-memory instrumentation, aimed at one specific unanswered question.

The arq worker grows from ~3.4 GB to ~8.5 GB during a single analysis and never
gives it back; a fresh worker is ~75 MB. The obvious suspects were ruled out by
elimination — ``summarize_pcap``'s 200 000-packet ``rdpcap`` and the
``network-mcp`` subprocess never ran on the measured jobs, because the sandbox
was unreachable and no capture was ever fetched — which leaves two hypotheses
that call for opposite fixes:

* **Retention.** Something keeps objects alive: the ``AsyncExitStack``\\ s parked
  on the process-wide agent loop, cached agents, tool evidence.
* **Fragmentation.** Nothing is retained, but glibc will not return the arenas.
  The worker is ``python:3.13-slim`` on a 32-core host with no cpu limit, so
  glibc permits ``8 x ncores`` arenas, and the process is genuinely
  multi-threaded (the arq loop, the agent loop, LangGraph's node threads, the
  ``to_thread`` executor).

Guessing between them wastes a day, so this module does not guess. Two numbers
decide it, and both are free:

``sys.getallocatedblocks()``
    RSS climbing while blocks stay flat is fragmentation, near-conclusively.
    RSS and blocks climbing together is retention — and then ``loop_tasks``
    says whether the leaked MCP transports are the ones doing it.

``malloc_trim()``
    RSS that falls when the allocator is asked to release is fragmentation,
    conclusively.

Everything here is cheap enough to leave on: one ``/proc`` read (one ``ps`` run
where there is no ``/proc``), two counters and a log line per pipeline node. The
expensive modes — a ``gc`` census, or ``tracemalloc`` snapshots — are opt-in
through ``MALSPARK_MEMPROBE`` and are never the default, because ``tracemalloc``
costs 2-4x runtime and hundreds of MB of its own.
"""

from __future__ import annotations

import asyncio
import ctypes
import functools
import gc
import os
import shutil
import subprocess
import sys
import threading
import time
import tracemalloc
from collections.abc import Callable
from typing import Any

from malspark.core.logger import logger

__all__ = [
    "instrument_node",
    "malloc_trim",
    "mode",
    "probe",
    "reset",
    "rss_mb",
]

# ── Modes ───────────────────────────────────────────────────────────
# "off"          — probe() is a no-op beyond returning the RSS reading
# "basic"        — the default: RSS, allocated blocks, gc counts, threads, tasks
# "objects"      — adds a gc.get_objects() type census (seconds; phases only)
# "tracemalloc"  — adds per-phase allocation diffs (2-4x slower)
_VALID_MODES = ("off", "basic", "objects", "tracemalloc")


def mode() -> str:
    """Read the probe mode fresh each call so tests can flip it."""
    value = (os.environ.get("MALSPARK_MEMPROBE") or "basic").strip().lower()
    return value if value in _VALID_MODES else "basic"


def _trim_enabled() -> bool:
    return (os.environ.get("MALSPARK_MALLOC_TRIM") or "").strip().lower() in ("1", "true", "yes")


# ── Readings ────────────────────────────────────────────────────────

_lock = threading.Lock()
_last: dict[str, float] = {}
_tracemalloc_prev: Any = None


# How long the ``ps`` reading of the resident set may take before it counts
# as no reading.
PS_TIMEOUT_SECONDS = 5.0
# How long one ``ps`` reading stands for the resident set. A probe runs per
# graph node, and two at a time around each; one ``ps`` a second at most is a
# cost a host without ``/proc`` can carry, and a figure a second old is as good
# to the recycle ceiling and the probes as a fresh one.
PS_READING_MAX_AGE_SECONDS = 1.0
# Where ``ps`` is looked for: the system's own, never one the job's PATH names.
PS_SEARCH_PATH = "/bin:/usr/bin"
# The last ``ps`` reading and when it was taken (``None`` for a window whose
# ``ps`` timed out); ``failed`` once ``ps`` was missing or gave no number,
# after which it is not started again.
_ps_lock = threading.Lock()
_ps_reading: dict[str, Any] = {"at": None, "mb": None, "failed": False}


def rss_mb() -> float | None:
    """Resident set size in MiB, or ``None`` where no reading could be taken.

    Deliberately reads ``VmRSS`` from ``/proc/self/status`` rather than taking a
    psutil dependency: it is the same number ``ps -eo rss`` prints, so readings
    here are directly comparable to the ones measured from a shell. Where there
    is no ``/proc`` the same number is asked of ``ps -o rss= -p <pid>`` (KiB on
    every Unix that has it): the current resident set, never the peak
    ``getrusage`` keeps. ``None`` is no reading, never zero megabytes.
    """
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return round(int(line.split()[1]) / 1024, 1)
    except (OSError, ValueError, IndexError):
        pass
    return _rss_mb_from_ps()


def _rss_mb_from_ps() -> float | None:
    """This process's resident set as ``ps`` reports it, in MiB, or ``None``.

    One reading stands for ``PS_READING_MAX_AGE_SECONDS``; callers in that
    second share it rather than each starting ``ps``. Once ``ps`` is missing or
    answers no number, it is not started again and the answer stays ``None``;
    a ``ps`` that timed out is no reading for that window only.
    """
    with _ps_lock:
        if _ps_reading["failed"]:
            return None
        now = time.monotonic()
        taken = _ps_reading["at"]
        if taken is not None and now - taken < PS_READING_MAX_AGE_SECONDS:
            kept: float | None = _ps_reading["mb"]
            return kept
        ps = shutil.which("ps", path=PS_SEARCH_PATH)
        try:
            if ps is None:
                raise FileNotFoundError("ps")
            shown = subprocess.run(  # noqa: S603 — fixed argv, no shell
                [ps, "-o", "rss=", "-p", str(os.getpid())],
                capture_output=True,
                text=True,
                timeout=PS_TIMEOUT_SECONDS,
                check=False,
            ).stdout.strip()
            mb = round(int(shown) / 1024, 1)
        except (FileNotFoundError, ValueError):
            # No ps, or one that answers no number: that does not change.
            _ps_reading.update(at=None, mb=None, failed=True)
            return None
        except (OSError, subprocess.SubprocessError):
            # A ps that hung or could not start this time: no reading for this
            # window, and the next window asks again.
            _ps_reading.update(at=now, mb=None)
            return None
        _ps_reading.update(at=now, mb=mb)
        return mb


_libc: Any = None
_libc_looked_up = False


def malloc_trim() -> float:
    """Ask glibc to return free heap to the OS; report the MiB reclaimed.

    A no-op returning 0.0 on musl, macOS or anywhere ``malloc_trim`` is absent.
    A large positive number here is the fragmentation verdict.
    """
    global _libc, _libc_looked_up
    if not _libc_looked_up:
        _libc_looked_up = True
        try:
            candidate = ctypes.CDLL("libc.so.6")
            _libc = candidate if hasattr(candidate, "malloc_trim") else None
        except (OSError, AttributeError):
            _libc = None
    if _libc is None:
        return 0.0

    before = rss_mb()
    try:
        _libc.malloc_trim(0)
    except (OSError, AttributeError):
        return 0.0
    after = rss_mb()
    if before is None or after is None:
        return 0.0
    return round(before - after, 1)


def _agent_loop_tasks() -> tuple[int, list[str]]:
    """Count — and name — the tasks parked on the shared agent loop.

    A monotonically rising count is the signature of the leaked MCP transports:
    every ``AsyncExitStack`` that is never closed leaves its anyio task group
    running on that loop for the life of the process.

    The names matter as much as the number. A bare "loop_tasks=3" is a question,
    not an answer; the coroutine names say straight away whether those three are
    transports nobody closed or something ordinary and expected.

    ``asyncio.all_tasks`` is not thread-safe and this is usually called from a
    different thread than the loop, so a concurrent mutation can raise — hence
    the blanket catch. Instrumentation that can break a run is worse than none.
    """
    try:
        from malspark.agents.base_agent import _AGENT_LOOP

        loop = _AGENT_LOOP
        if loop is None or loop.is_closed():
            return 0, []
        tasks = list(asyncio.all_tasks(loop))
        names: list[str] = []
        for task in tasks[:8]:
            coro = task.get_coro()
            names.append(getattr(coro, "__qualname__", None) or task.get_name())
        return len(tasks), names
    except Exception:  # noqa: BLE001 — instrumentation must never break a run
        return 0, []


def reset() -> None:
    """Forget the deltas. Called at job start so each job reads from zero."""
    global _tracemalloc_prev
    with _lock:
        _last.clear()
        _tracemalloc_prev = None


def probe(label: str, **extra: Any) -> dict[str, Any]:
    """Log one memory reading and return it.

    Never raises: a probe that can break an analysis is worse than no probe.
    """
    try:
        return _probe(label, **extra)
    except Exception as exc:  # noqa: BLE001 — see above
        logger.debug("memprobe(%s) failed: %s", label, exc)
        return {"rss_mb": None}


def _probe(label: str, **extra: Any) -> dict[str, Any]:
    current_mode = mode()
    rss = rss_mb()
    if current_mode == "off":
        return {"rss_mb": rss}

    blocks = sys.getallocatedblocks()
    loop_task_count, loop_task_names = _agent_loop_tasks()
    with _lock:
        d_rss = round(rss - _last.get("rss", rss), 1) if rss is not None else None
        d_blocks = blocks - int(_last.get("blocks", blocks))
        if rss is not None:
            _last["rss"] = rss
        _last["blocks"] = blocks

    reading: dict[str, Any] = {
        "rss_mb": rss,
        "d_rss_mb": d_rss,
        "blocks": blocks,
        "d_blocks": d_blocks,
        "gc": gc.get_count(),
        "threads": threading.active_count(),
        "loop_tasks": loop_task_count,
        **extra,
    }
    # Only when the set changes, so a steady state costs one line, not one per
    # probe — and a growing set is impossible to miss.
    if loop_task_names and loop_task_count != _last.get("loop_tasks"):
        reading["loop_task_names"] = loop_task_names
    _last["loop_tasks"] = loop_task_count

    if _trim_enabled():
        reading["trimmed_mb"] = malloc_trim()

    if current_mode in ("objects", "tracemalloc"):
        reading.update(_object_census())
    if current_mode == "tracemalloc":
        reading["top_alloc"] = _tracemalloc_delta()

    rss_text = (
        f"rss={rss:.1f}MB ({d_rss:+.1f})"
        if rss is not None and d_rss is not None
        else "rss=not read"
    )
    logger.info(
        "memprobe %s: %s blocks=%d (%+d) threads=%d loop_tasks=%d%s",
        label,
        rss_text,
        reading["blocks"],
        reading["d_blocks"],
        reading["threads"],
        reading["loop_tasks"],
        f" trimmed={reading['trimmed_mb']}MB" if "trimmed_mb" in reading else "",
        extra={"memprobe": reading, "label": label},
    )
    if "loop_task_names" in reading:
        logger.info("memprobe %s agent-loop tasks: %s", label, reading["loop_task_names"])
    if "top_alloc" in reading:
        for line in reading["top_alloc"]:
            logger.info("memprobe %s alloc: %s", label, line)
    return reading


def _object_census(top: int = 10) -> dict[str, Any]:
    from collections import Counter

    objects = gc.get_objects()
    counts = Counter(type(o).__name__ for o in objects)
    return {"objects": len(objects), "top_types": counts.most_common(top)}


def _tracemalloc_delta(top: int = 15) -> list[str]:
    global _tracemalloc_prev
    if not tracemalloc.is_tracing():
        tracemalloc.start(25)
        _tracemalloc_prev = tracemalloc.take_snapshot()
        return []
    snapshot = tracemalloc.take_snapshot()
    lines: list[str] = []
    if _tracemalloc_prev is not None:
        for stat in snapshot.compare_to(_tracemalloc_prev, "lineno")[:top]:
            lines.append(str(stat))
    _tracemalloc_prev = snapshot
    return lines


# ── Node instrumentation ────────────────────────────────────────────


def instrument_node(name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a graph node so it reports memory on the way in and out.

    Node boundaries are the right granularity: the worker's ``phase_change``
    events lump everything from the first analyst to the judge into a single
    ``analyzing`` phase, which is far too coarse to localise anything.

    Handles sync and async nodes alike — LangGraph accepts both, and the
    analysts are sync while the stage nodes are coroutines.
    """
    if asyncio.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            probe(f"node:{name}:enter")
            try:
                return await fn(*args, **kwargs)
            finally:
                probe(f"node:{name}:exit")

        return async_wrapper

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        probe(f"node:{name}:enter")
        try:
            return fn(*args, **kwargs)
        finally:
            probe(f"node:{name}:exit")

    return sync_wrapper
