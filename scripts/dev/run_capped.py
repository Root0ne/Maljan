#!/usr/bin/env python3
"""Run a heavy local command inside a capped, transient systemd user scope.

A benchmark or observation run against the local model, a replay over many
stored runs or a large test suite can take the host's memory with it; when the
memory runs out the whole desktop session goes, not only the run. This wrapper
starts the command as

    systemd-run --user --scope --unit=<name> -p MemoryMax=<cap> -p MemorySwapMax=0
                -p TasksMax=<n> -p CPUQuota=<q> -- <command>

so the kernel holds it to a hard memory cap with no swap, a task ceiling and a
CPU quota, and a watcher stops the scope when the host's ``MemAvailable``
falls below a floor (the cap holds the run; the floor holds the host against
everything else that runs beside it, such as the local model server). When
the command ends, the scope's memory events (``high``, ``max``, ``oom``,
``oom_kill``) are printed, and a stop by the watcher is said.

Usage (from the repository root):

    python scripts/dev/run_capped.py -- python scripts/replay/run.py --compare A B
    python scripts/dev/run_capped.py --memory 8G --floor 4G -- pytest tests/unit -q
    python scripts/dev/run_capped.py --dry-run -- true

When ``systemd-run --user`` cannot cap the command (no ``systemd-run``, no user
manager, or a controller the caps need is not delegated to it) the wrapper
fails with exit code 2 and says why. It never runs the command uncapped unless
``--allow-uncapped`` is given, and then says so on standard error.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path

DEFAULT_MEMORY = "12G"
DEFAULT_FLOOR = "3G"
DEFAULT_TASKS = 4096
DEFAULT_INTERVAL = 2.0
CGROUP_ROOT = Path("/sys/fs/cgroup")
MEMINFO = Path("/proc/meminfo")
# The controllers the caps need: MemoryMax/MemorySwapMax, TasksMax, CPUQuota.
# A user manager without one of them accepts the property and enforces nothing.
NEEDED_CONTROLLERS = ("memory", "pids", "cpu")
MEMORY_EVENTS = ("low", "high", "max", "oom", "oom_kill")

_SIZE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([KMGT]?)i?B?\s*$", re.IGNORECASE)
_UNITS = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}


class CapError(RuntimeError):
    """The command cannot be run capped; the message names why."""


def parse_size(text: str) -> int:
    """Bytes in ``text``: a plain number of bytes or one with a K/M/G/T suffix (base 1024)."""
    match = _SIZE.match(text)
    if not match:
        raise ValueError(
            f"not a size: {text!r} (use a number of bytes or one ending in K, M, G or T)"
        )
    value = float(match.group(1)) * _UNITS[match.group(2).upper()]
    if value <= 0:
        raise ValueError(f"a size must be above zero: {text!r}")
    return int(value)


def default_cpu_quota() -> str:
    """Three quarters of the host's CPUs, as systemd's CPUQuota (100% is one CPU)."""
    return f"{max(100, (os.cpu_count() or 1) * 75)}%"


def default_unit() -> str:
    return f"maljan-capped-{os.getpid()}-{int(time.time())}"


def build_command(
    unit: str, memory: int, tasks: int, cpu_quota: str, command: Sequence[str]
) -> list[str]:
    """The ``systemd-run`` line that runs ``command`` in the capped scope ``unit``."""
    return [
        "systemd-run",
        "--user",
        "--scope",
        "--quiet",
        f"--unit={unit}",
        "-p",
        f"MemoryMax={memory}",
        "-p",
        "MemorySwapMax=0",
        "-p",
        f"TasksMax={tasks}",
        "-p",
        f"CPUQuota={cpu_quota}",
        "--",
        *command,
    ]


def _user_show(*args: str) -> str:
    done = subprocess.run(
        ["systemctl", "--user", "show", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if done.returncode != 0:
        raise CapError(
            "the systemd user manager does not answer (systemctl --user show: "
            f"{done.stderr.strip() or f'exit {done.returncode}'})"
        )
    return done.stdout.strip()


def check_capable(cgroup_root: Path = CGROUP_ROOT) -> None:
    """Raise ``CapError`` unless ``systemd-run --user`` can enforce every cap."""
    if shutil.which("systemd-run") is None:
        raise CapError("systemd-run is not installed")
    manager_group = _user_show("-p", "ControlGroup", "--value")
    if not manager_group:
        raise CapError("the systemd user manager names no control group (is cgroup v2 mounted?)")
    controllers_file = cgroup_root / manager_group.lstrip("/") / "cgroup.controllers"
    try:
        delegated = set(controllers_file.read_text(encoding="utf-8").split())
    except OSError as exc:
        raise CapError(
            f"cannot read the user manager's controllers ({controllers_file}: {exc})"
        ) from exc
    missing = [name for name in NEEDED_CONTROLLERS if name not in delegated]
    if missing:
        raise CapError(
            "the user manager is not delegated the "
            + ", ".join(missing)
            + " controller(s); a cap on them would be accepted and not enforced"
        )


def mem_available(meminfo: Path = MEMINFO) -> int:
    """The host's ``MemAvailable`` in bytes."""
    for line in meminfo.read_text(encoding="utf-8").splitlines():
        if line.startswith("MemAvailable:"):
            return parse_size(line.split(":", 1)[1].replace("kB", "K"))
    raise ValueError(f"{meminfo} has no MemAvailable line")


def read_memory_events(unit: str, cgroup_root: Path = CGROUP_ROOT) -> dict[str, int] | None:
    """The scope's ``memory.events`` counters, or None while it has no control group."""
    try:
        group = _user_show("-p", "ControlGroup", "--value", f"{unit}.scope")
    except (CapError, OSError, subprocess.SubprocessError):
        return None
    if not group:
        return None
    try:
        text = (cgroup_root / group.lstrip("/") / "memory.events").read_text(encoding="utf-8")
    except OSError:
        return None
    events = {}
    for line in text.splitlines():
        name, _, count = line.partition(" ")
        if name in MEMORY_EVENTS and count.isdigit():
            events[name] = int(count)
    return events


class Watcher(threading.Thread):
    """Stops the scope when host MemAvailable falls below ``floor``; keeps its memory events."""

    def __init__(
        self,
        unit: str,
        floor: int,
        interval: float = DEFAULT_INTERVAL,
        available: Callable[[], int] = mem_available,
    ) -> None:
        super().__init__(daemon=True, name=f"watch-{unit}")
        self.unit = unit
        self.floor = floor
        self.interval = interval
        self.available = available
        self.done = threading.Event()
        self.stopped_at: int | None = None
        self.events: dict[str, int] | None = None

    def check_once(self) -> bool:
        """One poll; True when it stopped the scope.

        Below the floor before the scope has started, the stop finds no unit
        and fails; the watcher then keeps polling and stops it once it is there.
        """
        snapshot = read_memory_events(self.unit)
        if snapshot is not None:
            self.events = snapshot
        free = self.available()
        if free >= self.floor:
            return False
        stop = subprocess.run(
            ["systemctl", "--user", "stop", f"{self.unit}.scope"],
            capture_output=True,
            check=False,
            timeout=30,
        )
        if stop.returncode != 0:
            return False
        self.stopped_at = free
        print(
            f"run_capped: host MemAvailable {free // 1024**2} MiB is below the floor "
            f"{self.floor // 1024**2} MiB; stopped {self.unit}.scope",
            file=sys.stderr,
            flush=True,
        )
        return True

    def run(self) -> None:
        while not self.check_once() and not self.done.wait(self.interval):
            pass


def scope_result(unit: str) -> str:
    """Why systemd says the scope ended (``oom-kill``, ``signal`` …), or "" when it holds none.

    A scope that ended well is unloaded; one that failed stays loaded with its
    result until ``reset-failed``, which this then runs, so the name is free again.
    """
    try:
        result = _user_show("-p", "Result", "--value", f"{unit}.scope")
    except (CapError, OSError, subprocess.SubprocessError):
        return ""
    if result in ("", "success"):
        return ""
    subprocess.run(
        ["systemctl", "--user", "reset-failed", f"{unit}.scope"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    return result


def exit_status(code: int) -> int:
    """A child's return code as a shell exit status (killed by signal N: 128 + N)."""
    return 128 - code if code < 0 else code


def _parse(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="run_capped.py",
        description="Run a command inside a capped, transient systemd user scope.",
    )
    parser.add_argument(
        "--memory", default=DEFAULT_MEMORY, help=f"hard memory cap (default {DEFAULT_MEMORY})"
    )
    parser.add_argument(
        "--tasks", type=int, default=DEFAULT_TASKS, help=f"task ceiling (default {DEFAULT_TASKS})"
    )
    parser.add_argument(
        "--cpu", default=None, help="CPU quota, 100%% per CPU (default: 75%% of every CPU)"
    )
    parser.add_argument(
        "--unit", default=None, help="scope name (default maljan-capped-<pid>-<time>)"
    )
    parser.add_argument(
        "--floor",
        default=DEFAULT_FLOOR,
        help=f"stop the scope when host MemAvailable falls below this (default {DEFAULT_FLOOR})",
    )
    parser.add_argument(
        "--no-watch", action="store_true", help="run without the MemAvailable watcher"
    )
    parser.add_argument(
        "--interval", type=float, default=DEFAULT_INTERVAL, help="watcher poll interval in seconds"
    )
    parser.add_argument(
        "--allow-uncapped",
        action="store_true",
        help="when the caps cannot be enforced, run the command uncapped (said on stderr)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print the systemd-run line and exit"
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="the command, after --")
    args = parser.parse_args(argv)
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("no command given (put it after --)")
    if args.tasks <= 0:
        parser.error("--tasks must be above zero")
    try:
        args.memory_bytes = parse_size(args.memory)
        args.floor_bytes = parse_size(args.floor)
    except ValueError as exc:
        parser.error(str(exc))
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse(sys.argv[1:] if argv is None else argv)
    unit = args.unit or default_unit()
    cpu = args.cpu or default_cpu_quota()
    line = build_command(unit, args.memory_bytes, args.tasks, cpu, args.command)
    if args.dry_run:
        print(" ".join(line))
        return 0
    try:
        check_capable()
    except (CapError, OSError, subprocess.SubprocessError) as exc:
        if not args.allow_uncapped:
            print(
                f"run_capped: cannot cap the command: {exc}. Not running it; "
                "pass --allow-uncapped to run it without caps.",
                file=sys.stderr,
            )
            return 2
        print(
            f"run_capped: cannot cap the command: {exc}. --allow-uncapped given: running it "
            "UNCAPPED, with no memory cap, swap limit, task ceiling, CPU quota or watcher.",
            file=sys.stderr,
            flush=True,
        )
        return exit_status(subprocess.run(args.command, check=False).returncode)

    watch = "off" if args.no_watch else f"stop below {args.floor_bytes // 1024**2} MiB MemAvailable"
    print(
        f"run_capped: unit {unit}.scope (MemoryMax {args.memory_bytes // 1024**2} MiB, no swap, "
        f"TasksMax {args.tasks}, CPUQuota {cpu}, watcher {watch})",
        file=sys.stderr,
        flush=True,
    )
    watcher = None
    if not args.no_watch:
        watcher = Watcher(unit, args.floor_bytes, args.interval)
        watcher.start()
    child = subprocess.Popen(line)
    try:
        code = exit_status(child.wait())
    except KeyboardInterrupt:
        code = exit_status(child.wait())
    if watcher is None:
        shown = "not read (no watcher)"
    else:
        watcher.done.set()
        watcher.join(timeout=args.interval + 5)
        events = watcher.events
        shown = (
            ", ".join(f"{k} {v}" for k, v in events.items())
            if events
            else "not read (no poll found the scope running)"
        )
    result = scope_result(unit)
    ended = f"; systemd result {result}" if result else ""
    if watcher is not None and watcher.stopped_at is not None:
        ended += "; stopped by the watcher"
    print(
        f"run_capped: {unit}.scope exited {code}{ended}; last memory events: {shown}",
        file=sys.stderr,
    )
    return code


if __name__ == "__main__":
    sys.exit(main())
