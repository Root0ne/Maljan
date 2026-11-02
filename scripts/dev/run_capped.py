#!/usr/bin/env python3
"""Run a heavy local command inside a capped, transient systemd user scope.

A benchmark or observation run against the local model, a replay over many
stored runs or a large test suite can take the host's memory with it; when the
memory runs out the whole desktop session goes, not only the run. This wrapper
starts the command as

    systemd-run --user --scope --unit=<name> -p MemoryMax=<cap> -p MemorySwapMax=0
                -p TasksMax=<n> -p CPUQuota=<q> -p TimeoutStopSec=5s -- <command>

so the kernel holds it to a hard memory cap with no swap, a task ceiling and a
CPU quota. A watcher polls the scope: on the first poll that finds the
command in it, it reads the caps back from the scope's control group and
kills the scope when one was accepted but not enforced; on every poll it
keeps the scope's memory events (``high``, ``max``, ``oom``, ``oom_kill``) and
stops the scope when the host's ``MemAvailable`` falls below a floor (the cap
holds the run; the floor holds the host against everything else that runs
beside it, such as the local model server). The watcher acts only on a scope
it has seen the command's own process in, never on another unit of the same
name. When the command ends, its exit status, systemd's result for a failed
scope, a stop by the watcher and the memory events at the last poll are said.

Usage (from the repository root):

    python scripts/dev/run_capped.py -- python scripts/replay/run.py --compare A B
    python scripts/dev/run_capped.py --memory 8G --floor 4G -- pytest tests/unit -q
    python scripts/dev/run_capped.py --dry-run -- true

When ``systemd-run --user`` cannot cap the command (no ``systemd-run``, no user
manager, or a controller the caps need is not delegated to it) the wrapper
fails with exit code 2 and says why. It never runs the command uncapped unless
``--allow-uncapped`` is given, and then says so on standard error. A unit name
that is already loaded, a memory cap at or above the host's memory, or a floor
at or above what is available at start is refused with exit code 2 as well.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from types import FrameType

DEFAULT_MEMORY = "12G"
DEFAULT_FLOOR = "3G"
DEFAULT_TASKS = 4096
DEFAULT_INTERVAL = 2.0
# Until the command is seen in its scope the watcher polls this often, so a
# short command is still read back and a systemd-run failure is told apart.
FIRST_POLLS = 0.05
STOP_TIMEOUT = "5s"
CGROUP_ROOT = Path("/sys/fs/cgroup")
PROC_ROOT = Path("/proc")
MEMINFO = Path("/proc/meminfo")
# The controllers the caps need: MemoryMax/MemorySwapMax, TasksMax, CPUQuota.
# A user manager without one of them accepts the property and enforces nothing.
NEEDED_CONTROLLERS = ("memory", "pids", "cpu")
MEMORY_EVENTS = ("low", "high", "max", "oom", "oom_kill")
# The kernel rounds memory.max down to a whole page.
PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

_SIZE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([KMGT]?)i?B?\s*$", re.IGNORECASE)
_UNITS = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
_UNIT_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9:_.\-]*$")
_CPU = re.compile(r"^(\d+(?:\.\d+)?)%$")


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


def parse_cpu(text: str) -> float:
    """The percentage in a CPUQuota such as ``400%`` (100% is one CPU)."""
    match = _CPU.match(text)
    if not match or float(match.group(1)) <= 0:
        raise ValueError(f"not a CPU quota: {text!r} (use a percentage above zero, as 400%)")
    return float(match.group(1))


def parse_unit(text: str) -> str:
    """A scope name without its ``.scope`` suffix, refused unless systemd would take it."""
    name = text.removesuffix(".scope")
    if not _UNIT_NAME.match(name):
        raise ValueError(
            f"not a unit name: {text!r} (letters, digits, '_' first, then also ':', '.', '-')"
        )
    return name


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
        "-p",
        f"TimeoutStopSec={STOP_TIMEOUT}",
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


def _systemctl(action: str, unit: str, *options: str) -> subprocess.CompletedProcess[str]:
    """``systemctl --user <action> [options] -- <unit>.scope``."""
    return subprocess.run(
        ["systemctl", "--user", action, *options, "--", f"{unit}.scope"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def check_capable(cgroup_root: Path | None = None) -> None:
    """Raise ``CapError`` unless ``systemd-run --user`` can enforce every cap."""
    root = CGROUP_ROOT if cgroup_root is None else cgroup_root
    if shutil.which("systemd-run") is None:
        raise CapError("systemd-run is not installed")
    manager_group = _user_show("-p", "ControlGroup", "--value")
    if not manager_group:
        raise CapError("the systemd user manager names no control group (is cgroup v2 mounted?)")
    group = root / manager_group.lstrip("/")
    try:
        delegated = set((group / "cgroup.controllers").read_text(encoding="utf-8").split())
    except OSError as exc:
        raise CapError(f"cannot read the user manager's controllers ({exc})") from exc
    missing = [name for name in NEEDED_CONTROLLERS if name not in delegated]
    if missing:
        raise CapError(
            "the user manager is not delegated the "
            + ", ".join(missing)
            + " controller(s); a cap on them would be accepted and not enforced"
        )
    if not (group / "memory.swap.max").exists():
        raise CapError(
            f"{group} has no memory.swap.max (swap accounting is off); "
            "MemorySwapMax=0 would be accepted and not enforced"
        )


def check_unit_free(unit: str) -> None:
    """Raise ``CapError`` when a unit of this name is loaded: it is not this run's to watch."""
    state = _user_show("-p", "LoadState", "--value", "--", f"{unit}.scope")
    if state != "not-found":
        raise CapError(f"{unit}.scope already exists (LoadState {state or 'unknown'})")


def meminfo(key: str, path: Path | None = None) -> int:
    """A ``/proc/meminfo`` value (``MemAvailable``, ``MemTotal``) in bytes."""
    source = MEMINFO if path is None else path
    for line in source.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{key}:"):
            return parse_size(line.split(":", 1)[1].replace("kB", "K"))
    raise ValueError(f"{source} has no {key} line")


def mem_available(path: Path | None = None) -> int:
    return meminfo("MemAvailable", path)


def check_sizes(memory: int, floor: int | None) -> None:
    """Raise ``CapError`` for a cap that holds nothing or a floor the host is already below."""
    total = meminfo("MemTotal")
    if memory >= total:
        raise CapError(
            f"the memory cap {memory // 1024**2} MiB is not below the host's "
            f"{total // 1024**2} MiB, so it holds nothing"
        )
    if floor is not None:
        available = mem_available()
        if floor >= available:
            raise CapError(
                f"the floor {floor // 1024**2} MiB is not below the {available // 1024**2} MiB "
                "available now, so the watcher would stop the run at once (lower --floor)"
            )


def scope_group(pid: int, unit: str, proc_root: Path | None = None) -> str | None:
    """The control group of ``pid`` when it is in ``<unit>.scope``, else None."""
    root = PROC_ROOT if proc_root is None else proc_root
    try:
        text = (root / str(pid) / "cgroup").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("0::") and line.endswith(f"/{unit}.scope"):
            return line[3:]
    return None


def check_caps(group: Path, memory: int, tasks: int, cpu_percent: float) -> str | None:
    """Why the scope at ``group`` does not hold the caps asked for, or None when it does."""
    read: dict[str, str] = {}
    for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max"):
        try:
            read[name] = (group / name).read_text(encoding="utf-8").strip()
        except OSError:
            return f"{name} is missing from the scope"
    if not read["memory.max"].isdigit() or abs(int(read["memory.max"]) - memory) >= PAGE:
        return f"memory.max is {read['memory.max']}, not {memory}"
    if read["memory.swap.max"] != "0":
        return f"memory.swap.max is {read['memory.swap.max']}, not 0"
    if read["pids.max"] != str(tasks):
        return f"pids.max is {read['pids.max']}, not {tasks}"
    quota, _, period = read["cpu.max"].partition(" ")
    if (
        not quota.isdigit()
        or not period.isdigit()
        or abs(int(quota) * 100 / int(period) - cpu_percent) > 0.5
    ):
        return f"cpu.max is {read['cpu.max']!r}, not {cpu_percent:g}% of a CPU"
    return None


def read_memory_events(group: Path) -> dict[str, int] | None:
    """The ``memory.events`` counters of the control group at ``group``."""
    try:
        text = (group / "memory.events").read_text(encoding="utf-8")
    except OSError:
        return None
    events = {}
    for line in text.splitlines():
        name, _, count = line.partition(" ")
        if name in MEMORY_EVENTS and count.isdigit():
            events[name] = int(count)
    return events


class Watcher(threading.Thread):
    """Polls the command's own scope: checks its caps, keeps its memory events, holds the floor."""

    def __init__(
        self,
        unit: str,
        pid: int,
        *,
        memory: int,
        tasks: int,
        cpu_percent: float,
        floor: int | None,
        interval: float = DEFAULT_INTERVAL,
        available: Callable[[], int] | None = None,
        kill_command: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(daemon=True, name=f"watch-{unit}")
        self.unit = unit
        self.pid = pid
        self.memory = memory
        self.tasks = tasks
        self.cpu_percent = cpu_percent
        self.floor = floor
        self.interval = interval
        self.available = available or (lambda: mem_available())
        # Kills the command's own process when systemd cannot kill the scope.
        self.kill_command = kill_command
        self.done = threading.Event()
        self.group: str | None = None
        self.events: dict[str, int] | None = None
        self.stopped_at: int | None = None
        self.cap_error: str | None = None
        self.error: str | None = None

    def check_once(self) -> bool:
        """One poll; True when the watcher is finished with the scope (killed or stopped).

        Nothing is read or done until the command's own process is in a scope
        of this name, so another unit of the same name is never touched.
        """
        group = scope_group(self.pid, self.unit)
        if group is None:
            return False
        directory = CGROUP_ROOT / group.lstrip("/")
        if self.group is None:
            self.group = group
            reason = check_caps(directory, self.memory, self.tasks, self.cpu_percent)
            if reason:
                self.cap_error = reason
                killed = _systemctl("kill", self.unit, "--signal=SIGKILL")
                if killed.returncode == 0:
                    how = f"killed {self.unit}.scope"
                else:
                    how = (
                        f"systemctl kill failed ({killed.stderr.strip() or killed.returncode}); "
                        "killed the command's own process instead"
                    )
                    if self.kill_command is not None:
                        self.kill_command()
                print(
                    f"run_capped: a cap was accepted but not enforced ({reason}); {how}",
                    file=sys.stderr,
                    flush=True,
                )
                return True
        events = read_memory_events(directory)
        if events is not None:
            self.events = events
        if self.floor is None:
            return False
        free = self.available()
        if free >= self.floor:
            return False
        stop = _systemctl("stop", self.unit)
        if stop.returncode != 0 and scope_group(self.pid, self.unit) is None:
            # The scope ended on its own between the poll and the stop.
            return True
        if stop.returncode != 0:
            raise RuntimeError(f"systemctl stop failed: {stop.stderr.strip() or stop.returncode}")
        self.stopped_at = free
        print(
            f"run_capped: host MemAvailable {free // 1024**2} MiB is below the floor "
            f"{self.floor // 1024**2} MiB; stopped {self.unit}.scope",
            file=sys.stderr,
            flush=True,
        )
        return True

    def run(self) -> None:
        try:
            while not self.check_once():
                if self.done.wait(self.interval if self.group else FIRST_POLLS):
                    return
        except Exception as exc:  # kept and reported, never lost
            self.error = f"{type(exc).__name__}: {exc}"
            print(
                f"run_capped: watcher failed: {self.error}; {self.unit}.scope runs unwatched",
                file=sys.stderr,
                flush=True,
            )


def scope_result(unit: str) -> str:
    """Why systemd says the scope ended (``oom-kill``, ``signal`` …), or "" when it holds none.

    A scope that ended well is unloaded; one that failed stays loaded with its
    result until ``reset-failed``, which this then runs, so the name is free again.
    """
    try:
        result = _user_show("-p", "Result", "--value", "--", f"{unit}.scope")
    except (CapError, OSError, subprocess.SubprocessError):
        return ""
    if result in ("", "success"):
        return ""
    _systemctl("reset-failed", unit)
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
        "--unit",
        default=None,
        help="scope name, not a loaded unit's (default maljan-capped-<pid>-<time>)",
    )
    parser.add_argument(
        "--floor",
        default=DEFAULT_FLOOR,
        help=f"stop the scope when host MemAvailable falls below this (default {DEFAULT_FLOOR})",
    )
    parser.add_argument(
        "--no-watch",
        action="store_true",
        help="no MemAvailable floor (the caps are still read back and the events kept)",
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
    if not args.interval > 0:
        parser.error("--interval must be above zero")
    args.cpu = args.cpu or default_cpu_quota()
    try:
        args.memory_bytes = parse_size(args.memory)
        args.floor_bytes = None if args.no_watch else parse_size(args.floor)
        args.cpu_percent = parse_cpu(args.cpu)
        args.unit = default_unit() if args.unit is None else parse_unit(args.unit)
    except ValueError as exc:
        parser.error(str(exc))
    return args


def _run_uncapped(command: Sequence[str], reason: object) -> int:
    print(
        f"run_capped: cannot cap the command: {reason}. --allow-uncapped given: running it "
        "UNCAPPED, with no memory cap, swap limit, task ceiling, CPU quota or watcher.",
        file=sys.stderr,
        flush=True,
    )
    return exit_status(subprocess.run(list(command), check=False).returncode)


def _wait(child: subprocess.Popen[bytes], unit: str) -> int:
    """Wait for the command; SIGTERM or SIGHUP stops its scope (or reaches it) first."""

    def on_signal(signum: int, _frame: FrameType | None) -> None:
        name = signal.Signals(signum).name
        if scope_group(child.pid, unit) is None:
            print(f"run_capped: {name} received; passing it to the command", file=sys.stderr)
            child.send_signal(signum)
            return
        print(f"run_capped: {name} received; stopping {unit}.scope", file=sys.stderr)
        try:
            stop = _systemctl("stop", unit)
            failure = (stop.stderr.strip() or f"exit {stop.returncode}") if stop.returncode else ""
        except subprocess.SubprocessError as exc:
            failure = str(exc)
        if failure:
            print(
                f"run_capped: stopping {unit}.scope failed ({failure}); killing the command",
                file=sys.stderr,
            )
            child.kill()

    previous = {sig: signal.signal(sig, on_signal) for sig in (signal.SIGTERM, signal.SIGHUP)}
    try:
        while True:
            try:
                return exit_status(child.wait())
            except KeyboardInterrupt:
                # The terminal sent the interrupt to the command too; wait for it to end.
                continue
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse(sys.argv[1:] if argv is None else argv)
    unit = args.unit
    line = build_command(unit, args.memory_bytes, args.tasks, args.cpu, args.command)
    if args.dry_run:
        print(shlex.join(line))
        return 0
    try:
        check_capable()
    except (CapError, OSError, subprocess.SubprocessError) as exc:
        if args.allow_uncapped:
            return _run_uncapped(args.command, exc)
        print(
            f"run_capped: cannot cap the command: {exc}. Not running it; "
            "pass --allow-uncapped to run it without caps.",
            file=sys.stderr,
        )
        return 2
    try:
        check_unit_free(unit)
        check_sizes(args.memory_bytes, args.floor_bytes)
    except (CapError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"run_capped: not running the command: {exc}", file=sys.stderr)
        return 2

    floor = args.floor_bytes
    watch = "off" if floor is None else f"stop below {floor // 1024**2} MiB MemAvailable"
    print(
        f"run_capped: unit {unit}.scope (MemoryMax {args.memory_bytes // 1024**2} MiB, no swap, "
        f"TasksMax {args.tasks}, CPUQuota {args.cpu}, floor {watch})",
        file=sys.stderr,
        flush=True,
    )
    child = subprocess.Popen(line)
    watcher = Watcher(
        unit,
        child.pid,
        memory=args.memory_bytes,
        tasks=args.tasks,
        cpu_percent=args.cpu_percent,
        floor=floor,
        interval=args.interval,
        kill_command=child.kill,
    )
    watcher.start()
    code = _wait(child, unit)
    watcher.done.set()
    watcher.join(timeout=args.interval + 35)

    # A watcher error was printed by the watcher when it happened.
    if watcher.cap_error:
        print(
            f"run_capped: {unit}.scope was killed: a cap was not enforced ({watcher.cap_error})",
            file=sys.stderr,
        )
        return 2
    if watcher.group is None:
        why = (
            "the command ended before the first poll; caps and memory events not read"
            if code == 0
            else "systemd-run failed; command not run, unless the command itself failed "
            "before the first poll"
        )
        print(
            f"run_capped: {unit}.scope was never seen holding the command (exit {code}): {why}",
            file=sys.stderr,
        )
        return code
    result = scope_result(unit)
    ended = f"; systemd result {result}" if result else ""
    if watcher.stopped_at is not None:
        ended += "; stopped by the watcher"
    events = watcher.events
    shown = ", ".join(f"{k} {v}" for k, v in events.items()) if events else "not read"
    print(
        f"run_capped: {unit}.scope exited {code}{ended}; "
        f"memory events at the watcher's last poll: {shown}",
        file=sys.stderr,
    )
    return code


if __name__ == "__main__":
    sys.exit(main())
