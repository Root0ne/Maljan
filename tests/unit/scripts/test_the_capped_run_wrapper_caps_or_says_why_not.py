"""``scripts/dev/run_capped.py`` builds its capped scope, and never runs uncapped silently.

No test here starts a systemd scope: every ``subprocess`` call the wrapper
makes is replaced, and the cgroup, ``/proc`` and meminfo files are written
under tmp_path.
"""

from __future__ import annotations

import importlib.util
import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "run_capped_under_test", ROOT / "scripts/dev/run_capped.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["run_capped_under_test"] = module
    spec.loader.exec_module(module)
    return module


rc = _load()


def _done(returncode: int = 0, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _refuse(*_a: Any, **_k: Any) -> Any:
    raise AssertionError("nothing may be started here")


def _scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pid: int = 4242,
    unit: str = "u1",
    memory: int = 1024**3,
    tasks: int = 64,
    cpu_max: str = "200000 100000",
) -> Path:
    """A scope's control group and a ``/proc/<pid>/cgroup`` naming it, under tmp_path."""
    group = f"/user.slice/user-1000.slice/user@1000.service/app.slice/{unit}.scope"
    proc = tmp_path / "proc" / str(pid)
    proc.mkdir(parents=True)
    (proc / "cgroup").write_text(f"0::{group}\n", encoding="utf-8")
    directory = tmp_path / "cgroup" / group.lstrip("/")
    directory.mkdir(parents=True)
    for name, value in (
        ("memory.max", str(memory)),
        ("memory.swap.max", "0"),
        ("pids.max", str(tasks)),
        ("cpu.max", cpu_max),
        ("memory.events", "low 0\nhigh 2\nmax 1\noom 0\noom_kill 0\n"),
    ):
        (directory / name).write_text(value + "\n", encoding="utf-8")
    monkeypatch.setattr(rc, "PROC_ROOT", tmp_path / "proc")
    monkeypatch.setattr(rc, "CGROUP_ROOT", tmp_path / "cgroup")
    return directory


def _watcher(floor: int | None = None, available: int = 8 * 1024**3, **kw: Any) -> Any:
    return rc.Watcher(
        kw.pop("unit", "u1"),
        kw.pop("pid", 4242),
        memory=kw.pop("memory", 1024**3),
        tasks=kw.pop("tasks", 64),
        cpu_percent=kw.pop("cpu_percent", 200.0),
        floor=floor,
        interval=0.01,
        available=lambda: available,
    )


# -- the command line -----------------------------------------------------------


def test_the_command_line_holds_every_cap_and_the_command_after_the_separator() -> None:
    line = rc.build_command("maljan-capped-x", 8 * 1024**3, 512, "400%", ["pytest", "-q"])
    assert line[:5] == ["systemd-run", "--user", "--scope", "--quiet", "--unit=maljan-capped-x"]
    props = [line[i + 1] for i, word in enumerate(line) if word == "-p"]
    assert props == [
        f"MemoryMax={8 * 1024**3}",
        "MemorySwapMax=0",
        "TasksMax=512",
        "CPUQuota=400%",
        "TimeoutStopSec=5s",
    ]
    assert line[line.index("--") + 1 :] == ["pytest", "-q"]


def test_a_dry_run_prints_a_line_that_splits_back_and_starts_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(subprocess, "run", _refuse)
    monkeypatch.setattr(subprocess, "Popen", _refuse)
    command = ["python", "-c", "print('a b; c')"]
    args = ["--dry-run", "--memory", "2G", "--tasks", "64", "--cpu", "200%", "--unit", "u1"]
    assert rc.main([*args, "--", *command]) == 0
    printed = shlex.split(capsys.readouterr().out)
    assert printed == rc.build_command("u1", 2 * 1024**3, 64, "200%", command)


# -- argument checks ------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("4096", 4096),
        ("512K", 512 * 1024),
        ("3G", 3 * 1024**3),
        ("1.5g", int(1.5 * 1024**3)),
        ("2GiB", 2 * 1024**3),
        ("1T", 1024**4),
        (" 10485760 K", 10485760 * 1024),
    ],
)
def test_sizes_and_thresholds_parse_in_base_1024(text: str, expected: int) -> None:
    assert rc.parse_size(text) == expected


@pytest.mark.parametrize("text", ["", "G", "3X", "-1G", "0", "lots", "3 G B extra"])
def test_a_size_that_is_not_one_is_refused_by_name(text: str) -> None:
    with pytest.raises(ValueError):
        rc.parse_size(text)


@pytest.mark.parametrize(
    ("flags", "message"),
    [
        (["--floor", "plenty"], "not a size"),
        (["--interval", "0"], "--interval must be above zero"),
        (["--interval", "-1"], "--interval must be above zero"),
        (["--cpu", "400"], "not a CPU quota"),
        (["--cpu", "0%"], "not a CPU quota"),
        (["--cpu", "1e3%"], "not a CPU quota"),
        (["--unit=-x"], "not a unit name"),
        (["--unit", "a/b"], "not a unit name"),
        (["--unit", ".scope"], "not a unit name"),
        (["--tasks", "0"], "--tasks must be above zero"),
    ],
)
def test_bad_arguments_are_argument_errors(
    flags: list[str], message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exited:
        rc.main([*flags, "--", "true"])
    assert exited.value.code == 2
    assert message in capsys.readouterr().err


def test_a_unit_named_with_its_suffix_is_the_same_unit() -> None:
    assert rc._parse(["--unit", "x.scope", "--", "true"]).unit == "x"
    assert rc.parse_unit("bench:run_1.a-b") == "bench:run_1.a-b"


def test_meminfo_values_are_read_in_bytes(tmp_path: Path) -> None:
    path = tmp_path / "meminfo"
    path.write_text("MemTotal:       31000000 kB\nMemAvailable:    9000000 kB\n", encoding="utf-8")
    assert rc.mem_available(path) == 9000000 * 1024
    assert rc.meminfo("MemTotal", path) == 31000000 * 1024
    path.write_text("MemTotal:       31000000 kB\n", encoding="utf-8")
    with pytest.raises(ValueError, match="MemAvailable"):
        rc.mem_available(path)


def test_a_cap_above_the_host_or_a_floor_above_what_is_free_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "meminfo"
    path.write_text("MemTotal: 8388608 kB\nMemAvailable: 4194304 kB\n", encoding="utf-8")
    monkeypatch.setattr(rc, "MEMINFO", path)
    with pytest.raises(rc.CapError, match="holds nothing"):
        rc.check_sizes(8 * 1024**3, None)
    with pytest.raises(rc.CapError, match="lower --floor"):
        rc.check_sizes(2 * 1024**3, 4 * 1024**3)
    rc.check_sizes(2 * 1024**3, 3 * 1024**3)
    rc.check_sizes(2 * 1024**3, None)


# -- uncappable hosts -----------------------------------------------------------


def test_no_systemd_run_refuses_and_names_why(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(rc.shutil, "which", lambda _name: None)
    monkeypatch.setattr(subprocess, "run", _refuse)
    monkeypatch.setattr(subprocess, "Popen", _refuse)
    assert rc.main(["--", "true"]) == 2
    err = capsys.readouterr().err
    assert "systemd-run is not installed" in err and "--allow-uncapped" in err


def test_a_silent_user_manager_refuses(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(rc.shutil, "which", lambda _name: "/usr/bin/systemd-run")
    monkeypatch.setattr(
        subprocess, "run", lambda *_a, **_k: _done(1, stderr="Failed to connect to bus")
    )
    monkeypatch.setattr(subprocess, "Popen", _refuse)
    assert rc.main(["--", "true"]) == 2
    assert "Failed to connect to bus" in capsys.readouterr().err


def _manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    group = tmp_path / "user.slice/user-1000.slice/user@1000.service"
    group.mkdir(parents=True)
    monkeypatch.setattr(rc.shutil, "which", lambda _name: "/usr/bin/systemd-run")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: _done(stdout="/user.slice/user-1000.slice/user@1000.service\n"),
    )
    return group


def test_an_undelegated_controller_or_no_swap_accounting_is_named(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    group = _manager(tmp_path, monkeypatch)
    (group / "cgroup.controllers").write_text("cpu pids\n", encoding="utf-8")
    with pytest.raises(rc.CapError, match="memory controller"):
        rc.check_capable(tmp_path)
    (group / "cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")
    with pytest.raises(rc.CapError, match="memory.swap.max"):
        rc.check_capable(tmp_path)
    (group / "memory.swap.max").write_text("max\n", encoding="utf-8")
    rc.check_capable(tmp_path)


def test_a_missing_controllers_file_is_named(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _manager(tmp_path, monkeypatch)
    with pytest.raises(rc.CapError, match="cannot read the user manager's controllers"):
        rc.check_capable(tmp_path)


def test_allow_uncapped_runs_the_command_and_says_so(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(rc.shutil, "which", lambda _name: None)
    ran: list[list[str]] = []

    def run(cmd: list[str], **_k: Any) -> SimpleNamespace:
        ran.append(cmd)
        return _done(-9)

    monkeypatch.setattr(subprocess, "run", run)
    assert rc.main(["--allow-uncapped", "--", "make", "test"]) == 128 + 9
    assert ran == [["make", "test"]]
    assert "UNCAPPED" in capsys.readouterr().err


# -- a unit that is not this run's ----------------------------------------------


def test_an_existing_unit_is_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(rc, "check_capable", lambda: None)
    asked: list[list[str]] = []

    def run(cmd: list[str], **_k: Any) -> SimpleNamespace:
        asked.append(cmd)
        return _done(stdout="loaded\n")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(subprocess, "Popen", _refuse)
    assert rc.main(["--unit", "bench", "--", "true"]) == 2
    assert asked == [
        ["systemctl", "--user", "show", "-p", "LoadState", "--value", "--", "bench.scope"]
    ]
    assert "bench.scope already exists" in capsys.readouterr().err


def test_the_watcher_never_touches_a_unit_its_command_is_not_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _scope(tmp_path, monkeypatch, pid=4242, unit="other")
    monkeypatch.setattr(subprocess, "run", _refuse)
    watcher = _watcher(floor=1024**4, unit="u1", pid=4242)
    assert watcher.check_once() is False
    assert watcher.group is None and watcher.events is None and watcher.stopped_at is None
    gone = _watcher(floor=1024**4, unit="u1", pid=999999)
    assert gone.check_once() is False


# -- the watcher ----------------------------------------------------------------


def test_the_watcher_stops_its_own_scope_below_the_floor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _scope(tmp_path, monkeypatch)
    calls: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **_k: calls.append(cmd) or _done())
    above = _watcher(floor=4 * 1024**3, available=5 * 1024**3)
    assert above.check_once() is False and calls == []
    assert above.events == {"low": 0, "high": 2, "max": 1, "oom": 0, "oom_kill": 0}
    below = _watcher(floor=4 * 1024**3, available=1024**3)
    assert below.check_once() is True
    assert below.stopped_at == 1024**3
    assert calls == [["systemctl", "--user", "stop", "--", "u1.scope"]]


def test_a_cap_accepted_but_not_enforced_kills_the_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    directory = _scope(tmp_path, monkeypatch)
    (directory / "memory.swap.max").write_text("max\n", encoding="utf-8")
    calls: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **_k: calls.append(cmd) or _done())
    watcher = _watcher()
    assert watcher.check_once() is True
    assert watcher.cap_error == "memory.swap.max is max, not 0"
    assert calls == [["systemctl", "--user", "kill", "--signal=SIGKILL", "--", "u1.scope"]]


@pytest.mark.parametrize(
    ("name", "value", "reason"),
    [
        ("memory.max", "max", "memory.max is max"),
        ("pids.max", "max", "pids.max is max"),
        ("cpu.max", "max 100000", "cpu.max is 'max 100000'"),
        ("cpu.max", "100000 100000", "not 200% of a CPU"),
        ("memory.max", None, "memory.max is missing"),
    ],
)
def test_each_cap_is_read_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str, value: str | None, reason: str
) -> None:
    directory = _scope(tmp_path, monkeypatch)
    if value is None:
        (directory / name).unlink()
    else:
        (directory / name).write_text(value + "\n", encoding="utf-8")
    assert reason in (rc.check_caps(directory, 1024**3, 64, 200.0) or "")


def test_a_stop_that_times_out_is_reported_not_lost(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _scope(tmp_path, monkeypatch)

    def run(cmd: list[str], **_k: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd, 30)

    monkeypatch.setattr(subprocess, "run", run)
    watcher = _watcher(floor=4 * 1024**3, available=1024**3)
    watcher.run()
    assert watcher.error is not None and watcher.error.startswith("TimeoutExpired")
    assert "watcher failed: TimeoutExpired" in capsys.readouterr().err


def test_reset_failed_runs_only_for_a_failed_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    answer = {"Result": "oom-kill"}

    def run(cmd: list[str], **_k: Any) -> SimpleNamespace:
        calls.append(cmd)
        return _done(stdout=answer["Result"] + "\n")

    monkeypatch.setattr(subprocess, "run", run)
    assert rc.scope_result("u1") == "oom-kill"
    assert calls == [
        ["systemctl", "--user", "show", "-p", "Result", "--value", "--", "u1.scope"],
        ["systemctl", "--user", "reset-failed", "--", "u1.scope"],
    ]
    calls.clear()
    answer["Result"] = "success"
    assert rc.scope_result("u1") == ""
    assert len(calls) == 1


# -- main with the watcher wired in ---------------------------------------------


class _Child:
    pid = 4242

    def __init__(self, line: list[str], code: int = 3, during: Any = None) -> None:
        self.line = line
        self.code = code
        self.during = during
        self.signals: list[int] = []

    def wait(self) -> int:
        deadline = time.monotonic() + 0.3
        if self.during:
            self.during()
        while time.monotonic() < deadline:
            time.sleep(0.01)
        return self.code

    def send_signal(self, signum: int) -> None:
        self.signals.append(signum)

    def kill(self) -> None:
        self.signals.append(signal.SIGKILL)


def _capped(monkeypatch: pytest.MonkeyPatch, available: int) -> list[list[str]]:
    monkeypatch.setattr(rc, "check_capable", lambda: None)
    monkeypatch.setattr(rc, "check_unit_free", lambda _unit: None)
    monkeypatch.setattr(rc, "check_sizes", lambda *_a: None)
    monkeypatch.setattr(rc, "mem_available", lambda: available)
    calls: list[list[str]] = []

    def run(cmd: list[str], **_k: Any) -> SimpleNamespace:
        calls.append(cmd)
        return _done(stdout="success\n")

    monkeypatch.setattr(subprocess, "run", run)
    return calls


ARGS = ["--unit", "u1", "--memory", "1G", "--tasks", "64", "--cpu", "200%", "--interval", "0.02"]


def test_main_reports_the_watcher_s_events_and_its_stop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _scope(tmp_path, monkeypatch)
    calls = _capped(monkeypatch, available=1024**3)
    started: list[_Child] = []
    monkeypatch.setattr(
        subprocess, "Popen", lambda line: started.append(_Child(line, code=-15)) or started[-1]
    )
    assert rc.main([*ARGS, "--floor", "2G", "--", "make", "bench"]) == 143
    assert started[0].line == rc.build_command("u1", 1024**3, 64, "200%", ["make", "bench"])
    assert ["systemctl", "--user", "stop", "--", "u1.scope"] in calls
    err = capsys.readouterr().err
    assert "unit u1.scope" in err
    assert "u1.scope exited 143; stopped by the watcher" in err
    assert "memory events at the watcher's last poll: low 0, high 2, max 1" in err


def test_main_says_when_the_scope_never_held_the_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(rc, "PROC_ROOT", tmp_path)
    calls = _capped(monkeypatch, available=8 * 1024**3)
    monkeypatch.setattr(subprocess, "Popen", lambda line: _Child(line, code=1))
    assert rc.main([*ARGS, "--no-watch", "--", "true"]) == 1
    assert "systemd-run failed; command not run" in capsys.readouterr().err
    assert calls == []  # no result read and no reset-failed for a unit never seen


def test_main_fails_a_run_whose_cap_was_not_enforced(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = _scope(tmp_path, monkeypatch)
    (directory / "pids.max").write_text("max\n", encoding="utf-8")
    _capped(monkeypatch, available=8 * 1024**3)
    monkeypatch.setattr(subprocess, "Popen", lambda line: _Child(line, code=-9))
    assert rc.main([*ARGS, "--no-watch", "--", "true"]) == 2
    assert "a cap was not enforced (pids.max is max, not 64)" in capsys.readouterr().err


def test_sigterm_to_the_wrapper_stops_its_scope_and_keeps_waiting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _scope(tmp_path, monkeypatch)
    calls = _capped(monkeypatch, available=8 * 1024**3)
    before = signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda line: _Child(line, code=-15, during=lambda: os.kill(os.getpid(), signal.SIGTERM)),
    )
    assert rc.main([*ARGS, "--no-watch", "--", "sleep", "60"]) == 143
    assert ["systemctl", "--user", "stop", "--", "u1.scope"] in calls
    err = capsys.readouterr().err
    assert "SIGTERM received; stopping u1.scope" in err and "u1.scope exited 143" in err
    assert signal.getsignal(signal.SIGTERM) is before


def test_sigterm_before_the_scope_holds_the_command_is_passed_to_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(rc, "PROC_ROOT", tmp_path)
    _capped(monkeypatch, available=8 * 1024**3)
    child = _Child([], code=-15, during=lambda: os.kill(os.getpid(), signal.SIGTERM))
    assert rc._wait(child, "u1") == 143
    assert child.signals == [signal.SIGTERM]


def test_a_signal_is_a_shell_exit_status() -> None:
    assert rc.exit_status(0) == 0
    assert rc.exit_status(3) == 3
    assert rc.exit_status(-15) == 143
