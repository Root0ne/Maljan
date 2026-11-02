"""``scripts/dev/run_capped.py`` builds its capped scope, and never runs uncapped silently.

No test here starts a systemd scope: every ``subprocess`` call the wrapper
makes is replaced, and the cgroup and meminfo files are written under tmp_path.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
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


def test_the_command_line_holds_every_cap_and_the_command_after_the_separator() -> None:
    line = rc.build_command("maljan-capped-x", 8 * 1024**3, 512, "400%", ["pytest", "-q"])
    assert line[:5] == ["systemd-run", "--user", "--scope", "--quiet", "--unit=maljan-capped-x"]
    props = [line[i + 1] for i, word in enumerate(line) if word == "-p"]
    assert props == [
        f"MemoryMax={8 * 1024**3}",
        "MemorySwapMax=0",
        "TasksMax=512",
        "CPUQuota=400%",
    ]
    assert line[line.index("--") + 1 :] == ["pytest", "-q"]


def test_a_dry_run_prints_the_line_and_starts_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("a dry run must not start a process")

    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    code = rc.main(
        ["--dry-run", "--memory", "2G", "--tasks", "64", "--cpu", "200%", "--unit", "u1", "--"]
        + ["python", "-c", "pass"]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "--unit=u1" in out and f"MemoryMax={2 * 1024**3}" in out
    assert "MemorySwapMax=0" in out and "TasksMax=64" in out and "CPUQuota=200%" in out
    assert out.strip().endswith("-- python -c pass")


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


def test_a_bad_floor_is_an_argument_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exited:
        rc.main(["--floor", "plenty", "--", "true"])
    assert exited.value.code == 2
    assert "not a size" in capsys.readouterr().err


def test_mem_available_is_read_from_meminfo_in_bytes(tmp_path: Path) -> None:
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(
        "MemTotal:       31000000 kB\nMemAvailable:    9000000 kB\n", encoding="utf-8"
    )
    assert rc.mem_available(meminfo) == 9000000 * 1024
    meminfo.write_text("MemTotal:       31000000 kB\n", encoding="utf-8")
    with pytest.raises(ValueError, match="MemAvailable"):
        rc.mem_available(meminfo)


def test_no_systemd_run_refuses_and_names_why(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(rc.shutil, "which", lambda _name: None)

    def refuse(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("an uncappable command must not run")

    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
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
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: pytest.fail("ran uncapped"))
    assert rc.main(["--", "true"]) == 2
    assert "Failed to connect to bus" in capsys.readouterr().err


def test_an_undelegated_controller_is_named_not_accepted_quietly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    group = tmp_path / "user.slice/user-1000.slice/user@1000.service"
    group.mkdir(parents=True)
    (group / "cgroup.controllers").write_text("cpu pids\n", encoding="utf-8")
    monkeypatch.setattr(rc.shutil, "which", lambda _name: "/usr/bin/systemd-run")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: _done(stdout="/user.slice/user-1000.slice/user@1000.service\n"),
    )
    with pytest.raises(rc.CapError, match="memory controller"):
        rc.check_capable(tmp_path)
    (group / "cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")
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


def test_a_capped_run_starts_the_built_line_and_reports_the_unit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(rc, "check_capable", lambda: None)
    monkeypatch.setattr(rc, "scope_result", lambda _unit: "")
    started: list[list[str]] = []

    class Child:
        def __init__(self, line: list[str]) -> None:
            started.append(line)

        def wait(self) -> int:
            return 3

    monkeypatch.setattr(subprocess, "Popen", Child)
    code = rc.main(["--no-watch", "--unit", "bench", "--memory", "1G", "--", "make", "bench"])
    assert code == 3
    assert started == [
        rc.build_command(
            "bench", 1024**3, rc.DEFAULT_TASKS, rc.default_cpu_quota(), ["make", "bench"]
        )
    ]
    err = capsys.readouterr().err
    assert "unit bench.scope" in err and "watcher off" in err
    assert "bench.scope exited 3" in err and "not read (no watcher)" in err


def test_the_watcher_stops_the_scope_below_the_floor_and_keeps_polling_before_it_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rc, "read_memory_events", lambda _unit: {"max": 0, "oom_kill": 0})
    stops: list[list[str]] = []
    answers = [1, 0]

    def run(cmd: list[str], **_k: Any) -> SimpleNamespace:
        stops.append(cmd)
        return _done(answers.pop(0))

    monkeypatch.setattr(subprocess, "run", run)
    above = rc.Watcher("u2", floor=4 * 1024**3, available=lambda: 5 * 1024**3)
    assert above.check_once() is False and stops == []
    below = rc.Watcher("u2", floor=4 * 1024**3, available=lambda: 1024**3)
    assert below.check_once() is False  # the scope is not there yet: stop failed
    assert below.stopped_at is None
    assert below.check_once() is True
    assert below.stopped_at == 1024**3
    assert stops == [["systemctl", "--user", "stop", "u2.scope"]] * 2
    assert below.events == {"max": 0, "oom_kill": 0}


def test_memory_events_are_read_from_the_scope_s_own_group(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    group = tmp_path / "app.slice/u3.scope"
    group.mkdir(parents=True)
    (group / "memory.events").write_text(
        "low 0\nhigh 2\nmax 5\noom 1\noom_kill 1\noom_group_kill 0\n", encoding="utf-8"
    )
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: _done(stdout="/app.slice/u3.scope\n"))
    assert rc.read_memory_events("u3", tmp_path) == {
        "low": 0,
        "high": 2,
        "max": 5,
        "oom": 1,
        "oom_kill": 1,
    }
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: _done(stdout="\n"))
    assert rc.read_memory_events("u3", tmp_path) is None


def test_a_signal_is_a_shell_exit_status() -> None:
    assert rc.exit_status(0) == 0
    assert rc.exit_status(3) == 3
    assert rc.exit_status(-15) == 143
