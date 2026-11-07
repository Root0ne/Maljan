"""The worker's resident set is read where the host gives it, and said unread where it does not.

``/proc/self/status`` first, then ``ps -o rss=`` (one reading a second at most,
and never again once ``ps`` failed); with neither, ``None``, which is no
reading, never a worker of zero megabytes (the recycle ceiling reads it).
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any

import pytest

from malspark.core import memprobe


def _no_proc(path: Any, *args: Any, **kwargs: Any) -> Any:
    raise FileNotFoundError(2, "No such file or directory", str(path))


@pytest.fixture(autouse=True)
def _no_ps_reading_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test starts with no ``ps`` reading taken and none failed."""
    monkeypatch.setattr(memprobe, "_ps_reading", {"at": None, "mb": None, "failed": False})


def _answering(calls: list[list[str]], kib: str = "20480") -> Any:
    def answer(argv: list[str], **_kwargs: Any) -> Any:
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, f" {kib}\n", "")

    return answer


def test_this_host_gives_a_reading() -> None:
    rss = memprobe.rss_mb()
    assert rss is not None and rss > 0


def test_without_proc_the_reading_is_asked_of_ps(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[list[str]] = []
    real = subprocess.run

    def spy(argv: list[str], **kwargs: Any) -> Any:
        asked.append(list(argv))
        return real(argv, **kwargs)

    monkeypatch.setattr(memprobe, "open", _no_proc, raising=False)
    monkeypatch.setattr(memprobe.subprocess, "run", spy)

    rss = memprobe.rss_mb()

    assert asked and Path(asked[0][0]).name == "ps"
    assert asked[0][1:4] == ["-o", "rss=", "-p"]
    assert rss is not None and rss > 0


@pytest.mark.parametrize(
    "failure",
    [FileNotFoundError(2, "ps"), subprocess.TimeoutExpired(["ps"], 5.0)],
    ids=["no_ps", "ps_hangs"],
)
def test_with_neither_there_is_no_reading(
    monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise failure

    monkeypatch.setattr(memprobe, "open", _no_proc, raising=False)
    monkeypatch.setattr(memprobe.subprocess, "run", refuse)

    assert memprobe.rss_mb() is None


def test_ps_is_given_a_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def answer(argv: list[str], **kwargs: Any) -> Any:
        seen.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, " 20480\n", "")

    monkeypatch.setattr(memprobe, "open", _no_proc, raising=False)
    monkeypatch.setattr(memprobe.subprocess, "run", answer)

    assert memprobe.rss_mb() == 20.0
    assert seen["timeout"] == memprobe.PS_TIMEOUT_SECONDS


def test_a_probe_without_a_reading_says_so_and_does_not_fail(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(memprobe, "rss_mb", lambda: None)
    monkeypatch.setenv("MALSPARK_MEMPROBE", "basic")
    memprobe.reset()

    with caplog.at_level(logging.INFO, logger="malspark"):
        reading = memprobe.probe("job:start")

    assert reading["rss_mb"] is None and reading["d_rss_mb"] is None
    assert any("rss=not read" in record.getMessage() for record in caplog.records)


def test_one_reading_stands_for_a_second(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    clock = [100.0]
    monkeypatch.setattr(memprobe, "open", _no_proc, raising=False)
    monkeypatch.setattr(memprobe.subprocess, "run", _answering(calls))
    monkeypatch.setattr(memprobe.time, "monotonic", lambda: clock[0])

    assert memprobe.rss_mb() == memprobe.rss_mb() == 20.0
    assert len(calls) == 1, "two readings in the same second start ps once"
    clock[0] += memprobe.PS_READING_MAX_AGE_SECONDS
    assert memprobe.rss_mb() == 20.0
    assert len(calls) == 2, "a reading a second old is taken again"


def test_ps_is_not_started_again_once_it_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[int] = []
    clock = [100.0]

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        started.append(1)
        raise subprocess.TimeoutExpired(["ps"], memprobe.PS_TIMEOUT_SECONDS)

    monkeypatch.setattr(memprobe, "open", _no_proc, raising=False)
    monkeypatch.setattr(memprobe.subprocess, "run", refuse)
    monkeypatch.setattr(memprobe.time, "monotonic", lambda: clock[0])

    assert memprobe.rss_mb() is None
    clock[0] += 60
    assert memprobe.rss_mb() is None
    assert started == [1]


def test_ps_is_looked_for_in_the_systems_directories_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    looked: list[tuple[str, Any]] = []
    calls: list[list[str]] = []

    def which(name: str, path: Any = None, **_kwargs: Any) -> str | None:
        looked.append((name, path))
        return None

    monkeypatch.setattr(memprobe, "open", _no_proc, raising=False)
    monkeypatch.setattr(memprobe.shutil, "which", which)
    monkeypatch.setattr(memprobe.subprocess, "run", _answering(calls))
    monkeypatch.setenv("PATH", "/somewhere/a/job/put/its/own/ps")

    assert memprobe.rss_mb() is None
    assert looked == [("ps", "/bin:/usr/bin")]
    assert calls == [], "no ps outside the system's directories is started"
