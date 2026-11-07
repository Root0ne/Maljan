"""The worker's resident set is read where the host gives it, and said unread where it does not.

``/proc/self/status`` first, then ``ps -o rss=``; with neither, ``None``, which
is no reading, never a worker of zero megabytes (the recycle ceiling reads it).
"""

from __future__ import annotations

import logging
import subprocess
from typing import Any

import pytest

from malspark.core import memprobe


def _no_proc(path: Any, *args: Any, **kwargs: Any) -> Any:
    raise FileNotFoundError(2, "No such file or directory", str(path))


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

    assert asked and asked[0][:4] == ["ps", "-o", "rss=", "-p"]
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
