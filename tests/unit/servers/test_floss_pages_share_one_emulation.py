"""Pages of one FLOSS answer share one emulation, and no child outlives the sidecar.

The sidecar joined a FLOSS run by the whole call, paging included, so two
pages asked at once were two runs and the run one caller abandoned killed the
child the other was waiting on. The emulation is now joined per file and
length and each page is read from the one remembered result; a bad pattern
is still refused before any emulation. Every child still running is killed
when the server ends. FLOSS itself is not run: its runner is replaced.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from maljan.tools import children, emulated_strings

ROOT = Path(__file__).resolve().parents[3]
KILLED: list[int] = []


@pytest.fixture(scope="module")
def analysis() -> Any:
    path = ROOT / "services" / "analysis-mcp" / "server.py"
    spec = importlib.util.spec_from_file_location("analysis_mcp_floss_pages", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _document(count: int) -> str:
    decoded = [
        {"string": f"text-{index:03d}", "decoding_routine": 0x10001000, "decoded_at": 0x10001010}
        for index in range(count)
    ]
    return json.dumps(
        {
            "metadata": {"version": "3.1.1", "imagebase": 0x10000000},
            "strings": {"decoded_strings": decoded, "stack_strings": [], "tight_strings": []},
        }
    )


@pytest.fixture
def emulations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[list[int]]:
    emulated_strings.forget_documents()
    KILLED.clear()
    calls: list[int] = []

    def _run(argv: Any, _timeout: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(1)
        # How the real child is registered: killed when its run is abandoned.
        children.register(lambda: KILLED.append(1))
        time.sleep(0.4)
        return subprocess.CompletedProcess(list(argv), 0, _document(10), "")

    monkeypatch.setattr(emulated_strings, "find_floss", lambda _env=None: (tmp_path / "f", ""))
    monkeypatch.setattr(emulated_strings, "_run", _run)
    yield calls
    emulated_strings.forget_documents()


def _sample(tmp_path: Path, analysis: Any, monkeypatch: pytest.MonkeyPatch) -> str:
    target = tmp_path / "s.dll"
    target.write_bytes(b"MZ" + bytes(62))
    monkeypatch.setenv("MALJAN_SAMPLE_ROOTS", str(tmp_path))
    return str(target)


def test_two_pages_at_once_are_one_emulation(
    analysis: Any, emulations: list[int], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _sample(tmp_path, analysis, monkeypatch)

    async def _both() -> list[dict[str, Any]]:
        return list(
            await asyncio.gather(
                analysis.floss(path=path, limit=4, offset=0),
                analysis.floss(path=path, limit=4, offset=4),
            )
        )

    first, second = asyncio.run(_both())

    assert emulations == [1]
    assert [row["string"] for row in first["strings"]] == [f"text-{i:03d}" for i in range(4)]
    assert [row["string"] for row in second["strings"]] == [f"text-{i:03d}" for i in range(4, 8)]
    assert second["next_offset"] == 8


def test_a_bad_pattern_is_refused_before_any_emulation(
    analysis: Any, emulations: list[int], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _sample(tmp_path, analysis, monkeypatch)

    answer = asyncio.run(analysis.floss(path=path, pattern="re:(("))

    assert "bad pattern" in answer["error"]["message"]
    assert emulations == []


def test_a_page_abandoned_does_not_kill_the_emulation_another_page_waits_on(
    analysis: Any, emulations: list[int], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _sample(tmp_path, analysis, monkeypatch)

    async def _one_gives_up() -> dict[str, Any]:
        first = asyncio.ensure_future(analysis.floss(path=path, limit=4, offset=0))
        second = asyncio.ensure_future(analysis.floss(path=path, limit=4, offset=4))
        await asyncio.sleep(0.1)
        first.cancel()
        return dict(await second)

    answer = asyncio.run(_one_gives_up())

    assert KILLED == []
    assert emulations == [1]
    assert [row["string"] for row in answer["strings"]] == [f"text-{i:03d}" for i in range(4, 8)]


def test_kill_all_kills_every_child_still_registered() -> None:
    killed: list[str] = []
    ready = threading.Event()
    done = threading.Event()

    def _hold(name: str) -> None:
        with children.running_as(("test-run", name)):
            children.register(lambda: killed.append(name))
            ready.set()
            done.wait(5)

    workers = [threading.Thread(target=_hold, args=(name,)) for name in ("a", "b")]
    for worker in workers:
        ready.clear()
        worker.start()
        ready.wait(5)

    assert children.kill_all() == 2
    done.set()
    for worker in workers:
        worker.join(5)
    assert sorted(killed) == ["a", "b"]
    children.reopen()


def test_the_run_hands_its_result_to_its_waiters(
    analysis: Any, emulations: list[int], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A remembered result cleared right after the run does not cost a waiter its page."""
    path = _sample(tmp_path, analysis, monkeypatch)
    real = emulated_strings.recovered

    def _then_cleared(*args: Any, **kwargs: Any) -> dict[str, Any]:
        answer = real(*args, **kwargs)
        emulated_strings.forget_documents()
        return answer

    monkeypatch.setattr(emulated_strings, "recovered", _then_cleared)

    answer = asyncio.run(analysis.floss(path=path, limit=4, offset=4))

    assert emulations == [1]
    assert [row["string"] for row in answer["strings"]] == [f"text-{i:03d}" for i in range(4, 8)]


def test_the_joined_key_is_the_remembered_key(
    analysis: Any, emulations: list[int], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _sample(tmp_path, analysis, monkeypatch)
    runs: list[Any] = []
    real = children.joined

    async def _spy(run: Any, work: Any) -> Any:
        runs.append(run)
        return await real(run, work)

    monkeypatch.setattr(analysis.children, "joined", _spy)

    async def _two() -> list[dict[str, Any]]:
        return list(
            await asyncio.gather(
                analysis.floss(path=path, min_len=2, timeout_s=30),
                analysis.floss(path=path, min_len=3, timeout_s=60),
            )
        )

    first, second = asyncio.run(_two())

    key = ("floss", *emulated_strings.remembered_key(path, 3))
    assert runs and all(run == key for run in runs)
    assert emulations == [1]
    assert first["strings"] == second["strings"]
