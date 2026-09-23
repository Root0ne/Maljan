"""FLOSS runs beside capa when the host has room for it, and its entry is still last.

On PuTTY the pack ran capa (185 s on the benchmark host) and then FLOSS
(132 s), one after the other, although neither reads anything the other
writes. FLOSS now starts as soon as the routed format says PE and runs while
capa and the rest of the pack do. It adds its own memory to the pack's peak —
bounded at ``FLOSS_ADDRESS_SPACE_BYTES`` — so it does so only while the host
has that bound twice over available; otherwise the two run in turn, as before.
Measured on PuTTY with both real tools: 312.0 s → 183.1 s, peak resident
memory of the pack's process tree 1,600 MB → 2,291 MB.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from maljan.pipeline import triage_pack
from maljan.pipeline.triage_pack import floss_fits_beside_capa
from maljan.tools import emulated_strings, rules
from tests.unit.pipeline.test_decoded_strings_in_the_pack import (
    ROWS,
    _answer,
    _floss_entry,
    _installed,
    _pack,
)

GIB = 1024 * 1024 * 1024
WORK = 0.4


def _slow_capa(path: str, **_: Any) -> dict[str, Any]:
    time.sleep(WORK)
    return {"capabilities": [], "meta": {}}


@pytest.fixture
def _slow_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rules, "capa", _slow_capa)
    fake = _installed(monkeypatch, _answer(ROWS))
    answer = fake.answer

    def _slow_floss(path: str, **kwargs: Any) -> dict[str, Any]:
        fake.calls.append({"path": path, **kwargs})
        time.sleep(WORK)
        return answer

    monkeypatch.setattr(emulated_strings, "floss", _slow_floss)


def _available(monkeypatch: pytest.MonkeyPatch, amount: int | None) -> None:
    monkeypatch.setattr(triage_pack, "available_memory_bytes", lambda: amount)


class TestTheRoomItNeeds:
    def test_twice_its_own_bound_available(self) -> None:
        bound = emulated_strings.FLOSS_ADDRESS_SPACE_BYTES

        assert floss_fits_beside_capa(2 * bound)
        assert not floss_fits_beside_capa(2 * bound - 1)
        assert not floss_fits_beside_capa(None)

    def test_the_host_s_own_figure_is_read(self) -> None:
        available = triage_pack.available_memory_bytes()

        assert available is None or available > 0


@pytest.mark.usefixtures("_slow_tools")
class TestBesideCapa:
    def test_the_two_overlap_and_floss_keeps_its_place_and_its_own_clock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _available(monkeypatch, 16 * GIB)

        started = time.monotonic()
        result = _pack(tmp_path)
        took = time.monotonic() - started

        assert took < 2 * WORK, f"{took:.2f}s: capa and FLOSS still ran one after the other"
        assert result.entries[-1].tool == "floss"
        entry = _floss_entry(result)
        assert entry.ok is True
        assert entry.duration_ms < 2 * WORK * 1000, "the entry's clock is FLOSS's own"

    def test_a_host_without_the_room_runs_them_in_turn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _available(monkeypatch, 6 * GIB)

        started = time.monotonic()
        result = _pack(tmp_path)

        assert time.monotonic() - started >= 2 * WORK
        assert result.entries[-1].tool == "floss"

    def test_a_run_started_beside_the_pack_is_recorded_when_the_budget_is_spent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It began within the budget; what it did is its entry, not "not run"."""
        _available(monkeypatch, 16 * GIB)

        result = _pack(tmp_path, budget_s=WORK / 4)

        entry = _floss_entry(result)
        assert entry.ok is True
        assert "floss" not in result.stopped_by_budget

    def test_a_failure_beside_the_pack_is_a_failed_entry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _available(monkeypatch, 16 * GIB)

        def _fails(path: str, **_: Any) -> dict[str, Any]:
            raise RuntimeError("floss crashed")

        monkeypatch.setattr(emulated_strings, "floss", _fails)

        result = _pack(tmp_path)

        entry = _floss_entry(result)
        assert entry.ok is False
        assert "floss crashed" in str(entry.error)
        assert "floss" in result.failed


def test_a_sample_that_is_not_a_pe_starts_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.unit.tools.test_binary import _elf

    calls = _installed(monkeypatch, _answer(ROWS))
    _available(monkeypatch, 16 * GIB)

    result = _pack(tmp_path, blob=_elf(), file_type="elf")

    assert calls.calls == []
    assert not [e for e in result.entries if e.tool == "floss"]
