"""FLOSS runs beside capa when the host has room for it, and its entry is still last.

On PuTTY the pack ran capa (185 s on the benchmark host) and then FLOSS
(132 s), one after the other, although neither reads anything the other
writes. FLOSS now starts as soon as the routed format says PE and runs while
capa and the rest of the pack do. It adds its own memory to capa's, so it does
so only when the host's available memory, less capa's measured peak and
FLOSS's bound (``FLOSS_ADDRESS_SPACE_BYTES``), stays above
``triage.memory_floor_mb``, and the worker's cgroup limit, where it has one,
holds both; otherwise the two run in turn, as before, and the summary says why.
Measured on PuTTY with both real tools: 312.0 s → 183.1 s, peak resident
memory of the pack's process tree 1,600 MB → 2,291 MB.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from maljan.pipeline import triage_pack
from maljan.pipeline.triage_pack import cgroup_headroom_bytes, floss_beside_capa
from maljan.providers.static import capa_yara
from maljan.tools import emulated_strings, rules
from tests.unit.pipeline.test_decoded_strings_in_the_pack import (
    ROWS,
    _answer,
    _floss_entry,
    _installed,
    _pack,
)

GIB = 1024 * 1024 * 1024
MIB = 1024 * 1024
WORK = 0.4
BOUND = emulated_strings.FLOSS_ADDRESS_SPACE_BYTES
FLOOR = 10 * GIB


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


def _available(
    monkeypatch: pytest.MonkeyPatch,
    amount: int | None,
    *,
    capa_peak: int | None = 2 * GIB,
    cgroup: int | None = None,
) -> None:
    monkeypatch.setattr(triage_pack, "available_memory_bytes", lambda: amount)
    monkeypatch.setattr(triage_pack, "cgroup_headroom_bytes", lambda: cgroup)
    monkeypatch.setattr(capa_yara, "_CAPA_PEAK_BYTES", capa_peak)


class TestTheRoomItNeeds:
    def test_capa_s_peak_and_floss_s_bound_above_the_floor(self) -> None:
        need = 2 * GIB + BOUND

        assert (
            floss_beside_capa(
                host_available=FLOOR + need, cgroup_left=None, capa_peak=2 * GIB, floor=FLOOR
            )
            == ""
        )
        short = floss_beside_capa(
            host_available=FLOOR + need - 1, cgroup_left=None, capa_peak=2 * GIB, floor=FLOOR
        )
        assert "under the 10240 MiB floor" in short

    def test_a_worker_limit_that_cannot_hold_both(self) -> None:
        why = floss_beside_capa(
            host_available=64 * GIB, cgroup_left=4 * GIB, capa_peak=2 * GIB, floor=FLOOR
        )
        assert why.startswith("the worker's memory limit leaves 4096 MiB")

    def test_nothing_measured_nothing_run_together(self) -> None:
        assert (
            floss_beside_capa(
                host_available=64 * GIB, cgroup_left=None, capa_peak=None, floor=FLOOR
            )
            == "capa's memory has not been measured in this worker yet"
        )
        assert (
            floss_beside_capa(host_available=None, cgroup_left=None, capa_peak=GIB, floor=FLOOR)
            == "the host does not report its available memory"
        )

    def test_the_host_s_own_figure_is_read(self) -> None:
        available = triage_pack.available_memory_bytes()

        assert available is None or available > 0


class TestTheWorkersOwnLimit:
    def test_cgroup_v2(self, tmp_path: Path) -> None:
        (tmp_path / "memory.max").write_text(str(8 * GIB))
        (tmp_path / "memory.current").write_text(str(3 * GIB))

        assert cgroup_headroom_bytes(tmp_path) == 5 * GIB

    def test_no_limit_is_none(self, tmp_path: Path) -> None:
        (tmp_path / "memory.max").write_text("max")
        (tmp_path / "memory.current").write_text(str(3 * GIB))

        assert cgroup_headroom_bytes(tmp_path) is None

    def test_cgroup_v1(self, tmp_path: Path) -> None:
        (tmp_path / "memory").mkdir()
        (tmp_path / "memory" / "memory.limit_in_bytes").write_text(str(8 * GIB))
        (tmp_path / "memory" / "memory.usage_in_bytes").write_text(str(6 * GIB))

        assert cgroup_headroom_bytes(tmp_path) == 2 * GIB

    def test_a_v1_limit_of_none(self, tmp_path: Path) -> None:
        (tmp_path / "memory").mkdir()
        (tmp_path / "memory" / "memory.limit_in_bytes").write_text(str(1 << 62))
        (tmp_path / "memory" / "memory.usage_in_bytes").write_text(str(6 * GIB))

        assert cgroup_headroom_bytes(tmp_path) is None


class TestCapaSPeakIsMeasured:
    def test_the_largest_peak_is_kept(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(capa_yara, "_CAPA_PEAK_BYTES", None)

        capa_yara.note_capa_peak(3 * GIB)
        capa_yara.note_capa_peak(GIB)
        capa_yara.note_capa_peak("not a number")

        assert capa_yara.measured_capa_peak_bytes() == 3 * GIB

    def test_the_child_s_peak_is_read_before_its_answer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(capa_yara, "_CAPA_PEAK_BYTES", None)
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"MZ")

        document = capa_yara.run_capa_document(
            sample_path=str(sample),
            rules_dir=str(tmp_path),
            signatures_dir=str(tmp_path),
            backend_name="BACKEND_VIV",
            timeout_seconds=60,
            target=_peak_then_answer,
        )

        assert document == {"rules": {}}
        assert capa_yara.measured_capa_peak_bytes() == 1234 * MIB


def _peak_then_answer(sample_path, rules_dir, signatures_dir, backend_name, queue):  # type: ignore[no-untyped-def]
    """Module-level so the spawn start method can import it in the child."""
    queue.put(("peak", 1234 * 1024 * 1024))
    queue.put(("ok", {"rules": {}}))


@pytest.mark.usefixtures("_slow_tools")
class TestBesideCapa:
    def test_the_two_overlap_and_floss_keeps_its_place_and_its_own_clock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _available(monkeypatch, 32 * GIB)

        started = time.monotonic()
        result = _pack(tmp_path)
        took = time.monotonic() - started

        assert took < 2 * WORK, f"{took:.2f}s: capa and FLOSS still ran one after the other"
        assert result.entries[-3].tool == "floss"
        entry = _floss_entry(result)
        assert entry.ok is True
        assert entry.duration_ms < 2 * WORK * 1000, "the entry's clock is FLOSS's own"
        assert result.to_state()["floss"] == "beside capa"

    def test_a_worker_that_has_not_measured_capa_runs_them_in_turn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _available(monkeypatch, 64 * GIB, capa_peak=None)

        started = time.monotonic()
        result = _pack(tmp_path)

        assert time.monotonic() - started >= 2 * WORK
        assert result.entries[-3].tool == "floss"
        assert result.to_state()["floss"] == (
            "in turn: capa's memory has not been measured in this worker yet"
        )

    def test_a_run_started_beside_the_pack_is_recorded_when_the_budget_is_spent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It began within the budget; what it did is its entry, not "not run"."""
        _available(monkeypatch, 32 * GIB)

        result = _pack(tmp_path, budget_s=WORK / 4)

        entry = _floss_entry(result)
        assert entry.ok is True
        assert "floss" not in result.stopped_by_budget

    def test_a_failure_beside_the_pack_is_a_failed_entry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _available(monkeypatch, 32 * GIB)

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
    _available(monkeypatch, 32 * GIB)

    result = _pack(tmp_path, blob=_elf(), file_type="elf")

    assert calls.calls == []
    assert not [e for e in result.entries if e.tool == "floss"]
    assert "floss" not in result.to_state()


def test_the_summary_says_how_floss_ran() -> None:
    from maljan.analysis.run_summary import RunSummaryBuilder

    summary = (
        RunSummaryBuilder(start_time=0.0)
        .set_triage({"entries": 11, "failed": 0, "duration_ms": 5, "floss": "beside capa"})
        .build()
        .to_dict()
    )

    assert summary["triage"]["floss"] == "beside capa"
