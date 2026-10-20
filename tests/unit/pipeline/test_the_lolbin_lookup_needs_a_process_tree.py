"""A report with no process tree gets no lolbin lookup over zero command lines."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .test_triage_pack import SANDBOX_REPORT, _pack, _pe, _tools, _write


def _report(**behavior: Any) -> dict[str, Any]:
    return {**SANDBOX_REPORT, "behavior": behavior}


def test_no_process_tree_records_no_lookup(tmp_path: Path) -> None:
    result = _pack(_write(tmp_path, "s.exe", _pe()), "pe", sandbox_report=_report())

    assert "lolbin_lookup" not in _tools(result)


def test_a_process_tree_is_still_looked_up(tmp_path: Path) -> None:
    result = _pack(_write(tmp_path, "s.exe", _pe()), "pe", sandbox_report=SANDBOX_REPORT)

    assert "lolbin_lookup" in _tools(result)
