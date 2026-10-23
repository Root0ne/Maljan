"""The frozen record of shipped tool declarations is reproduced by its generator (T-134)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _generator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "write_shipped_tool_declarations_under_test",
        ROOT / "scripts/dev/write_shipped_tool_declarations.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _history_present(commits: tuple[str, ...]) -> bool:
    for commit in commits:
        probe = subprocess.run(
            ["git", "-C", str(ROOT), "cat-file", "-e", f"{commit}^{{commit}}"],
            capture_output=True,
            check=False,
        )
        if probe.returncode:
            return False
    return True


def test_the_generator_reproduces_the_committed_record_byte_for_byte() -> None:
    writer = _generator()
    if not _history_present(writer.RELEASES):
        pytest.skip("the release history is not in this clone (a shallow checkout)")
    assert writer.RECORD.read_text(encoding="utf-8") == writer.rendered()


def test_the_record_lists_exactly_the_generator_s_releases() -> None:
    writer = _generator()
    record = json.loads(writer.RECORD.read_text(encoding="utf-8"))
    for block in record["blocks"].values():
        listed = [commit for group in block["releases"] for commit in group]
        assert sorted(listed) == sorted(writer.RELEASES)
        assert len(block["releases"]) == len(block["states"])
