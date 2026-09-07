"""The evaluation gate admits text edits and rejects everything else."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "paper" / "check_evaluation_diff.py"
_spec = importlib.util.spec_from_file_location("check_evaluation_diff", _SCRIPT)
assert _spec is not None and _spec.loader is not None
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

OLD = '''"""Module docstring."""

import pytest

THRESHOLD = 0.5


def test_thing():
    if THRESHOLD > 1:
        pytest.skip("Run: uv run python scripts/prepare_tram_dataset.py")
    assert THRESHOLD == 0.5, "threshold drifted"
'''


def test_docstring_and_message_edits_are_text_only() -> None:
    new = OLD.replace("Module docstring.", "Module docstring, reworded.").replace(
        "scripts/prepare_tram_dataset.py", "scripts/knowledge/prepare_tram_dataset.py"
    )
    assert gate.text_only_change(OLD, new)
    assert gate.classify("tests/evaluation/test_x.py", OLD, new) is None


def test_a_rewrapped_string_concatenation_is_text_only() -> None:
    # Adjacent literals fold into one constant at parse time, so re-wrapping
    # a long message across lines is still a text-only edit.
    new = OLD.replace(
        'pytest.skip("Run: uv run python scripts/prepare_tram_dataset.py")',
        'pytest.skip("Run: uv run python "\n'
        '            "scripts/knowledge/prepare_tram_dataset.py")',
    )
    assert gate.text_only_change(OLD, new)


def test_a_changed_number_is_rejected() -> None:
    new = OLD.replace("THRESHOLD = 0.5", "THRESHOLD = 0.6")
    assert gate.classify("tests/evaluation/test_x.py", OLD, new) == (
        "only string literals and docstrings may change"
    )


def test_a_changed_condition_is_rejected() -> None:
    new = OLD.replace("if THRESHOLD > 1:", "if THRESHOLD > 2:")
    assert gate.classify("tests/evaluation/test_x.py", OLD, new) is not None


def test_an_added_test_is_rejected() -> None:
    new = OLD + "\n\ndef test_more():\n    assert True\n"
    assert gate.classify("tests/evaluation/test_x.py", OLD, new) is not None


def test_non_python_artefacts_are_rejected() -> None:
    reason = gate.classify("tests/evaluation/test_suite_count.json", "{}", "{ }")
    assert reason == "only .py files may change under tests/evaluation/"


def test_added_and_deleted_files_are_rejected() -> None:
    assert gate.classify("tests/evaluation/new.py", None, "x = 1\n") is not None
    assert gate.classify("tests/evaluation/old.py", "x = 1\n", None) is not None


def test_paths_outside_the_tree_are_ignored() -> None:
    assert gate.classify("tests/unit/test_x.py", OLD, OLD + "y = 2\n") is None


def test_unparseable_sources_are_rejected() -> None:
    assert gate.text_only_change(OLD, OLD + "def (:\n") is False
