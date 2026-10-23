"""Fragments fold into Unreleased in a stable order, once, and a bad fragment stops the fold."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "changelog" / "fold.py"

_CHANGELOG = """# Changelog

Intro.

## Unreleased

### Fixed

- **Old fix.** Stays.

### Added

- **Old add.** Stays.
"""


def _fold() -> Any:
    spec = importlib.util.spec_from_file_location("changelog_fold_under_test", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def tree(tmp_path: Path) -> tuple[Path, Path]:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(_CHANGELOG, encoding="utf-8")
    fragments = tmp_path / "changelog.d"
    fragments.mkdir()
    return changelog, fragments


def _run(tree: tuple[Path, Path], *extra: str) -> int:
    changelog, fragments = tree
    return int(_fold().main(["--changelog", str(changelog), "--fragments", str(fragments), *extra]))


def test_fragments_fold_by_section_then_file_name(tree: tuple[Path, Path]) -> None:
    changelog, fragments = tree
    (fragments / "b-branch.md").write_text("### Fixed\n\n- **B fix.**\n", encoding="utf-8")
    (fragments / "a-branch.md").write_text(
        "### Fixed\n\n- **A fix.**\n\n### Added\n\n- **A add.**\n", encoding="utf-8"
    )
    assert _run(tree) == 0
    text = changelog.read_text(encoding="utf-8")
    assert text.index("**A add.**") < text.index("**Old add.**")
    assert text.index("**A fix.**") < text.index("**B fix.**") < text.index("**Old fix.**")
    assert "**A fix.**\n\n- **B fix.**\n\n- **Old fix.**" in text
    assert text.index("## Unreleased") < text.index("**A fix.**")
    assert not list(fragments.glob("*.md"))


def test_a_section_missing_from_unreleased_is_added_at_its_end(tree: tuple[Path, Path]) -> None:
    changelog, fragments = tree
    (fragments / "x.md").write_text("### Security\n\n- **S.**\n", encoding="utf-8")
    assert _run(tree) == 0
    text = changelog.read_text(encoding="utf-8")
    assert text.endswith("- **Old add.** Stays.\n\n### Security\n\n- **S.**\n")


def test_folding_twice_changes_nothing_more(tree: tuple[Path, Path]) -> None:
    changelog, fragments = tree
    (fragments / "x.md").write_text("### Changed\n\n- **C.**\n", encoding="utf-8")
    assert _run(tree) == 0
    once = changelog.read_text(encoding="utf-8")
    assert _run(tree) == 0
    assert changelog.read_text(encoding="utf-8") == once


def test_the_output_does_not_depend_on_the_order_files_were_made(tmp_path: Path) -> None:
    outputs = []
    for order in (("a.md", "b.md"), ("b.md", "a.md")):
        root = tmp_path / order[0]
        root.mkdir()
        changelog = root / "CHANGELOG.md"
        changelog.write_text(_CHANGELOG, encoding="utf-8")
        fragments = root / "changelog.d"
        fragments.mkdir()
        for name in order:
            (fragments / name).write_text(f"### Added\n\n- **{name}.**\n", encoding="utf-8")
        assert _run((changelog, fragments)) == 0
        outputs.append(changelog.read_text(encoding="utf-8"))
    assert outputs[0] == outputs[1]


def test_an_empty_or_missing_fragment_directory_changes_nothing(tree: tuple[Path, Path]) -> None:
    changelog, fragments = tree
    (fragments / "README.md").write_text("# About\n", encoding="utf-8")
    assert _run(tree) == 0
    assert _run(tree, "--check") == 0
    assert changelog.read_text(encoding="utf-8") == _CHANGELOG
    fragments.joinpath("README.md").unlink()
    fragments.rmdir()
    assert _run(tree) == 0
    assert changelog.read_text(encoding="utf-8") == _CHANGELOG


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("### Wrong\n\n- x\n", "unknown section"),
        ("### Fixed\n\n", "is empty"),
        ("", "empty"),
        ("- x\n", "outside a known"),
        ("### Fixed\n\n<<<<<<< HEAD\n- x\n=======\n- y\n>>>>>>> branch\n", "conflict marker"),
        ("### Fixed\n\n- a\n\n### Fixed\n\n- b\n", "repeated"),
    ],
)
def test_check_rejects_a_bad_fragment_and_writes_nothing(
    tree: tuple[Path, Path], content: str, message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    changelog, fragments = tree
    bad = fragments / "bad.md"
    bad.write_text(content, encoding="utf-8")
    assert _run(tree, "--check") == 1
    assert message in capsys.readouterr().err
    assert changelog.read_text(encoding="utf-8") == _CHANGELOG
    assert bad.exists()


def test_a_bad_fragment_stops_the_fold_without_deleting_a_good_one(
    tree: tuple[Path, Path],
) -> None:
    changelog, fragments = tree
    (fragments / "good.md").write_text("### Added\n\n- **G.**\n", encoding="utf-8")
    (fragments / "bad.md").write_text("### Nope\n\n- x\n", encoding="utf-8")
    assert _run(tree) == 1
    assert (fragments / "good.md").exists()
    assert changelog.read_text(encoding="utf-8") == _CHANGELOG


def test_check_accepts_valid_fragments_and_keeps_them(tree: tuple[Path, Path]) -> None:
    changelog, fragments = tree
    (fragments / "ok.md").write_text("### Added\n\n- **OK.**\n", encoding="utf-8")
    assert _run(tree, "--check") == 0
    assert (fragments / "ok.md").exists()
    assert changelog.read_text(encoding="utf-8") == _CHANGELOG


def test_a_changelog_without_unreleased_is_refused(tree: tuple[Path, Path]) -> None:
    changelog, fragments = tree
    changelog.write_text("# Changelog\n", encoding="utf-8")
    (fragments / "ok.md").write_text("### Added\n\n- **OK.**\n", encoding="utf-8")
    assert _run(tree) == 1
    assert (fragments / "ok.md").exists()
