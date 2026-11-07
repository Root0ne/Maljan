"""A pinned tree whose tag does not build as released is patched after the checkout, once.

``scripts/dev/patches/<name>-<ref>.patch`` is applied to the tree the script
checked out. A second run finds it in place and leaves the tree alone; a patch
that neither applies nor is in place stops the script, so an image is never
built from a tree that is neither the release nor the fixed release. Named
targets fetch only those trees, and ``MALSPARK_EXTERNAL_DIR`` moves them.
Everything here is a local ``file://`` repository.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "dev" / "fetch_external.sh"
PATCHES = ROOT / "scripts" / "dev" / "patches"

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

# The developer's own git config (core.autocrlf, url.*.insteadOf) never reaches these runs.
_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}

_PATCH = """A note before the diff, as the shipped patches carry.

diff --git a/build.txt b/build.txt
--- a/build.txt
+++ b/build.txt
@@ -1,2 +1,2 @@
-version=1
+version=2
 name=tool
"""


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-c", "user.name=T", "-c", "user.email=t@example.com", *args],
        cwd=cwd,
        env=_ENV,
        check=True,
        capture_output=True,
        text=True,
    )
    return done.stdout.strip()


def _upstream(tmp_path: Path, content: bytes = b"version=1\r\nname=tool\r\n") -> Path:
    """A repo whose tag v1 holds a CRLF file, as a release built on Windows does."""
    repo = tmp_path / "upstream"
    repo.mkdir()
    _git(repo, "init", "--quiet", "-b", "main")
    (repo / "build.txt").write_bytes(content)
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "release")
    _git(repo, "tag", "v1")
    return repo


def _tree(tmp_path: Path, url: str, patch: str | None = _PATCH) -> Path:
    """A copy of the script whose targets are the local repo, as `tool` and `other`."""
    tree = tmp_path / "tree"
    (tree / "scripts" / "dev" / "patches").mkdir(parents=True)
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index("targets=(")
    end = text.index("\n)\n", start) + 3
    text = text[:start] + f'targets=(\n  "tool|{url}|v1"\n  "other|{url}|v1"\n)\n' + text[end:]
    (tree / "scripts" / "dev" / "fetch_external.sh").write_text(text, encoding="utf-8")
    # Leaves a mark, so a run that reaches capa's step is told apart from one that does not.
    (tree / "scripts" / "dev" / "fetch_capa_data.sh").write_text(
        f'touch "{tree}/capa-ran"\n', encoding="utf-8"
    )
    (tree / "data" / "sigma_rules").mkdir(parents=True)
    if patch is not None:
        (tree / "scripts" / "dev" / "patches" / "tool-v1.patch").write_text(patch, encoding="utf-8")
    return tree


def _fetch(
    tree: Path, *names: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(tree / "scripts" / "dev" / "fetch_external.sh"), *names],
        capture_output=True,
        text=True,
        env={**_ENV, **(env or {})},
        check=False,
        timeout=120,
    )


class TestThePatchIsAppliedOnce:
    def test_a_fresh_clone_is_patched_and_a_second_run_leaves_it(self, tmp_path: Path) -> None:
        tree = _tree(tmp_path, _upstream(tmp_path).as_uri())
        first = _fetch(tree)
        assert first.returncode == 0, first.stderr
        assert "patch    tool tool-v1.patch" in first.stdout
        built = tree / "external" / "tool" / "build.txt"
        # Only the changed line takes the patch's ending; the rest of the CRLF file is kept.
        assert built.read_bytes() == b"version=2\nname=tool\r\n"

        second = _fetch(tree)
        assert second.returncode == 0, second.stderr
        assert "ok       tool carries tool-v1.patch" in second.stdout
        assert built.read_bytes() == b"version=2\nname=tool\r\n"

    def test_a_tree_whose_line_endings_an_editor_changed_still_counts_as_patched(
        self, tmp_path: Path
    ) -> None:
        tree = _tree(tmp_path, _upstream(tmp_path).as_uri())
        assert _fetch(tree).returncode == 0
        built = tree / "external" / "tool" / "build.txt"
        built.write_bytes(built.read_bytes().replace(b"\r\n", b"\n"))
        again = _fetch(tree)
        assert again.returncode == 0, again.stderr
        assert "carries tool-v1.patch" in again.stdout

    def test_a_tree_without_a_patch_is_only_checked_out(self, tmp_path: Path) -> None:
        tree = _tree(tmp_path, _upstream(tmp_path).as_uri(), patch=None)
        done = _fetch(tree)
        assert done.returncode == 0, done.stderr
        assert (
            tree / "external" / "tool" / "build.txt"
        ).read_bytes() == b"version=1\r\nname=tool\r\n"


class TestAPatchThatNoLongerFitsStopsTheScript:
    def test_a_tag_the_patch_does_not_fit(self, tmp_path: Path) -> None:
        upstream = _upstream(tmp_path, content=b"version=7\nname=tool\n")
        tree = _tree(tmp_path, upstream.as_uri())
        done = _fetch(tree)
        assert done.returncode == 1
        assert "FAIL     tool: tool-v1.patch neither applies" in done.stderr
        assert not (tree / "capa-ran").exists()
        assert (tree / "external" / "tool" / "build.txt").read_bytes() == b"version=7\nname=tool\n"


class TestNamedTargetsAndAnotherDirectory:
    def test_a_named_target_fetches_that_tree_and_nothing_after_it(self, tmp_path: Path) -> None:
        tree = _tree(tmp_path, _upstream(tmp_path).as_uri())
        done = _fetch(tree, "tool")
        assert done.returncode == 0, done.stderr
        assert (tree / "external" / "tool" / "build.txt").exists()
        assert not (tree / "external" / "other").exists()
        assert not (tree / "capa-ran").exists()

    def test_a_run_without_names_reaches_the_rule_corpora(self, tmp_path: Path) -> None:
        tree = _tree(tmp_path, _upstream(tmp_path).as_uri())
        assert _fetch(tree).returncode == 0
        assert (tree / "external" / "other").exists()
        assert (tree / "capa-ran").exists()

    def test_the_trees_land_in_the_directory_the_variable_names(self, tmp_path: Path) -> None:
        tree = _tree(tmp_path, _upstream(tmp_path).as_uri())
        elsewhere = tmp_path / "elsewhere"
        done = _fetch(tree, "tool", env={"MALSPARK_EXTERNAL_DIR": str(elsewhere)})
        assert done.returncode == 0, done.stderr
        assert (elsewhere / "tool" / "build.txt").read_bytes() == b"version=2\nname=tool\r\n"
        assert not (tree / "external").exists()


def test_every_shipped_patch_names_a_pinned_target() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    pins = {
        f"{name}-{ref}.patch"
        for name, ref in re.findall(r'^  "([^|"]+)\|[^|]+\|([^"]+)"$', text, re.M)
    }
    shipped = {path.name for path in PATCHES.glob("*.patch")}
    assert shipped, "no patch shipped"
    assert shipped <= pins, shipped - pins
