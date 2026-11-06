"""A fresh clone of a pinned external tree ends at the pin, whatever the default branch added.

A tool's default branch can add a ``.gitattributes`` with line-ending
normalisation while the pinned tag still holds CRLF files. A clone that checks
out the default branch first sees those files as modified and the checkout of
the pin stops. The script clones without a checkout, so that tree is never
written. Everything here is a local ``file://`` repository.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "dev" / "fetch_external.sh"

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

# The developer's own git config (core.autocrlf, url.*.insteadOf) never reaches these runs.
_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(
        [
            "git",
            "-c",
            "user.name=T",
            "-c",
            "user.email=t@example.com",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        cwd=cwd,
        env=_ENV,
        check=True,
        capture_output=True,
        text=True,
    )
    return done.stdout.strip()


def _upstream(tmp_path: Path) -> Path:
    """A repo with CRLF files at tag v1 and a default branch that normalises them."""
    repo = tmp_path / "upstream"
    repo.mkdir()
    _git(repo, "init", "--quiet", "-b", "main")
    (repo / "setup.ps1").write_bytes(b"echo one\r\necho two\r\n")
    (repo / "gradlew.bat").write_bytes(b"@echo off\r\nexit\r\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "crlf files")
    _git(repo, "tag", "v1")
    # The default branch moves on in the same files, still CRLF, so they differ from the tag ...
    (repo / "setup.ps1").write_bytes(b"echo three\r\n")
    (repo / "gradlew.bat").write_bytes(b"@echo off\r\nexit 1\r\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "move on")
    # ... and then adds the rule, which makes those CRLF files look modified once checked out.
    (repo / ".gitattributes").write_text("* text eol=lf\n")
    _git(repo, "add", ".gitattributes")
    _git(repo, "commit", "--quiet", "-m", "normalise line endings")
    return repo


def _tree_with_script(tmp_path: Path, url: str, ref: str) -> Path:
    """A copy of the script whose one target is the local repo, with nothing else fetched."""
    tree = tmp_path / "tree"
    (tree / "scripts" / "dev").mkdir(parents=True)
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index("targets=(")
    end = text.index("\n)\n", start) + 3
    text = text[:start] + f'targets=(\n  "tool|{url}|{ref}"\n)\n' + text[end:]
    (tree / "scripts" / "dev" / "fetch_external.sh").write_text(text, encoding="utf-8")
    (tree / "scripts" / "dev" / "fetch_capa_data.sh").write_text("exit 0\n")
    # Present and not a checkout: the script skips the Sigma clone instead of fetching it.
    (tree / "data" / "sigma_rules").mkdir(parents=True)
    return tree


def _fetch(tree: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(tree / "scripts" / "dev" / "fetch_external.sh")],
        capture_output=True,
        text=True,
        env=_ENV,
        check=False,
    )


class TestAFreshCloneEndsAtThePin:
    def test_a_tag_whose_files_the_default_branch_normalises(self, tmp_path: Path) -> None:
        upstream = _upstream(tmp_path)
        tree = _tree_with_script(tmp_path, upstream.as_uri(), "v1")
        done = _fetch(tree)
        assert done.returncode == 0, done.stderr
        dest = tree / "external" / "tool"
        assert _git(dest, "rev-parse", "HEAD") == _git(upstream, "rev-parse", "v1^{commit}")
        assert (dest / "setup.ps1").read_bytes() == b"echo one\r\necho two\r\n"
        assert not (dest / ".gitattributes").exists()

    def test_a_commit_sha_and_a_branch_are_checked_out_as_well(self, tmp_path: Path) -> None:
        upstream = _upstream(tmp_path)
        _git(upstream, "branch", "release", "v1")
        sha = _git(upstream, "rev-parse", "v1^{commit}")
        for number, ref in enumerate((sha, "release")):
            tree = _tree_with_script(tmp_path / str(number), upstream.as_uri(), ref)
            done = _fetch(tree)
            assert done.returncode == 0, done.stderr
            assert _git(tree / "external" / "tool", "rev-parse", "HEAD") == sha
