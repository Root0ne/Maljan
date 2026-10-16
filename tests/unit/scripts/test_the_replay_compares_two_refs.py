"""The replay runs under two git refs and names what the change between them moved.

A repository of the test's own holds this checkout's rules (``src`` and the
``data`` tables, written out with ``git archive``) at a first commit, and a
second commit that renames one code. ``--compare`` writes each ref out of that
repository's object store, replays the tiny stored run under each in a process
of its own, and names the code the second ref lost and the one it gained.
The same ref twice decides the same. No sample is written out with the rules.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess  # nosec B404 — git, argument lists only
import tarfile
from pathlib import Path

import pytest
from scripts.replay import run as replay_cli

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "tests" / "fixtures" / "replay" / "tiny"
RULE_FILE = "src/maljan/agents/evidence_recorder.py"
OLD_CODE = '"tool.argument_names_its_parameter"'
NEW_CODE = '"tool.argument_is_its_own_name"'
# A commit of the test's own needs a name, and no hook or signing of the
# machine's may run on it.
GIT = (
    "-c",
    "user.name=Replay Test",
    "-c",
    "user.email=replay-test@example.invalid",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "commit.gpgsign=false",
)


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(  # nosec B603 B607 — a fixed git argument list
        ["git", *GIT, "-C", str(repo), *args], capture_output=True, check=True
    )
    return done.stdout.decode().strip()


def _repository_with_two_refs(at: Path) -> tuple[Path, str, str]:
    """A repository holding this checkout's rules at one commit and one renamed code at the next."""
    if shutil.which("git") is None:
        pytest.skip("git is not on this machine")
    archive = subprocess.run(  # nosec B603 B607 — a fixed git argument list
        [
            "git",
            "-C",
            str(ROOT),
            "archive",
            "--format=tar",
            "HEAD",
            "--",
            "src",
            "data",
            ":(exclude)data/samples",
        ],
        capture_output=True,
        check=True,
    ).stdout
    repo = at / "rules"
    repo.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(repo, filter="data")  # nosec B202 — our own archive, the data filter
    _git(repo, "init", "--quiet")
    _git(repo, "add", "--all")
    _git(repo, "commit", "--quiet", "-m", "the rules as they are")
    first = _git(repo, "rev-parse", "HEAD")
    rule = repo / RULE_FILE
    text = rule.read_text(encoding="utf-8")
    assert OLD_CODE in text
    rule.write_text(text.replace(OLD_CODE, NEW_CODE), encoding="utf-8")
    _git(repo, "commit", "--quiet", "--all", "-m", "one code renamed")
    second = _git(repo, "rev-parse", "HEAD")
    return repo, first, second


@pytest.mark.slow
def test_two_refs_are_replayed_and_the_moved_code_is_named(tmp_path: Path) -> None:
    repo, first, second = _repository_with_two_refs(tmp_path)
    work = tmp_path / "work"
    out = tmp_path / "diff.json"

    status = replay_cli.main(
        [
            str(FIXTURE),
            "--compare",
            first,
            second,
            "--repo",
            str(repo),
            "--work",
            str(work),
            "--json",
            str(out),
            "--quiet",
        ]
    )

    assert status == 1
    diff = json.loads(out.read_text(encoding="utf-8"))
    assert diff["codes_lost"] == [
        {
            "part": "tool",
            "owner": "ev_0002",
            "code": "tool.argument_names_its_parameter",
            "count": 1,
        }
    ]
    assert diff["codes_gained"] == [
        {"part": "tool", "owner": "ev_0002", "code": "tool.argument_is_its_own_name", "count": 1}
    ]
    assert set(diff) <= {"run", "codes_lost", "codes_gained", "totals"}
    tree = work / "a-tree"
    assert (tree / "data" / "attck_techniques.json").is_file()
    assert not (tree / "data" / "samples").exists()

    same = tmp_path / "same.json"
    assert (
        replay_cli.main(
            [
                str(FIXTURE),
                "--compare",
                first,
                first,
                "--repo",
                str(repo),
                "--json",
                str(same),
                "--quiet",
            ]
        )
        == 0
    )
    assert json.loads(same.read_text(encoding="utf-8")) == {"run": "tiny"}
