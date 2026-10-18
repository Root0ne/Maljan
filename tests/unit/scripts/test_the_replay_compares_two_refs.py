"""The replay runs under two git refs, each with its own harness, and names what moved.

A repository of the test's own holds this checkout's replay as its working
tree has it (``pyproject.toml``, ``src``, ``data`` with a placeholder under
``data/samples``, and ``scripts/replay``), so that what each ref's tree
replays is what this process replays. Its first commit lacks
``scripts/replay``; the second adds it; the third renames one code; the
fourth breaks one rule.

``--compare HEAD HEAD`` writes HEAD out of that repository's object store
twice and replays the tiny run under each tree's own harness, in a process of
its own, as well as the stored run ``MALJAN_REPLAY_RUN`` names when it is set
(the benchmark's runs are not in the repository). Each tree's record is the
record this process replays, with no part that raised, and the comparison says
no difference. A ref from before the replay tool cannot be compared (status
2). The renamed code is named as one code lost and one gained (status 1). A
rule that raises in both trees is a status 2, and is never "no difference".
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # nosec B404 — git, argument lists only
from pathlib import Path
from typing import Any

import pytest
from scripts.replay import run as replay_cli
from scripts.replay.rules import replay_run
from scripts.replay.stored import read_run

from tests.unit.scripts._replay_tiny import EXPECTED_TOTALS, FIXTURE

ROOT = Path(__file__).resolve().parents[3]
RULE_FILE = "src/maljan/agents/evidence_recorder.py"
OLD_CODE = '"tool.argument_names_its_parameter"'
NEW_CODE = '"tool.argument_is_its_own_name"'
# A rule that raises whenever it is called, put after the one it replaces.
BROKEN_RULE = (
    "\n\ndef self_named_arguments(*_args, **_kwargs):\n"
    '    raise RuntimeError("a rule that breaks")\n'
)
# How a part that raised is named, should a harness ever leave out its mark.
RAISED = re.compile(r"^\w+ at [\w.-]+\.py:\d+ \(")
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


def _working_tree_files() -> list[str]:
    """This checkout's replay files as its working tree has them, committed or not."""
    if shutil.which("git") is None:
        pytest.skip("git is not on this machine")
    listed = subprocess.run(  # nosec B603 B607 — a fixed git argument list
        [
            "git",
            "-C",
            str(ROOT),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "pyproject.toml",
            "src",
            "data",
            ":(exclude)data/samples",
            "scripts/replay",
        ],
        capture_output=True,
        check=False,
    )
    if listed.returncode != 0:
        pytest.skip("this checkout is not a git repository")
    names = [name for name in listed.stdout.decode().split("\0") if name]
    return [name for name in names if (ROOT / name).is_file()]


def _repository(at: Path) -> dict[str, Any]:
    """The test's repository and its four commits."""
    repo = at / "rules"
    for name in _working_tree_files():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, repo / name)
    placeholder = repo / "data" / "samples" / "placeholder.json"
    placeholder.parent.mkdir(parents=True, exist_ok=True)
    placeholder.write_text("{}", encoding="utf-8")
    _git(repo, "init", "--quiet")
    _git(repo, "add", "--", "pyproject.toml", "src", "data")
    _git(repo, "commit", "--quiet", "-m", "the rules, before the replay tool")
    before = _git(repo, "rev-parse", "HEAD")
    _git(repo, "add", "--", "scripts/replay")
    _git(repo, "commit", "--quiet", "-m", "the replay tool")
    tool = _git(repo, "rev-parse", "HEAD")
    return {"repo": repo, "before": before, "tool": tool}


def _commit_change(repo: Path, change: Any, message: str) -> str:
    rule = repo / RULE_FILE
    rule.write_text(change(rule.read_text(encoding="utf-8")), encoding="utf-8")
    _git(repo, "commit", "--quiet", "--all", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _without(record: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k not in keys}


def _raised(record: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        row
        for row in record.get("not_replayed") or []
        if row.get("error") or RAISED.match(str(row.get("why") or ""))
    ]


@pytest.mark.slow
def test_each_ref_is_replayed_by_its_own_harness_and_a_crash_is_never_no_difference(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    made = _repository(tmp_path)
    repo: Path = made["repo"]
    runs = [FIXTURE]
    extra = os.environ.get("MALJAN_REPLAY_RUN")
    if extra:
        runs.append(Path(extra))

    # HEAD against itself: each tree replays what this process replays.
    work = tmp_path / "work"
    out = tmp_path / "same.json"
    argv = [str(r) for r in runs] + ["--repo", str(repo), "--work", str(work)]
    assert replay_cli.main([*argv, "--compare", "HEAD", "HEAD", "--json", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "no difference: both refs decide the same over this run" in printed
    diffs = json.loads(out.read_text(encoding="utf-8"))
    diffs = diffs if isinstance(diffs, list) else [diffs]
    assert diffs == [{"run": run.name} for run in runs]
    in_process = [replay_run(read_run(run)) for run in runs]
    assert in_process[0]["totals"] == EXPECTED_TOTALS
    for side in ("a", "b"):
        records = json.loads((work / f"{side}-replay.json").read_text(encoding="utf-8"))
        records = records if isinstance(records, list) else [records]
        for record, expected in zip(records, in_process, strict=True):
            assert Path(record["rules"]["tree"]) == (work / f"{side}-tree").resolve()
            assert _raised(record) == []
            assert _without(record, "rules", "stored") == _without(expected, "rules")
    tree = work / "a-tree"
    assert (tree / "pyproject.toml").is_file()
    assert (tree / "scripts" / "replay" / "run.py").is_file()
    assert (tree / "data" / "attck_techniques.json").is_file()
    assert not (tree / "data" / "samples").exists()

    # A ref from before the replay tool has no harness to replay its rules with.
    with pytest.raises(SystemExit) as ended:
        replay_cli.main([str(FIXTURE), "--repo", str(repo), "--compare", made["before"], "HEAD"])
    assert ended.value.code == 2
    assert "predates the replay tool" in capsys.readouterr().err

    # A ref's replay given less time than it takes is stopped, and the ref named.
    with pytest.raises(SystemExit) as ended:
        replay_cli.main(
            [str(FIXTURE), "--repo", str(repo), "--compare", "HEAD", "HEAD", "--timeout", "0.001"]
        )
    assert ended.value.code == 2
    assert "HEAD: the replay under" in (said := capsys.readouterr().err)
    assert "did not finish within 0.001 s and was stopped" in said

    # One code renamed: one lost, one gained, and nothing else moved.
    renamed = _commit_change(repo, lambda text: text.replace(OLD_CODE, NEW_CODE), "a code renamed")
    moved = tmp_path / "moved.json"
    argv = [str(FIXTURE), "--repo", str(repo), "--json", str(moved), "--quiet"]
    assert replay_cli.main([*argv, "--compare", made["tool"], renamed]) == 1
    diff = json.loads(moved.read_text(encoding="utf-8"))
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

    # A rule that raises in both trees: the same failure on both sides is an
    # error, not an agreement.
    broken = _commit_change(repo, lambda text: text + BROKEN_RULE, "a rule that breaks")
    crashed = tmp_path / "crashed.json"
    argv = [str(FIXTURE), "--repo", str(repo), "--json", str(crashed)]
    assert replay_cli.main([*argv, "--compare", broken, broken]) == 2
    printed = capsys.readouterr().out
    assert "ERROR under A" in printed and "ERROR under B" in printed
    assert "no difference" not in printed
    diff = json.loads(crashed.read_text(encoding="utf-8"))
    for side in ("a", "b"):
        assert [row["part"] for row in diff["errors"][side]] == ["tool"]
        assert diff["errors"][side][0]["error"] is True
        assert diff["errors"][side][0]["why"].startswith("RuntimeError at evidence_recorder.py:")
    assert set(diff) == {"run", "errors"}
