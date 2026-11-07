"""``make create-admin`` hands the address to the command as written, and nothing else.

The address is the operator's text pasted into a recipe: a quote in it once
closed the recipe's quoting and ran what followed, a ``$(...)`` was expanded by
make, and a leading ``-`` was read as an option. The recipe is read from
``make -n`` and also run, with a ``docker`` on PATH that prints each argument
it is given on a line of its own.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(shutil.which("make") is None, reason="needs make")

ADDRESSES = [
    "you@example.com",
    "o'neil@example.com",
    "x'; touch {canary}; '",
    "$(shell touch {canary})a@example.com",
    "$(touch {canary})a@example.com",
    "`touch {canary}`a@example.com",
    '-x"y@example.com',
]


def _env(tmp_path: Path) -> dict[str, str]:
    shims = tmp_path / "shims"
    shims.mkdir(exist_ok=True)
    docker = shims / "docker"
    docker.write_text('#!/bin/sh\nfor a in "$@"; do printf "[%s]\\n" "$a"; done\n')
    docker.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k != "EMAIL"}
    env["PATH"] = f"{shims}{os.pathsep}{env.get('PATH', '')}"
    return env


@pytest.mark.parametrize("template", ADDRESSES)
def test_the_address_reaches_the_command_as_one_argument_after_a_double_dash(
    tmp_path: Path, template: str
) -> None:
    canary = tmp_path / "ran"
    address = template.format(canary=canary)
    run = subprocess.run(
        ["make", "-s", "create-admin", f"EMAIL={address}"],
        cwd=ROOT,
        env=_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.splitlines() == [
        "[compose]",
        "[exec]",
        "[backend-api]",
        "[malspark]",
        "[create-admin]",
        "[--]",
        f"[{address}]",
    ]
    assert not canary.exists()


@pytest.mark.parametrize("template", ADDRESSES)
def test_a_dry_run_prints_the_address_quoted_and_runs_nothing(
    tmp_path: Path, template: str
) -> None:
    canary = tmp_path / "ran"
    address = template.format(canary=canary)
    dry = subprocess.run(
        ["make", "-s", "-n", "create-admin", f"EMAIL={address}"],
        cwd=ROOT,
        env=_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout
    quoted = "'" + address.replace("'", "'\\''") + "'"
    assert f"malspark create-admin -- {quoted}" in dry
    assert not canary.exists()


def test_the_address_may_come_from_the_environment(tmp_path: Path) -> None:
    env = {**_env(tmp_path), "EMAIL": "env'@example.com"}
    run = subprocess.run(
        ["make", "-s", "create-admin"], cwd=ROOT, env=env, capture_output=True, text=True
    )
    assert run.returncode == 0 and run.stdout.splitlines()[-1] == "[env'@example.com]"


def test_without_an_address_the_target_says_how_to_call_it(tmp_path: Path) -> None:
    run = subprocess.run(
        ["make", "-s", "create-admin"], cwd=ROOT, env=_env(tmp_path), capture_output=True, text=True
    )
    assert run.returncode != 0 and "usage: make create-admin EMAIL=" in run.stderr
    assert run.stdout == ""
