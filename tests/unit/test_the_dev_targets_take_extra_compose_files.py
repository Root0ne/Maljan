"""The dev targets append the compose files COMPOSE_FILE_EXTRA names.

Compose reads ``docker-compose.override.yml`` on its own only when it is given
no ``-f``; ``make dev-up`` gives it two (the shipped file and the dev overlay),
so a host's own overrides reach the dev stack only through COMPOSE_FILE_EXTRA.
Read from ``make -n``, make's own expansion, from the environment and from the
command line alike.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SHIPPED = "-f docker/docker-compose.yml -f docker/docker-compose.dev.yml"

pytestmark = pytest.mark.skipif(shutil.which("make") is None, reason="needs make")

TARGETS = {"dev-up": " up -d", "dev-down": " --profile '*' down", "dev-logs": " logs -f"}


def _compose_line(target: str, *args: str, extra: str | None = None) -> str:
    env = {k: v for k, v in os.environ.items() if k != "COMPOSE_FILE_EXTRA"}
    if extra is not None:
        env["COMPOSE_FILE_EXTRA"] = extra
    dry = subprocess.run(
        ["make", "-s", "-n", target, *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout
    [line] = [line for line in dry.splitlines() if "docker compose" in line]
    return " ".join(line[line.index("docker compose") :].split())


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_without_extra_files_the_two_shipped_files_are_passed(target: str) -> None:
    assert _compose_line(target) == f"docker compose {SHIPPED}{TARGETS[target]}"


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_each_extra_file_is_appended_after_the_shipped_ones_in_order(target: str) -> None:
    line = _compose_line(target, extra="docker/local.yml  /srv/gpu.yml")
    expected = f"docker compose {SHIPPED} -f docker/local.yml -f /srv/gpu.yml{TARGETS[target]}"
    assert line == expected


def test_the_extra_files_may_be_given_on_the_command_line() -> None:
    line = _compose_line("dev-up", "COMPOSE_FILE_EXTRA=docker/local.yml")
    assert line == f"docker compose {SHIPPED} -f docker/local.yml up -d"
