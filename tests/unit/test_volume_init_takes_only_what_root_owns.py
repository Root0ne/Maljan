"""volume-init hands what root owns to the backend's uid and never takes anyone else's files.

The backend containers used to run as root, so an existing deployment's sample
mirror, upload staging and ATT&CK cache hold root-owned entries the
unprivileged services could not write. The compose file's one-shot
``volume-init`` service chowns exactly those entries to MALJAN_UID:MALJAN_GID.
An entry owned by any other uid or gid belongs to somebody (a developer's own
checkout, typically): the script stops before changing anything and names the
id to set, so the stack refuses to start rather than take the files.

The script is run here as the compose file ships it: on the host against
scratch directories for the refusals, and as root in a throwaway container for
the chown itself (it needs a root-owned file to hand over).
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker" / "docker-compose.yml"
DOCKERFILE = ROOT / "docker" / "Dockerfile.backend"
MOUNTS = ("data/samples", "data/uploads", "attck_cache")


def _script() -> str:
    """The script as the container's shell receives it (compose's ``$$`` is one ``$``)."""
    service = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["volume-init"]
    assert service["command"][:2] == ["/bin/sh", "-euc"]
    return str(service["command"][-1]).replace("$$", "$")


def _run_on_host(tmp_path: Path, uid: str, gid: str) -> subprocess.CompletedProcess[str]:
    for mount in MOUNTS:
        (tmp_path / "own" / mount).mkdir(parents=True, exist_ok=True)
    script = _script().replace("/own/", f"{tmp_path}/own/")
    return subprocess.run(
        ["sh", "-euc", script],
        env={"PATH": "/usr/bin:/bin", "MALJAN_UID": uid, "MALJAN_GID": gid},
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.mark.parametrize(
    ("uid", "gid"),
    [("0", "10001"), ("10001", "0"), ("", "10001"), ("10001", ""), ("00", "10001"), ("x1", "1")],
)
def test_root_and_empty_or_non_numeric_ids_are_refused(tmp_path: Path, uid: str, gid: str) -> None:
    result = _run_on_host(tmp_path, uid, gid)
    assert result.returncode != 0
    assert "MALJAN_UID and MALJAN_GID must be non-zero numbers" in result.stderr


host_find = pytest.mark.skipif(
    not sys.platform.startswith("linux") or os.geteuid() == 0,
    reason="needs GNU find and a non-root user, whose own files are someone else's to the script",
)


@host_find
def test_files_another_uid_owns_stop_it_with_the_id_to_set(tmp_path: Path) -> None:
    mine = os.getuid()
    other = mine + 1
    result = _run_on_host(tmp_path, str(other), str(os.getgid()))
    assert result.returncode != 0
    assert (
        f"volume-init: data/samples is owned by uid {mine}; "
        f"set MALJAN_UID/MALJAN_GID={mine} in docker/.env"
    ) in result.stderr


@host_find
def test_files_another_gid_owns_stop_it_too(tmp_path: Path) -> None:
    mine = os.getgid()
    result = _run_on_host(tmp_path, str(os.getuid()), str(mine + 1))
    assert result.returncode != 0
    assert f"volume-init: data/samples is owned by gid {mine}; set MALJAN_GID={mine}" in (
        result.stderr
    )


@host_find
def test_volumes_already_the_target_s_are_left_alone(tmp_path: Path) -> None:
    (tmp_path / "own" / "data" / "samples").mkdir(parents=True)
    (tmp_path / "own" / "data" / "samples" / "kept").write_bytes(b"x")
    result = _run_on_host(tmp_path, str(os.getuid()), str(os.getgid()))
    assert result.returncode == 0, result.stderr


# Run as root in a container: seed root-owned, already-correct, foreign and
# symbolic-link entries, run the shipped script with only the capabilities the
# service has, and print what it left.
CONTAINER_CHECK = r"""
set -u
mkdir -p /own/data/samples/.work/abc /own/data/uploads /own/attck_cache /outside
chmod 700 /own/data/samples/.work /own/data/samples/.work/abc
printf 'sample' > /own/data/samples/.work/abc/f
chmod 600 /own/data/samples/.work/abc/f
printf 'keep' > /outside/keep
ln -s /outside/keep /own/data/samples/link
mkdir /own/data/uploads/done
touch /own/data/uploads/done/rootfile
chmod 700 /own/data/uploads/done
chown 10001:10001 /own/data/uploads/done
if [ "$PHASE" = foreign ]; then
  chown 4242 /own/data/uploads
  sh -euc "$(cat /s.sh)"; echo "foreign=$?"
  find /own -printf 'AFTER %U:%G %p\n'
else
  sh -euc "$(cat /s.sh)"; echo "first=$?"
  sh -euc "$(cat /s.sh)"; echo "second=$?"
  find /own /outside -printf 'OWNER %U:%G %p\n'
  sha256sum /own/data/samples/.work/abc/f
fi
"""


def _base_image() -> str:
    images = re.findall(r"^FROM (\S+) AS base$", DOCKERFILE.read_text(encoding="utf-8"), re.M)
    assert len(images) == 1
    return str(images[0])


def _image_present(image: str) -> bool:
    if shutil.which("docker") is None:
        return False
    found = subprocess.run(
        ["docker", "image", "inspect", image], capture_output=True, text=True, timeout=60
    )
    return found.returncode == 0


@pytest.mark.skipif(
    not _image_present(_base_image()), reason="docker or the backend's base image not present"
)
def test_only_root_owned_entries_are_handed_over_and_a_foreign_owner_stops_it(
    tmp_path: Path,
) -> None:
    script = tmp_path / "s.sh"
    script.write_text(_script())
    check = tmp_path / "t.sh"
    check.write_text(CONTAINER_CHECK)

    def run(phase: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "0:0",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "CHOWN",
                "--cap-add",
                "DAC_READ_SEARCH",
                "--security-opt",
                "no-new-privileges:true",
                "-e",
                "MALJAN_UID=10001",
                "-e",
                "MALJAN_GID=10001",
                "-e",
                f"PHASE={phase}",
                "-v",
                f"{script}:/s.sh:ro",
                "-v",
                f"{check}:/t.sh:ro",
                "--entrypoint",
                "/bin/sh",
                _base_image(),
                "/t.sh",
            ],  # fmt: skip
            capture_output=True,
            text=True,
            timeout=180,
        )

    result = run("migrate")
    out = result.stdout
    assert result.returncode == 0, result.stderr

    assert "first=0" in out and "second=0" in out
    owners = dict(
        (line.split(" ", 2)[2], line.split(" ", 2)[1])
        for line in out.splitlines()
        if line.startswith("OWNER ")
    )
    mounts = tuple(f"/own/{mount}" for mount in MOUNTS)
    for path, owner in owners.items():
        if path.startswith(mounts):
            assert owner == "10001:10001", (path, owner)
    # Every root-owned entry was handed over, the link itself and not its target.
    assert owners["/own/data/samples/.work/abc/f"] == "10001:10001"
    assert owners["/own/data/samples/link"] == "10001:10001"
    assert owners["/own/data/uploads/done/rootfile"] == "10001:10001"
    assert owners["/outside/keep"] == "0:0"
    # Not a mount it was given.
    assert owners["/own"] == owners["/own/data"] == "0:0"
    # Ownership only: the sample's bytes are what they were.
    digest = re.search(r"^([0-9a-f]{64})  /own/data/samples/\.work/abc/f$", out, re.M)
    assert digest
    assert digest.group(1) == hashlib.sha256(b"sample").hexdigest()

    # A foreign owner anywhere stops it before it changes anything.
    result = run("foreign")
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "foreign=1" in out
    assert "data/uploads is owned by uid 4242; set MALJAN_UID/MALJAN_GID=4242" in result.stderr
    after = dict(
        (line.split(" ", 2)[2], line.split(" ", 2)[1])
        for line in out.splitlines()
        if line.startswith("AFTER ")
    )
    assert after["/own/data/samples/.work/abc/f"] == "0:0"
    assert after["/own/data/uploads"] == "4242:0"


# The Makefile's up targets choose the ids volume-init hands the volumes to.
# Their prefix is taken from `make -n` (make's own unescaping) and run under
# dash, the /bin/sh make uses on Debian and Ubuntu.
needs_make_and_dash = pytest.mark.skipif(
    shutil.which("make") is None or shutil.which("dash") is None,
    reason="needs make and dash",
)


def _compose_ids(
    tmp_path: Path, env: dict[str, str], dotenv: str | None = None, uid: int = 1000
) -> tuple[str, str]:
    dry = subprocess.run(
        ["make", "-s", "-n", "docker-up"], cwd=ROOT, capture_output=True, text=True, timeout=60
    ).stdout
    prefix = dry.split(" cd docker &&", 1)[0]
    assert prefix.rstrip().endswith(";"), dry
    (tmp_path / "docker").mkdir(exist_ok=True)
    if dotenv is not None:
        (tmp_path / "docker" / ".env").write_text(dotenv)
    # `id` answers as the user it is told to be.
    shims = tmp_path / "shims"
    shims.mkdir(exist_ok=True)
    fake = shims / "id"
    fake.write_text(f"#!/bin/sh\necho {uid}\n")
    fake.chmod(0o755)
    result = subprocess.run(
        ["dash", "-c", prefix + ' printf "%s %s" "$MALJAN_UID" "$MALJAN_GID"'],
        cwd=tmp_path,
        env={"PATH": f"{shims}:/usr/bin:/bin", **env},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    uid_out, gid_out = result.stdout.split(" ")
    return uid_out, gid_out


@needs_make_and_dash
def test_under_sudo_the_ids_are_the_invoking_user_s(tmp_path: Path) -> None:
    ids = _compose_ids(tmp_path, {"SUDO_UID": "1234", "SUDO_GID": "1235"}, uid=0)
    assert ids == ("1234", "1235")


@needs_make_and_dash
def test_an_id_that_comes_out_root_falls_back_to_the_image_s(tmp_path: Path) -> None:
    assert _compose_ids(tmp_path, {}, uid=0) == ("10001", "10001")
    assert _compose_ids(tmp_path, {"SUDO_UID": "0", "SUDO_GID": "0"}, uid=0) == ("10001", "10001")


@needs_make_and_dash
def test_a_plain_user_s_own_ids_are_used(tmp_path: Path) -> None:
    assert _compose_ids(tmp_path, {}, uid=1000) == ("1000", "1000")


@needs_make_and_dash
def test_docker_env_is_read_without_quotes_spaces_or_comment(tmp_path: Path) -> None:
    dotenv = "X=1\nMALJAN_UID=\"2000\"\n  MALJAN_GID = '2001'  # the docs group\r\n"
    assert _compose_ids(tmp_path, {"SUDO_UID": "1234"}, dotenv=dotenv, uid=0) == ("2000", "2001")


@needs_make_and_dash
def test_the_environment_wins_over_docker_env(tmp_path: Path) -> None:
    dotenv = "MALJAN_UID=2000\nMALJAN_GID=2001\n"
    assert _compose_ids(tmp_path, {"MALJAN_UID": "3000"}, dotenv=dotenv) == ("3000", "2001")
