"""Which FLOSS executable the ``floss`` tool accepts on each machine (T-573).

FLARE's standalone build is x86-64 only. On arm64 the backend image runs the
same release from an environment of its own through ``scripts/floss/floss``,
so the digest an executable must have depends on the host's machine: the
launcher's on arm64, the standalone build's on every other, x86-64 among them.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from malspark.tools import emulated_strings as tool

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize("machine", ["x86_64", "AMD64", "i686", "riscv64", ""])
def test_every_machine_but_arm64_accepts_the_standalone_build_alone(machine: str) -> None:
    assert tool.accepted_sha256s(machine) == {tool.FLOSS_BINARY_SHA256}


@pytest.mark.parametrize("machine", ["aarch64", "arm64", "ARM64"])
def test_arm64_accepts_the_launcher_and_the_standalone_build(machine: str) -> None:
    # The standalone build stays acceptable there: under x86-64 emulation it
    # runs, and the version probe is what says whether it does.
    assert tool.accepted_sha256s(machine) == {
        tool.FLOSS_BINARY_SHA256,
        tool.FLOSS_LAUNCHER_SHA256,
    }


def test_the_launcher_is_the_file_the_module_pins() -> None:
    launcher = ROOT / "scripts" / "floss" / "floss"
    assert hashlib.sha256(launcher.read_bytes()).hexdigest() == tool.FLOSS_LAUNCHER_SHA256
    assert tool.FLOSS_LAUNCHER_SHA256 != tool.FLOSS_BINARY_SHA256
    first = launcher.read_text(encoding="utf-8").splitlines()[0]
    # The environment's own interpreter, isolated from the caller's variables,
    # the user's site directory and the directory the run's copy sits in, not
    # importing site (so no .pth runs before the check) and writing no bytecode.
    assert first == "#!/opt/floss/bin/python3 -ISB"


def _fake(tmp_path: Path, name: str) -> Path:
    target = tmp_path / name
    target.write_bytes(f"#!/bin/sh\n# {name}\n".encode())
    target.chmod(0o755)
    return target


def test_only_an_arm64_host_accepts_the_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    standalone, launcher = _fake(tmp_path, "standalone"), _fake(tmp_path, "launcher")
    digest = {
        path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (standalone, launcher)
    }
    monkeypatch.setattr(tool, "FLOSS_BINARY_SHA256", digest[standalone])
    monkeypatch.setattr(tool, "FLOSS_LAUNCHER_SHA256", digest[launcher])
    expected = {
        "aarch64": {standalone: True, launcher: True},
        "x86_64": {standalone: True, launcher: False},
    }
    for machine, verdicts in expected.items():
        monkeypatch.setattr(tool.platform, "machine", lambda machine=machine: machine)
        for path, accepted in verdicts.items():
            tool._VERIFIED.clear()
            assert tool._is_pinned_build(path) is accepted, (machine, path.name)
    tool._VERIFIED.clear()


def test_the_image_installs_the_release_from_hashes_on_arm64_and_the_zip_on_amd64() -> None:
    dockerfile = (ROOT / "docker" / "Dockerfile.backend").read_text(encoding="utf-8")
    assert re.search(r"^FROM floss-\$\{TARGETARCH\} AS floss$", dockerfile, re.MULTILINE)
    assert re.findall(r"^FROM \S+ AS (floss-\w+)$", dockerfile, re.MULTILINE) == [
        "floss-amd64",
        "floss-arm64",
    ]
    arm64 = dockerfile[dockerfile.index(" AS floss-arm64") : dockerfile.index(" AS floss\n")]
    assert "--require-hashes -r scripts/floss/requirements-build.txt" in arm64
    assert "--require-hashes --no-build-isolation -r scripts/floss/requirements.txt" in arm64
    assert "scripts/floss/floss" in arm64
    requirements = (ROOT / "scripts" / "floss" / "requirements.txt").read_text(encoding="utf-8")
    assert f"flare-floss=={tool.FLOSS_VERSION} \\" in requirements
    for name in ("requirements.txt", "requirements-build.txt"):
        text = (ROOT / "scripts" / "floss" / name).read_text(encoding="utf-8")
        pins = re.findall(r"^[A-Za-z0-9_.-]+==\S+", text, re.MULTILINE)
        hashed = re.findall(r"^[A-Za-z0-9_.-]+==\S+[^\n]*\\\n\s+--hash=sha256:", text, re.MULTILINE)
        assert pins and len(hashed) == len(pins), name
