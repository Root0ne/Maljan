"""The images built natively for amd64 and arm64 verify what they fetch (T-573).

Each per-architecture download is checked against its own sha256 before it is
unpacked or installed, GoReSym's arm64 stage builds the pinned commit with the
image's own toolchain and the checksum database left on, and the backend's
arm64 FLOSS environment comes from hashed requirements alone.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

NATIVE_DOCKERFILES = (
    "docker/Dockerfile.backend",
    "services/goresym-mcp/Dockerfile",
    "services/jadx-mcp/Dockerfile",
    "services/unblob-mcp/Dockerfile",
    "services/webcrack-mcp/Dockerfile",
    "services/yarax-mcp/Dockerfile",
)
# What unpacks or installs a fetched file, which only a checked file may reach.
CONSUMERS = ("tarfile.open", "zipfile.ZipFile", "tar -x", "apt-get install", "install -m", "mv ")


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _runs(dockerfile: str) -> list[str]:
    """Each RUN instruction with its continuation lines joined."""
    joined = re.sub(r"\\\n", " ", dockerfile)
    return [line[4:] for line in joined.splitlines() if line.startswith("RUN ")]


@pytest.mark.parametrize("relative", NATIVE_DOCKERFILES)
def test_each_pinned_digest_is_checked_before_what_it_pins_is_used(relative: str) -> None:
    dockerfile = _text(relative)
    runs = _runs(dockerfile)
    digests = re.findall(r"^ARG (\w*SHA256)=[0-9a-f]{64}$", dockerfile, re.MULTILINE)
    assert digests, relative
    for name in digests:
        (run,) = [run for run in runs if "${" + name + "}" in run]
        # Checked directly, or through the variable the architecture's case set.
        held = re.findall(rf'(\w+)="\$\{{{name}\}}"', run)
        checked = [name, *held]
        assert any(
            re.search(rf'echo "\$\{{{var}\}}  [^"]+" \| sha256sum -c -', run) for var in checked
        ), (relative, name)
        first_check = run.index("sha256sum -c -")
        used = [run.find(token) for token in CONSUMERS if token in run]
        if "go build" in run:
            # A binary built here is checked last and copied by a later stage.
            assert run.index("go build") < first_check, (relative, name)
            continue
        assert used and min(used) > first_check, (relative, name)


def test_the_goresym_arm64_stage_builds_the_pinned_commit_with_its_own_toolchain() -> None:
    dockerfile = _text("services/goresym-mcp/Dockerfile")
    stage = dockerfile[dockerfile.index("AS goresym-arm64") : dockerfile.index("AS goresym\n")]
    assert re.search(
        r"^FROM --platform=\$BUILDPLATFORM golang:\S+@sha256:[0-9a-f]{64} AS goresym-arm64$",
        dockerfile,
        re.MULTILINE,
    )
    assert "GOTOOLCHAIN=local" in stage
    (goflags,) = re.findall(r'GOFLAGS="([^"]*)"', stage)
    assert "-mod=readonly" in goflags.split()
    for weakened in ("GOSUMDB=off", "GONOSUMDB", "GOPRIVATE", "GOINSECURE", "GOPROXY", "-mod=mod"):
        assert weakened not in dockerfile, weakened
    assert re.search(r"^ARG GORESYM_COMMIT=[0-9a-f]{40}$", stage, re.MULTILINE)
    assert 'commit="$(git rev-parse HEAD)"' in stage
    assert '"${commit}" != "${GORESYM_COMMIT}"' in stage
    assert "GOARCH=arm64 go build" in stage
    assert re.search(
        r'echo "\$\{GORESYM_ARM64_BINARY_SHA256\}  /out/GoReSym" \| sha256sum -c -', stage
    )


@pytest.mark.parametrize("name", ["requirements.txt", "requirements-build.txt"])
def test_the_floss_environment_comes_from_hashed_pins_alone(name: str) -> None:
    text = (ROOT / "scripts" / "floss" / name).read_text(encoding="utf-8")
    lines = [line.strip() for line in text.splitlines() if not line.lstrip().startswith("#")]
    for line in lines:
        # No other index, no local or editable source, no URL to fetch from.
        assert not re.match(r"(-i|-f|-e|--index-url|--extra-index-url|--find-links)\b", line), line
        assert not line.startswith(("--trusted-host", "--editable")), line
        assert "://" not in line and " @ " not in line, line
    pins = re.findall(r"^[A-Za-z0-9_.-]+==\S+", text, re.MULTILINE)
    hashed = re.findall(r"^[A-Za-z0-9_.-]+==\S+[^\n]*\\\n\s+--hash=sha256:", text, re.MULTILINE)
    assert pins and len(hashed) == len(pins)


def test_the_arm64_floss_stage_stops_unless_the_launcher_reports_the_release() -> None:
    dockerfile = _text("docker/Dockerfile.backend")
    stage = dockerfile[dockerfile.index("AS floss-arm64") : dockerfile.index("AS floss\n")]
    assert '/out/usr/local/bin/floss --version | grep -F "${FLOSS_VERSION}"' in stage
    assert stage.count("--no-compile --require-hashes") == 2
    assert "find /opt/floss -name __pycache__" in stage
