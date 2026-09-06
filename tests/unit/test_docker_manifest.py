"""Every COPY source in the Docker images must exist in the tree.

``docker build`` is the slowest way to learn that a directory was renamed, and on
this box it is also the most expensive. Each Dockerfile's COPY operands are a
manifest of what the image needs; checking them against the working tree costs
milliseconds and catches the sidecar move (Task 3) and the manifests-first
rewrite (Task 2) at commit time.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "docker" / "Dockerfile.backend"
FRONTEND = ROOT / "docker" / "Dockerfile.frontend"


def copy_sources(dockerfile: Path) -> list[str]:
    """The <src> operands of every COPY that reads from the build context."""
    sources: list[str] = []
    for raw in dockerfile.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line.upper().startswith("COPY "):
            continue
        parts = line.split()[1:]
        # ``COPY --from=<image> ...`` reads from another stage, not the context.
        if any(p.startswith("--from=") for p in parts):
            continue
        parts = [p for p in parts if not p.startswith("--")]
        # The last operand is the destination inside the image.
        sources.extend(parts[:-1])
    return sources


def test_the_backend_dockerfile_copies_something() -> None:
    assert len(copy_sources(BACKEND)) >= 4


def _copy_source_exists(source: str) -> bool:
    """A trailing ``*`` is a Docker glob for an optional file; match it."""
    if source.endswith("*"):
        return any(ROOT.glob(source))
    return (ROOT / source.rstrip("/")).exists()


@pytest.mark.parametrize("dockerfile", [BACKEND, FRONTEND], ids=["backend", "frontend"])
def test_every_copy_source_exists(dockerfile: Path) -> None:
    missing = sorted(s for s in copy_sources(dockerfile) if not _copy_source_exists(s))
    assert missing == [], f"{dockerfile.name} copies paths that are not there: {missing}"
