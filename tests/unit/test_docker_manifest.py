"""Every COPY source in the backend Dockerfile must exist in the tree.

``docker build`` is the slowest way to learn that a directory was renamed, and on
this box it is also the most expensive. The Dockerfile's COPY operands are a
manifest of what the image needs; checking them against the working tree costs
milliseconds and catches the sidecar move (Task 3) and the manifests-first
rewrite (Task 2) at commit time.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "docker" / "Dockerfile.backend"


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


def test_every_backend_copy_source_exists() -> None:
    missing = sorted(s for s in copy_sources(BACKEND) if not (ROOT / s.rstrip("/")).exists())
    assert missing == [], f"Dockerfile.backend copies paths that are not there: {missing}"
