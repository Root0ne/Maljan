"""Every backend service that can start a stdio tool server mounts the same trees.

A console trust grant (``tool_declarations.granted_launch``) is recorded by the
API with the files a server's launch resolves to there, and is checked where
the server is started: the analysis worker and the enrichment worker. A tree a
command, working directory or argument may live in that one of them mounts and
another does not resolves differently, so the grant would silently never hold
there. Each compose file mounts, in every such service it defines, the same
trees under ``/app``; a writable mount below one of them (the sample and upload
directories) changes no path and is left to each service, and so is a cache
mounted outside ``/app`` (a path there fails closed at grant time in the API).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILES = sorted((ROOT / "docker").glob("docker-compose*.yml"))

# The services built from the backend image that start stdio tool servers.
LAUNCHERS = ("backend-api", "backend-worker", "enrichment-worker")


def _trees(service: dict) -> set[str]:
    """The ``/app`` trees a service bind-mounts, a mount below another one left out."""
    targets: set[str] = set()
    for entry in service.get("volumes") or []:
        if isinstance(entry, str) and entry.startswith(".."):
            target = entry.split(":")[1]
            if target.startswith("/app/"):
                targets.add(target)
    return {t for t in targets if not any(t.startswith(f"{o}/") for o in targets if o != t)}


def test_the_compose_files_are_found() -> None:
    assert {p.name for p in COMPOSE_FILES} >= {"docker-compose.yml", "docker-compose.dev.yml"}


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_every_launching_service_mounts_the_trees_the_others_mount(path: Path) -> None:
    services = yaml.safe_load(path.read_text(encoding="utf-8")).get("services") or {}
    held = {name: _trees(services[name]) for name in LAUNCHERS if name in services}
    mounting = {name: trees for name, trees in held.items() if trees}
    union = set().union(*mounting.values()) if mounting else set()
    for name, trees in mounting.items():
        assert trees == union, (path.name, name, sorted(union - trees))


def test_the_production_file_mounts_the_launch_trees_in_every_launching_service() -> None:
    services = yaml.safe_load((ROOT / "docker" / "docker-compose.yml").read_text())["services"]
    for name in LAUNCHERS:
        assert _trees(services[name]) >= {"/app/data", "/app/services", "/app/src"}, name
