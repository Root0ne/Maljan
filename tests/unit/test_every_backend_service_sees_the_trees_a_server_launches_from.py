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
The development overlay is checked merged over the production file as well, the
way ``make dev-up`` starts them: an overlay that remounts a tree in one service
but not in another changes what the stack runs with although each file alone
holds.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILES = sorted((ROOT / "docker").glob("docker-compose*.yml"))

BASE = ROOT / "docker" / "docker-compose.yml"
OVERLAY = ROOT / "docker" / "docker-compose.dev.yml"

# The services built from the backend image that start stdio tool servers.
LAUNCHERS = ("backend-api", "backend-worker", "enrichment-worker")


def _services(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")).get("services") or {}


def _target(entry: object) -> str | None:
    """The container path a volume entry mounts at, short or long syntax."""
    if isinstance(entry, dict):
        target = entry.get("target")
        return target if isinstance(target, str) else None
    if isinstance(entry, str):
        parts = entry.split(":")
        return parts[1] if len(parts) > 1 else parts[0]
    return None


def _merged(base: dict, overlay: dict) -> dict:
    """``base`` with ``overlay`` applied per service, volumes merged by target as compose does."""
    services = {name: dict(service or {}) for name, service in base.items()}
    for name, service in overlay.items():
        merged = services.setdefault(name, {})
        for key, value in (service or {}).items():
            if key != "volumes":
                merged[key] = value
                continue
            by_target = {_target(e): e for e in merged.get("volumes") or []}
            by_target.update({_target(e): e for e in value or []})
            merged["volumes"] = list(by_target.values())
    return services


def _trees(service: dict) -> set[str]:
    """The ``/app`` trees a service bind-mounts, a mount below another one left out."""
    targets: set[str] = set()
    for entry in service.get("volumes") or []:
        if isinstance(entry, str) and entry.startswith(".."):
            target = entry.split(":")[1]
            if target.startswith("/app/"):
                targets.add(target)
    return {t for t in targets if not any(t.startswith(f"{o}/") for o in targets if o != t)}


def _assert_same_trees(label: str, services: dict) -> None:
    held = {name: _trees(services[name]) for name in LAUNCHERS if name in services}
    mounting = {name: trees for name, trees in held.items() if trees}
    union = set().union(*mounting.values()) if mounting else set()
    for name, trees in mounting.items():
        assert trees == union, (label, name, sorted(union - trees))


def test_the_compose_files_are_found() -> None:
    assert {p.name for p in COMPOSE_FILES} >= {"docker-compose.yml", "docker-compose.dev.yml"}


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_every_launching_service_mounts_the_trees_the_others_mount(path: Path) -> None:
    _assert_same_trees(path.name, _services(path))


def test_the_overlay_merged_over_the_production_file_mounts_the_same_trees_everywhere() -> None:
    merged = _merged(_services(BASE), _services(OVERLAY))
    _assert_same_trees(f"{BASE.name}+{OVERLAY.name}", merged)
    for name in LAUNCHERS:
        assert _trees(merged[name]) >= {"/app/data", "/app/services", "/app/src"}, name


def test_the_merge_replaces_a_volume_by_its_target_and_keeps_the_rest() -> None:
    base = {"svc": {"volumes": ["../src:/app/src:ro", "../data:/app/data:ro"]}}
    overlay = {"svc": {"volumes": ["../src:/app/src"]}, "only": {"volumes": ["../x:/app/x"]}}
    merged = _merged(base, overlay)
    assert merged["svc"]["volumes"] == ["../src:/app/src", "../data:/app/data:ro"]
    assert merged["only"]["volumes"] == ["../x:/app/x"]
    # A tree the overlay mounts in one launcher only is caught on the merged result.
    split = _merged(
        {
            "backend-api": {"volumes": ["../src:/app/src"]},
            "backend-worker": {"volumes": ["../src:/app/src"]},
        },
        {"backend-api": {"volumes": ["../extra:/app/extra:ro"]}},
    )
    with pytest.raises(AssertionError):
        _assert_same_trees("split", split)


def test_the_production_file_mounts_the_launch_trees_in_every_launching_service() -> None:
    services = _services(BASE)
    for name in LAUNCHERS:
        assert _trees(services[name]) >= {"/app/data", "/app/services", "/app/src"}, name
