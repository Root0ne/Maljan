"""Every backend service that can start a stdio tool server mounts the same trees.

A console trust grant (``tool_declarations.granted_launch``) is recorded by the
API with the files a server's launch resolves to there, and is checked where
the server is started: the analysis worker and the enrichment worker. A tree a
command, working directory or argument may live in that one of them mounts and
another does not resolves differently, so the grant would silently never hold
there. Each compose file mounts, in every such service it defines, the same
trees under ``/app``, each from the same source and of the same kind (a bind,
a named volume, an anonymous one), whatever its mode; a mount below another
is compared as any other, except the writable ones below ``/app/data``
(the sample and upload directories), which change no launch path and are
left to each service, and so is a cache mounted outside ``/app`` (a path there fails
closed at grant time in the API). The development overlay is checked merged
over the production file as well, the way ``make dev-up`` starts them: an
overlay that remounts a tree in one service but not in another, or from
another source, changes what the stack runs with although each file alone
holds.
"""

from __future__ import annotations

import posixpath
import re
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


# A short-syntax entry: ``source:target[:mode]`` or an anonymous ``target``;
# a ``${VAR:-default}`` source and a Windows drive (``C:\\x``) keep their colon.
_SHORT = re.compile(
    r"^(?P<a>(?:[A-Za-z]:(?=[\\/]))?(?:\$\{[^}]*\}|[^:])+)(?::(?P<b>[^:]+))?(?::[^:]*)?$"
)
_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def _mount(entry: object) -> tuple[str, str, str] | None:
    """A volume entry as (kind, normalised source, target): its mode is not read.

    ``bind`` for a host path (relative, absolute, ``~`` or interpolated),
    ``volume`` for a named volume, ``anonymous`` for one with no source.
    """
    if isinstance(entry, dict):
        target, source = entry.get("target"), entry.get("source")
        if not isinstance(target, str):
            return None
        kind = str(entry.get("type") or ("volume" if source else "anonymous"))
        source = source if isinstance(source, str) else ""
    elif isinstance(entry, str):
        match = _SHORT.match(entry.strip())
        if match is None:
            return None
        if match.group("b") is None:
            return "anonymous", "", match.group("a").rstrip("/") or "/"
        source, target = match.group("a"), match.group("b")
        named = not source.startswith((".", "/", "~", "$")) and not _DRIVE.match(source)
        kind = "volume" if named else "bind"
    else:
        return None
    if kind == "bind" and not source.startswith("$"):
        source = posixpath.normpath(source)
    return kind, source.rstrip("/") or source, target.rstrip("/") or "/"


def _target(entry: object) -> str | None:
    """The container path a volume entry mounts at, short or long syntax."""
    mount = _mount(entry)
    return mount[2] if mount else None


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


# The one tree whose sub-mounts (the writable sample and upload directories)
# legitimately differ between the launchers: no launch resolves into them.
PER_SERVICE_BELOW = "/app/data/"


def _trees(service: dict) -> set[tuple[str, str, str]]:
    """The ``/app`` trees a service mounts, by kind and source; one below ``/app/data`` left out."""
    return {
        m
        for m in map(_mount, service.get("volumes") or [])
        if m and m[2].startswith("/app/") and not m[2].startswith(PER_SERVICE_BELOW)
    }


def _targets(service: dict) -> set[str]:
    return {target for _kind, _source, target in _trees(service)}


def _assert_same_trees(label: str, services: dict) -> None:
    held = {name: _trees(services[name]) for name in LAUNCHERS if name in services}
    mounting = {name: trees for name, trees in held.items() if trees}
    union = set().union(*mounting.values()) if mounting else set()
    for name, trees in mounting.items():
        assert trees == union, (label, name, sorted(union - trees), sorted(trees - union))


def test_the_compose_files_are_found() -> None:
    assert {p.name for p in COMPOSE_FILES} >= {"docker-compose.yml", "docker-compose.dev.yml"}


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_every_launching_service_mounts_the_trees_the_others_mount(path: Path) -> None:
    _assert_same_trees(path.name, _services(path))


def test_the_overlay_merged_over_the_production_file_mounts_the_same_trees_everywhere() -> None:
    merged = _merged(_services(BASE), _services(OVERLAY))
    _assert_same_trees(f"{BASE.name}+{OVERLAY.name}", merged)
    for name in LAUNCHERS:
        assert _targets(merged[name]) >= {"/app/data", "/app/services", "/app/src"}, name


def test_the_merge_replaces_a_volume_by_its_target_and_keeps_the_rest() -> None:
    base = {"svc": {"volumes": ["../src:/app/src:ro", "../data:/app/data:ro"]}}
    overlay = {
        "svc": {"volumes": [{"type": "bind", "source": "../src", "target": "/app/src/"}]},
        "only": {"volumes": ["../x:/app/x"]},
    }
    merged = _merged(base, overlay)
    assert merged["svc"]["volumes"] == [
        {"type": "bind", "source": "../src", "target": "/app/src/"},
        "../data:/app/data:ro",
    ]
    assert merged["only"]["volumes"] == ["../x:/app/x"]


def test_a_mount_s_mode_is_not_read_and_its_source_and_target_are_normalised() -> None:
    same = [
        "../src:/app/src:ro",
        "../src/:/app/src/",
        "./../src:/app/src:rw",
        {"type": "bind", "source": "../src", "target": "/app/src", "read_only": True},
    ]
    assert {_mount(entry) for entry in same} == {("bind", "../src", "/app/src")}
    assert _mount("${X:-../x}:/app/x:ro") == ("bind", "${X:-../x}", "/app/x")
    assert _mount("/home/u/x:/app/x") == ("bind", "/home/u/x", "/app/x")
    assert _mount("cache:/app/x") == ("volume", "cache", "/app/x")
    assert _mount("C:\\x:/app/x:ro") == ("bind", "C:\\x", "/app/x")
    assert _mount("/app/x") == ("anonymous", "", "/app/x")
    assert _mount({"type": "volume", "source": "cache", "target": "/app/x"}) == (
        "volume",
        "cache",
        "/app/x",
    )


LAUNCHING = {name: {"volumes": ["../src:/app/src:ro"]} for name in LAUNCHERS}


@pytest.mark.parametrize(
    "overlay",
    [
        ["../evil:/app/src"],
        ["../evil:/app/src/"],
        [{"type": "bind", "source": "../evil", "target": "/app/src"}],
        ["../extra:/app/extra:ro"],
        [{"type": "bind", "source": "../x", "target": "/app/x"}],
        ["/home/u/x:/app/x"],
        ["./x:/app/x"],
        ["${X:-../x}:/app/x"],
        ["src:/app/src"],
        ["/app/src"],
        ["../evil:/app/src/malspark"],
        ["../evil:/app/services/x:ro"],
        ["C:\\x:/app/x"],
    ],
    ids=[
        "swapped-source",
        "swapped-source-trailing-slash",
        "swapped-source-long-syntax",
        "new-tree",
        "new-tree-long-syntax",
        "absolute-source",
        "dot-relative-source",
        "interpolated-source",
        "named-volume",
        "anonymous-volume",
        "sub-mount-under-src",
        "sub-mount-under-services",
        "windows-drive-source",
    ],
)
def test_an_overlay_that_changes_a_tree_in_one_launcher_only_is_caught(overlay: list) -> None:
    merged = _merged(LAUNCHING, {"backend-api": {"volumes": overlay}})
    with pytest.raises(AssertionError):
        _assert_same_trees("one", merged)


def test_a_writable_directory_below_the_data_tree_is_left_to_each_service() -> None:
    merged = _merged(LAUNCHING, {"backend-api": {"volumes": ["../data/samples:/app/data/samples"]}})
    _assert_same_trees("data", merged)


def test_an_overlay_that_changes_only_a_mode_holds() -> None:
    merged = _merged(LAUNCHING, {"backend-api": {"volumes": ["../src/:/app/src/:rw"]}})
    _assert_same_trees("mode", merged)


def test_the_production_file_mounts_the_launch_trees_in_every_launching_service() -> None:
    services = _services(BASE)
    for name in LAUNCHERS:
        assert _targets(services[name]) >= {"/app/data", "/app/services", "/app/src"}, name
