"""The production stack mounts its source trees read-only and the API does not reload.

A process in the API or a worker opens hostile bytes. With the source trees
mounted writable and the API reloading on any change under /app, a parser bug
there could plant Python the API ran at once and a later worker ran on its next
start, and it changed the host's working tree as well. The production file now
mounts src/, apps/, tests/ and services/ read-only in every service built from
the backend image, and keeps data/ writable for the uploads and the sample
mirrors. The development overlay mounts them writable again and turns the
API's reload back on.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PRODUCTION = ROOT / "docker" / "docker-compose.yml"
DEVELOPMENT = ROOT / "docker" / "docker-compose.dev.yml"

# The services that run this codebase from the backend image.
BACKEND = ("migrate", "backend-api", "backend-worker", "enrichment-worker")
SOURCE_TREES = ("/app/src", "/app/apps", "/app/tests", "/app/services")

# The variables the production file refuses to render without (as
# ``test_compose_config.REQUIRED_ENV``).
REQUIRED_ENV = {
    "REDIS_PASSWORD": "p" * 32,
    "MINIO_ROOT_USER": "maljan",
    "MINIO_ROOT_PASSWORD": "m" * 32,
    "JWT_SECRET_KEY": "j" * 32,
    "SETTINGS_ENCRYPTION_KEY": "s" * 32,
    "POSTGRES_PASSWORD": "d" * 32,
}


def _services(path: Path) -> dict:
    return dict(yaml.safe_load(path.read_text(encoding="utf-8"))["services"])


def _mounts(service: dict) -> dict[str, str]:
    """``{target: mode}`` of a service's short-form bind mounts (``rw`` when none is written)."""
    out: dict[str, str] = {}
    for entry in service.get("volumes") or []:
        if not isinstance(entry, str) or not entry.startswith(".."):
            continue
        parts = entry.split(":")
        out[parts[1]] = parts[2] if len(parts) > 2 else "rw"
    return out


def test_every_backend_service_mounts_the_source_trees_read_only() -> None:
    services = _services(PRODUCTION)
    for name in BACKEND:
        mounts = _mounts(services[name])
        trees = {target: mode for target, mode in mounts.items() if target in SOURCE_TREES}
        assert trees, name
        assert set(trees.values()) == {"ro"}, (name, trees)


def test_data_stays_writable_where_it_is_mounted() -> None:
    services = _services(PRODUCTION)
    for name in ("backend-api", "backend-worker"):
        assert _mounts(services[name])["/app/data"] == "rw", name


def test_the_production_api_does_not_reload() -> None:
    command = str(_services(PRODUCTION)["backend-api"]["command"])
    assert "uvicorn" in command
    assert "--reload" not in command


def test_the_development_overlay_gives_both_back() -> None:
    services = _services(DEVELOPMENT)
    assert "--reload" in str(services["backend-api"]["command"])
    for name in ("backend-api", "backend-worker"):
        mounts = _mounts(services[name])
        assert {mounts[target] for target in SOURCE_TREES} == {"rw"}, (name, mounts)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_the_overlay_replaces_the_read_only_mounts_when_compose_merges_them(
    tmp_path: Path,
) -> None:
    """Rendered from copies with an empty env file: nothing is started or read from disk."""
    compose_dir = tmp_path / "docker"
    compose_dir.mkdir()
    production = compose_dir / "docker-compose.yml"
    development = compose_dir / "docker-compose.dev.yml"
    shutil.copy(PRODUCTION, production)
    shutil.copy(DEVELOPMENT, development)
    empty_env = tmp_path / ".env"
    empty_env.write_text("")

    def render(*files: Path) -> dict:
        flags = [arg for path in files for arg in ("-f", str(path))]
        out = subprocess.run(
            ["docker", "compose", "--env-file", str(empty_env), *flags, "config"],
            env={**REQUIRED_ENV, "PATH": "/usr/bin:/bin"},
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        return dict(yaml.safe_load(out)["services"])

    def read_only(service: dict) -> dict[str, bool]:
        return {
            str(mount["target"]): bool(mount.get("read_only"))
            for mount in service.get("volumes") or []
            if mount.get("type") == "bind"
        }

    shipped = render(production)
    developed = render(production, development)
    for name in ("backend-api", "backend-worker"):
        assert {read_only(shipped[name])[t] for t in SOURCE_TREES} == {True}, name
        assert {read_only(developed[name])[t] for t in SOURCE_TREES} == {False}, name
        assert read_only(developed[name])["/app/data"] is False, name
    assert "--reload" not in " ".join(shipped["backend-api"]["command"])
    assert "--reload" in " ".join(developed["backend-api"]["command"])
