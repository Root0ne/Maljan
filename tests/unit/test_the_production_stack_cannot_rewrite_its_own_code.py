"""The production stack mounts its source trees read-only and the API does not reload.

A process in the API or a worker opens hostile bytes. With the source trees
mounted writable and the API reloading on any change under /app, a parser bug
there could plant Python the API ran at once and a later worker ran on its next
start, and it changed the host's working tree as well. The production file now
mounts src/, apps/, tests/ and services/ read-only in every service built from
the backend image, and data/ read-only with only the uploads and the sample
mirrors under it writable. The development overlay mounts the sources writable
again and turns the API's reload back on.

The backend services also run as an unprivileged uid with every capability
dropped, from an image whose virtual environment is root-owned; a one-shot
service hands the writable volumes an earlier root deployment left to that uid
(AUD-32-M5).
"""

from __future__ import annotations

import re
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


WRITABLE_DATA = ("/app/data/samples", "/app/data/uploads")


def test_data_is_read_only_but_for_the_samples_and_the_uploads() -> None:
    services = _services(PRODUCTION)
    for name in ("backend-api", "backend-worker"):
        mounts = _mounts(services[name])
        assert mounts["/app/data"] == "ro", name
        assert {mounts[target] for target in WRITABLE_DATA} == {"rw"}, (name, mounts)
    for name, service in services.items():
        for target, mode in _mounts(service).items():
            if target.startswith("/app/data") and target not in WRITABLE_DATA:
                assert mode == "ro", (name, target)


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
        assert read_only(developed[name])["/app/data"] is True, name
        assert {read_only(developed[name])[t] for t in WRITABLE_DATA} == {False}, name
    assert "--reload" not in " ".join(shipped["backend-api"]["command"])
    assert "--reload" in " ".join(developed["backend-api"]["command"])


def test_no_backend_process_can_gain_a_privilege() -> None:
    """``no-new-privileges`` on every service built from the backend image (AUD-32)."""
    services = _services(PRODUCTION)
    for name in BACKEND:
        assert "no-new-privileges:true" in (services[name].get("security_opt") or []), name


def test_every_backend_service_runs_unprivileged_with_no_capability() -> None:
    """A fixed non-root uid/gid and ``cap_drop: [ALL]`` with nothing added back (AUD-32-M5)."""
    services = _services(PRODUCTION)
    for name in BACKEND:
        service = services[name]
        assert service.get("user") == "${MALJAN_UID:-10001}:${MALJAN_GID:-10001}", name
        assert service.get("cap_drop") == ["ALL"], name
        assert not service.get("cap_add"), name


def test_the_backend_image_runs_as_its_own_account_over_a_root_owned_venv() -> None:
    dockerfile = (ROOT / "docker" / "Dockerfile.backend").read_text(encoding="utf-8")
    final = dockerfile.rsplit("\nFROM ", 1)[1]
    assert "--uid 10001 --gid 10001" in final
    assert "\nUSER 10001:10001\n" in final
    user_at = final.index("USER 10001:10001")
    # Every install and copy happens as root, before the switch.
    assert final.rindex("uv sync") < user_at
    assert final.rindex("\nCOPY ") < user_at
    assert "UV_NO_SYNC=1" in final
    assert user_at < final.index("CMD ")


def test_volume_init_is_root_with_chown_alone_over_the_writable_volumes() -> None:
    """Its settings; what its script does is held by test_volume_init_takes_only_what_root_owns."""
    services = _services(PRODUCTION)
    init = services["volume-init"]
    assert init["user"] == "0:0"
    assert init["cap_drop"] == ["ALL"]
    assert sorted(init["cap_add"]) == ["CHOWN", "DAC_READ_SEARCH"]
    assert "no-new-privileges:true" in init["security_opt"]
    assert init["network_mode"] == "none"
    assert init["restart"] == "no"
    assert init["volumes"] == [
        "../data/samples:/own/data/samples",
        "../data/uploads:/own/data/uploads",
        "attck_cache:/own/attck_cache",
    ]
    for name in ("backend-api", "backend-worker"):
        waits = services[name]["depends_on"]["volume-init"]
        assert waits["condition"] == "service_completed_successfully", name


def test_the_worker_s_attck_cache_mounts_at_the_image_s_home_cache() -> None:
    dockerfile = (ROOT / "docker" / "Dockerfile.backend").read_text(encoding="utf-8")
    homes = re.findall(r"^ENV HOME=(\S+)", dockerfile, re.MULTILINE)
    assert len(homes) == 1, homes
    worker = _services(PRODUCTION)["backend-worker"]
    caches = [
        entry.split(":", 1)[1]
        for entry in worker["volumes"]
        if isinstance(entry, str) and entry.startswith("attck_cache:")
    ]
    assert caches == [f"{homes[0]}/.cache/maljan"]
    # Created in the image root-owned and 1777, so a fresh volume starts
    # root-owned and volume-init hands it over like an old one.
    assert f"{homes[0]}/.cache/maljan" in dockerfile.split("chmod 1777", 1)[1].split("\n", 1)[0]


def test_the_frontend_runs_unprivileged_with_no_capability() -> None:
    frontend = _services(PRODUCTION)["frontend"]
    assert frontend.get("cap_drop") == ["ALL"]
    assert "no-new-privileges:true" in (frontend.get("security_opt") or [])
    dockerfile = (ROOT / "docker" / "Dockerfile.frontend").read_text(encoding="utf-8")
    runner = dockerfile.split("AS runner", 1)[1]
    assert "\nUSER node\n" in runner
    assert runner.index("USER node") < runner.index("CMD ")
    for line in runner.splitlines():
        if line.startswith("COPY --from=builder"):
            assert "--chown=node:node" in line, line
