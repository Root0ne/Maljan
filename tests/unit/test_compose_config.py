import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


# Every variable docker-compose.yml's `${VAR:?...}` guards refuse to render
# without. Bootstrap secrets (JWT_SECRET_KEY, SETTINGS_ENCRYPTION_KEY) and the
# MinIO root credentials (also read as MINIO_ACCESS_KEY/MINIO_SECRET_KEY by the
# api/worker services) joined the original three infrastructure secrets when
# the api/worker services stopped defaulting to "minioadmin".
REQUIRED_ENV = {
    "GHIDRA_MCP_AUTH_TOKEN": "t" * 32,
    "REDIS_PASSWORD": "p" * 32,
    "QDRANT_API_KEY": "q" * 32,
    "MINIO_ROOT_USER": "maljan",
    "MINIO_ROOT_PASSWORD": "m" * 32,
    "JWT_SECRET_KEY": "j" * 32,
    "SETTINGS_ENCRYPTION_KEY": "s" * 32,
    "POSTGRES_PASSWORD": "d" * 32,
}


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_compose_binds_loopback_and_requires_the_secrets(tmp_path):
    env = {**REQUIRED_ENV, "PATH": "/usr/bin:/bin"}
    # Render a copy of the compose file, not the real one: docker compose
    # config reads docker/.env from disk for interpolation regardless of the
    # subprocess env passed below, so rendering the real file would fold the
    # developer's actual secrets into `out` and, on a failing assertion,
    # into the pytest report.
    compose_dir = tmp_path / "docker"
    compose_dir.mkdir()
    copy = compose_dir / "docker-compose.yml"
    shutil.copy(ROOT / "docker" / "docker-compose.yml", copy)
    empty_env = tmp_path / ".env"
    empty_env.write_text("")

    out = subprocess.run(
        ["docker", "compose", "--env-file", str(empty_env), "-f", str(copy), "config"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "maljan_ghidra_secret_2026" not in out
    config = yaml.safe_load(out)
    found_a_published_port = False
    for service in config["services"].values():
        for published in service.get("ports", []):
            # docker compose config always expands "ports:" into the long
            # mapping form, so every entry has to carry a host_ip once one
            # is set anywhere in the file.
            assert "host_ip" in published, published
            assert published["host_ip"] == "127.0.0.1"
            found_a_published_port = True
    assert found_a_published_port

    redis_service = config["services"]["redis"]
    healthcheck_test = " ".join(redis_service["healthcheck"]["test"])
    # Exec-form "$$REDIS_PASSWORD" never goes through a shell, so redis-cli
    # received the literal string "$REDIS_PASSWORD" as its -a argument and
    # exited 0 on WRONGPASS regardless — the container reported healthy no
    # matter what. The fixed healthcheck must authenticate via REDISCLI_AUTH
    # (never in argv) and tie its exit code to an actual PONG.
    assert "$REDIS_PASSWORD" not in healthcheck_test
    assert "PONG" in healthcheck_test
    assert "REDISCLI_AUTH" in redis_service["environment"]

    missing = subprocess.run(
        ["docker", "compose", "--env-file", str(empty_env), "-f", str(copy), "config"],
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    # docker compose iterates services in map order, which Go randomizes per
    # run, so which required variable is reported first is not deterministic —
    # assert on any of them rather than pinning one name.
    assert missing.returncode != 0
    assert any(name in missing.stderr for name in REQUIRED_ENV)

    # Every guard fires on its own, not just when everything is missing at
    # once: render with the full set minus exactly one variable and confirm
    # that variable's own message is the one reported.
    for var in REQUIRED_ENV:
        partial_env = {k: v for k, v in REQUIRED_ENV.items() if k != var}
        partial_env["PATH"] = "/usr/bin:/bin"
        result = subprocess.run(
            ["docker", "compose", "--env-file", str(empty_env), "-f", str(copy), "config"],
            env=partial_env,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, var
        assert var in result.stderr, (var, result.stderr)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_migrations_run_once_before_the_api_and_the_worker(tmp_path):
    """A fresh compose deploy has an empty database and the API does not
    migrate on startup, so without this step no table the API reads exists
    and every request fails until someone migrates by hand."""
    compose_dir = tmp_path / "docker"
    compose_dir.mkdir()
    copy = compose_dir / "docker-compose.yml"
    shutil.copy(ROOT / "docker" / "docker-compose.yml", copy)
    empty_env = tmp_path / ".env"
    empty_env.write_text("")

    out = subprocess.run(
        ["docker", "compose", "--env-file", str(empty_env), "-f", str(copy), "config"],
        env={**REQUIRED_ENV, "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    config = yaml.safe_load(out)

    migrate = config["services"]["migrate"]
    assert "alembic upgrade head" in " ".join(migrate["command"])
    assert migrate["depends_on"]["postgres"]["condition"] == "service_healthy"

    api = config["services"]["backend-api"]
    worker = config["services"]["backend-worker"]
    assert api["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
    assert worker["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
    # The API's lifespan runs the one-time configuration import; a job taken
    # before it finishes would run on catalog defaults (final review I4).
    assert worker["depends_on"]["backend-api"]["condition"] == "service_healthy"
    assert "/health" in " ".join(api["healthcheck"]["test"])
    # Migrating on startup stays off: a multi-replica deployment must not have
    # every replica racing the same upgrade.
    assert api["environment"]["RUN_MIGRATIONS_ON_STARTUP"] == "false"

    # One image for the three services that run this codebase, not one built
    # and stored per service (re-review M2).
    images = {config["services"][s]["image"] for s in ("migrate", "backend-api", "backend-worker")}
    assert images == {"maljan-backend"}
