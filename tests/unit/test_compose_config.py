import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


# Every variable docker-compose.yml's `${VAR:?...}` guards refuse to render
# without. Bootstrap secrets (JWT_SECRET_KEY, SETTINGS_ENCRYPTION_KEY) and the
# MinIO root credentials (also read as MINIO_ACCESS_KEY/MINIO_SECRET_KEY by the
# api/worker services) joined the infrastructure secrets when the api/worker
# services stopped defaulting to "minioadmin". The tokens of the optional
# services (Ghidra, Qdrant) are not among them: see OPTIONAL_ENV.
REQUIRED_ENV = {
    "REDIS_PASSWORD": "p" * 32,
    "MINIO_ROOT_USER": "maljan",
    "MINIO_ROOT_PASSWORD": "m" * 32,
    "JWT_SECRET_KEY": "j" * 32,
    "SETTINGS_ENCRYPTION_KEY": "s" * 32,
    "POSTGRES_PASSWORD": "d" * 32,
}

# The tokens of the services that run only under their profile.
OPTIONAL_ENV = {
    "GHIDRA_MCP_AUTH_TOKEN": "t" * 32,
    "QDRANT_API_KEY": "q" * 32,
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


def test_every_pulled_image_names_a_version() -> None:
    # A service compose pulls rather than builds runs the version its tag
    # names: never ``latest`` or no tag, which move under a deployment that
    # pulls again. A built image is this repository's own.
    config = yaml.safe_load((ROOT / "docker" / "docker-compose.yml").read_text())
    pulled = {
        name: service["image"]
        for name, service in config["services"].items()
        if "image" in service and "build" not in service
    }
    assert "minio" in pulled
    for name, image in pulled.items():
        reference = image.rsplit("/", 1)[-1]
        assert ":" in reference, f"{name}: {image} names no tag"
        assert reference.split(":", 1)[1] != "latest", f"{name}: {image}"


DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def test_every_pulled_and_base_image_is_pinned_by_digest() -> None:
    # A tag can be pushed again; a digest names one image (AUD-33-L1). Each
    # reference keeps its tag beside the digest so a reader and Dependabot
    # still see the version.
    config = yaml.safe_load((ROOT / "docker" / "docker-compose.yml").read_text())
    for name, service in config["services"].items():
        if "image" in service and "build" not in service:
            assert DIGEST.search(service["image"]), f"{name}: {service['image']}"
    for dockerfile in sorted((ROOT / "docker").glob("Dockerfile.*")):
        text = dockerfile.read_text(encoding="utf-8")
        stages = set(re.findall(r"^FROM \S+ AS (\S+)$", text, re.MULTILINE))
        for base in re.findall(r"^FROM (\S+)", text, re.MULTILINE):
            assert DIGEST.search(base), f"{dockerfile.name}: FROM {base}"
        for source in re.findall(r"COPY --from=(\S+)", text):
            if source not in stages:
                assert DIGEST.search(source), f"{dockerfile.name}: COPY --from={source}"


def _workflow_service_images() -> dict[str, str]:
    images = {}
    for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        for job_name, job in (yaml.safe_load(workflow.read_text()).get("jobs") or {}).items():
            for name, service in (job.get("services") or {}).items():
                images[f"{workflow.name}:{job_name}:{name}"] = service["image"]
    return images


def test_every_workflow_service_image_is_pinned_by_digest() -> None:
    images = _workflow_service_images()
    assert images
    for where, image in images.items():
        assert DIGEST.search(image), f"{where}: {image}"


def test_ci_tests_against_the_qdrant_compose_runs() -> None:
    config = yaml.safe_load((ROOT / "docker" / "docker-compose.yml").read_text())
    compose = config["services"]["qdrant"]["image"]
    ci = [image for image in _workflow_service_images().values() if "qdrant" in image]
    assert ci == [compose]


def test_every_action_is_pinned_by_commit_with_its_version() -> None:
    uses = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$")
    for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        for line in workflow.read_text(encoding="utf-8").splitlines():
            match = uses.match(line)
            if not match or match.group(1).startswith("./"):
                continue
            action, rest = match.groups()
            assert re.search(r"@[0-9a-f]{40}$", action), f"{workflow.name}: {line.strip()}"
            assert re.match(r"\s+# v\d", rest), f"{workflow.name}: {line.strip()}"


def _render_ghidra(tmp_path: Path, **extra: str) -> dict:
    compose_dir = tmp_path / "docker"
    compose_dir.mkdir(exist_ok=True)
    copy = compose_dir / "docker-compose.yml"
    shutil.copy(ROOT / "docker" / "docker-compose.yml", copy)
    empty_env = tmp_path / ".env"
    empty_env.write_text("")
    out = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(empty_env),
            "-f",
            str(copy),
            "--profile",
            "ghidra",
            "config",
        ],
        env={**REQUIRED_ENV, **OPTIONAL_ENV, **extra, "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return yaml.safe_load(out)["services"]["ghidra-mcp"]


GIB = 1024**3


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_the_ghidra_knobs_default_to_the_values_they_replaced(tmp_path):
    ghidra = _render_ghidra(tmp_path)
    assert ghidra["restart"] == "unless-stopped"
    assert int(ghidra["mem_limit"]) == 6 * GIB
    assert int(ghidra["memswap_limit"]) == 6 * GIB
    # The image's own default, now written where an operator can change it.
    assert ghidra["environment"]["JAVA_OPTS"] == "-Xmx4g -XX:+UseG1GC"


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_a_lighter_ghidra_is_three_variables(tmp_path):
    ghidra = _render_ghidra(
        tmp_path,
        GHIDRA_JAVA_OPTS="-Xmx2g -XX:+UseG1GC",
        GHIDRA_MEM_LIMIT="4g",
        GHIDRA_RESTART="no",
    )
    assert ghidra["restart"] == "no"
    # One variable sets both, so swap cannot outgrow the memory limit.
    assert int(ghidra["mem_limit"]) == int(ghidra["memswap_limit"]) == 4 * GIB
    assert ghidra["environment"]["JAVA_OPTS"] == "-Xmx2g -XX:+UseG1GC"


def _render(tmp_path: Path, *profiles: str, env: dict[str, str] | None = None) -> dict:
    """The rendered compose file with ``profiles`` on, from a copy and an empty env file."""
    compose_dir = tmp_path / "docker"
    compose_dir.mkdir(exist_ok=True)
    copy = compose_dir / "docker-compose.yml"
    shutil.copy(ROOT / "docker" / "docker-compose.yml", copy)
    empty_env = tmp_path / ".env"
    empty_env.write_text("")
    flags = [arg for profile in profiles for arg in ("--profile", profile)]
    out = subprocess.run(
        ["docker", "compose", "--env-file", str(empty_env), "-f", str(copy), *flags, "config"],
        env={**(REQUIRED_ENV if env is None else env), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return yaml.safe_load(out)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_the_stack_renders_without_ghidra_and_qdrant_and_without_their_tokens(tmp_path):
    services = _render(tmp_path)["services"]
    assert "ghidra-mcp" not in services
    assert "qdrant" not in services
    for name in ("backend-api", "backend-worker", "migrate", "enrichment-worker", "frontend"):
        assert name in services, name


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_no_service_waits_for_an_optional_one(tmp_path):
    services = _render(tmp_path, "ghidra", "qdrant", env={**REQUIRED_ENV, **OPTIONAL_ENV})[
        "services"
    ]
    assert {"ghidra-mcp", "qdrant"} <= set(services)
    for name, service in services.items():
        waits = set(service.get("depends_on") or {})
        assert not waits & {"ghidra-mcp", "qdrant"}, (name, waits)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_each_optional_service_runs_under_its_own_profile(tmp_path):
    config = _render(tmp_path, "ghidra", "qdrant", env={**REQUIRED_ENV, **OPTIONAL_ENV})
    assert config["services"]["ghidra-mcp"]["profiles"] == ["ghidra"]
    assert config["services"]["qdrant"]["profiles"] == ["qdrant"]
    for name in ("ghidra-mcp", "qdrant"):
        ports = config["services"][name]["ports"]
        assert ports and all(p["host_ip"] == "127.0.0.1" for p in ports), (name, ports)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_qdrant_without_its_key_refuses_to_start_rather_than_run_open(tmp_path):
    qdrant = _render(tmp_path, "qdrant")["services"]["qdrant"]
    script = " ".join(qdrant["entrypoint"])
    # ``config`` writes a literal dollar escaped again, as ``$$``; the container's
    # shell is handed ``$QDRANT__SERVICE__API_KEY``, the variable set above it.
    assert '[ -n "$$QDRANT__SERVICE__API_KEY" ]' in script
    assert qdrant["environment"]["QDRANT__SERVICE__API_KEY"] == ""
    assert "exit 1" in script
    assert script.endswith("exec ./entrypoint.sh")


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_no_service_is_handed_a_samples_path_named_for_one_tool(tmp_path):
    services = _render(tmp_path, "ghidra", "qdrant", env={**REQUIRED_ENV, **OPTIONAL_ENV})[
        "services"
    ]
    for name, service in services.items():
        assert "GHIDRA_CONTAINER_SAMPLES_PATH" not in (service.get("environment") or {}), name


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_the_shipped_env_file_runs_ghidra_and_qdrant_as_before(tmp_path):
    """Optional means an operator may take a profile out, not that it is off by default."""
    compose_dir = tmp_path / "docker"
    compose_dir.mkdir()
    copy = compose_dir / "docker-compose.yml"
    shutil.copy(ROOT / "docker" / "docker-compose.yml", copy)
    out = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(ROOT / "docker" / ".env.example"),
            "-f",
            str(copy),
            "config",
        ],
        env={**REQUIRED_ENV, **OPTIONAL_ENV, "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    services = yaml.safe_load(out)["services"]
    assert {"ghidra-mcp", "qdrant"} <= set(services)


def test_a_down_stops_the_optional_services_too():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    downs = [line for line in makefile.splitlines() if line.rstrip().endswith(" down")]
    assert downs and all("--profile '*'" in line for line in downs), downs


def test_the_migration_sees_the_retired_attck_variable() -> None:
    # The revision that retired it reads its own process environment, which
    # in compose is the migrate service's.
    config = yaml.safe_load((ROOT / "docker" / "docker-compose.yml").read_text())
    environment = config["services"]["migrate"]["environment"]
    assert environment["MALJAN_ATTCK_MAX_AGE_DAYS"] == "${MALJAN_ATTCK_MAX_AGE_DAYS:-}"
