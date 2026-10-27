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
    "DIE_MCP_AUTH_TOKEN": "e" * 32,
    "ILSPY_MCP_AUTH_TOKEN": "i" * 32,
    "GORESYM_MCP_AUTH_TOKEN": "g" * 32,
    "YARAX_MCP_AUTH_TOKEN": "y" * 32,
    "OLETOOLS_MCP_AUTH_TOKEN": "o" * 32,
    "WEBCRACK_MCP_AUTH_TOKEN": "w" * 32,
    "UNBLOB_MCP_AUTH_TOKEN": "u" * 32,
    "JADX_MCP_AUTH_TOKEN": "j" * 32,
    "ANALYSIS_MCP_AUTH_TOKEN": "a" * 32,
    "NETWORK_MCP_AUTH_TOKEN": "n" * 32,
}

# The sidecars of one analysis program each (the identification sidecars and
# the rule and document sidecars), each under its own profile, by profile: the
# sidecar, its published-port relay and the port the server listens on.
ONE_PROGRAM = {
    "die": ("die-mcp", "die-port", 8090),
    "ilspy": ("ilspy-mcp", "ilspy-port", 8091),
    "goresym": ("goresym-mcp", "goresym-port", 8092),
    "yarax": ("yarax-mcp", "yarax-port", 8093),
    "oletools": ("oletools-mcp", "oletools-port", 8094),
    "webcrack": ("webcrack-mcp", "webcrack-port", 8095),
    "unblob": ("unblob-mcp", "unblob-port", 8096),
    "jadx": ("jadx-mcp", "jadx-port", 8097),
}
# Each one's memory-and-swap ceiling by default, in GiB, and the variable that
# sets it.
ONE_PROGRAM_MEMORY = {
    "die": ("DIE_MEM_LIMIT", 2),
    "ilspy": ("ILSPY_MEM_LIMIT", 4),
    "goresym": ("GORESYM_MEM_LIMIT", 2),
    "yarax": ("YARAX_MEM_LIMIT", 2),
    "oletools": ("OLETOOLS_MEM_LIMIT", 2),
    "webcrack": ("WEBCRACK_MEM_LIMIT", 2),
    "unblob": ("UNBLOB_MEM_LIMIT", 2),
    "jadx": ("JADX_MEM_LIMIT", 4),
}
# The mounts a sidecar holds beside the samples directory, by profile: YARA-X
# reads the operator's rule files, read-only, from the directory
# YARA_X_RULES_DIR names (data/yara-x-rules by default).
RULE_MOUNTS = {"yarax": ("YARA_X_RULES_DIR", ("data", "yara-x-rules"), "/data/rules")}
# The variables a sidecar is handed beside its token, by profile, none of them
# a secret: unblob's bound on what one extraction writes (the console's upload
# bound) and how long it keeps an extraction's files.
SIDECAR_SETTINGS = {"unblob": {"UPLOAD_MAX_BYTES", "CARVED_KEEP_SECONDS", "UNBLOB_MAX_ENTRIES"}}
# The sidecars whose /tmp is a tmpfs sized below their memory ceiling, by
# profile: the variable that sets it and its size by default, in MiB.
TMPFS_SIZES = {"unblob": ("UNBLOB_TMPFS_SIZE", 1536), "jadx": ("JADX_TMPFS_SIZE", 1536)}
# The platform's own sample readers (the analysis and network servers), each in
# a container of its own under its profile, by profile: the server, its relay,
# its port, its memory-and-swap ceiling's variable and default in GiB, and its
# tmpfs's variable and default in MiB.
READERS = {
    "analysis": ("analysis-mcp", "analysis-port", 8098, ("ANALYSIS_MEM_LIMIT", 8), 2048),
    "network": ("network-mcp", "network-port", 8099, ("NETWORK_MEM_LIMIT", 2), 512),
}
ALL_PROFILES = ("ghidra", "qdrant", *ONE_PROGRAM, *READERS)


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
    for sidecar, relay, *_rest in (*ONE_PROGRAM.values(), *READERS.values()):
        assert sidecar not in services and relay not in services
    for name in ("backend-api", "backend-worker", "migrate", "enrichment-worker", "frontend"):
        assert name in services, name


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_no_service_waits_for_an_optional_one(tmp_path):
    services = _render(tmp_path, *ALL_PROFILES, env={**REQUIRED_ENV, **OPTIONAL_ENV})["services"]
    optional = {
        "ghidra-mcp",
        "qdrant",
        *(names[0] for names in ONE_PROGRAM.values()),
        *(names[0] for names in READERS.values()),
    }
    assert optional <= set(services)
    for name, service in services.items():
        waits = set(service.get("depends_on") or {})
        assert not waits & optional, (name, waits)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_each_optional_service_runs_under_its_own_profile(tmp_path):
    config = _render(tmp_path, "ghidra", "qdrant", env={**REQUIRED_ENV, **OPTIONAL_ENV})
    assert config["services"]["ghidra-mcp"]["profiles"] == ["ghidra"]
    assert config["services"]["ghidra-port"]["profiles"] == ["ghidra"]
    assert config["services"]["qdrant"]["profiles"] == ["qdrant"]
    config = _render(tmp_path, *ALL_PROFILES, env={**REQUIRED_ENV, **OPTIONAL_ENV})
    for profile, (sidecar, relay, _port) in ONE_PROGRAM.items():
        assert config["services"][sidecar]["profiles"] == [profile]
        assert config["services"][relay]["profiles"] == [profile]
    # Ghidra's port is published by its relay; ghidra-mcp publishes none.
    for name in ("ghidra-port", "qdrant"):
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


# ---------------------------------------------------------------------------
# The containers that open the sample (X2)
# ---------------------------------------------------------------------------

# The platform's own image: the API, the workers and their one-shots, which
# hold the platform's credentials by design. Every other container that
# mounts the sample directory opens the sample, and is found from its mounts,
# not by its name.
BACKEND_IMAGE = "maljan-backend"
# The project network every service is on unless it names others.
DEFAULT_NETWORK = "default"


def _render_with(
    tmp_path: Path,
    *files: str,
    profiles: tuple[str, ...] = (),
    env: dict[str, str] | None = None,
) -> dict:
    """The rendered stack from copies of ``files`` (under docker/), with ``profiles`` on."""
    compose_dir = tmp_path / "docker"
    compose_dir.mkdir(exist_ok=True)
    flags: list[str] = []
    for name in files:
        shutil.copy(ROOT / "docker" / name, compose_dir / name)
        flags += ["-f", str(compose_dir / name)]
    empty_env = tmp_path / ".env"
    empty_env.write_text("")
    out = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(empty_env),
            *flags,
            *[arg for profile in profiles for arg in ("--profile", profile)],
            "config",
        ],
        env={**REQUIRED_ENV, **OPTIONAL_ENV, **(env or {}), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return yaml.safe_load(out)


def _mounts_samples(service: dict) -> bool:
    return any(
        volume.get("type") == "bind"
        and Path(str(volume.get("source"))).parts[-2:] == ("data", "samples")
        for volume in service.get("volumes") or []
    )


# Where the platform's own services mount the samples directory: the API's
# and the worker's working tree, whose mirrors they write, and volume-init's
# hand-over. Every other mount of it is a container that opens the sample,
# whatever image it runs, the backend's included.
PLATFORM_SAMPLE_TARGETS = ("/app/", "/own/")


def _sample_openers(config: dict) -> dict[str, dict]:
    def platform(service: dict) -> bool:
        return any(
            str(volume.get("target") or "").startswith(PLATFORM_SAMPLE_TARGETS)
            for volume in service.get("volumes") or []
            if _mounts_samples({"volumes": [volume]})
        )

    return {
        name: service
        for name, service in config["services"].items()
        if _mounts_samples(service) and not platform(service)
    }


def _networks_of(service: dict) -> set[str]:
    return set(service.get("networks") or {DEFAULT_NETWORK: None})


STACKS = [
    pytest.param(("docker-compose.yml",), id="production"),
    pytest.param(("docker-compose.yml", "docker-compose.dev.yml"), id="development"),
]


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
@pytest.mark.parametrize("files", STACKS)
def test_every_container_that_opens_the_sample_is_kept_from_the_platform(
    tmp_path: Path, files: tuple[str, ...]
) -> None:
    from maljan.core.platform_secrets import is_platform_secret

    # A value no service could hold by chance, so finding one is finding the secret.
    secrets = {var: f"x2-{var.lower()}-value" for var in REQUIRED_ENV}
    config = _render_with(tmp_path, *files, profiles=ALL_PROFILES, env=secrets)
    openers = _sample_openers(config)
    # The worker does hold them, so their absence below is not a render that dropped them.
    assert secrets["JWT_SECRET_KEY"] in yaml.safe_dump(config["services"]["backend-worker"])
    # Found from the mounts, so the checks below never pass on an empty set.
    assert set(openers) == {
        "ghidra-mcp",
        *(names[0] for names in ONE_PROGRAM.values()),
        *(names[0] for names in READERS.values()),
    }
    for name, service in openers.items():
        # Not root, no capability, no way to gain one.
        uid = str(service.get("user") or "0").split(":", 1)[0]
        assert uid.isdigit() and int(uid) != 0, (name, service.get("user"))
        assert service.get("cap_drop") == ["ALL"], name
        assert "no-new-privileges:true" in (service.get("security_opt") or []), name
        assert not service.get("cap_add"), name
        assert service.get("privileged") is not True, name
        assert int(service["pids_limit"]) > 0, name
        # The sample read-only.
        samples = [v for v in service["volumes"] if _mounts_samples({"volumes": [v]})]
        assert samples and all(v.get("read_only") for v in samples), name
        # None of the platform's credentials, by name or by value.
        environment = service.get("environment") or {}
        assert not [key for key in environment if is_platform_secret(key)], name
        assert not service.get("env_file"), name
        rendered = yaml.safe_dump(service)
        for var, value in secrets.items():
            assert value not in rendered, (name, var)
        # No route out: never the project network, every network of its own
        # internal (no gateway), and no port published, which an internal
        # network cannot carry and a non-internal one would need.
        assert service.get("network_mode") is None, name
        networks = _networks_of(service)
        assert DEFAULT_NETWORK not in networks, name
        for network in networks:
            assert config["networks"][network].get("internal") is True, (name, network)
        assert not service.get("ports"), name


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
@pytest.mark.parametrize("files", STACKS)
def test_only_the_platforms_callers_share_a_network_with_a_sample_opener(
    tmp_path: Path, files: tuple[str, ...]
) -> None:
    config = _render_with(tmp_path, *files, profiles=ALL_PROFILES)
    services = config["services"]
    for name, opener in _sample_openers(config).items():
        for network in _networks_of(opener):
            members = {other for other, s in services.items() if network in _networks_of(s)}
            # The stores (postgres, redis, minio, qdrant) and the frontend are
            # never on it: only the platform's own services that call it, and
            # relays that mount nothing and hold nothing.
            for other in members - {name}:
                service = services[other]
                if service.get("image") == BACKEND_IMAGE:
                    continue
                assert _is_bare_relay(service), (name, network, other)
    # The API and the worker keep the project network and reach Ghidra and
    # each sidecar of one analysis program on its own.
    for caller in ("backend-api", "backend-worker"):
        assert _networks_of(services[caller]) == {
            DEFAULT_NETWORK,
            "ghidra",
            *ONE_PROGRAM,
            *READERS,
        }, caller
    for network in ("ghidra", *ONE_PROGRAM, *READERS):
        assert config["networks"][network]["internal"] is True


def _is_bare_relay(service: dict) -> bool:
    """Mounts nothing, holds no environment, runs as nobody-like with no capability."""
    uid = str(service.get("user") or "0").split(":", 1)[0]
    return (
        not service.get("volumes")
        and not service.get("environment")
        and not service.get("env_file")
        and uid.isdigit()
        and int(uid) != 0
        and service.get("cap_drop") == ["ALL"]
        and "no-new-privileges:true" in (service.get("security_opt") or [])
        and service.get("read_only") is True
        and not service.get("cap_add")
    )


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
@pytest.mark.parametrize("files", STACKS)
def test_ghidras_port_is_published_by_a_relay_that_opens_nothing(
    tmp_path: Path, files: tuple[str, ...]
) -> None:
    config = _render_with(tmp_path, *files, profiles=("ghidra",))
    relay = config["services"]["ghidra-port"]
    assert _is_bare_relay(relay)
    assert not _mounts_samples(relay)
    assert relay["user"] == "65534:65534"
    assert DEFAULT_NETWORK not in _networks_of(relay)
    assert _networks_of(relay) == {"ghidra", "ghidra-publish"}
    # The publishing network is the relay's alone.
    others = {
        name
        for name, service in config["services"].items()
        if "ghidra-publish" in _networks_of(service)
    }
    assert others == {"ghidra-port"}
    assert config["networks"]["ghidra-publish"].get("internal") is not True
    (port,) = relay["ports"]
    assert (port["host_ip"], str(port["published"]), port["target"]) == (
        "127.0.0.1",
        "8089",
        8089,
    )
    assert relay["command"] == ["tcp-listen:8089,fork,reuseaddr", "tcp-connect:ghidra-mcp:8089"]
    assert DIGEST.search(relay["image"])


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_ghidra_starts_as_its_user_only_after_its_projects_changed_hands(tmp_path: Path) -> None:
    services = _render_with(tmp_path, "docker-compose.yml", profiles=("ghidra",))["services"]
    ghidra, init = services["ghidra-mcp"], services["volume-init"]
    assert ghidra["depends_on"]["volume-init"]["condition"] == "service_completed_successfully"
    assert ghidra["user"] == services["backend-worker"]["user"] == "10001:10001"
    targets = {v["target"]: v["source"] for v in init["volumes"]}
    assert targets["/own/ghidra_projects"] == "ghidra_projects"
    (projects,) = [v for v in ghidra["volumes"] if v["target"] == "/projects"]
    assert projects["source"] == "ghidra_projects"
    assert projects["volume"]["nocopy"] is True
    # Unset, the JVM's own name; an operator with root-owned projects sets it.
    assert ghidra["environment"]["GHIDRA_USER"] == ""
    assert "/own/ghidra_projects" in " ".join(init["command"])
    assert init["network_mode"] == "none"
    # A writable home for the JVM whatever JAVA_OPTS an operator sets.
    assert ghidra["environment"]["JAVA_TOOL_OPTIONS"] == "-Duser.home=/tmp"
    assert ghidra["environment"]["JAVA_OPTS"] == "-Xmx4g -XX:+UseG1GC"


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
@pytest.mark.parametrize("files", STACKS)
@pytest.mark.parametrize("profile", sorted(ONE_PROGRAM))
def test_each_one_program_sidecar_is_held_as_ghidra_is(
    tmp_path: Path, files: tuple[str, ...], profile: str
) -> None:
    from maljan.core.config import Settings

    sidecar_name, relay_name, port = ONE_PROGRAM[profile]
    config = _render_with(tmp_path, *files, profiles=(profile,))
    sidecar, relay = config["services"][sidecar_name], config["services"][relay_name]
    # Built from its own directory under services/, as the worker's ids, with a
    # read-only root whose only writable place is a tmpfs.
    assert sidecar["build"]["dockerfile"] == f"{sidecar_name}/Dockerfile"
    assert Path(sidecar["build"]["context"]).name == "services"
    assert sidecar["user"] == config["services"]["backend-worker"]["user"]
    assert sidecar["read_only"] is True
    if profile in TMPFS_SIZES:
        # Sized below the memory ceiling, so too much written fills it, not memory.
        size_variable, mib = TMPFS_SIZES[profile]
        assert sidecar["tmpfs"] == [f"/tmp:size={mib}m"]
        limit = ONE_PROGRAM_MEMORY[profile][1] * GIB
        tmpfs = mib * 1024 * 1024
        # The room each leaves beside its tmpfs: unblob's at most three
        # quarters of its ceiling, JADX's its ceiling less its heap (half of
        # it) and half a GiB for the runtime.
        if profile == "unblob":
            assert tmpfs <= limit * 3 // 4
        else:
            assert tmpfs <= limit - limit // 2 - GIB // 2
        resized = _render_with(tmp_path, *files, profiles=(profile,), env={size_variable: "512m"})
        assert resized["services"][sidecar_name]["tmpfs"] == ["/tmp:size=512m"]
    else:
        assert sidecar["tmpfs"] == ["/tmp"]
    # A memory ceiling the kernel enforces, swap pinned to it, as Ghidra's.
    variable, gib = ONE_PROGRAM_MEMORY[profile]
    assert int(sidecar["mem_limit"]) == int(sidecar["memswap_limit"]) == gib * GIB
    lighter = _render_with(tmp_path, *files, profiles=(profile,), env={variable: "1g"})
    held = lighter["services"][sidecar_name]
    assert int(held["mem_limit"]) == int(held["memswap_limit"]) == GIB
    # The one secret it is handed is its own token; unblob's settings beside it.
    settings = SIDECAR_SETTINGS.get(profile, set())
    assert set(sidecar["environment"]) == {"MCP_AUTH_TOKEN", *settings}
    if settings:
        given = {name: "7" for name in settings}
        held = _render_with(tmp_path, *files, profiles=(profile,), env=given)
        assert {k: held["services"][sidecar_name]["environment"][k] for k in settings} == given
    # The samples directory, read-only, at the mount its block declares, and
    # nothing else but YARA-X's rule directory, read-only too.
    block = Settings(_env_file=None).mcp.servers[profile]
    mount, *others = sidecar["volumes"]
    assert _mounts_samples(sidecar) and mount["read_only"] is True
    assert mount["target"] == block.sample_mount
    if profile in RULE_MOUNTS:
        variable, source, target = RULE_MOUNTS[profile]
        (rules,) = others
        assert Path(rules["source"]).parts[-2:] == source and (ROOT / Path(*source)).is_dir()
        assert (rules["target"], rules["read_only"]) == (target, True)
        elsewhere = _render_with(tmp_path, *files, profiles=(profile,), env={variable: "/srv/r"})
        assert elsewhere["services"][sidecar_name]["volumes"][1]["source"] == "/srv/r"
    else:
        assert others == []
    assert _networks_of(sidecar) == {profile}
    # The block reaches it by its service name on its own port.
    assert block.url == f"http://{sidecar_name}:{port}/mcp"
    # Its relay forwards that port and nothing else, from a network of its own.
    assert _is_bare_relay(relay) and not _mounts_samples(relay)
    assert _networks_of(relay) == {profile, f"{profile}-publish"}
    assert relay["command"] == [
        f"tcp-listen:{port},fork,reuseaddr",
        f"tcp-connect:{sidecar_name}:{port}",
    ]
    (published,) = relay["ports"]
    assert (published["host_ip"], str(published["published"]), published["target"]) == (
        "127.0.0.1",
        str(port),
        port,
    )
    others = {
        name
        for name, service in config["services"].items()
        if f"{profile}-publish" in _networks_of(service)
    }
    assert others == {relay_name}
    assert DIGEST.search(relay["image"])


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
@pytest.mark.parametrize("files", STACKS)
@pytest.mark.parametrize("profile", sorted(READERS))
def test_each_sample_reader_is_held_as_the_sidecars_are(
    tmp_path: Path, files: tuple[str, ...], profile: str
) -> None:
    server_name, relay_name, port, (variable, gib), mib = READERS[profile]
    config = _render_with(tmp_path, *files, profiles=(profile,))
    services = config["services"]
    server, relay = services[server_name], services[relay_name]
    # The worker's own image and ids, serving over HTTP from its own directory.
    assert server["image"] == BACKEND_IMAGE
    assert server["user"] == services["backend-worker"]["user"]
    assert server["command"] == ["python", "server.py", "--http"]
    assert server["working_dir"] == f"/app/services/{server_name}"
    assert server["profiles"] == [profile] and relay["profiles"] == [profile]
    # No capability, no way to gain one, a pids limit, a read-only root whose
    # only writable place is a tmpfs sized well below its memory ceiling.
    assert server["cap_drop"] == ["ALL"] and not server.get("cap_add")
    assert "no-new-privileges:true" in server["security_opt"]
    assert server.get("privileged") is not True
    assert int(server["pids_limit"]) > 0
    assert server["read_only"] is True
    assert int(server["mem_limit"]) == int(server["memswap_limit"]) == gib * GIB
    size = f"{mib // 1024}g" if mib % 1024 == 0 else f"{mib}m"
    assert server["tmpfs"] == [f"/tmp:size={size}"]
    assert mib * 1024 * 1024 <= gib * GIB // 4
    lighter = _render_with(tmp_path, *files, profiles=(profile,), env={variable: "1g"})
    held = lighter["services"][server_name]
    assert int(held["mem_limit"]) == int(held["memswap_limit"]) == GIB
    # Its only secret is its own token; the rest says where it listens and reads.
    environment = server["environment"]
    assert set(environment) == {
        "MCP_AUTH_TOKEN",
        "MCP_BIND_ADDRESS",
        "MCP_PORT",
        "MALJAN_SAMPLE_ROOTS",
        "HOME",
    }
    assert environment["MCP_AUTH_TOKEN"] == OPTIONAL_ENV[f"{profile.upper()}_MCP_AUTH_TOKEN"]
    assert str(environment["MCP_PORT"]) == str(port)
    assert environment["MALJAN_SAMPLE_ROOTS"] == "/data/samples"
    # Everything it mounts is read-only: the worker's source and data, and the
    # samples at /data/samples, the mount its block is pointed at.
    volumes = server["volumes"]
    assert volumes and all(volume.get("read_only") is True for volume in volumes)
    (samples,) = [volume for volume in volumes if _mounts_samples({"volumes": [volume]})]
    assert samples["target"] == "/data/samples"
    assert {volume["target"] for volume in volumes} == {
        "/app/src",
        "/app/services",
        "/app/data",
        "/data/samples",
    }
    # An internal network of its own, shared only with the API, the worker
    # and its relay, and no port of its own.
    assert _networks_of(server) == {profile}
    assert config["networks"][profile]["internal"] is True
    members = {name for name, service in services.items() if profile in _networks_of(service)}
    assert members == {server_name, relay_name, "backend-api", "backend-worker"}
    assert not server.get("ports")
    # Its relay forwards that port and nothing else.
    assert _is_bare_relay(relay) and not _mounts_samples(relay)
    assert _networks_of(relay) == {profile, f"{profile}-publish"}
    assert relay["command"] == [
        f"tcp-listen:{port},fork,reuseaddr",
        f"tcp-connect:{server_name}:{port}",
    ]
    (published,) = relay["ports"]
    assert (published["host_ip"], str(published["published"]), published["target"]) == (
        "127.0.0.1",
        str(port),
        port,
    )
