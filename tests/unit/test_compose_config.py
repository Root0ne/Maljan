import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_compose_binds_loopback_and_requires_the_secrets(tmp_path):
    env = {
        "GHIDRA_MCP_AUTH_TOKEN": "t" * 32,
        "REDIS_PASSWORD": "p" * 32,
        "QDRANT_API_KEY": "q" * 32,
        "PATH": "/usr/bin:/bin",
    }
    # Render a copy of the compose file, not the real one: docker compose
    # config reads two files from disk regardless of the subprocess env
    # passed below (docker/.env for interpolation, and each service's
    # env_file: ../.env), so rendering the real file would fold the
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

    missing = subprocess.run(
        ["docker", "compose", "--env-file", str(empty_env), "-f", str(copy), "config"],
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    # docker compose iterates services in map order, which Go randomizes per
    # run, so which of the three required variables is reported first is not
    # deterministic — assert on any of them rather than pinning one name.
    assert missing.returncode != 0
    assert any(
        name in missing.stderr
        for name in ("GHIDRA_MCP_AUTH_TOKEN", "REDIS_PASSWORD", "QDRANT_API_KEY")
    )
