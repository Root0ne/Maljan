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
    out = subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "docker" / "docker-compose.yml"), "config"],
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
        ["docker", "compose", "-f", str(ROOT / "docker" / "docker-compose.yml"), "config"],
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert missing.returncode != 0 and "GHIDRA_MCP_AUTH_TOKEN" in missing.stderr
