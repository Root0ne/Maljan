"""Nothing outside the providers names a provider."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ALLOWED = {
    "src/maljan/core/config.py",  # the alias table
    "src/maljan/providers/static/ghidra.py",
    "src/maljan/providers/sandbox/cape2.py",
}


def test_no_module_outside_the_providers_reads_the_legacy_mcp_paths():
    out = subprocess.run(
        ["grep", "-rn", r"mcp\.ghidra\|mcp\.cape", "src", "apps/api"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    ).stdout
    offenders = {line.split(":", 1)[0] for line in out.splitlines() if line.strip()}
    assert offenders <= ALLOWED, sorted(offenders - ALLOWED)


def test_the_function_hash_gate_is_a_capability_read():
    source = (ROOT / "src" / "maljan" / "pipeline" / "nodes.py").read_text(encoding="utf-8")
    assert "provides_function_hashes" in source
    assert 'transport == "http"' not in source


def test_the_mirror_gate_is_a_capability_read():
    source = (ROOT / "apps" / "api" / "app" / "worker" / "analysis_worker.py").read_text(
        encoding="utf-8"
    )
    assert "needs_sample_mirror" in source
    assert "ghidra_container_samples_path" in source, "the compose bind mount is still the path"
