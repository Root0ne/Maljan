"""Nothing outside the providers names a provider."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ALLOWED = {
    "src/malspark/core/config.py",  # the read-only compatibility view on MCPConfig
    "src/malspark/providers/static/ghidra/provider.py",
    "src/malspark/providers/sandbox/cape2.py",
    # A released migration carries its own frozen copy of the 2026-09-03 renames.
    "apps/api/alembic/versions/20260903000000_rename_provider_setting_keys.py",
}
LEGACY_PATH = re.compile(r"mcp\.ghidra|mcp\.cape")


def test_no_module_outside_the_providers_reads_the_legacy_mcp_paths():
    # Every text file of the two trees is read, as a recursive grep reads them;
    # compiled caches are not source, and whether a tree holds any (and how a
    # grep reports a binary match) must not decide the answer.
    offenders = set()
    for tree in ("src", "apps/api"):
        for path in sorted((ROOT / tree).rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            body = path.read_bytes()
            if b"\0" not in body and LEGACY_PATH.search(body.decode("utf-8", "replace")):
                offenders.add(path.relative_to(ROOT).as_posix())
    assert offenders <= ALLOWED, sorted(offenders - ALLOWED)


def test_the_function_hash_gate_is_a_capability_read():
    source = (ROOT / "src" / "malspark" / "pipeline" / "nodes.py").read_text(encoding="utf-8")
    assert "provides_function_hashes" in source
    assert 'transport == "http"' not in source


def test_the_mirror_gate_is_a_capability_read():
    source = (ROOT / "apps" / "api" / "app" / "worker" / "analysis_worker.py").read_text(
        encoding="utf-8"
    )
    assert "needs_sample_mirror" in source
    assert "ghidra_container_samples_path" not in source
    assert "path_in_server" in source, "each server is handed the sample under its own mount"
