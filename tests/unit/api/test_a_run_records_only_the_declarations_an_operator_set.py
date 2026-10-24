"""A run's settings snapshot keeps the declarations an operator set, and digests the rest.

A built-in's shipped declaration runs to a thousand leaves and is the same on
every run of a release, so the snapshot keeps only the declaration fields the
stored overrides set and names everything in force by a digest per source and
one of the shipped data (``settings_overrides.trim_declarations``).
"""

from __future__ import annotations

from app.worker.analysis_worker import settings_snapshot
from maljan.core.builtin_declarations import shipped_digest
from maljan.core.config import Settings


def _leaves(snap: dict, field: str) -> list[str]:
    return [k for k in snap if f".{field}" in k and not k.startswith("declaration_digest.")]


def test_a_run_with_no_overrides_records_no_shipped_declaration() -> None:
    snap = settings_snapshot(Settings(), {})
    for field in ("tool_facts", "error_patterns", "prompt_fragment", "roles", "work_dir"):
        assert not _leaves(snap, field), field
    assert snap["declaration_digest.shipped"] == shipped_digest()
    assert snap["declaration_digest.mcp:analysis"]
    assert snap["declaration_digest.provider:ghidra"]
    # ``sample_open`` is recorded as it was before the other fields existed.
    assert "static.ghidra.sample_open.open_tool" in snap


def test_a_field_an_operator_set_is_recorded() -> None:
    stored = {"threatintel": {"command": "python", "roles": ["reputation", "mine"]}}
    settings = Settings.model_validate({"mcp": {"servers": stored}})
    overrides = {"mcp.servers": stored, "static.ghidra.prompt_fragment": "Mine."}
    settings.static.ghidra.prompt_fragment = "Mine."
    snap = settings_snapshot(settings, overrides)
    assert snap["mcp.servers.threatintel.roles"] == ["reputation", "mine"]
    assert snap["static.ghidra.prompt_fragment"] == "Mine."
    assert not _leaves(snap, "tool_facts")
    assert snap["overridden_keys"] == ["mcp.servers", "static.ghidra.prompt_fragment"]


def test_a_changed_declaration_changes_its_digest() -> None:
    base = settings_snapshot(Settings(), {})
    stored = {"analysis": {"command": "python", "roles": []}}
    changed = settings_snapshot(Settings.model_validate({"mcp": {"servers": stored}}), {})
    assert base["declaration_digest.mcp:analysis"] != changed["declaration_digest.mcp:analysis"]
    assert base["declaration_digest.mcp:knowledge"] == changed["declaration_digest.mcp:knowledge"]


def test_the_snapshot_keeps_its_old_size() -> None:
    snap = settings_snapshot(Settings(), {})
    # Each built-in server adds its launch settings (some 26 leaves) and one
    # digest, never its declaration's leaves: the bound grew by the
    # one-program sidecars' share (the identification, document, container
    # and Android servers), not by a thousand.
    assert len(snap) < 800
    assert not _leaves(snap, "tool_facts")
