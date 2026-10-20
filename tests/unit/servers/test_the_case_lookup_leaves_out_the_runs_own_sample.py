"""The case lookup leaves out the run's own sample, and the platform says which it is.

``similar_cases`` takes ``exclude_sample_id`` so a re-analysis is not its own
prior art. The model never supplies it: the knowledge sidecar reads the run's
sample sha256 from ``MALJAN_SAMPLE_SHA256``, which the platform writes into the
child's environment at attach, for a server that asks for it, and clears first.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.providers.servers import ServerHandle, ServerRegistry
from maljan.tools import knowledge as knowledge_tools

ROOT = Path(__file__).resolve().parents[3]
SHA = "ab" * 32


def _server() -> Any:
    spec = importlib.util.spec_from_file_location(
        "knowledge_sidecar_cases", ROOT / "services" / "knowledge-mcp" / "server.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_sidecar_passes_the_runs_sample_and_the_model_cannot_set_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[dict[str, Any]] = []

    def _spy(**kwargs: Any) -> dict[str, Any]:
        seen.append(kwargs)
        return {"cases": [], "techniques": []}

    monkeypatch.setattr(knowledge_tools, "similar_cases", _spy)
    monkeypatch.setenv(knowledge_tools.SAMPLE_SHA256_ENV, SHA)
    server = _server()
    server.similar_cases("beaconing", 3)
    assert seen[0]["exclude_sample_id"] == SHA
    assert seen[0]["k"] == 3
    # Not an argument the model is offered.
    import asyncio

    (tool,) = [t for t in asyncio.run(server.mcp.list_tools()) if t.name == "similar_cases"]
    assert "exclude_sample_id" not in tool.inputSchema["properties"]


def test_the_platform_writes_the_sample_into_a_server_that_asks_for_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(knowledge_tools.SAMPLE_SHA256_ENV, "parent-value")
    settings = Settings(_env_file=None)
    asking = ServerHandle("knowledge", settings.mcp.servers["knowledge"])
    asking._sample_sha256 = SHA
    env: dict[str, str] = {knowledge_tools.SAMPLE_SHA256_ENV: "stale"}
    asking._name_the_sample(env)
    assert env[knowledge_tools.SAMPLE_SHA256_ENV] == SHA

    other = ServerHandle("analysis", settings.mcp.servers["analysis"])
    other._sample_sha256 = SHA
    env = {knowledge_tools.SAMPLE_SHA256_ENV: "stale"}
    other._name_the_sample(env)
    assert knowledge_tools.SAMPLE_SHA256_ENV not in env


def test_the_registry_gives_every_attach_the_runs_sample() -> None:
    registry = ServerRegistry(Settings(_env_file=None), sample_sha256=lambda: SHA)
    assert registry._attach({"sample_sha256": "model-said-this"})["sample_sha256"] == SHA
    assert ServerRegistry(Settings(_env_file=None))._attach({})["sample_sha256"] == ""
