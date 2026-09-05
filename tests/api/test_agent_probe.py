"""The agent probe answers "what would this agent get" without spending a token.

An operator clicking Resolve wants the prompt size, the tool names and the
model id. A probe that ran the agent would be a job, so the LLM registry this
builds refuses to hand out a model at all, and the test fails loudly if
anything reaches for one.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import Any

import pytest

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.services import settings_probes  # noqa: E402
from app.services.settings_probes import PROBES, probe_agent, run_agent_probe  # noqa: E402


class _Exploding:
    """Any attempt to build or call a model fails the test."""

    def build_model(self, *a: Any, **k: Any) -> Any:
        raise AssertionError("the agent probe must never build an LLM")

    def build_model_for_agent(self, *a: Any, **k: Any) -> Any:
        raise AssertionError("the agent probe must never build an LLM")


@pytest.fixture(autouse=True)
def _no_llm(monkeypatch):
    monkeypatch.setattr(
        "maljan.llm.registry.LLMProviderRegistry",
        lambda *a, **k: _Exploding(),
        raising=False,
    )


@pytest.fixture(autouse=True)
def _no_servers(monkeypatch):
    """Every server attaches instantly and offers two tools."""

    async def _atools_for(self, role, job_id, *, exclude="", **ctx):  # type: ignore[no-untyped-def]
        from langchain_core.tools import StructuredTool

        if role != "network":
            return [], []
        return [
            StructuredTool.from_function(func=lambda: "x", name=n, description=n)
            for n in ("extract_dns", "read_pcap_summary")
        ], []

    async def _atools_for_ref(self, ref, job_id, **ctx):  # type: ignore[no-untyped-def]
        return [], []

    monkeypatch.setattr("maljan.providers.servers.ServerRegistry.atools_for", _atools_for)
    monkeypatch.setattr("maljan.providers.servers.ServerRegistry.atools_for_ref", _atools_for_ref)


@pytest.mark.asyncio
async def test_a_built_in_agent_resolves_to_its_prompt_and_its_tools():
    result = await probe_agent({"name": "network", "settings": {}})
    assert result.ok is True
    assert result.tools == ["extract_dns", "read_pcap_summary"]
    assert result.details["prompt_chars"] > 0
    assert len(result.details["prompt_sha256"]) == 64
    assert result.details["static_provider"] == "ghidra"
    assert result.details["llm"]["provider"] == "openai"
    assert [s["key"] for s in result.details["servers"]] == ["network"]
    assert result.details["servers"][0]["status"] == "ok"


@pytest.mark.asyncio
async def test_the_detail_line_says_what_an_operator_wanted_to_know():
    result = await probe_agent({"name": "network", "settings": {}})
    assert "2 tools" in result.detail and "extract_dns" in result.detail


@pytest.mark.asyncio
async def test_a_generic_agent_resolves_to_the_prompt_the_operator_typed():
    import hashlib

    staged = {
        "agents.definitions": {"strings": {"role": "generic", "prompt": "read strings"}},
        "agents.profiles": {"one": {"analysts": ["strings"]}},
        "agents.profile": "one",
    }
    result = await probe_agent({"name": "strings", "settings": staged})
    assert result.ok is True
    assert result.details["prompt_chars"] == len("read strings")
    assert result.details["prompt_sha256"] == hashlib.sha256(b"read strings").hexdigest()
    assert result.tools == []


@pytest.mark.asyncio
async def test_an_unknown_agent_is_a_legible_failure_not_a_stack_trace():
    result = await probe_agent({"name": "ghost", "settings": {}})
    assert result.ok is False and "ghost" in result.detail


@pytest.mark.asyncio
async def test_a_degraded_server_is_reported_per_server_rather_than_failing_the_probe(monkeypatch):
    async def _atools_for(self, role, job_id, *, exclude="", **ctx):  # type: ignore[no-untyped-def]
        return [], ["mcp server 'network' unavailable"]

    monkeypatch.setattr("maljan.providers.servers.ServerRegistry.atools_for", _atools_for)
    result = await probe_agent({"name": "network", "settings": {}})
    assert result.ok is True
    assert result.details["servers"][0]["status"] == "mcp server 'network' unavailable"


@pytest.mark.asyncio
async def test_a_wedged_server_open_is_bounded_by_the_probe_budget_not_by_its_own_cleanup(
    monkeypatch,
):
    """F9's own lesson, reused: the probe never waits for a wedged cleanup.

    A server whose ``atools_for`` never returns, and whose cancellation is
    itself slow to unwind — exactly the shape ``handshake_tools``' own
    docstring describes for ``aopen`` — must still bound the probe's *visible*
    latency to the budget, not to however long the server eventually takes to
    actually stop. The container's own close is picked up in the background
    once the wedged call finally gives up.
    """
    monkeypatch.setattr(settings_probes, "PROBE_BUDGET_SECONDS", 0.05)

    async def _wedged(self, role, job_id, *, exclude="", **ctx):  # type: ignore[no-untyped-def]
        try:
            await asyncio.sleep(999)
        except asyncio.CancelledError:
            # Cancellation itself is slow to unwind — the wedge F9 describes.
            await asyncio.sleep(0.2)
            raise

    cleaned_up = asyncio.Event()

    async def _closed(self) -> None:  # type: ignore[no-untyped-def]
        cleaned_up.set()

    monkeypatch.setattr("maljan.providers.servers.ServerRegistry.atools_for", _wedged)
    monkeypatch.setattr("maljan.core.container.ServiceContainer.aclose", _closed)

    t0 = time.perf_counter()
    result = await probe_agent({"name": "network", "settings": {}})
    elapsed = time.perf_counter() - t0

    assert result.ok is False
    assert "did not answer within" in result.detail
    # Bounded by the (monkeypatched) budget plus the fixed cancellation grace,
    # nowhere near the 999s + 0.2s the wedged server actually takes to unwind.
    assert elapsed < 1.0

    # The container's close is still scheduled and eventually runs, in the
    # background, once the wedged cancellation finally gives up.
    await asyncio.wait_for(cleaned_up.wait(), timeout=2.0)


@pytest.mark.asyncio
async def test_each_bound_server_reports_only_its_own_tools(monkeypatch):
    staged = {
        "mcp.servers": {
            "serverA": {"enabled": True, "agents": []},
            "serverB": {"enabled": True, "agents": []},
        },
        "agents.definitions": {
            "multi": {
                "role": "generic",
                "prompt": "multi",
                "tools": [
                    {"kind": "mcp", "server": "serverA"},
                    {"kind": "mcp", "server": "serverB"},
                ],
            }
        },
        "agents.profiles": {"multi_profile": {"analysts": ["multi"]}},
        "agents.profile": "multi_profile",
    }

    async def _atools_for_ref(self, ref, job_id, **ctx):  # type: ignore[no-untyped-def]
        from langchain_core.tools import StructuredTool

        name = f"{ref.server}_tool"
        return [StructuredTool.from_function(func=lambda: "x", name=name, description=name)], []

    monkeypatch.setattr("maljan.providers.servers.ServerRegistry.atools_for_ref", _atools_for_ref)
    result = await probe_agent({"name": "multi", "settings": staged})

    assert result.ok is True
    by_key = {s["key"]: s["tools"] for s in result.details["servers"]}
    assert by_key["serverA"] == ["serverA_tool"]
    assert by_key["serverB"] == ["serverB_tool"]


@pytest.mark.asyncio
async def test_staged_values_win_over_stored_ones():
    stored = {"core.agents.definitions": {"strings": {"role": "generic", "prompt": "stored"}}}
    staged = {"core.agents.definitions": {"strings": {"role": "generic", "prompt": "staged"}}}
    result = await run_agent_probe("strings", staged, stored)
    assert result.details["prompt_chars"] == len("staged")


@pytest.mark.asyncio
async def test_a_stored_definition_alone_is_enough():
    stored = {"core.agents.definitions": {"strings": {"role": "generic", "prompt": "stored"}}}
    result = await run_agent_probe("strings", {}, stored)
    assert result.ok is True and result.details["prompt_chars"] == len("stored")


def test_the_probe_is_registered_under_its_own_name():
    assert "agent" in PROBES


def test_the_route_is_admin_only_and_passes_the_name_through(monkeypatch):
    from unittest.mock import AsyncMock, MagicMock, patch

    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin
    from app.services.settings_probes import ProbeResult
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id="1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    client = TestClient(app)

    seen: list[str] = []

    async def _fake(name, values, stored):  # type: ignore[no-untyped-def]
        seen.append(name)
        return ProbeResult(True, 1, "ok", None, ["a"], {"prompt_chars": 3})

    with (
        patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})),
        patch("app.api.v1.settings.run_agent_probe", _fake),
    ):
        response = client.post("/api/v1/settings/test/agent?name=strings", json={"values": {}})
    assert response.status_code == 200
    assert seen == ["strings"]
    assert response.json()["details"] == {"prompt_chars": 3}
