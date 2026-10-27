from __future__ import annotations

import pytest

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.providers.base import SandboxProvider


def test_cape2_settings_select_the_cape2_provider():
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "cape2"
    container = ServiceContainer(config=cfg, mock=False)
    provider = container.get_sandbox_provider()
    assert provider.id == "cape2"
    assert isinstance(provider, SandboxProvider)


def test_mock_mode_overrides_the_configured_provider():
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "cape2"
    container = ServiceContainer(config=cfg, mock=True)
    assert container.get_sandbox_provider().id == "mock"


def test_providers_are_cached():
    container = ServiceContainer(config=Settings(_env_file=None), mock=True)
    assert container.get_sandbox_provider() is container.get_sandbox_provider()
    assert container.get_static_provider() is container.get_static_provider()


def test_the_default_profile_is_ghidra_plus_the_cape_equivalent():
    """The smoke test the spec's gate (6) names: today's .env, today's wiring."""
    container = ServiceContainer(config=Settings(_env_file=None), mock=False)
    assert container.get_static_provider().id == "ghidra"
    assert container.get_sandbox_provider().id == "mock"


def test_the_registry_is_built_once_per_container():
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    container = ServiceContainer(config=Settings(_env_file=None), mock=True)
    assert container.get_server_registry() is container.get_server_registry()
    assert [h.name for h in container.get_server_registry().for_agent("judge")] == ["threatintel"]


@pytest.mark.asyncio
async def test_aclose_closes_the_registry_only_when_one_was_built():
    from unittest.mock import MagicMock

    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    def _container() -> ServiceContainer:
        return ServiceContainer(config=Settings(_env_file=None), mock=True)

    container = _container()
    await container.aclose()  # never touched the registry: nothing to close

    container = _container()
    registry = container.get_server_registry()
    registry.close_all = MagicMock(return_value=[])
    await container.aclose()
    registry.close_all.assert_called_once()


# The threat-intel lookups, each withheld by its host without its service's key.
LOOKUPS = ("check_domain_reputation", "check_hash", "check_ip_reputation")
INTEL_KEYS = ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY")
# The sandbox report's views, in the order the in-process tools are built.
SANDBOX_VIEWS = (
    "report_section",
    "processes",
    "network",
    "signatures",
    "dropped_files",
    "registry_ops",
    "api_calls",
    "mutexes",
    "services_and_tasks",
    "channels",
    "items",
)


@pytest.mark.asyncio
@pytest.mark.parametrize("keys", [False, True], ids=["no_intel_keys", "intel_keys_set"])
async def test_the_judge_agent_the_container_hands_out_can_reach_the_registry(monkeypatch, keys):
    """``get_judge_agent`` must wire ``_container`` the same way ``get_agent`` does.

    Run without the threat-intel keys (the lookups are withheld, each with its
    reason) and with placeholder keys (every pinned tool arrives; attaching
    asks no service).

    Without it, ``JudgeAgent._server_registry()`` always reads ``None`` and
    the judge runs with zero threat-intel tools in production — the bug this
    regression test is here to catch stays caught only by going through the
    real ``ServiceContainer``, not a fake one built to look like it wires
    things up.

    ``mock=True`` short-circuits LLM construction (``ConfigurationError:
    Cannot build LLM in mock mode``), so this needs ``mock=False`` and a
    throwaway ``OPENAI_API_KEY`` — the default provider only needs the key to
    be present to build the client, never to make a network call.
    """
    import asyncio
    import json
    import shutil
    import sys
    from pathlib import Path

    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    if not sys.executable or not shutil.which(sys.executable):
        pytest.skip("no python interpreter available to launch the sidecar")

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")
    for name in INTEL_KEYS:
        if keys:
            monkeypatch.setenv(name, "attach-only")
        else:
            monkeypatch.delenv(name, raising=False)

    container = ServiceContainer(config=Settings(_env_file=None), mock=False)

    judge = container.get_judge_agent()
    await asyncio.wait_for(judge._initialize_mcp_client(), timeout=20.0)
    try:
        # Both servers bound to the judge, each contributing its whole pinned
        # manifest: the point of the regression is that the registry is
        # reachable at all, so every server it binds has to arrive.
        goldens = Path(__file__).resolve().parents[2] / "fixtures" / "golden" / "mcp_tools"
        # Under the registry's collision rule: a name the first server already
        # offered arrives from the second prefixed with that server's key,
        # which is what both sidecars' ``capabilities`` tool now does. The
        # role-bound server attaches first, the definition's reference after.
        #
        # A tool its host withholds (its manifest says a setting it needs is
        # missing) does not arrive, and the registry records why: those are
        # read from the registry's own degradation reasons, so the check is
        # "every tool the host can run arrived, and every other is accounted
        # for", whichever keys the host holds.
        reasons = list(container.get_server_registry().degradation_reasons)
        withheld = {
            (key, name)
            for reason in reasons
            for key in ("threatintel", "knowledge")
            for prefix in (f"server.{key}.",)
            if reason.startswith(prefix) and "_unavailable(" in reason
            for name in (reason[len(prefix) :].split("_unavailable(", 1)[0],)
        }
        expected: list[str] = []
        for key in ("threatintel", "knowledge"):
            for name in json.loads((goldens / f"{key}.json").read_text(encoding="utf-8"))["tools"]:
                if (key, name) in withheld:
                    continue
                expected.append(f"{key}__{name}" if name in expected else name)
        # Ahead of the servers' tools, the in-process half of the judge's seed
        # (T-415d): the job's sandbox report tools and one ask per agent it
        # names. Nothing else: no server's tool arrives a second time this way.
        in_process = [
            *(f"sandbox_{name}" for name in SANDBOX_VIEWS),
            "ask_reverser",
            "ask_static",
        ]
        assert [t.name for t in judge.tools][: len(in_process)] == in_process
        assert sorted(t.name for t in judge.tools[len(in_process) :]) == sorted(expected)
        if keys:
            assert withheld == set(), reasons
        else:
            assert {name for key, name in withheld if key == "threatintel"} == set(LOOKUPS)
            for name in LOOKUPS:
                (said,) = [r for r in reasons if r.startswith(f"server.threatintel.{name}_")]
                assert "is not configured" in said, said
    finally:
        await judge.aclose()

    expert = container.get_judge_agent(role="expert")
    assert expert._container is container
