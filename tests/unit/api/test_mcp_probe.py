"""The connection test launches the same server a job launches."""

from __future__ import annotations

import pytest

from app.services.settings_probes import PROBES, handshake_tools, probe_mcp, run_mcp_probe


class _Handle:
    """Records what it was asked to attach, and answers with a manifest."""

    made: list = []

    def __init__(self, name, config):
        self.name = name
        self.config = config
        _Handle.made.append(self)
        self.closed = False

    async def aopen(self, job_id, **kw):
        return None

    async def aclose(self):
        self.closed = True

    def all_tool_names(self):
        return ["open_file", "analyze", "list_imports"]


@pytest.fixture(autouse=True)
def _no_live_server(monkeypatch):
    _Handle.made = []
    monkeypatch.setattr("app.services.settings_probes.ServerHandle", _Handle)


@pytest.mark.asyncio
async def test_the_probe_reports_the_manifest_and_names_it_in_the_detail():
    result = await probe_mcp({"name": "r2custom", "entry": {"enabled": True, "command": "r2mcp"}})
    assert result.ok is True
    assert result.tools == ["open_file", "analyze", "list_imports"]
    assert "3 tools" in result.detail and "open_file" in result.detail


@pytest.mark.asyncio
async def test_the_probe_forces_the_server_on_and_ignores_the_stored_allow_list():
    """A probe exists to read the manifest, so it must not be narrowed by it."""
    await probe_mcp({"name": "x", "entry": {"enabled": False, "command": "mcp", "tools": []}})
    assert _Handle.made[-1].config.enabled is True
    assert _Handle.made[-1].config.tools is None


@pytest.mark.asyncio
async def test_a_hanging_server_is_killed_and_reported(monkeypatch):
    import asyncio

    async def hang(self, job_id, **kw):
        await asyncio.sleep(30)

    monkeypatch.setattr(_Handle, "aopen", hang)
    monkeypatch.setattr("app.services.settings_probes.PROBE_BUDGET_SECONDS", 0.05)
    result = await probe_mcp({"name": "x", "entry": {"enabled": True, "command": "mcp"}})
    assert result.ok is False and "no MCP handshake" in result.detail
    assert _Handle.made[-1].closed is True, "the child is killed, not left running"


@pytest.mark.asyncio
async def test_a_wedged_aopen_whose_cancellation_also_hangs_does_not_stretch_the_budget(
    monkeypatch,
):
    """Regression (F9): a probe's 5 s budget used to be able to stretch to
    ~25 s -- ``wait_for`` cancels a wedged ``aopen`` and then waits for that
    cancellation to finish, and ``aopen``'s own handler awaits an internal
    cleanup bounded at 20 s. A fake ``aopen`` that not only hangs but also
    ignores cancellation (its own ``asyncio.shield``ed sleep) proves the fix
    does not fall back to waiting for it: the probe returns close to the
    budget, not close to the internal cleanup's own bound."""
    import asyncio
    import time

    async def deaf_to_cancellation(self, job_id, **kw):
        # Shielded, so ``task.cancel()`` does not interrupt this sleep --
        # standing in for a real wedged subprocess handshake/cleanup that
        # does not respond to cancellation quickly either.
        await asyncio.shield(asyncio.sleep(0.3))

    monkeypatch.setattr(_Handle, "aopen", deaf_to_cancellation)
    monkeypatch.setattr("app.services.settings_probes.PROBE_BUDGET_SECONDS", 0.05)

    t0 = time.perf_counter()
    result = await probe_mcp({"name": "x", "entry": {"enabled": True, "command": "mcp"}})
    elapsed = time.perf_counter() - t0

    assert result.ok is False and "no MCP handshake" in result.detail
    assert elapsed < 2.0, f"probe took {elapsed:.2f}s, far past its 0.05s+grace budget"


@pytest.mark.asyncio
async def test_a_missing_binary_names_itself(monkeypatch):
    async def boom(self, job_id, **kw):
        raise FileNotFoundError("r2mcp")

    # Through monkeypatch, not a direct class assignment: a bare assignment
    # would outlive this test and take down every later one that opens a
    # handle, since ``_Handle`` is one module-level class shared by them all.
    monkeypatch.setattr(_Handle, "aopen", boom)
    result = await probe_mcp({"name": "x", "entry": {"enabled": True, "command": "r2mcp"}})
    assert result.ok is False and "r2mcp" in result.detail


@pytest.mark.asyncio
async def test_run_mcp_probe_layers_staged_values_over_the_stored_map():
    result = await run_mcp_probe(
        "r2custom",
        {"core.mcp.servers": {"r2custom": {"enabled": True, "command": "staged"}}},
        {"core.mcp.servers": {"r2custom": {"enabled": True, "command": "stored"}}},
    )
    assert result.ok is True
    assert _Handle.made[-1].config.command == "staged"


@pytest.mark.asyncio
async def test_run_mcp_probe_merges_fields_a_staged_url_keeps_the_stored_token():
    result = await run_mcp_probe(
        "r2custom",
        {"core.mcp.servers": {"r2custom": {"url": "http://new-host"}}},
        {
            "core.mcp.servers": {
                "r2custom": {
                    "enabled": True,
                    "transport": "http",
                    "url": "http://old-host",
                    "auth_token": "s3cr3t-token",
                }
            }
        },
    )
    assert result.ok is True
    config = _Handle.made[-1].config
    assert config.url == "http://new-host"
    assert config.auth_token.get_secret_value() == "s3cr3t-token"


@pytest.mark.asyncio
async def test_run_mcp_probe_treats_a_staged_mask_as_unchanged():
    result = await run_mcp_probe(
        "r2custom",
        {"core.mcp.servers": {"r2custom": {"enabled": True, "auth_token": "**********"}}},
        {"core.mcp.servers": {"r2custom": {"enabled": True, "auth_token": "s3cr3t-token"}}},
    )
    assert result.ok is True
    assert _Handle.made[-1].config.auth_token.get_secret_value() == "s3cr3t-token"


@pytest.mark.asyncio
async def test_run_mcp_probe_uses_a_staged_real_token_and_never_echoes_it():
    result = await run_mcp_probe(
        "r2custom",
        {"core.mcp.servers": {"r2custom": {"enabled": True, "auth_token": "brand-new-token"}}},
        {"core.mcp.servers": {"r2custom": {"enabled": True, "auth_token": "old-token"}}},
    )
    assert result.ok is True
    assert _Handle.made[-1].config.auth_token.get_secret_value() == "brand-new-token"
    assert "brand-new-token" not in result.detail
    assert "old-token" not in result.detail


@pytest.mark.asyncio
async def test_an_unknown_server_is_a_legible_failure():
    result = await run_mcp_probe("nope", {}, {})
    assert result.ok is False and "nope" in result.detail


def test_the_probe_is_registered_under_its_own_name():
    assert "mcp" in PROBES


@pytest.mark.asyncio
async def test_the_r2_probe_speaks_the_same_handshake(monkeypatch):
    from app.services.settings_probes import probe_r2

    result = await probe_r2({"binary_path": "r2mcp"})
    assert result.ok is True and result.tools == ["open_file", "analyze", "list_imports"]
    assert _Handle.made[-1].config.command == "r2mcp"
    assert handshake_tools is not None


class TestTheVirustotalServer:
    """The probe names the one state a fresh VirusTotal built-in is in.

    An unauthenticated handshake against VirusTotal's endpoint fails as a
    transport error whose text says nothing about credentials, so the probe
    answers the question the operator is actually asking before it dials.
    """

    @pytest.mark.asyncio
    async def test_without_a_token_it_reports_that_no_agent_is_registered(self):
        from maljan.core.config import Settings

        entry = Settings(_env_file=None).mcp.servers["virustotal"].model_dump(mode="json")
        result = await probe_mcp({"name": "virustotal", "entry": entry})

        assert result.ok is False
        assert "no agent token" in result.detail
        assert not _Handle.made, "nothing is dialled without a credential"

    @pytest.mark.asyncio
    async def test_with_a_token_it_dials_the_endpoint_like_any_other_server(self):
        from maljan.core.config import Settings

        entry = Settings(_env_file=None).mcp.servers["virustotal"].model_dump(mode="json")
        entry["auth_token"] = "vtai_" + "c" * 43

        result = await probe_mcp({"name": "virustotal", "entry": entry})

        assert result.ok is True
        assert _Handle.made[-1].config.url == "https://ai.virustotal.com/mcp"


class _HandleWithManifest(_Handle):
    """A server that also answers ``capabilities``, as the registry keeps it."""

    async def aopen(self, job_id, **kw):
        from maljan.tools.capabilities import ServerCapabilities

        self.capabilities = ServerCapabilities.from_payload(
            self.name,
            {
                "server": self.name,
                "version": "1.0",
                "tools": [
                    {"name": "open_file", "available": True, "reason": None},
                    {
                        "name": "analyze",
                        "available": False,
                        "reason": "olefile is not installed",
                        "remediation": "uv sync --extra tools",
                    },
                ],
            },
        )


@pytest.mark.asyncio
async def test_the_probe_returns_the_manifest_and_counts_the_unavailable(monkeypatch):
    monkeypatch.setattr("app.services.settings_probes.ServerHandle", _HandleWithManifest)
    result = await probe_mcp({"name": "analysis", "entry": {"enabled": True, "command": "x"}})
    assert result.ok is True
    assert result.details is not None
    manifest = result.details["capabilities"]
    assert manifest["version"] == "1.0"
    assert [c["name"] for c in manifest["tools"] if not c["available"]] == ["analyze"]
    assert "1 unavailable on this host" in result.detail


@pytest.mark.asyncio
async def test_a_server_without_a_manifest_has_no_details():
    result = await probe_mcp({"name": "r2custom", "entry": {"enabled": True, "command": "r2mcp"}})
    assert result.ok is True and result.details is None
