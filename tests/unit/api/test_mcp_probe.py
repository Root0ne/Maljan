"""The connection test launches the same server a job launches."""

from __future__ import annotations

import pytest

from app.services.settings_probes import handshake_tools, known_probe, probe_mcp, run_mcp_probe


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
    assert known_probe("mcp")


@pytest.mark.asyncio
async def test_the_r2_probe_speaks_the_same_handshake(monkeypatch):
    from maljan.core.settings_overrides import build_settings
    from maljan.providers import servers
    from maljan.providers.static import r2

    provider = r2.R2StaticProvider.from_settings(build_settings({}))
    _Handle.made = []
    monkeypatch.setattr(servers, "ServerHandle", _Handle)
    monkeypatch.setattr(
        r2, "resolve_r2_binary", lambda configured, env=None: r2.R2Binary(configured, ())
    )
    result = await provider.probe()
    assert result.ok is True and result.tools == ["open_file", "analyze", "list_imports"]
    assert _Handle.made[-1].config.command == "r2mcp"
    assert handshake_tools is not None


class TestAServerThatDeclaresHowItsCredentialIsObtained:
    """The probe names the one state such a server is in before it is set up.

    An unauthenticated handshake against such an endpoint can fail as a
    transport error whose text says nothing about credentials, so the probe
    answers the question the operator is actually asking before it dials.
    """

    @pytest.mark.asyncio
    async def test_without_a_token_it_reports_that_no_credential_was_obtained(self):
        from maljan.core.config import Settings

        entry = Settings(_env_file=None).mcp.servers["virustotal"].model_dump(mode="json")
        result = await probe_mcp({"name": "virustotal", "entry": entry})

        assert result.ok is False
        assert "no credential" in result.detail
        assert not _Handle.made, "nothing is dialled without a credential"

    @pytest.mark.asyncio
    async def test_an_invented_server_with_a_declaration_is_told_the_same(self):
        host = ".".join(["issuer", "example"])
        entry = {
            "enabled": True,
            "transport": "streamable-http",
            "url": f"https://{host}/mcp",
            "credential_bootstrap": {"url": f"https://{host}/register", "token_json_path": "/t"},
        }
        result = await probe_mcp({"name": "invented", "entry": entry})

        assert result.ok is False
        assert "no credential" in result.detail
        assert not _Handle.made

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


@pytest.mark.asyncio
async def test_a_built_in_is_probed_with_the_environment_names_it_cannot_run_without():
    """A row stored before a sidecar gained a variable must not make the
    connection test launch a different server than the run launches."""
    from maljan.core.config import Settings
    from maljan.tools.roots import SAMPLE_ROOTS_ENV

    stored = Settings(_env_file=None).mcp.servers["analysis"].model_dump(mode="json")
    stored.pop("auth_token", None)
    stored["env_allow"] = [n for n in stored["env_allow"] if n != SAMPLE_ROOTS_ENV]

    result = await run_mcp_probe("analysis", {}, {"core.mcp.servers": {"analysis": stored}})

    assert result.ok is True
    assert SAMPLE_ROOTS_ENV in _Handle.made[-1].config.env_allow


@pytest.mark.asyncio
async def test_a_server_the_operator_added_is_probed_with_exactly_its_own_names():
    from maljan.tools.roots import SAMPLE_ROOTS_ENV

    result = await run_mcp_probe(
        "r2custom",
        {},
        {
            "core.mcp.servers": {
                "r2custom": {"enabled": True, "command": "r2mcp", "env_allow": ["R2_HOME"]}
            }
        },
    )

    assert result.ok is True
    assert _Handle.made[-1].config.env_allow == ["R2_HOME"]
    assert SAMPLE_ROOTS_ENV not in _Handle.made[-1].config.env_allow


@pytest.mark.asyncio
async def test_a_built_in_is_probed_without_a_shipped_name_an_admin_took_away():
    """The console tests the server a run gets, and a run gets no intel key
    once the admin has emptied that list."""
    from maljan.core.config import Settings

    stored = Settings(_env_file=None).mcp.servers["threatintel"].model_dump(mode="json")
    stored.pop("auth_token", None)
    stored["env_allow"] = []

    result = await run_mcp_probe("threatintel", {}, {"core.mcp.servers": {"threatintel": stored}})

    assert result.ok is True
    assert _Handle.made[-1].config.env_allow == []


class _HandleThatDeclares(_Handle):
    """A server whose listing declares one of its tools under ``_meta``."""

    def all_tool_names(self):
        return ["scan"]

    def tool_definitions(self):
        return [
            {
                "name": "scan",
                "inputSchema": {"type": "object"},
                "_meta": {"maljan/tool_facts": {"kind": "identification", "rows": "/d/*"}},
            }
        ]


@pytest.mark.asyncio
@pytest.mark.parametrize(("trusts", "confidence"), [(False, "medium"), (True, "high")])
async def test_what_a_server_declares_is_proposed_as_far_as_its_block_trusts_it(
    monkeypatch, trusts, confidence
):
    monkeypatch.setattr("app.services.settings_probes.ServerHandle", _HandleThatDeclares)
    entry = {"enabled": True, "command": "x", "trusts_served_declaration": trusts}
    result = await probe_mcp({"name": "mine", "entry": entry})
    assert result.ok is True and result.details is not None
    kind = result.details["proposals"]["tools"]["scan"]["fields"]["kind"]
    assert kind["confidence"] == confidence
    assert any("(the server's own claim)" in e for e in kind["evidence"]) is (not trusts)


@pytest.mark.asyncio
async def test_a_repointed_built_in_does_not_post_back_its_shipped_trust(monkeypatch):
    from maljan.core.config import Settings

    monkeypatch.setattr("app.services.settings_probes.ServerHandle", _HandleThatDeclares)
    entry = Settings(_env_file=None).mcp.servers["analysis"].model_dump(mode="json")
    entry["command"] = "/usr/bin/third-party-mcp"
    entry["args"] = []
    assert entry["trusts_served_declaration"] is True
    result = await probe_mcp({"name": "analysis", "entry": entry})
    assert result.ok is True and result.details is not None
    kind = result.details["proposals"]["tools"]["scan"]["fields"]["kind"]
    assert kind["confidence"] == "medium"
    assert any("(the server's own claim)" in e for e in kind["evidence"])
