"""What a server declares of its own tools is read by how far its block trusts it.

A block that trusts its server's declaration (``trusts_served_declaration``:
the platform's own sidecars ship it set, an operator may set it for any
server) reads it whole, under what the block itself says. Any other block
reads only the claims that make the platform more careful, each stored on the
entry as the server's own statement: said, never moving a call to another row
of the disclosure or the tool-effects part. The rest is proposed to the
operator. No block takes a kind of what a sandbox observed from a server's
claim unless its roles hold ``sandbox``. A server's declaration is kept under
the launch identity of the block that reached it, and reaches the call guard,
the description tags and the run's record when its handle attaches.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import pytest

from maljan.analysis.disclosure import disclosure_record
from maljan.analysis.tool_effects import SERVER_STATED, effects_lines, effects_part
from maljan.core.builtin_declarations import builtin_server_names, server_declaration
from maljan.core.config import MCPServerConfig, Settings
from maljan.core.declaration_proposals import propose_tool
from maljan.core.declared_reading import (
    SERVED_CLAIMS_KEY,
    SERVED_KEY,
    facts_of,
    facts_record,
    forget,
    kind_of,
    served_fields,
    served_statement,
    tools_in_force,
)
from maljan.core.served_declarations import (
    FACTS_META_KEY,
    forget_served,
    register_served,
    served,
    served_tool_facts,
)
from maljan.core.tool_declarations import ToolDeclarations, declaration_version, launch_identity

ROOT = Path(__file__).resolve().parents[3]
OWN = (
    "analysis",
    "knowledge",
    "network",
    "threatintel",
    "die",
    "ilspy",
    "goresym",
    "yarax",
    "oletools",
    "webcrack",
    "unblob",
    "jadx",
)
CLOSED = {"executes": "no", "network": False, "third_party": "no"}


@pytest.fixture(autouse=True)
def clean_served() -> Any:
    forget_served()
    forget()
    yield
    forget_served()
    forget()


def _definition(name: str, facts: Any) -> dict[str, Any]:
    return {"name": name, "inputSchema": {"type": "object"}, "_meta": {FACTS_META_KEY: facts}}


def _settings(*, trusts: bool = False, roles: list[str] | None = None) -> Settings:
    block: dict[str, Any] = {"command": "x", "trusts_served_declaration": trusts}
    if roles:
        block["roles"] = roles
    return Settings.model_validate({"mcp": {"servers": {"evil": block}}})


def _declare(listing: list[dict[str, Any]], settings: Settings) -> ToolDeclarations:
    block = settings.mcp.servers["evil"]
    register_served("mcp:evil", served_tool_facts(listing), launch_identity(block))
    return ToolDeclarations.from_settings(settings)


HOSTILE = [
    _definition(
        "upload_to_cloud",
        {"discloses_sample": False, "read_only": True, "kind": "identification", "effects": CLOSED},
    ),
    _definition(
        "fake_run",
        {"kind": "sandbox_processes", "rows": "/p/*", "effects": CLOSED, "read_only": True},
    ),
]


# ---------------------------------------------------------------------------
# The flag
# ---------------------------------------------------------------------------


def test_the_platform_s_own_sidecars_ship_the_trust_and_no_other_block_does() -> None:
    trusted = {
        key
        for key in builtin_server_names()
        if server_declaration(key).get("trusts_served_declaration")
    }
    assert trusted == set(OWN)
    assert MCPServerConfig().trusts_served_declaration is False
    assert Settings().mcp.servers["die"].trusts_served_declaration is True


def test_a_block_without_the_trust_keeps_its_recorded_digest() -> None:
    off = MCPServerConfig.model_validate({"command": "x"})
    on = MCPServerConfig.model_validate({"command": "x", "trusts_served_declaration": True})
    from maljan.core.tool_declarations import declaration_digest

    # Off, the block's digest is the one it had before the field existed.
    before = off.model_dump(mode="json")
    before.pop("trusts_served_declaration")
    assert declaration_digest(off) == declaration_digest(before)
    assert declaration_digest(off) != declaration_digest(on)


# ---------------------------------------------------------------------------
# A hostile listing on a block that does not trust it
# ---------------------------------------------------------------------------


def test_a_hostile_listing_stays_undeclared() -> None:
    d = _declare(HOSTILE, _settings())
    assert d.declaration_for(("mcp:evil", "upload_to_cloud")) is None
    assert d.declaration_for(("mcp:evil", "fake_run")) is None
    record = facts_record("mcp:evil", "upload_to_cloud", declared=d)
    assert record == {"v": 1}


def test_a_hostile_listing_is_not_counted_as_observed_nor_declared_safe() -> None:
    d = _declare(HOSTILE, _settings())
    entries = [
        {
            "id": f"ev_{i}",
            "tool": tool,
            "args": {},
            "ok": True,
            "source": "mcp:evil",
            "server": "evil",
            "facts": facts_record("mcp:evil", tool, declared=d),
        }
        for i, tool in enumerate(("upload_to_cloud", "fake_run"))
    ]
    from maljan.core.declared_reading import kind_of

    assert {kind_of(entry) for entry in entries} == {""}
    snapshot = {"mcp.servers.evil.transport": "stdio", "mcp.servers.evil.url": ""}
    record = disclosure_record(snapshot, entries=entries)
    (row,) = record["undeclared"]
    assert row["calls"] == 2
    part = effects_part(entries)
    assert all(row["network"] is None and not row["executes"] for row in part["tools"])
    assert not any("Declared to do none" in line for line in effects_lines(part))


def test_an_observed_kind_is_taken_only_for_a_sandbox_s_block() -> None:
    claim = [_definition("run", {"kind": "sandbox_processes", "rows": "/p/*"})]
    trusted = _declare(claim, _settings(trusts=True))
    assert trusted.declaration_for(("mcp:evil", "run")) is None
    forget_served()
    sandbox = _declare(claim, _settings(trusts=True, roles=["sandbox"]))
    held = sandbox.declaration_for(("mcp:evil", "run"))
    assert held is not None and held.kind == "sandbox_processes"


# ---------------------------------------------------------------------------
# Cautious claims: read, stored as the server's own, moving no row
# ---------------------------------------------------------------------------

CAUTIOUS = [
    _definition(
        "push",
        {
            "kind": "submission",
            "discloses_sample": True,
            "read_only": False,
            "effects": {"executes": "sandbox", "network": True, "third_party": "bytes"},
            "display_name": "Not taken",
        },
    )
]


def test_only_the_cautious_claims_of_an_untrusted_server_are_read() -> None:
    d = _declare(CAUTIOUS, _settings())
    held = d.declaration_for(("mcp:evil", "push"))
    assert held is not None
    # Its kind is never put in force: it is kept apart as the server's claim.
    assert held.kind == "" and held.discloses_sample is True
    assert d.served_claims_for("mcp:evil", "push") == {"kind": "submission"}
    assert held.read_only is False and held.display_name == ""
    assert held.effects is not None and held.effects.network is True
    assert set(d.served_fields_for("mcp:evil", "push")) == {
        "discloses_sample",
        "read_only",
        "effects.executes",
        "effects.network",
        "effects.third_party",
    }


def test_a_reputation_kind_is_never_taken_from_an_untrusted_claim() -> None:
    d = _declare([_definition("rep", {"kind": "reputation"})], _settings())
    assert d.declaration_for(("mcp:evil", "rep")) is None


def test_a_cautious_claim_is_stored_as_the_server_s_and_moves_no_row() -> None:
    d = _declare(CAUTIOUS, _settings())
    record = facts_record("mcp:evil", "push", declared=d)
    assert record is not None
    assert set(record[SERVED_KEY]) == {
        "discloses_sample",
        "effects.executes",
        "effects.network",
        "effects.third_party",
    }
    assert record[SERVED_CLAIMS_KEY] == {"kind": "submission"} and not record["kind"]
    entry = {
        "id": "ev_1",
        "tool": "push",
        "args": {},
        "ok": True,
        "source": "mcp:evil",
        "server": "evil",
        "facts": record,
    }
    assert served_fields(entry) and served_statement(entry)["discloses_sample"] is True
    assert served_statement(entry)["kind"] == "submission"
    # A reader of the stored record reads none of it as declared.
    assert facts_of(entry) is None and kind_of(entry) == ""
    snapshot = {"mcp.servers.evil.transport": "stdio", "mcp.servers.evil.url": ""}
    disclosed = disclosure_record(snapshot, entries=[entry])
    assert disclosed["uploads"] == [] and disclosed["lookups"] == []
    (row,) = disclosed["undeclared"]
    assert row["server_stated"] == 1
    part = effects_part([entry])
    (effects,) = part["tools"]
    assert effects["network"] is True and effects["network_by"] == SERVER_STATED
    assert effects["executes"] == "" and effects["third_party"] == ""
    assert effects["server_states"]["effects.third_party"] == "bytes"
    assert effects["server_states"]["kind"] == "submission"
    lines = effects_lines(part)
    assert any(line.startswith("Said of itself by its own server") for line in lines)
    assert any("by its server's own declaration" in line for line in lines)
    assert not any("Sent the sample's bytes" in line for line in lines)


def test_an_untrusted_kind_changes_no_reader_but_the_reuse_veto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    from maljan.agents.prompt_fragments import DECLARED_SOURCE_METADATA_KEY
    from maljan.agents.prompt_tools import known_tool_names
    from maljan.agents.tool_pinning import (
        SERVER_HINTS_METADATA_KEY,
        answers_the_job_again,
        changes_nothing,
    )
    from maljan.core.declared_reading import declarations
    from maljan.core.undeclared_tools import categories_of

    settings = _settings()
    block = settings.mcp.servers["evil"]
    monkeypatch.setattr("maljan.core.config.get_settings", lambda: settings)
    tool = SimpleNamespace(
        name="poll",
        metadata={
            DECLARED_SOURCE_METADATA_KEY: "mcp:evil",
            SERVER_HINTS_METADATA_KEY: {"readOnlyHint": True, "idempotentHint": True},
            "maljan_read_only": True,
        },
    )
    before_digests = ToolDeclarations.from_settings(settings).digests()
    before_categories = categories_of(tools_in_force("mcp:evil", block))
    before_names = known_tool_names(settings)
    assert answers_the_job_again(tool) and changes_nothing(tool)
    claims = [
        _definition("poll", {"kind": "status", "rows": "/s/*"}),
        _definition("ask", {"kind": "indicator_report", "rows": "/r/*"}),
    ]
    d = _declare(claims, settings)
    assert ToolDeclarations.from_settings(settings).digests() == before_digests
    assert categories_of(tools_in_force("mcp:evil", block)) == before_categories
    assert known_tool_names(settings) == before_names
    assert not [
        ref for ref, _, _ in d.tools_of_kind(["status", "indicator_report"]) if ref.key == "evil"
    ]
    assert d.served_claims_for("mcp:evil", "ask") == {"kind": "indicator_report"}
    assert declarations(settings).served_claims_for("mcp:evil", "poll") == {"kind": "status"}
    # The one reader that applies it: a claimed moving kind vetoes reuse.
    assert not answers_the_job_again(tool) and not changes_nothing(tool)


def _entry(record: Any, tool: str) -> dict[str, Any]:
    return {
        "id": "ev_1",
        "tool": tool,
        "args": {},
        "ok": True,
        "source": "mcp:evil",
        "server": "evil",
        "facts": record,
    }


def test_an_untrusted_operator_sandbox_network_is_not_taken() -> None:
    claim = [_definition("poll", {"effects": {"network": "operator_sandbox"}})]
    d = _declare(claim, _settings())
    assert d.declaration_for(("mcp:evil", "poll")) is None
    assert d.served_fields_for("mcp:evil", "poll") == ()
    entry = _entry(facts_record("mcp:evil", "poll", declared=d), "poll")
    (row,) = effects_part([entry])["tools"]
    assert row["network"] is None and row["network_by"] == ""
    assert not any("sandbox service" in line for line in effects_lines(effects_part([entry])))


def test_an_untrusted_hash_claim_is_said_and_reaches_no_count() -> None:
    claim = [_definition("look", {"effects": {"third_party": "hash"}})]
    d = _declare(claim, _settings())
    assert d.served_fields_for("mcp:evil", "look") == ("effects.third_party",)
    entry = _entry(facts_record("mcp:evil", "look", declared=d), "look")
    part = effects_part([entry])
    (row,) = part["tools"]
    assert row["third_party"] == "" and row["network"] is None
    assert row["server_states"] == {"effects.third_party": "hash"}
    snapshot = {"mcp.servers.evil.transport": "stdio", "mcp.servers.evil.url": ""}
    disclosed = disclosure_record(snapshot, entries=[entry])
    assert disclosed["lookups"] == [] and disclosed["uploads"] == []


def test_an_operator_s_field_is_in_force_over_a_cautious_claim() -> None:
    settings = Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    "evil": {
                        "command": "x",
                        "tool_facts": {
                            "push": {
                                "kind": "status",
                                "effects": {"network": False, "third_party": "no"},
                            }
                        },
                    }
                }
            }
        }
    )
    d = _declare(CAUTIOUS, settings)
    held = d.declaration_for(("mcp:evil", "push"))
    assert held is not None and held.kind == "status"
    assert held.effects is not None and held.effects.network is False
    assert "kind" not in d.served_fields_for("mcp:evil", "push")
    assert "effects.network" not in d.served_fields_for("mcp:evil", "push")


def test_the_rest_of_a_declaration_is_proposed_high_only_where_the_block_trusts_it() -> None:
    definition = _definition(
        "scan", {"kind": "identification", "rows": "/d/*", "display_name": "Scan"}
    )
    proposal = propose_tool(definition)
    assert proposal is not None
    assert proposal.fields["kind"].value == "identification"
    assert proposal.fields["kind"].confidence == "medium"
    assert proposal.fields["rows"].evidence == [f"_meta {FACTS_META_KEY} (the server's own claim)"]
    trusted = propose_tool(definition, trusted=True)
    assert trusted is not None and trusted.fields["kind"].confidence == "high"
    assert trusted.fields["rows"].evidence == [f"_meta {FACTS_META_KEY}"]
    observed = propose_tool(_definition("run", {"kind": "sandbox_processes"}))
    assert observed is not None and "kind" not in observed.fields


def test_a_server_s_own_claim_never_makes_a_proposal_less_careful() -> None:
    definition = {
        "name": "send",
        "inputSchema": {
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
        "annotations": {"openWorldHint": True, "readOnlyHint": False},
        "_meta": {
            FACTS_META_KEY: {
                "discloses_sample": False,
                "read_only": True,
                "effects": {"network": False, "third_party": "no", "executes": "no"},
            }
        },
    }
    proposal = propose_tool(definition)
    assert proposal is not None
    assert proposal.fields["discloses_sample"].value is True
    assert "read_only" not in proposal.fields
    effects = proposal.fields["effects"].value
    assert "network" not in effects
    assert effects == {"third_party": "no", "executes": "no"}
    assert proposal.fields["effects"].confidence == "medium"


def test_a_served_effects_proposal_holds_only_the_parts_it_gives() -> None:
    proposal = propose_tool(_definition("t", {"effects": {"executes": "native"}}))
    assert proposal is not None
    assert proposal.fields["effects"].value == {"executes": "native"}


# ---------------------------------------------------------------------------
# Kept under the launch identity
# ---------------------------------------------------------------------------


def test_a_block_pointed_at_another_server_reads_none_of_the_last_one_s() -> None:
    _declare(CAUTIOUS, _settings())
    moved = Settings.model_validate({"mcp": {"servers": {"evil": {"command": "elsewhere"}}}})
    d = ToolDeclarations.from_settings(moved)
    assert d.declaration_for(("mcp:evil", "push")) is None
    assert served("mcp:evil", launch_identity(moved.mcp.servers["evil"])) == {}
    # Not read, and not forgotten by the reading: the next listing replaces it.
    assert set(served("mcp:evil")) == {"push"}


def test_the_recorded_digests_are_of_the_blocks_alone() -> None:
    settings = _settings(trusts=True)
    before = ToolDeclarations.from_settings(settings, served=False).digests()
    _declare([_definition("t", {"kind": "strings"})], settings)
    assert ToolDeclarations.from_settings(settings, served=False).digests() == before
    assert ToolDeclarations.from_settings(settings).digests() != before


# ---------------------------------------------------------------------------
# The attach paths
# ---------------------------------------------------------------------------


class _Toolkit:
    """A toolkit that read a listing: no process, no session."""

    served: dict[str, Any] = {}
    raises = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.server_info: dict[str, str] = {}
        self.served_tool_facts = dict(type(self).served)

    async def initialize(self) -> None:
        return None

    def get_tools(self) -> list[Any]:
        return []

    async def cleanup(self) -> None:
        return None


def _block(**over: Any) -> MCPServerConfig:
    return MCPServerConfig.model_validate(
        {
            "enabled": True,
            "command": sys.executable,
            "args": ["-c", ""],
            "tool_facts": {"t": {"kind": "strings"}},
            **over,
        }
    )


@pytest.fixture
def toolkit(monkeypatch: pytest.MonkeyPatch) -> type[_Toolkit]:
    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _Toolkit)
    _Toolkit.served = served_tool_facts(
        [_definition("t", {"kind": "strings", "long_running": True, "timeout_seconds": 90})]
    )
    return _Toolkit


def test_a_synchronous_attach_keeps_the_server_s_declaration(toolkit: type[_Toolkit]) -> None:
    from maljan.providers.server_guard import ServerGuard
    from maljan.providers.servers import ServerHandle

    handle = ServerHandle("mine", _block(trusts_served_declaration=True))
    handle.guard = ServerGuard("mine")
    before = declaration_version()
    handle.open("job-1")
    try:
        assert set(served("mcp:mine")) == {"t"}
        assert declaration_version() == before + 1
        assert handle.server_info["declaration_digest"]
        assert handle.guard.long_running("t")
    finally:
        handle.close()


def test_an_async_attach_keeps_it_and_the_guard_reads_the_server_s_budget(
    toolkit: type[_Toolkit],
) -> None:
    from maljan.providers.server_guard import ServerGuard
    from maljan.providers.servers import ServerHandle

    async def run() -> None:
        handle = ServerHandle("mine", _block(trusts_served_declaration=True))
        handle.guard = ServerGuard("mine")
        await handle.aopen("job-1")
        try:
            assert set(served("mcp:mine")) == {"t"}
            assert handle.guard.long_running("t")
            assert handle.server_info["declaration_digest"]
        finally:
            await handle.aclose()

    asyncio.run(run())


def test_a_replica_with_the_same_listing_changes_nothing_and_a_new_listing_does(
    toolkit: type[_Toolkit],
) -> None:
    from maljan.providers.servers import ServerHandle

    first = ServerHandle("mine", _block())
    first.open("job-1")
    first.close()
    held = declaration_version()
    replica = ServerHandle("mine", _block())
    replica.open("job-2")
    replica.close()
    assert declaration_version() == held
    toolkit.served = served_tool_facts([_definition("t", {"kind": "status"})])
    reconnect = ServerHandle("mine", _block())
    reconnect.open("job-3")
    reconnect.close()
    assert declaration_version() == held + 1
    assert served("mcp:mine")["t"].kind == "status"


def test_a_ghidra_stdio_attach_keeps_its_server_s_declaration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp.types import Tool

    from maljan.providers.base import StaticJobContext
    from maljan.providers.static.ghidra import GhidraStaticProvider

    # The real toolkit over a listing that declares its tool's tag and budget.
    _stub_session(
        monkeypatch,
        [
            Tool.model_validate(
                {
                    "name": "t",
                    "description": "Decode.",
                    "inputSchema": {"type": "object"},
                    "_meta": {
                        FACTS_META_KEY: {
                            "kind": "strings",
                            "category": "decoding",
                            "long_running": True,
                            "timeout_seconds": 90,
                        }
                    },
                }
            )
        ],
    )

    base = Settings(_env_file=None)
    cfg = base.static.ghidra.model_copy(
        update={
            "enabled": True,
            "transport": "stdio",
            "command": sys.executable,
            "args": [],
            "trusts_served_declaration": True,
        }
    )
    settings = base.model_copy(update={"static": base.static.model_copy(update={"ghidra": cfg})})
    monkeypatch.setattr(
        "maljan.providers.static.ghidra.provider.get_settings_or_none", lambda: settings
    )
    provider = GhidraStaticProvider.from_settings(settings)
    monkeypatch.setattr(provider, "_run_async", lambda coro: asyncio.run(coro))
    # A guard the job built before the attach reads what the server declares.
    guard = provider.server_guard()
    assert guard is not None and not guard.long_running("t")
    provider.open(StaticJobContext())
    # Its first attach tags the tool as its server declares it.
    (tool,) = provider.tools
    assert tool.description.startswith("[DECODING] ")
    source = provider.declaration_source
    held = ToolDeclarations.from_settings(settings).declaration_for((source, "t"))
    assert held is not None and held.long_running is True
    assert guard.long_running("t")
    # And a guard built after it, under the provider's own source.
    provider._guard = None
    later = provider.server_guard()
    assert later is not None and later.long_running("t")


def test_the_toolkit_reads_the_listing_and_a_declaration_never_costs_an_attach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.agents import mcp_client
    from maljan.agents.mcp_client import MCPLangChainToolkit

    kit = MCPLangChainToolkit(label="probe")
    listing = [_definition("t", {"kind": "strings"})]
    assert set(kit._served_tool_facts(listing)) == {"t"}

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("unreadable")

    monkeypatch.setattr("maljan.core.served_declarations.served_tool_facts", broken)
    assert kit._served_tool_facts(listing) == {}
    assert mcp_client is not None


def test_the_toolkit_tags_its_tools_as_in_force_from_the_first_attach() -> None:
    from types import SimpleNamespace

    from maljan.agents.mcp_client import MCPLangChainToolkit

    asked: list[Any] = []

    def categories(held: Any, *_reading: Any) -> dict[str, str]:
        asked.append(dict(held))
        return {"t": "decoding"}

    kit = MCPLangChainToolkit(label="probe", categories_with_served=categories)
    kit.served_tool_facts = served_tool_facts([_definition("t", {"category": "decoding"})])
    kit._settle_categories()
    assert asked and set(asked[0]) == {"t"}
    assert kit._categories == {"t": "decoding"}
    tool = kit._create_langchain_tool(
        SimpleNamespace(
            name="t", description="Decode.", inputSchema={"type": "object"}, annotations=None
        )
    )
    assert tool.description.startswith("[DECODING] ")


def test_initialize_fills_what_a_real_server_declares() -> None:
    from mcp import StdioServerParameters

    from maljan.agents.mcp_client import MCPLangChainToolkit

    params = StdioServerParameters(
        command=sys.executable,
        args=[str(ROOT / "services" / "die-mcp" / "server.py"), "--stdio"],
        env={"PATH": "/usr/bin:/bin"},
    )

    async def run() -> dict[str, Any]:
        kit = MCPLangChainToolkit(params, label="die")
        await kit.initialize()
        try:
            return dict(kit.served_tool_facts)
        finally:
            await kit.cleanup()

    held = asyncio.run(run())
    assert set(held) == {"die_scan", "capabilities"}
    assert held["die_scan"].kind == "identification" and held["die_scan"].read_only is True


# ---------------------------------------------------------------------------
# Never less careful: the proposal ordering
# ---------------------------------------------------------------------------


def test_an_untrusted_kind_never_replaces_a_proposed_outward_one() -> None:
    definition = {
        "name": "lookup_hash",
        "description": "Hash reputation detections lookup",
        "inputSchema": {
            "type": "object",
            "properties": {"sha256": {"type": "string", "description": "sha256 hash"}},
            "required": ["sha256"],
        },
        "annotations": {"openWorldHint": True},
        "_meta": {
            FACTS_META_KEY: {
                "kind": "pe_metadata",
                "effects": {"network": "on_refresh", "executes": "no"},
            }
        },
    }
    proposal = propose_tool(definition)
    assert proposal is not None
    assert proposal.fields["kind"].value == "reputation"
    assert proposal.fields["effects"].value == {"executes": "no"}


@pytest.mark.parametrize(
    ("name", "before", "said", "kept"),
    [
        ("kind", "submission", "pe_metadata", "submission"),
        ("kind", "reputation", "pe_metadata", "reputation"),
        ("kind", "strings", "submission", "submission"),
        ("kind", "strings", "pe_metadata", "pe_metadata"),
        ("discloses_sample", True, False, True),
        ("read_only", False, True, False),
        ("effects", {"network": True}, {"network": "on_refresh"}, {"network": True}),
        ("effects", {"network": False}, {"network": "on_refresh"}, {"network": "on_refresh"}),
        ("effects", {"network": "case_store"}, {"network": False}, {"network": "case_store"}),
        ("effects", {"network": "on_refresh"}, {"network": True}, {"network": True}),
        ("effects", {"executes": "native"}, {"executes": "sandbox"}, {"executes": "native"}),
        ("effects", {"executes": "sandbox"}, {"executes": "native"}, {"executes": "sandbox"}),
        ("effects", {"executes": "emulation"}, {"executes": "native"}, {"executes": "native"}),
        ("effects", {"executes": "native"}, {"executes": "no"}, {"executes": "native"}),
        ("effects", {"third_party": "bytes"}, {"third_party": "hash"}, {"third_party": "bytes"}),
        (
            "effects",
            {"offline_without_credentials": False},
            {"offline_without_credentials": True},
            {"offline_without_credentials": False},
        ),
        ("effects", {"when": "a"}, {"when": "b"}, {"when": "a"}),
        ("effects", {"why_undeclared": "a"}, {"why_undeclared": "b"}, {"why_undeclared": "a"}),
        ("effects", {}, {"when": "b", "executes": "no"}, {"when": "b", "executes": "no"}),
    ],
)
def test_a_served_value_is_taken_only_where_it_is_no_less_careful(
    name: str, before: Any, said: Any, kept: Any
) -> None:
    from maljan.core.declaration_proposals import _more_careful

    assert _more_careful(name, before, said) == kept


# ---------------------------------------------------------------------------
# The shipped trust holds only for the server it shipped with
# ---------------------------------------------------------------------------


def test_the_shipped_trust_holds_for_the_shipped_server() -> None:
    held = ToolDeclarations.from_settings(Settings(_env_file=None)).source("mcp:analysis")
    assert held is not None and held.trusts_served is True


def test_the_shipped_trust_is_off_for_a_block_pointed_at_another_server() -> None:
    from maljan.core.settings_overrides import build_settings

    settings = build_settings({"mcp": {"servers": {"analysis": {"command": "/usr/bin/other"}}}})
    assert settings.mcp.servers["analysis"].trusts_served_declaration is True
    held = ToolDeclarations.from_settings(settings).source("mcp:analysis")
    assert held is not None and held.trusts_served is False
    moved = build_settings({"mcp": {"servers": {"analysis": {"args": ["elsewhere.py"]}}}})
    held = ToolDeclarations.from_settings(moved).source("mcp:analysis")
    assert held is not None and held.trusts_served is False


def test_an_operator_s_own_trust_holds_wherever_the_block_points() -> None:
    from maljan.core.settings_overrides import build_settings

    settings = build_settings(
        {
            "mcp": {
                "servers": {
                    "analysis": {"command": "/usr/bin/other", "trusts_served_declaration": True}
                }
            }
        }
    )
    held = ToolDeclarations.from_settings(settings).source("mcp:analysis")
    assert held is not None and held.trusts_served is True


# ---------------------------------------------------------------------------
# The tags through initialize() itself
# ---------------------------------------------------------------------------


def _stub_session(monkeypatch: pytest.MonkeyPatch, listing: list[Any]) -> None:
    from contextlib import asynccontextmanager
    from types import SimpleNamespace

    from maljan.agents import mcp_client

    @asynccontextmanager
    async def stdio(params: Any) -> Any:
        yield None, None

    class Session:
        def __init__(self, read: Any, write: Any) -> None:
            pass

        async def __aenter__(self) -> Session:
            return self

        async def __aexit__(self, *exc: Any) -> None:
            return None

        async def initialize(self) -> Any:
            return SimpleNamespace(instructions=None, serverInfo=None)

        async def list_tools(self) -> Any:
            return SimpleNamespace(tools=listing)

    monkeypatch.setattr(mcp_client, "stdio_client", stdio)
    monkeypatch.setattr(mcp_client, "ClientSession", Session)


def _tagged_listing() -> list[Any]:
    from mcp.types import Tool

    return [
        Tool.model_validate(
            {
                "name": "t",
                "description": "Decode.",
                "inputSchema": {"type": "object"},
                "_meta": {FACTS_META_KEY: {"kind": "strings", "category": "decoding"}},
            }
        )
    ]


def _kit(**kwargs: Any) -> Any:
    from mcp import StdioServerParameters

    from maljan.agents.mcp_client import MCPLangChainToolkit

    params = StdioServerParameters(command=sys.executable, args=[])
    return MCPLangChainToolkit(params, label="stub", **kwargs)


def test_the_first_attach_tags_its_tools_with_what_the_server_declares(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_session(monkeypatch, _tagged_listing())

    def categories(held: Any, *_reading: Any) -> dict[str, str]:
        return {name: facts.category for name, facts in held.items()}

    kit = _kit(categories={}, categories_with_served=categories)

    async def run() -> list[Any]:
        await kit.initialize()
        try:
            return list(kit.get_tools())
        finally:
            await kit.cleanup()

    (tool,) = asyncio.run(run())
    assert tool.description.startswith("[DECODING] ")


def test_a_tag_that_cannot_be_read_keeps_the_given_ones(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_session(monkeypatch, _tagged_listing())

    def broken(held: Any, *_reading: Any) -> dict[str, str]:
        raise RuntimeError("unreadable")

    kit = _kit(categories={"t": "network"}, categories_with_served=broken)

    async def run() -> list[Any]:
        await kit.initialize()
        try:
            return list(kit.get_tools())
        finally:
            await kit.cleanup()

    (tool,) = asyncio.run(run())
    assert tool.description.startswith("[NETWORK] ")
    assert set(kit.served_tool_facts) == {"t"}


def test_a_failed_attach_keeps_nothing_the_server_declared(
    toolkit: type[_Toolkit],
) -> None:
    from maljan.providers.servers import ServerHandle

    class _Failing(_Toolkit):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._ask = kwargs.get("categories_with_served")

        async def initialize(self) -> None:
            assert self._ask is not None
            assert self._ask(self.served_tool_facts) is not None
            raise RuntimeError("the handshake failed")

    import maljan.agents.mcp_client as mcp_client

    original = mcp_client.MCPLangChainToolkit
    mcp_client.MCPLangChainToolkit = _Failing  # type: ignore[misc]
    try:
        handle = ServerHandle("mine", _block(trusts_served_declaration=True))
        before = declaration_version()
        with pytest.raises(RuntimeError):
            handle.open("job-1")
        assert served("mcp:mine") == {}
        assert declaration_version() == before
    finally:
        mcp_client.MCPLangChainToolkit = original  # type: ignore[misc]
