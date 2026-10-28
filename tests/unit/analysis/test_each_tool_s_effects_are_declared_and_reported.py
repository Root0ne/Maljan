"""Each tool a run called says what it does beyond answering, or that it does not say.

Whether it runs the sample's code (natively, under emulation, in a sandbox),
reaches the network, or sends the sample's hash or bytes to a third party: read
from the tool's declaration as its ledger entry stored it, else (for the
network) from the ``openWorldHint`` its own MCP server gave it when it was
attached, else undeclared, and never taken as safe. The part sits in the
disclosure record and agrees with its upload rows and its isolation part.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from maljan.analysis.disclosure import STOPPED_PART_WAY, disclosure_lines, disclosure_record
from maljan.analysis.tool_effects import (
    INTRO_SENTENCE,
    effects_lines,
    effects_part,
    entry_effects,
    sends_sample_bytes,
)
from maljan.core.config import Settings
from maljan.core.declared_reading import facts_record, with_hints
from maljan.core.tool_declarations import (
    ToolDeclarations,
    ToolEffects,
    ToolFacts,
    strict_declarations,
)

LOCAL_LLM = {"llm.provider": "openai", "llm.openai.base_url": "http://127.0.0.1:8080/v1"}
STDIO = {"mcp.servers.analysis.transport": "stdio", "mcp.servers.analysis.url": ""}


@pytest.fixture(scope="module")
def shipped() -> ToolDeclarations:
    """The declarations a fresh deployment runs with: the built-ins' shipped ones."""
    return ToolDeclarations.from_settings(Settings(_env_file=None))


def _entry(source: str | None, tool: str, facts: Any = None, **over: Any) -> dict[str, Any]:
    row: dict[str, Any] = {"id": "ev_0001", "tool": tool, "args": {}, "ok": True}
    if source is not None:
        row["source"] = source
        if source.startswith("mcp:"):
            row["server"] = source.partition(":")[2]
    if facts is not None:
        row["facts"] = facts
    row.update(over)
    return row


def _row(part: dict[str, Any], tool: str) -> dict[str, Any]:
    (row,) = [row for row in part["tools"] if row["tool"] == tool]
    return row


# ---------------------------------------------------------------------------
# Built-in declarations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "tool"),
    [
        ("mcp:analysis", "floss"),
        ("provider:ghidra", "emulate_function"),
        ("provider:ghidra", "emulate_hash_batch"),
        ("pack", "floss"),
    ],
)
def test_a_built_in_emulator_is_declared_to_run_the_sample_s_code(
    shipped: ToolDeclarations, source: str, tool: str
) -> None:
    facts = facts_record(source, tool, declared=shipped)
    assert facts is not None
    assert facts["effects"] == {"executes": "emulation", "network": False, "third_party": "no"}

    effects = entry_effects(_entry(source, tool, facts))
    assert (effects.executes, effects.network, effects.third_party) == ("emulation", False, "no")


def test_the_emulator_is_told_with_where_its_source_read_the_sample(
    shipped: ToolDeclarations,
) -> None:
    floss = _entry(
        "mcp:analysis",
        "floss",
        facts_record("mcp:analysis", "floss", declared=shipped),
        args={"path": "/samples/x.exe"},
    )
    pe = _entry(
        "mcp:analysis", "pe_info", facts_record("mcp:analysis", "pe_info", declared=shipped)
    )
    record = disclosure_record({**LOCAL_LLM, **STDIO}, entries=[floss, pe])

    row = _row(record["effects"], "floss")
    assert (row["executes"], row["read_where"], row["read_isolated"]) == (
        "emulation",
        "child",
        False,
    )
    lines = effects_lines(record["effects"])
    assert lines[0] == (
        "Ran the sample's code under emulation: `floss` on tool server `analysis`, read in a "
        "process the worker started, not shown to be kept from the worker."
    )
    assert "Declared to do none of these: 1 tool, on tool server `analysis`." in lines


def test_an_emulator_kept_by_a_declared_launcher_is_told_as_the_declaration(
    shipped: ToolDeclarations,
) -> None:
    floss = _entry(
        "mcp:analysis",
        "floss",
        facts_record("mcp:analysis", "floss", declared=shipped),
        args={"path": "/samples/x.exe"},
    )
    kept = {
        "uid": 10003,
        "same_uid_as_worker": False,
        "shares_group_with_worker": False,
        "own_pid_namespace": True,
        "own_net_namespace": True,
        "own_mount_namespace": True,
        "cap_eff_zero": True,
        "cap_prm_zero": True,
        "cap_amb_zero": True,
        "no_new_privs": True,
        "platform_names_in_env": [],
        "depth": 1,
    }
    launcher = {
        **kept,
        "uid": 1000,
        "same_uid_as_worker": True,
        "own_pid_namespace": False,
        "descendants": [kept],
        "descendants_judged": True,
        "descendants_why": "",
    }
    record = disclosure_record(
        {**LOCAL_LLM, **STDIO, "mcp.servers.analysis.launcher_depth": 1},
        entries=[floss],
        opened={"mcp:analysis": [{"where": "child", **launcher}]},
        worker={"uid": 1000, "platform_names_in_env": []},
    )
    row = _row(record["effects"], "floss")
    assert (row["read_isolated"], row["read_isolated_by"]) == (True, "declaration")
    assert effects_lines(record["effects"])[0].endswith(
        "read in a process the worker started, kept from the worker as its block's "
        "declaration of a launcher says."
    )


def test_a_threat_intel_lookup_is_declared_to_reach_the_network_and_send_the_hash(
    shipped: ToolDeclarations,
) -> None:
    hashed = facts_record("mcp:threatintel", "check_hash", declared=shipped)
    domain = facts_record("mcp:threatintel", "check_domain_reputation", declared=shipped)
    assert hashed is not None and domain is not None
    assert hashed["effects"] == {"executes": "no", "network": True, "third_party": "hash"}
    assert domain["effects"]["third_party"] == "no"

    part = effects_part(
        [
            _entry("mcp:threatintel", "check_hash", hashed),
            _entry("mcp:threatintel", "check_domain_reputation", domain),
        ]
    )
    assert [(row["tool"], row["network"], row["third_party"]) for row in part["tools"]] == [
        ("check_domain_reputation", True, "no"),
        ("check_hash", True, "hash"),
    ]
    assert effects_lines(part) == [
        "Reached the network: `check_domain_reputation` and `check_hash` on tool server "
        "`threatintel`.",
        "Sent the sample's hash to a third party: `check_hash` on tool server `threatintel`.",
    ]


def test_a_tool_that_runs_any_script_it_is_given_is_left_undeclared(
    shipped: ToolDeclarations,
) -> None:
    facts = facts_record("provider:r2", "run_command", declared=shipped)
    assert facts is not None
    assert set(facts["effects"]) == {"why_undeclared"}
    part = effects_part([_entry("provider:r2", "run_command", facts)])
    assert effects_lines(part) == [
        "Undeclared whether it may run the sample's code, reach the network or send the "
        "sample's hash or bytes to a third party, so not taken as safe: `run_command` on the "
        "`r2` provider's tool server; its declaration says why: it runs whatever script or "
        "command it is given, so what it does is whatever that does."
    ]


def _declared_as_shipped(key: str) -> dict[str, Any]:
    """A built-in server's tools as the platform reads them: its block's, its own under them."""
    from maljan.core.declared_reading import builtin_tools

    return {
        tool: facts.model_dump(mode="json", exclude_defaults=True)
        for tool, facts in builtin_tools(key).items()
    }


def _provider_sources() -> list[str]:
    from maljan.core import builtin_declarations as built

    return list(built.provider_block_paths())


def _in_force(source: str) -> dict[str, Any]:
    """A shipped provider block's tools as the platform reads them, its listing included."""
    from maljan.core.config import Settings
    from maljan.core.tool_declarations import ToolDeclarations

    held = ToolDeclarations.from_settings(Settings(_env_file=None)).source(source)
    assert held is not None, source
    return {
        tool: facts.model_dump(mode="json", exclude_defaults=True)
        for tool, facts in held.tools.items()
    }


def _shipped_blocks() -> list[tuple[str, dict[str, Any]]]:
    from maljan.core import builtin_declarations as built

    blocks = [
        (f"mcp:{key}", {"tool_facts": _declared_as_shipped(key)})
        for key in built.builtin_server_names()
    ]
    # A provider's tools as the platform reads them too: Ghidra's and radare2's
    # effects are read from their listings under their blocks' statement.
    blocks += [(source, {"tool_facts": _in_force(source)}) for source in _provider_sources()]
    blocks += [
        (str(ref), cfg.model_dump(mode="json"))
        for ref, cfg in built.in_process_declarations().items()
    ]
    return blocks


def test_every_built_in_tool_declares_its_effects_or_says_why_not() -> None:
    from maljan.core.tool_declarations import strict_declarations

    unsaid: list[str] = []
    for source, block in _shipped_blocks():
        assert block.get("tool_facts"), source
        for tool, raw in block["tool_facts"].items():
            with strict_declarations():
                effects = ToolFacts.model_validate(raw).effects
            if effects is None:
                unsaid.append(f"{source} {tool}: no effects")
                continue
            # The bytes going out may be said by ``discloses_sample`` alone.
            sends = effects.third_party or sends_sample_bytes(ToolFacts.model_validate(raw))
            whole = effects.executes and effects.network is not None and sends
            if not whole and not effects.why_undeclared:
                unsaid.append(f"{source} {tool}: {effects!r} with no reason")
    assert unsaid == []


@pytest.mark.parametrize(
    ("tool", "network"),
    [
        ("get_cuckoo_status", "operator_sandbox"),
        ("search_task", "operator_sandbox"),
        ("get_task_status", "operator_sandbox"),
        ("get_task_report", "operator_sandbox"),
        ("get_task_iocs", "operator_sandbox"),
        ("get_task_config", "operator_sandbox"),
    ],
)
def test_the_cape_sidecar_asks_the_operator_s_own_sandbox(
    shipped: ToolDeclarations, tool: str, network: str
) -> None:
    facts = facts_record("provider:cape2", tool, declared=shipped)
    assert facts is not None and facts["kind"] == ""
    assert facts["effects"] == {"executes": "no", "network": network, "third_party": "no"}


def test_a_submission_to_the_sidecar_s_sandbox_is_told_where_the_disclosure_placed_it(
    shipped: ToolDeclarations,
) -> None:
    cape = facts_record("provider:cape2", "submit_file", declared=shipped)
    vt = facts_record("mcp:virustotal", "submit_file", declared=shipped)
    assert cape is not None and cape["discloses_sample"] is True
    assert cape["effects"] == {
        "executes": "sandbox",
        "network": "operator_sandbox",
        "third_party": "bytes",
    }
    part = effects_part(
        [_entry("provider:cape2", "submit_file", cape), _entry("mcp:virustotal", "submit_file", vt)]
    )
    assert [(row["source"], row["third_party"], row["network"]) for row in part["tools"]] == [
        ("mcp:virustotal", "bytes", True),
        ("provider:cape2", "bytes", "operator_sandbox"),
    ]
    lines = effects_lines(part)
    assert lines[:2] == [
        "Had the sample run in the sandbox service its server fronts: `submit_file` on the "
        "`cape2` provider's tool server, where it went cannot be told: the disclosure does not "
        "place it.",
        "Handed the sample to a third party's sandbox, which may run it: `submit_file` on tool "
        "server `virustotal`.",
    ]
    assert not any("not a third party" in line for line in lines)
    assert (
        "Sent the sample's bytes to a third party: `submit_file` on tool server `virustotal`; "
        "where each call sent them is in the upload rows of the disclosure above."
    ) in lines


@pytest.mark.parametrize(
    ("block", "host", "where"),
    [
        ({"sandbox.cape2.mcp.transport": "stdio"}, "", "unknown"),
        (
            {
                "sandbox.cape2.mcp.transport": "streamable-http",
                "sandbox.cape2.mcp.url": "https://cape.example/mcp",
            },
            "cape.example",
            "remote",
        ),
        (
            {
                "sandbox.cape2.mcp.transport": "streamable-http",
                "sandbox.cape2.mcp.url": "http://10.0.0.5:9000/mcp",
            },
            "10.0.0.5",
            "unknown",
        ),
    ],
)
def test_the_sandbox_line_and_the_upload_row_place_the_call_alike(
    shipped: ToolDeclarations, block: dict[str, str], host: str, where: str
) -> None:
    cape = facts_record("provider:cape2", "submit_file", declared=shipped)
    record = disclosure_record(
        {**LOCAL_LLM, **block}, entries=[_entry("provider:cape2", "submit_file", cape)]
    )
    (upload,) = [row for row in record["uploads"] if row["by"] == "tool"]
    row = _row(record["effects"], "submit_file")
    assert (row["placed_where"], row["placed_host"], row["placed_why"]) == (
        upload["where"],
        upload["host"],
        upload["why"],
    )
    assert (upload["where"], upload["host"]) == (where, host)
    lines = effects_lines(record["effects"])
    if upload["why"]:
        assert f"where it went cannot be told: {upload['why']}" in lines[0]
    else:
        assert "outside this machine; whether it is the operator's own" in lines[0]
    assert not any("not a third party" in line for line in lines)


def test_reference_refreshes_and_the_case_store_are_named(shipped: ToolDeclarations) -> None:
    for tool in ("attck_lookup", "attck_validate", "family_lookup", "resolve_technique"):
        held = facts_record("mcp:knowledge", tool, declared=shipped)
        assert held is not None and held["effects"]["network"] == "on_refresh", tool
    attck = facts_record("mcp:knowledge", "attck_lookup", declared=shipped)
    matches = facts_record("pack", "function_matches", declared=shipped)
    assert attck is not None and attck["effects"]["network"] == "on_refresh"
    assert matches is not None and matches["effects"]["network"] == "case_store"
    part = effects_part(
        [
            _entry("mcp:knowledge", "attck_lookup", attck),
            _entry("pack", "function_matches", matches),
        ]
    )
    assert effects_lines(part) == [
        "Reached the configured case-memory store, which the disclosure's case-memory row "
        "places: `function_matches` on Triage pack (`pack`).",
        "Reach the network only to fetch or refresh reference data they keep, sending nothing "
        "of the sample: `attck_lookup` on tool server `knowledge`.",
    ]
    with pytest.raises(ValueError, match="network"):
        ToolEffects(network="sometimes")
    with strict_declarations(), pytest.raises(ValueError, match="on_refresh"):
        ToolFacts.model_validate({"effects": {"third_party": "hash", "network": "on_refresh"}})


# ---------------------------------------------------------------------------
# A map an operator saved whole before the field existed
# ---------------------------------------------------------------------------


def test_a_map_saved_whole_keeps_the_shipped_effects_and_the_operator_s_own_values() -> None:
    from maljan.core.tool_declarations import (
        merge_tool_facts,
        stored_changes,
        stored_in_force,
    )

    shipped = _declared_as_shipped("analysis")
    # Saved whole by an earlier release: no mark, no ``effects`` anywhere, and
    # an operator's own budget on FLOSS and own effects on ``strings``.
    whole = {
        tool: {k: v for k, v in facts.items() if k != "effects"} for tool, facts in shipped.items()
    }
    whole["floss"] = {**whole["floss"], "timeout_seconds": 30}
    whole["strings"] = {**whole["strings"], "effects": {"executes": "no", "network": True}}

    in_force, refused = stored_in_force(shipped, whole)
    assert refused == []
    assert in_force["floss"]["effects"] == shipped["floss"]["effects"]
    assert in_force["floss"]["timeout_seconds"] == 30
    assert in_force["pe_info"]["effects"] == shipped["pe_info"]["effects"]
    # Merged sub-field by sub-field: the shipped ``third_party`` stays.
    assert in_force["strings"]["effects"] == {
        "executes": "no",
        "network": True,
        "third_party": "no",
    }

    # The same map read as the changes a save stores puts the same in force.
    again = merge_tool_facts(shipped, stored_changes(whole, shipped))
    assert again["floss"]["effects"] == shipped["floss"]["effects"]
    assert again["strings"]["effects"] == in_force["strings"]["effects"]
    assert again["floss"]["timeout_seconds"] == 30


# ---------------------------------------------------------------------------
# MCP hints, and a tool nothing declares
# ---------------------------------------------------------------------------


def test_an_open_world_hint_says_the_tool_reaches_the_network_by_its_server_s_word() -> None:
    hinted = with_hints({"v": 1}, SimpleNamespace(openWorldHint=True, readOnlyHint=True))
    assert hinted == {"v": 1, "hints": {"readOnlyHint": True, "openWorldHint": True}}
    part = effects_part([_entry("mcp:intel", "lookup", hinted)])

    row = _row(part, "lookup")
    assert (row["network"], row["network_by"], row["executes"], row["third_party"]) == (
        True,
        "server_hint",
        "",
        "",
    )
    assert row["hints"] == {"readOnlyHint": True, "openWorldHint": True}
    assert effects_lines(part) == [
        "Reached the network: `lookup` on tool server `intel`, by its server's own hint.",
        "Undeclared whether it may run the sample's code or send the sample's hash or bytes to "
        "a third party, so not taken as safe: `lookup` on tool server `intel`.",
    ]


def test_a_tool_with_no_hints_and_no_declaration_reads_undeclared() -> None:
    bare = with_hints({"v": 1}, None)
    assert bare == {"v": 1}
    part = effects_part([_entry("mcp:intel", "poll", bare)])
    row = _row(part, "poll")
    assert (row["executes"], row["network"], row["third_party"], row["hints"]) == (
        "",
        None,
        "",
        {},
    )
    assert effects_lines(part) == [
        "Undeclared whether it may run the sample's code, reach the network or send the "
        "sample's hash or bytes to a third party, so not taken as safe: `poll` on tool server "
        "`intel`."
    ]


def test_a_declaration_wins_over_the_server_s_hint() -> None:
    facts = with_hints({"v": 1, "effects": {"network": False}}, SimpleNamespace(openWorldHint=True))
    effects = entry_effects(_entry("mcp:intel", "look", facts))
    assert (effects.network, effects.network_by) == (False, "declared")


def test_an_entry_with_no_source_is_never_read_by_its_tool_s_name() -> None:
    # ``floss`` ships a declaration, but an entry that recorded no source has
    # none: its effects are undeclared, never borrowed from the built-in.
    effects = entry_effects(_entry(None, "floss", server="analysis"))
    assert (effects.executes, effects.network, effects.third_party) == ("", None, "")


def test_the_server_s_hints_ride_from_attach_to_the_entry() -> None:
    from langchain_core.tools import StructuredTool
    from pydantic import BaseModel

    from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
    from maljan.agents.mcp_client import MCPLangChainToolkit
    from maljan.agents.tool_pinning import SERVER_HINTS_METADATA_KEY, SERVER_METADATA_KEY

    client = MCPLangChainToolkit.__new__(MCPLangChainToolkit)
    client._categories = {}
    attached = client._create_langchain_tool(
        SimpleNamespace(
            name="lookup",
            description="lookup",
            inputSchema={"properties": {}, "required": []},
            annotations=SimpleNamespace(openWorldHint=True, destructiveHint=False),
        )
    )
    hints = (attached.metadata or {})[SERVER_HINTS_METADATA_KEY]
    assert hints == {"destructiveHint": False, "openWorldHint": True}
    bare = client._create_langchain_tool(
        SimpleNamespace(
            name="poll",
            description="poll",
            inputSchema={"properties": {}, "required": []},
            annotations=None,
        )
    )
    assert SERVER_HINTS_METADATA_KEY not in (bare.metadata or {})

    class _Args(BaseModel):
        pass

    async def _answer() -> str:
        return "ok"

    tool = StructuredTool.from_function(
        coroutine=_answer,
        name="lookup",
        description="lookup",
        args_schema=_Args,
        metadata={SERVER_METADATA_KEY: "intel", SERVER_HINTS_METADATA_KEY: hints},
    )
    recorder = EvidenceRecorder("static")
    (wrapped,) = record_tools([tool], recorder)
    asyncio.run(wrapped.ainvoke({}))
    (entry,) = recorder.entries
    assert entry.source == "mcp:intel"
    assert entry.facts is not None and entry.facts["hints"] == hints
    assert entry_effects(entry).network is True


# ---------------------------------------------------------------------------
# One source of truth with the disclosure
# ---------------------------------------------------------------------------


def test_the_bytes_sent_agree_with_the_disclosure_s_upload_rows(
    shipped: ToolDeclarations,
) -> None:
    snapshot = {
        **LOCAL_LLM,
        "mcp.servers.virustotal.transport": "streamable-http",
        "mcp.servers.virustotal.url": "https://vt.example/mcp",
        "mcp.servers.acme.transport": "streamable-http",
        "mcp.servers.acme.url": "https://acme.example/mcp",
    }
    submit = facts_record("mcp:virustotal", "submit_file", declared=shipped)
    report = facts_record("mcp:virustotal", "get_file_report", declared=shipped)
    # An operator's server that says so by its effects alone.
    sent = {"v": 1, "kind": "submission", "effects": {"third_party": "bytes"}}
    record = disclosure_record(
        snapshot,
        entries=[
            _entry("mcp:virustotal", "submit_file", submit),
            _entry("mcp:virustotal", "get_file_report", report),
            _entry("mcp:acme", "push", sent),
        ],
    )
    said = {row["source"] for row in record["effects"]["tools"] if row["third_party"] == "bytes"}
    uploaded = {row["source"] for row in record["uploads"] if row["by"] == "tool"}
    assert said == uploaded == {"mcp:virustotal", "mcp:acme"}
    assert _row(record["effects"], "submit_file")["executes"] == "sandbox"
    assert _row(record["effects"], "push")["network"] is True
    lines = effects_lines(record["effects"])
    assert (
        "Sent the sample's bytes to a third party: `push` on tool server `acme`; `submit_file` "
        "on tool server `virustotal`; where each call sent them is in the upload rows of the "
        "disclosure above."
    ) in lines
    assert any(
        line.startswith("Sample upload: tool server `acme`") for line in disclosure_lines(record)
    )


def test_a_tool_declared_to_reach_the_network_through_a_local_server_cannot_be_placed() -> None:
    snapshot = {**LOCAL_LLM, "mcp.servers.loc.transport": "stdio", "mcp.servers.loc.url": ""}
    fetch = {"v": 1, "kind": "page", "effects": {"network": True}}
    hinted = with_hints({"v": 1, "kind": "page"}, {"openWorldHint": True})
    closed = {"v": 1, "effects": {"executes": "no", "network": False, "third_party": "no"}}
    record = disclosure_record(
        snapshot,
        entries=[_entry("mcp:loc", "fetch", fetch), _entry("mcp:loc", "peek", hinted)],
    )
    assert record["nothing_left"] is False
    whys = sorted(row["why"] for row in record["servers"])
    assert whys == [
        "its tool declares that it reaches the network, and the settings do not say where a "
        "local tool server sends what it is given",
    ]
    # The hint alone moves nothing: the hinted tool of a kind stays where its
    # kind put it.
    assert record["local_servers"] == ["mcp:loc"]
    # A tool of no kind that declares it reaches no network is placed by its server.
    quiet = disclosure_record(
        snapshot,
        entries=[_entry("mcp:loc", "count", closed)],
        tokens={"llm_calls": 0, "per_agent": {}},
        runtimes={"http://127.0.0.1:8080": "llama.cpp /props"},
    )
    assert quiet["undeclared"] == [] and quiet["local_servers"] == ["mcp:loc"]


def test_the_rule_for_bytes_is_one_rule() -> None:
    assert sends_sample_bytes(ToolFacts(discloses_sample=True))
    assert sends_sample_bytes(ToolFacts(effects=ToolEffects(third_party="bytes")))
    assert not sends_sample_bytes(ToolFacts(effects=ToolEffects(third_party="hash")))
    assert not sends_sample_bytes(None)


def test_an_operator_s_contradiction_is_refused_and_a_stored_one_read_cautiously() -> None:
    # The tick of ``discloses_sample`` is the explicit word: it lifts the effects.
    with strict_declarations():
        lifted = ToolFacts.model_validate(
            {"discloses_sample": True, "effects": {"third_party": "no", "network": False}}
        ).effects
    assert lifted is not None and (lifted.third_party, lifted.network) == ("bytes", True)
    with strict_declarations(), pytest.raises(ValueError, match="network"):
        ToolFacts.model_validate({"effects": {"third_party": "hash", "network": False}})
    with pytest.raises(ValueError, match="executes"):
        ToolEffects(executes="maybe")
    stored = {"v": 1, "discloses_sample": True, "effects": {"third_party": "no", "network": False}}
    effects = entry_effects(_entry("mcp:x", "t", stored))
    assert (effects.third_party, effects.network) == ("bytes", True)


# ---------------------------------------------------------------------------
# The report, a stopped run, a stored run
# ---------------------------------------------------------------------------


def test_the_report_prints_the_block_after_the_isolation_part(
    shipped: ToolDeclarations,
) -> None:
    from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
    from maljan.reporting.renderers import HtmlRenderer, MarkdownRenderer

    floss = facts_record("mcp:analysis", "floss", declared=shipped)
    record = disclosure_record(
        {**LOCAL_LLM, **STDIO},
        entries=[_entry("mcp:analysis", "floss", floss, args={"path": "/s/x"})],
    )
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary={"disclosure": record},
    )
    assert "Tool effects:" in HtmlRenderer().render(report, nonce="fixed")
    text = MarkdownRenderer().render(report)
    assert INTRO_SENTENCE in text
    assert text.index("**Isolation") < text.index(INTRO_SENTENCE)
    assert "- Ran the sample's code under emulation: `floss` on tool server `analysis`" in text


def test_a_record_stored_before_the_part_prints_no_block() -> None:
    record = disclosure_record(LOCAL_LLM)
    record.pop("effects")
    assert effects_lines(record.get("effects")) == []
    assert effects_lines(None) == []


def test_a_stopped_run_says_its_effects_may_be_incomplete(shipped: ToolDeclarations) -> None:
    from maljan.core.token_ledger import TokenLedger
    from maljan.pipeline.stopped_run import partial_report, stopped_run_summary

    settings = Settings.model_validate(
        {"llm": {"provider": "openai", "openai": {"base_url": "http://127.0.0.1:1/v1"}}}
    )
    ledger = TokenLedger()
    held = SimpleNamespace(config=settings, sample_uploads=[], get_token_ledger=lambda: ledger)
    floss = facts_record("mcp:analysis", "floss", declared=shipped)
    state = {
        "run_summary": {"final_decision": "Malware", "stages": []},
        "malware_report": {"run_summary": {"final_decision": "Malware"}},
        "evidence_ledger": [_entry("mcp:analysis", "floss", floss)],
    }

    summary = stopped_run_summary(state, held, note="stopped")
    report = partial_report(state, held, note="stopped")
    for record in (summary["disclosure"], report["run_summary"]["disclosure"]):
        part = record["effects"]
        assert part["partial_reason"] == STOPPED_PART_WAY
        assert _row(part, "floss")["executes"] == "emulation"
        lines = effects_lines(part)
        assert lines[0] == (
            f"This part may be incomplete: {STOPPED_PART_WAY}, and a call made in the step it "
            "stopped in may not be recorded."
        )


def test_a_run_that_called_no_tool_says_so() -> None:
    assert effects_lines(effects_part([])) == [
        "This run recorded no tool call, so no tool's effects are said."
    ]


def test_repeats_and_questions_to_the_team_are_not_calls() -> None:
    part = effects_part(
        [
            _entry("mcp:intel", "a", {"v": 1}),
            _entry("mcp:intel", "a", {"v": 1}, id="ev_0002", repeated_of="ev_0001"),
            {"id": "ev_0003", "tool": "ask_static", "server": "team"},
            # The platform's own read-again tool: no source and no server.
            {"id": "ev_0004", "tool": "read_evidence", "ok": False, "error": "unknown"},
        ]
    )
    assert [(row["tool"], row["calls"]) for row in part["tools"]] == [("a", 1)]


def test_ten_times_the_entries_cost_at_most_ten_times() -> None:
    import time

    def _timed(count: int) -> float:
        entries = [
            _entry(f"mcp:s{i % 50}", f"t{i % 200}", {"v": 1, "effects": {"network": True}})
            for i in range(count)
        ]
        start = time.perf_counter()
        effects_part(entries)
        return time.perf_counter() - start

    _timed(2_000)
    small = min(_timed(2_000) for _ in range(3))
    large = min(_timed(20_000) for _ in range(3))
    assert large < small * 10 * 3


# ---------------------------------------------------------------------------
# Calls that did not complete
# ---------------------------------------------------------------------------


def test_each_way_a_call_ended_is_counted_and_said_apart(shipped: ToolDeclarations) -> None:
    floss = facts_record("pack", "floss", declared=shipped)
    submit = facts_record("mcp:virustotal", "submit_file", declared=shipped)
    report = facts_record("mcp:virustotal", "get_file_report", declared=shipped)
    part = effects_part(
        [
            # The pack's budget stopped FLOSS before it started.
            _entry("pack", "floss", floss, ok=False, error="not run: the budget was spent"),
            # A guard answered the submission with no tool run.
            _entry("mcp:virustotal", "submit_file", submit, id="ev_0002", repeated_of="ev_0002"),
            # The lookup was made and broke.
            _entry(
                "mcp:virustotal", "get_file_report", report, id="ev_0003", ok=False, error="401"
            ),
        ]
    )
    counted = {
        row["tool"]: (row["completed"], row["failed"], row["not_run"], row["refused"])
        for row in part["tools"]
    }
    assert counted == {
        "floss": (0, 0, 1, 0),
        "submit_file": (0, 0, 0, 1),
        "get_file_report": (0, 1, 0, 0),
    }
    lines = effects_lines(part)
    assert lines == [
        "Was not run, so none of its declared effects happened: `floss` on Triage pack (`pack`).",
        "Was refused, so nothing was sent: `submit_file` on tool server `virustotal`.",
        "Failed, so whether its declared effects happened cannot be told: `get_file_report` on "
        "tool server `virustotal`.",
    ]
    assert not any(line.startswith(("Ran ", "Sent ", "Handed ", "Reached ")) for line in lines)


def test_a_tool_with_calls_that_ended_both_ways_is_counted_both_ways(
    shipped: ToolDeclarations,
) -> None:
    report = facts_record("mcp:virustotal", "get_file_report", declared=shipped)
    part = effects_part(
        [
            _entry("mcp:virustotal", "get_file_report", report),
            _entry("mcp:virustotal", "get_file_report", report, id="ev_0002", ok=False),
        ]
    )
    lines = effects_lines(part)
    assert "Reached the network: `get_file_report` on tool server `virustotal`." in lines
    assert (
        "Failed, so whether its declared effects happened cannot be told: `get_file_report` on "
        "tool server `virustotal`, 1 of 2 calls."
    ) in lines


def test_an_undeclared_tool_hinted_open_stays_an_undeclared_row() -> None:
    snapshot = {**LOCAL_LLM, "mcp.servers.loc.transport": "stdio", "mcp.servers.loc.url": ""}
    hinted = with_hints({"v": 1}, {"openWorldHint": True})
    record = disclosure_record(snapshot, entries=[_entry("mcp:loc", "peek", hinted)])
    (row,) = record["undeclared"]
    assert row["open_world_hints"] == 1 and record["servers"] == []
    assert any(
        "the servers' own hints (openWorldHint) say 1 of them may reach it" in line
        for line in disclosure_lines(record)
    )


# ---------------------------------------------------------------------------
# An operator's change over the shipped declaration
# ---------------------------------------------------------------------------


def test_a_tick_of_discloses_sample_on_put_sample_saves_and_says_bytes() -> None:
    from maljan.core.tool_declarations import merge_tool_facts, strict_declarations

    shipped = _declared_as_shipped("analysis")
    assert shipped["put_sample"]["effects"]["third_party"] == "no"
    in_force = merge_tool_facts(shipped, {"put_sample": {"discloses_sample": True}})
    with strict_declarations():
        facts = ToolFacts.model_validate(in_force["put_sample"])
    assert facts.effects is not None
    assert (facts.effects.third_party, facts.effects.network) == ("bytes", True)
    assert sends_sample_bytes(facts)


def test_an_operator_s_effects_merge_with_the_shipped_ones_sub_field_by_sub_field() -> None:
    from maljan.core.tool_declarations import merge_tool_facts, tool_facts_changes

    shipped = _declared_as_shipped("knowledge")
    change = {"attck_lookup": {"effects": {"network": True}}}
    in_force = merge_tool_facts(shipped, change)
    assert in_force["attck_lookup"]["effects"] == {
        "executes": "no",
        "network": True,
        "third_party": "no",
    }
    # Stored back as the one sub-field that differs, so a later correction of
    # another sub-field still reaches the tool.
    assert tool_facts_changes(in_force, shipped) == change
    corrected = {
        **shipped,
        "attck_lookup": {
            **shipped["attck_lookup"],
            "effects": {**shipped["attck_lookup"]["effects"], "executes": "emulation"},
        },
    }
    assert merge_tool_facts(corrected, change)["attck_lookup"]["effects"]["executes"] == "emulation"
    # ``null`` clears the field.
    cleared = merge_tool_facts(shipped, {"attck_lookup": {"effects": None}})
    assert cleared["attck_lookup"]["effects"] is None


def test_r2_s_analysis_says_when_it_emulates(shipped: ToolDeclarations) -> None:
    facts = facts_record("provider:r2", "analyze", declared=shipped)
    assert facts is not None and facts["effects"]["executes"] == "emulation"
    assert "level 2" in facts["effects"]["when"]
    lines = effects_lines(effects_part([_entry("provider:r2", "analyze", facts)]))
    assert lines[0].startswith(
        "Ran the sample's code under emulation: `analyze` on the `r2` provider's tool server, "
        "at analysis level 2 and above"
    )
