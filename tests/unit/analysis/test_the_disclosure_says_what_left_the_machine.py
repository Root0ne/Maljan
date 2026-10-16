"""The disclosure record says what a run sent beyond this machine, right or absent.

Built from the settings snapshot, each ledger entry's recorded source and the
transport its settings block names, the token ledger's per-agent model labels
and the run's sandbox submissions; never from a tool's name. It says that
nothing left this machine only when every destination it names is local,
nothing is left unplaced, tracing is off and the record is complete.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from maljan.analysis.disclosure import (
    NOTHING_LEFT_SENTENCE,
    STOPPED_PART_WAY,
    TRACING_SENTENCE,
    disclosure_lines,
    disclosure_record,
    model_list,
    stage_agents,
    upload_record,
)

LOCAL_LLM = {"llm.provider": "openai", "llm.openai.base_url": "http://127.0.0.1:8080/v1"}
HOSTED_LLM = {"llm.provider": "openai", "llm.openai.base_url": "https://llm.example.org/v1"}
STDIO = {"mcp.servers.analysis.transport": "stdio", "mcp.servers.analysis.url": ""}


def _tokens(**per_agent: dict[str, int]) -> dict[str, Any]:
    agents = {
        agent: {"llm_calls": sum(models.values()), "models": dict(models)}
        for agent, models in per_agent.items()
    }
    return {"llm_calls": sum(row["llm_calls"] for row in agents.values()), "per_agent": agents}


def _entry(source: str | None, tool: str = "t", *, server: str | None = "", **over: Any) -> dict:
    row: dict[str, Any] = {"id": "ev_0001", "tool": tool, "args": {}, "ok": True}
    if source is not None:
        row["source"] = source
    if server == "" and source and source.startswith("mcp:"):
        server = source.partition(":")[2]
    row["server"] = server or None
    row.update(over)
    return row


def _lookup(source: str, **args: str) -> dict:
    return _entry(
        source,
        "lookup",
        args=args,
        facts={"v": 1, "kind": "reputation", "arguments": {"hash": "sha256"}},
    )


def test_a_run_that_stayed_local_says_nothing_left_this_machine() -> None:
    record = disclosure_record(
        {**LOCAL_LLM, **STDIO, "memory.backend": "memory"},
        entries=[
            _entry("mcp:analysis", "strings", facts={"v": 1, "kind": "strings"}),
            _entry("pack", "yara_scan", server="pipeline"),
            _entry("sandbox", "sandbox_processes"),
            _entry("provider:capa_yara", "capa"),
        ],
        tokens=_tokens(static={"openai/q @ http://127.0.0.1:8080": 3}),
        agents=["static"],
    )

    assert record["nothing_left"] is True
    assert record["lookups"] == record["uploads"] == record["servers"] == []
    assert record["stores"] == []
    (row,) = record["models"]
    assert (row["host"], row["where"], row["calls"], row["agents"]) == (
        "127.0.0.1",
        "local",
        3,
        {"static": 3},
    )
    lines = disclosure_lines(record)
    assert lines[0] == NOTHING_LEFT_SENTENCE
    assert lines[1] == "Model prompts: `127.0.0.1` (local) received 3 calls (static 3)."


def test_a_hosted_endpoint_is_named_with_its_agents_and_call_counts() -> None:
    label = "openai/deepseek-flash @ https://api.deepseek.com"
    record = disclosure_record(
        {**HOSTED_LLM, "llm.openai.base_url": "https://api.deepseek.com"},
        tokens=_tokens(judge={label: 5}, static={label: 9}),
        agents=["static", "judge"],
    )

    assert record["nothing_left"] is False
    (row,) = record["models"]
    assert row["host"] == "api.deepseek.com"
    assert row["where"] == "remote"
    assert row["calls"] == 14
    assert row["agents"] == {"judge": 5, "static": 9}
    assert disclosure_lines(record) == [
        "Model prompts: `api.deepseek.com` (outside this machine) received 14 calls "
        "(judge 5, static 9)."
    ]


def test_a_vendor_api_reached_with_no_address_is_named_as_the_vendor_api() -> None:
    record = disclosure_record(
        {"llm.provider": "anthropic", "llm.anthropic.base_url": None},
        tokens=_tokens(judge={"anthropic/claude-haiku-5-5": 12}),
        agents=["judge"],
    )

    (row,) = record["models"]
    assert row["host"] == ""
    assert row["service"]
    assert row["where"] == "remote"
    assert record["nothing_left"] is False
    assert disclosure_lines(record)[0].startswith(f"Model prompts: {row['service']} (outside")


def test_calls_filed_under_no_model_or_no_agent_are_said_not_placed() -> None:
    tokens = _tokens(static={"openai/q @ http://127.0.0.1:8080": 3})
    tokens["per_agent"]["static"]["llm_calls"] = 4
    tokens["llm_calls"] = 6

    record = disclosure_record({**LOCAL_LLM}, tokens=tokens, agents=["static"])

    unplaced = [row for row in record["models"] if row["where"] == "unknown"]
    assert len(unplaced) == 1
    assert unplaced[0]["calls"] == 3
    assert unplaced[0]["agents"] == {"": 2, "static": 1}
    assert record["nothing_left"] is False
    assert any(
        line.startswith("Model prompts: 3 calls (no agent 2, static 1); ")
        and line.endswith("so where they went cannot be told.")
        for line in disclosure_lines(record)
    )


def test_an_endpoint_in_a_model_list_with_no_answered_call_keeps_nothing_from_being_said() -> None:
    snapshot = {
        **LOCAL_LLM,
        "llm.agents.judge.provider": "openai",
        "llm.agents.judge.model": "q",
        "llm.agents.judge.base_url": None,
        "llm.agents.judge.fallbacks": [
            {"provider": "openai", "model": "big", "base_url": "https://llm.example.org/v1"}
        ],
    }
    record = disclosure_record(
        snapshot,
        tokens=_tokens(judge={"openai/q @ http://127.0.0.1:8080": 2}),
        agents=["judge"],
    )

    listed = [row for row in record["models"] if row["host"] == "llm.example.org"]
    assert listed and listed[0]["calls"] == 0 and listed[0]["configured_for"] == ["judge"]
    assert record["nothing_left"] is False
    assert any(
        "whether it received prompts cannot be told" in line for line in disclosure_lines(record)
    )


def test_the_model_list_is_read_from_the_snapshot_as_the_run_resolves_it() -> None:
    snapshot = {
        **HOSTED_LLM,
        "llm.agents.static.provider": "ollama",
        "llm.agents.static.base_url": "http://gpu-box:11434",
        "llm.agents.static.fallbacks": [{"provider": "openai", "model": "x", "base_url": None}],
    }

    assert [endpoint for _p, endpoint in model_list(snapshot, "static")] == [
        "http://gpu-box:11434",
        "https://llm.example.org/v1",
    ]
    # An agent with no entry calls the global provider at its configured address.
    assert model_list(snapshot, "judge") == [("openai", "https://llm.example.org/v1")]


def test_a_lookup_over_http_names_its_host_and_the_indicator_kinds_it_carried() -> None:
    snapshot = {
        **LOCAL_LLM,
        "mcp.servers.intel.transport": "streamable-http",
        "mcp.servers.intel.url": "https://user:secret@intel.example.org:8443/mcp?key=k",
    }
    entries = [
        _lookup("mcp:intel", sha256="a" * 64),
        _lookup("mcp:intel"),
        _entry(
            "mcp:intel",
            "domain_report",
            args={"domain": "x"},
            facts={"v": 1, "kind": "indicator_report"},
        ),
        _entry(
            "mcp:intel",
            "ip_lookup",
            args={"ip_address": "1.2.3.4"},
            facts={"v": 1, "kind": "other", "arguments": {"ip": "ip_address"}},
        ),
    ]

    record = disclosure_record(snapshot, entries=entries)

    (row,) = record["lookups"]
    assert (row["source"], row["transport"], row["host"], row["where"]) == (
        "mcp:intel",
        "streamable-http",
        "intel.example.org",
        "remote",
    )
    assert row["calls"] == 4
    assert row["kinds"] == {"hash": 1, "ip": 1}
    assert row["without_indicator"] == 2
    assert record["servers"] == []
    assert record["nothing_left"] is False
    # Only the host travels: never the userinfo, the port or the query.
    assert "secret" not in json.dumps(record) and "8443" not in json.dumps(record)
    assert disclosure_lines(record)[-1] == (
        "Lookups: `intel.example.org` (outside this machine) was asked 4 times through tool "
        "server `intel` (streamable-http): hash 1, ip 1, 2 giving no argument declared as an "
        "indicator."
    )


def test_a_lookup_through_a_server_run_on_this_machine_cannot_be_placed() -> None:
    snapshot = {**LOCAL_LLM, "mcp.servers.intel.transport": "stdio"}

    record = disclosure_record(snapshot, entries=[_lookup("mcp:intel", sha256="abc")])

    (row,) = record["lookups"]
    assert row["where"] == "unknown"
    assert row["host"] == ""
    assert record["nothing_left"] is False
    assert disclosure_lines(record)[-1].startswith(
        "Lookups: tool server `intel` (stdio, run on this machine) was asked once: hash 1; "
    )


def test_a_lookup_through_a_server_at_a_local_address_cannot_be_placed_either() -> None:
    snapshot = {
        **LOCAL_LLM,
        "mcp.servers.misp.transport": "http",
        "mcp.servers.misp.url": "http://10.0.0.5:8443/mcp",
    }
    entry = _entry(
        "mcp:misp",
        "ip_lookup",
        args={"value": "1.2.3.4"},
        facts={"v": 1, "kind": "indicator_reputation", "arguments": {"ip": "value"}},
    )

    record = disclosure_record(snapshot, entries=[entry])

    (row,) = record["lookups"]
    assert (row["host"], row["where"]) == ("10.0.0.5", "unknown")
    assert record["nothing_left"] is False
    assert disclosure_lines(record)[-1] == (
        "Lookups: tool server `misp` (http) at `10.0.0.5` was asked once: ip 1; the settings "
        "do not say where a local tool server sends what it is given, so where they went "
        "cannot be told."
    )


def test_a_tool_that_declares_nothing_outside_on_a_local_server_is_not_listed() -> None:
    record = disclosure_record(
        {**LOCAL_LLM, **STDIO},
        entries=[_entry("mcp:analysis", "anything", args={"domain": "x"})],
    )

    assert record["servers"] == record["lookups"] == []
    assert record["nothing_left"] is True


def test_a_tool_server_reached_over_http_is_listed_with_where_it_is() -> None:
    snapshot = {
        **LOCAL_LLM,
        "mcp.servers.far.transport": "sse",
        "mcp.servers.far.url": "https://mcp.example.org/sse",
        "mcp.servers.near.transport": "http",
        "mcp.servers.near.url": "http://ghidra-mcp:8089",
        "static.ghidra.transport": "streamable-http",
        "static.ghidra.url": "http://10.1.2.3:8080/mcp",
    }
    entries = [
        _entry("mcp:far", "a"),
        _entry("mcp:far", "b"),
        _entry("mcp:near", "c"),
        _entry("provider:ghidra", "decompile", server=None),
    ]

    record = disclosure_record(snapshot, entries=entries)

    by_source = {row["source"]: row for row in record["servers"]}
    assert (by_source["mcp:far"]["host"], by_source["mcp:far"]["where"]) == (
        "mcp.example.org",
        "remote",
    )
    assert by_source["mcp:far"]["calls"] == 2
    assert by_source["mcp:near"]["where"] == "local"
    assert (by_source["provider:ghidra"]["host"], by_source["provider:ghidra"]["where"]) == (
        "10.1.2.3",
        "local",
    )
    assert record["servers"][0]["source"] == "mcp:far", "what went outside is listed first"
    assert record["nothing_left"] is False
    lines = disclosure_lines(record)
    assert (
        "Tool calls: tool server `far` over sse at `mcp.example.org` (outside this machine): "
        "2 calls."
    ) in lines
    assert (
        "Tool calls: the `ghidra` provider's tool server over streamable-http at `10.1.2.3` "
        "(local): 1 call."
    ) in lines


def test_a_call_answered_from_an_earlier_entry_or_a_guard_sent_nothing() -> None:
    snapshot = {
        **LOCAL_LLM,
        "mcp.servers.far.transport": "http",
        "mcp.servers.far.url": "https://x.example",
    }
    record = disclosure_record(
        snapshot,
        entries=[
            _entry("mcp:far", repeated_of="ev_0001"),
            _entry("mcp:far", repeated_of="ev_0002"),
        ],
    )
    assert record["servers"] == []
    assert record["nothing_left"] is True


def test_an_entry_without_a_source_is_placed_only_when_nothing_ran_outside_the_worker() -> None:
    from maljan.agents.delegation import TEAM_SERVER

    record = disclosure_record(
        {**LOCAL_LLM},
        entries=[
            _entry(None, "in_process", server=None),
            _entry(None, "ask_static", server=TEAM_SERVER),
        ],
    )
    assert record["nothing_left"] is True

    unplaced = disclosure_record({**LOCAL_LLM}, entries=[_entry(None, "old", server="intel")])
    (row,) = unplaced["servers"]
    assert (row["source"], row["where"]) == ("intel", "unknown")
    assert unplaced["nothing_left"] is False


@pytest.mark.parametrize(
    ("snapshot", "why"),
    [
        ({}, "the settings name no tool server block for mcp:gone"),
        ({"mcp.servers.gone.transport": "carrier-pigeon"}, "no known transport for mcp:gone"),
        ({"mcp.servers.gone.transport": "http", "mcp.servers.gone.url": ""}, "names no host"),
    ],
)
def test_a_source_the_settings_cannot_place_is_said_so(snapshot: dict, why: str) -> None:
    record = disclosure_record({**LOCAL_LLM, **snapshot}, entries=[_entry("mcp:gone")])

    (row,) = record["servers"]
    assert row["where"] == "unknown"
    assert why in row["why"]
    assert record["nothing_left"] is False


def test_a_sandbox_submission_names_the_provider_and_its_host() -> None:
    snapshot = {**LOCAL_LLM, "sandbox.triage.base_url": "https://tria.ge/api/v0"}

    record = disclosure_record(snapshot, uploads=[upload_record("triage", submitted=True)])

    (row,) = record["uploads"]
    assert (row["by"], row["source"], row["host"], row["where"], row["calls"], row["failed"]) == (
        "sandbox",
        "triage",
        "tria.ge",
        "remote",
        1,
        0,
    )
    assert record["nothing_left"] is False
    assert disclosure_lines(record)[-1] == (
        "Sample upload: the sample was submitted once to the `triage` sandbox at `tria.ge` "
        "(outside this machine)."
    )


def test_a_submission_that_failed_is_still_said_and_a_private_sandbox_is_local() -> None:
    snapshot = {**LOCAL_LLM, "sandbox.cape2.base_url": "http://10.65.0.40:8000"}

    record = disclosure_record(snapshot, uploads=[upload_record("cape2", submitted=False)])

    (row,) = record["uploads"]
    assert (row["where"], row["failed"]) == ("local", 1)
    assert record["nothing_left"] is True
    assert (
        "1 of the attempts failed, so whether it arrived cannot be told"
        in disclosure_lines(record)[-1]
    )


def test_a_submission_is_placed_by_the_address_key_its_provider_declared() -> None:
    snapshot = {
        **LOCAL_LLM,
        "sandbox.acme.base_url": "http://127.0.0.1:1",
        "sandbox.rest.base_url": "https://detonate.example.org/api",
    }
    upload = upload_record("acme", submitted=True, address="sandbox.rest.base_url")

    (row,) = disclosure_record(snapshot, uploads=[upload])["uploads"]

    assert (row["source"], row["host"], row["where"]) == ("acme", "detonate.example.org", "remote")


def test_a_sandbox_with_no_address_in_the_settings_cannot_be_placed() -> None:
    record = disclosure_record({**LOCAL_LLM}, uploads=[upload_record("elsewhere", submitted=True)])

    (row,) = record["uploads"]
    assert row["where"] == "unknown"
    assert record["nothing_left"] is False
    assert disclosure_lines(record)[-1].endswith("so where it went cannot be told.")


@pytest.mark.parametrize(
    ("block", "where"),
    [
        (
            {
                "mcp.servers.vt.transport": "streamable-http",
                "mcp.servers.vt.url": "https://vt.example/mcp",
            },
            "remote",
        ),
        ({"mcp.servers.vt.transport": "stdio"}, "unknown"),
    ],
)
def test_a_tool_declared_to_send_the_sample_out_is_an_upload(block: dict, where: str) -> None:
    entry = _entry(
        "mcp:vt",
        "send",
        ok=False,
        facts={"v": 1, "kind": "submission", "discloses_sample": True},
    )

    record = disclosure_record({**LOCAL_LLM, **block}, entries=[entry])

    (row,) = record["uploads"]
    assert (row["by"], row["source"], row["where"], row["calls"], row["failed"]) == (
        "tool",
        "mcp:vt",
        where,
        1,
        1,
    )
    assert record["servers"] == record["lookups"] == []
    assert record["nothing_left"] is False
    assert "by a tool declared to send it out of the deployment" in disclosure_lines(record)[-1]


def test_the_declaration_to_send_the_sample_out_is_stored_on_the_entry_it_is_read_from() -> None:
    from maljan.core.config import Settings
    from maljan.core.declared_reading import facts_record
    from maljan.core.tool_declarations import ToolDeclarations

    settings = Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    "acme": {
                        "enabled": True,
                        "transport": "streamable-http",
                        "url": "https://acme.example/mcp",
                        "tool_facts": {
                            "send": {"kind": "submission", "discloses_sample": True},
                            "look": {"kind": "status"},
                        },
                    }
                }
            }
        }
    )
    declared = ToolDeclarations.from_settings(settings)
    sent = facts_record("mcp:acme", "send", declared=declared)
    looked = facts_record("mcp:acme", "look", declared=declared)

    assert sent is not None and sent["discloses_sample"] is True
    assert looked is not None and "discloses_sample" not in looked
    record = disclosure_record(
        {
            "mcp.servers.acme.transport": "streamable-http",
            "mcp.servers.acme.url": "https://acme.example/mcp",
        },
        entries=[_entry("mcp:acme", "send", facts=sent), _entry("mcp:acme", "look", facts=looked)],
    )
    assert [(row["by"], row["host"], row["calls"]) for row in record["uploads"]] == [
        ("tool", "acme.example", 1)
    ]
    assert [(row["source"], row["calls"]) for row in record["servers"]] == [("mcp:acme", 1)]


@pytest.mark.parametrize(
    ("snapshot", "rows", "nothing_left"),
    [
        ({"memory.backend": "qdrant", "memory.qdrant.url": "http://qdrant:6333"}, 1, True),
        (
            {"memory.backend": "qdrant", "memory.qdrant.url": "https://x.cloud.example:6333"},
            1,
            False,
        ),
        ({"memory.backend": "memory"}, 0, True),
        ({"memory.backend": "other", "memory.other.path": "/var/x"}, 1, False),
    ],
)
def test_the_memory_store_is_placed_where_its_backend_has_an_address(
    snapshot: dict, rows: int, nothing_left: bool
) -> None:
    record = disclosure_record({**LOCAL_LLM, **snapshot})

    assert len(record["stores"]) == rows
    assert record["nothing_left"] is nothing_left


def test_tracing_on_keeps_nothing_from_being_said() -> None:
    record = disclosure_record({**LOCAL_LLM, "langchain_tracing_v2": True})

    assert record["tracing"] is True
    assert record["nothing_left"] is False
    assert disclosure_lines(record)[-1] == TRACING_SENTENCE


def test_a_record_that_may_miss_a_call_never_says_nothing_left() -> None:
    record = disclosure_record({**LOCAL_LLM}, partial_reason=STOPPED_PART_WAY)

    assert record["nothing_left"] is False
    assert disclosure_lines(record)[0].startswith(
        f"This record may be incomplete: {STOPPED_PART_WAY}, "
    )


def test_a_tools_name_decides_nothing() -> None:
    snapshot = {
        **LOCAL_LLM,
        "mcp.servers.intel.transport": "http",
        "mcp.servers.intel.url": "https://i.example",
    }
    facts = {"v": 1, "kind": "reputation", "arguments": {"hash": "h"}}
    one = disclosure_record(
        snapshot, entries=[_entry("mcp:intel", "get_file_report", args={"h": "x"}, facts=facts)]
    )
    other = disclosure_record(
        snapshot, entries=[_entry("mcp:intel", "zz_anything", args={"h": "x"}, facts=facts)]
    )
    plain = disclosure_record(
        snapshot, entries=[_entry("mcp:intel", "get_file_report", args={"h": "x"})]
    )

    assert one == other
    assert plain["lookups"] == [] and plain["servers"][0]["calls"] == 1


def test_the_record_is_stable_and_stored_as_json() -> None:
    snapshot = {
        **HOSTED_LLM,
        "mcp.servers.b.transport": "http",
        "mcp.servers.b.url": "https://b.example",
        "mcp.servers.a.transport": "http",
        "mcp.servers.a.url": "https://a.example",
    }
    entries = [_entry("mcp:b"), _entry("mcp:a"), _entry("mcp:b")]
    tokens = _tokens(
        z={"openai/x @ https://llm.example.org": 1}, a={"openai/x @ https://llm.example.org": 2}
    )

    first = disclosure_record(snapshot, entries=entries, tokens=tokens, agents=["z", "a"])
    again = disclosure_record(
        snapshot, entries=list(reversed(entries)), tokens=tokens, agents=["a", "z"]
    )

    assert first == again
    assert json.loads(json.dumps(first)) == first
    assert list(first["models"][0]["agents"]) == ["a", "z"]


def test_the_agents_of_the_stages_that_ran_are_read_once_each() -> None:
    stages = [
        {"key": "a", "ran": True, "agents": ["static", "dynamic"]},
        {"key": "b", "ran": False, "agents": ["network"]},
        {"key": "c", "ran": True, "agents": ["static", "judge"]},
        "not a row",
    ]
    assert stage_agents(stages) == ["static", "dynamic", "judge"]
    assert stage_agents(None) == []


def test_no_record_renders_no_line() -> None:
    assert disclosure_lines(None) == []
    assert disclosure_lines("not a record") == []


def test_the_record_stays_linear_on_a_hostile_ledger() -> None:
    snapshot = {
        **LOCAL_LLM,
        "mcp.servers.far.transport": "http",
        "mcp.servers.far.url": "https://x.example",
    }

    def took(count: int) -> float:
        entries = [_lookup("mcp:far", sha256=str(n)) for n in range(count)]
        started = time.perf_counter()
        record = disclosure_record(snapshot, entries=entries)
        assert record["lookups"][0]["calls"] == count
        return time.perf_counter() - started

    small = took(2_000)
    large = took(20_000)
    assert large < max(small, 1e-3) * 30
