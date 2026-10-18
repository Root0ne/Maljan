"""The disclosure record says what a run sent beyond this machine, right or absent.

Built from the settings snapshot, each ledger entry's recorded source and the
transport its settings block names, the token ledger's per-agent model labels,
the endpoints that answered the window probe as a model runtime, and the run's
sandbox submissions and sample stagings; never from a tool's name. It says
that nothing left this machine only with positive knowledge of every path, and
then says what that rests on; any path it cannot place is said, with why.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from tests.credential_shapes import password

from maljan.analysis.disclosure import (
    FOOTNOTE_SENTENCE,
    STAGING_ATTEMPTED,
    STAGING_DONE,
    STAGING_FAILED,
    STOPPED_PART_WAY,
    TRACING_SENTENCE,
    configured_agents,
    disclosure_lines,
    disclosure_record,
    model_list,
    stage_agents,
    staging_record,
    upload_record,
)

LOCAL_LLM = {"llm.provider": "openai", "llm.openai.base_url": "http://127.0.0.1:8080/v1"}
HOSTED_LLM = {"llm.provider": "openai", "llm.openai.base_url": "https://llm.example.org/v1"}
STDIO = {"mcp.servers.analysis.transport": "stdio", "mcp.servers.analysis.url": ""}
# The window probe's answer for the local endpoint, as the container keeps it.
RUNTIME = {"http://127.0.0.1:8080": "llama.cpp /props"}
STRINGS = {"v": 1, "kind": "strings"}
# Built at run time: a credential written down is a secret to a scanner.
PW = password()


def _tokens(**per_agent: dict[str, int]) -> dict[str, Any]:
    agents = {
        agent: {"llm_calls": sum(models.values()), "models": dict(models)}
        for agent, models in per_agent.items()
    }
    return {"llm_calls": sum(row["llm_calls"] for row in agents.values()), "per_agent": agents}


LOCAL_TOKENS = _tokens(static={"openai/q @ http://127.0.0.1:8080": 3})


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


def _local(**over: Any) -> dict[str, Any]:
    """A record of a run whose every path is local, with ``over`` laid on its inputs."""
    inputs: dict[str, Any] = {
        "tokens": LOCAL_TOKENS,
        "agents": ["static"],
        "runtimes": RUNTIME,
    }
    snapshot = {**LOCAL_LLM, "memory.backend": "memory", **over.pop("snapshot", {})}
    inputs.update(over)
    return disclosure_record(snapshot, **inputs)


# ---------------------------------------------------------------------------
# Nothing, and what it rests on
# ---------------------------------------------------------------------------


def test_a_run_that_stayed_local_says_nothing_and_what_that_rests_on() -> None:
    record = _local(
        snapshot=STDIO,
        entries=[
            _entry("mcp:analysis", "strings", facts=STRINGS),
            _entry("pack", "yara_scan", server="pipeline"),
            _entry("sandbox", "sandbox_processes"),
            _entry("provider:capa_yara", "capa"),
        ],
    )

    assert record["nothing_left"] is True
    assert record["lookups"] == record["uploads"] == record["servers"] == []
    assert record["undeclared"] == record["stores"] == []
    assert record["local_servers"] == ["mcp:analysis"]
    (row,) = record["models"]
    assert (row["host"], row["where"], row["calls"], row["agents"], row["runtime"]) == (
        "127.0.0.1",
        "local",
        3,
        {"static": 3},
        "llama.cpp /props",
    )
    assert disclosure_lines(record) == [
        "Nothing left this machine. This rests on: every model endpoint in this run's settings "
        "is a local address that answered as a model runtime: `127.0.0.1` (llama.cpp /props); "
        "the local tool servers called (tool server `analysis`) were taken as local by their "
        "tools' declarations; the case-memory store is kept in the process or not configured; "
        "no lookup was asked, and tracing is off.",
        "Model prompts: `127.0.0.1` (local) received 3 calls (static 3); it answered as a model "
        "runtime (llama.cpp /props).",
    ]


def test_the_footnote_says_what_this_machine_covers_once() -> None:
    assert FOOTNOTE_SENTENCE.count("This machine") == 1
    for covered in ("loopback", "private", "link-local", "shared", "single-label"):
        assert covered in FOOTNOTE_SENTENCE


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


def test_a_hosted_endpoint_is_named_with_its_agents_and_call_counts() -> None:
    label = "openai/deepseek-flash @ https://api.deepseek.com"
    record = disclosure_record(
        {**HOSTED_LLM, "llm.openai.base_url": "https://api.deepseek.com"},
        tokens=_tokens(judge={label: 5}, static={label: 9}),
        agents=["static", "judge"],
    )

    assert record["nothing_left"] is False
    (row,) = record["models"]
    assert (row["host"], row["where"], row["calls"]) == ("api.deepseek.com", "remote", 14)
    assert row["agents"] == {"judge": 5, "static": 9}
    assert row["global"] is True
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

    record = disclosure_record({**LOCAL_LLM}, tokens=tokens, agents=["static"], runtimes=RUNTIME)

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


def test_a_local_endpoint_that_did_not_answer_as_a_runtime_may_forward_the_prompts() -> None:
    """A gateway on a local address forwards to a hosted API as easily as llama.cpp answers."""
    record = disclosure_record(
        {"llm.provider": "anthropic", "llm.anthropic.base_url": "http://localhost:4000"},
        tokens=_tokens(judge={"anthropic/claude-haiku-5-5 @ http://localhost:4000": 7}),
        agents=["judge"],
    )

    (row,) = record["models"]
    assert (row["host"], row["where"], row["runtime"]) == ("localhost", "local", "")
    assert record["nothing_left"] is False
    assert disclosure_lines(record) == [
        "Model prompts: `localhost` (local) received 7 calls (judge 7); a local address that "
        "did not answer as a model runtime may forward the prompts, so where they went cannot "
        "be told."
    ]


def test_every_endpoint_of_a_host_must_have_answered_as_a_runtime() -> None:
    snapshot = {
        **LOCAL_LLM,
        "memory.backend": "memory",
        "llm.agents.static.provider": "openai",
        "llm.agents.static.base_url": "http://127.0.0.1:8080/v1",
        "llm.agents.static.fallbacks": [
            {"provider": "openai", "model": "b", "base_url": "http://127.0.0.1:8081/v1"}
        ],
    }
    one = disclosure_record(snapshot, tokens=LOCAL_TOKENS, agents=["static"], runtimes=RUNTIME)
    both = disclosure_record(
        snapshot,
        tokens=LOCAL_TOKENS,
        agents=["static"],
        runtimes={**RUNTIME, "http://127.0.0.1:8081": "llama.cpp /props"},
    )

    assert one["models"][0]["runtime"] == "" and one["nothing_left"] is False
    assert both["models"][0]["runtime"] == "llama.cpp /props" and both["nothing_left"] is True


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
        runtimes=RUNTIME,
    )

    listed = [row for row in record["models"] if row["host"] == "llm.example.org"]
    assert listed and listed[0]["calls"] == 0 and listed[0]["configured_for"] == ["judge"]
    assert record["nothing_left"] is False
    assert any(
        "whether it received prompts cannot be told" in line for line in disclosure_lines(record)
    )


def test_every_agents_model_list_is_read_whether_or_not_the_agent_called() -> None:
    """The mediator's hosted fallback is listed though no stage or tally names the mediator."""
    snapshot = {
        **LOCAL_LLM,
        "memory.backend": "memory",
        "llm.agents.mediator.provider": "openai",
        "llm.agents.mediator.base_url": "http://127.0.0.1:8080/v1",
        "llm.agents.mediator.fallbacks": [
            {"provider": "openai", "model": "big", "base_url": "https://llm.example.org/v1"}
        ],
    }

    assert configured_agents(snapshot) == ["mediator"]
    record = disclosure_record(snapshot, tokens=LOCAL_TOKENS, agents=["static"], runtimes=RUNTIME)

    (hosted,) = [row for row in record["models"] if row["host"] == "llm.example.org"]
    assert (hosted["calls"], hosted["configured_for"], hosted["where"]) == (
        0,
        ["mediator"],
        "remote",
    )
    assert record["nothing_left"] is False


def test_the_global_endpoint_is_listed_when_no_call_was_counted() -> None:
    hosted = disclosure_record({**HOSTED_LLM, "memory.backend": "memory"})
    local = disclosure_record({**LOCAL_LLM, "memory.backend": "memory"})

    (row,) = hosted["models"]
    assert (row["host"], row["global"], row["calls"]) == ("llm.example.org", True, 0)
    assert hosted["nothing_left"] is False
    assert disclosure_lines(hosted) == [
        "Model prompts: `llm.example.org` (outside this machine) is the endpoint of the global "
        "model, which every agent without a model entry of its own calls; no answered call is "
        "recorded there; a request that failed is not always recorded, so whether it received "
        "prompts cannot be told."
    ]
    assert local["nothing_left"] is False, "an endpoint that never answered the probe"


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


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------


def test_a_lookup_over_http_names_its_host_and_the_indicator_kinds_it_carried() -> None:
    snapshot = {
        **LOCAL_LLM,
        "mcp.servers.intel.transport": "streamable-http",
        "mcp.servers.intel.url": f"https://user:{PW}@intel.example.org:8443/mcp?key=k",
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
    assert PW not in json.dumps(record) and "8443" not in json.dumps(record)
    assert (
        "Lookups: `intel.example.org` (outside this machine) was asked 4 times through tool "
        "server `intel` (streamable-http): hash 1, ip 1, 2 giving no argument declared as an "
        "indicator."
    ) in disclosure_lines(record)


def test_a_lookup_through_a_server_run_on_this_machine_cannot_be_placed() -> None:
    snapshot = {**LOCAL_LLM, "mcp.servers.intel.transport": "stdio"}

    record = disclosure_record(snapshot, entries=[_lookup("mcp:intel", sha256="abc")])

    (row,) = record["lookups"]
    assert row["where"] == "unknown"
    assert row["host"] == ""
    assert record["nothing_left"] is False
    assert any(
        line.startswith(
            "Lookups: tool server `intel` (stdio, run on this machine) was asked once: hash 1; "
        )
        for line in disclosure_lines(record)
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
    assert (
        "Lookups: tool server `misp` (http) at `10.0.0.5` was asked once: ip 1; the settings "
        "do not say where a local tool server sends what it is given, so where they went "
        "cannot be told."
    ) in disclosure_lines(record)


# ---------------------------------------------------------------------------
# Tool servers: gateways, undeclared tools, remote servers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "declares",
    [
        {"mcp.servers.gw.roles": ["reputation"]},
        {"mcp.servers.gw.roles": ["sandbox"]},
        {"mcp.servers.gw.tool_facts.other.kind": "indicator_report"},
        {"mcp.servers.gw.tool_facts.other.arguments.domain": "name"},
        {"mcp.servers.gw.tool_facts.other.discloses_sample": True},
    ],
)
def test_every_call_through_a_local_gateway_cannot_be_placed(declares: dict) -> None:
    """A server that declares a lookup or a sandbox anywhere may forward any call it is given."""
    snapshot = {**STDIO, "mcp.servers.gw.transport": "stdio", **declares}

    record = _local(snapshot=snapshot, entries=[_entry("mcp:gw", "status", facts=STRINGS)])

    (row,) = record["servers"]
    assert (row["source"], row["where"], row["calls"]) == ("mcp:gw", "unknown", 1)
    assert record["local_servers"] == []
    assert record["nothing_left"] is False
    assert (
        "Tool calls: tool server `gw` (stdio, run on this machine): 1 call; it is a local tool "
        "server that declares a lookup or a sandbox, so a call through it may go on to a "
        "service the settings do not name, so where they went cannot be told."
    ) in disclosure_lines(record)


def test_calls_to_tools_that_declare_no_effects_cannot_be_shown_to_stay() -> None:
    record = _local(
        snapshot=STDIO,
        entries=[
            _entry("mcp:analysis", "anything", args={"domain": "x"}),
            _entry("mcp:analysis", "other", facts={"v": 1}),
            _entry("mcp:analysis", "strings", facts=STRINGS),
        ],
    )

    (row,) = record["undeclared"]
    assert (row["source"], row["calls"]) == ("mcp:analysis", 2)
    assert record["nothing_left"] is False
    assert (
        "Tool calls: 2 calls to tools that declare no effects (tool server `analysis` (stdio, "
        "run on this machine) 2): whether they reached the network cannot be told."
    ) in disclosure_lines(record)


@pytest.mark.parametrize(
    "facts",
    [
        {"v": 1, "kind": "", "display_name": "Lookup"},
        {"v": 1, "kind": "", "words": ["fetch", "url"]},
        {"v": 1, "kind": "", "holds_strings": True},
    ],
    ids=["display-name-only", "words-only", "other-fact-only"],
)
def test_a_tool_that_names_no_kind_counts_as_undeclared(facts: dict) -> None:
    """The platform's own rule: a declaration without a kind leaves the tool undeclared."""
    record = _local(snapshot=STDIO, entries=[_entry("mcp:analysis", "fetch_url", facts=facts)])

    (row,) = record["undeclared"]
    assert row["calls"] == 1
    assert record["local_servers"] == []
    assert record["nothing_left"] is False


@pytest.mark.parametrize("kind", ["submission", "submission_status"])
def test_a_tool_of_a_kind_that_reaches_outside_is_never_taken_as_local(kind: str) -> None:
    """An operator's submission tool, with no ``discloses_sample``, stops "nothing"."""
    record = _local(
        snapshot=STDIO, entries=[_entry("mcp:analysis", "send_it", facts={"v": 1, "kind": kind})]
    )

    (row,) = record["servers"]
    assert (row["source"], row["where"], row["calls"]) == ("mcp:analysis", "unknown", 1)
    assert f"declares the kind {kind}" in row["why"]
    assert record["nothing_left"] is False


def test_a_server_that_declares_a_submission_tool_is_a_gateway() -> None:
    from maljan.analysis.disclosure import gateway_blocks

    snapshot = {**STDIO, "mcp.servers.analysis.tool_facts.send_it.kind": "submission"}

    assert gateway_blocks(snapshot) == frozenset({"mcp.servers.analysis"})
    record = _local(snapshot=snapshot, entries=[_entry("mcp:analysis", "strings", facts=STRINGS)])
    (row,) = record["servers"]
    assert row["where"] == "unknown" and record["nothing_left"] is False


def test_the_kinds_that_reach_outside_are_defined_once_with_their_meaning() -> None:
    from maljan.core.builtin_declarations import OUTWARD_KINDS, REPUTATION_KINDS
    from maljan.core.reputation import INDICATOR_LOOKUP_KINDS

    assert {"submission", "submission_status", *REPUTATION_KINDS, *INDICATOR_LOOKUP_KINDS} == set(
        OUTWARD_KINDS
    )
    assert all(meaning.strip() for meaning in OUTWARD_KINDS.values())


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
        _entry("mcp:far", "a", facts=STRINGS),
        _entry("mcp:far", "b", facts=STRINGS),
        _entry("mcp:near", "c", facts=STRINGS),
        _entry("provider:ghidra", "decompile", server=None, facts=STRINGS),
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
    assert record["local_servers"] == ["mcp:near", "provider:ghidra"]
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
    assert (
        "Tool calls: tool server `near` over http at `ghidra-mcp` (taken as local: a service "
        "name): 1 call."
    ) in lines


def test_a_call_answered_from_an_earlier_entry_or_a_guard_sent_nothing() -> None:
    snapshot = {"mcp.servers.far.transport": "http", "mcp.servers.far.url": "https://x.example"}
    record = _local(
        snapshot=snapshot,
        entries=[
            _entry("mcp:far", repeated_of="ev_0001"),
            _entry("mcp:far", repeated_of="ev_0002"),
        ],
    )
    assert record["servers"] == record["undeclared"] == []
    assert record["nothing_left"] is True


def test_an_entry_without_a_source_is_placed_only_when_nothing_ran_outside_the_worker() -> None:
    from maljan.agents.delegation import TEAM_SERVER

    record = _local(
        entries=[
            _entry(None, "in_process", server=None),
            _entry(None, "ask_static", server=TEAM_SERVER),
        ],
    )
    assert record["nothing_left"] is True

    unplaced = _local(entries=[_entry(None, "old", server="intel")])
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


def test_a_ledger_row_the_report_could_not_read_is_a_call_that_cannot_be_placed() -> None:
    record = _local(unreadable=2)

    assert record["unreadable_entries"] == 2
    assert record["nothing_left"] is False
    assert disclosure_lines(record)[-1] == (
        "The ledger held 2 rows the report could not read, so where their calls went cannot "
        "be told."
    )


# ---------------------------------------------------------------------------
# Uploads: sandbox submissions, stagings, tools that send the sample out
# ---------------------------------------------------------------------------


def test_a_sandbox_submission_names_the_provider_and_the_host_it_resolved() -> None:
    record = _local(uploads=[upload_record("triage", submitted=True, host="tria.ge")])

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
    assert (
        "Sample upload: the sample was submitted once to the `triage` sandbox at `tria.ge` "
        "(outside this machine)."
    ) in disclosure_lines(record)


def test_a_submission_that_failed_is_still_said_and_a_private_sandbox_is_local() -> None:
    record = _local(uploads=[upload_record("cape2", submitted=False, host="10.65.0.40")])

    (row,) = record["uploads"]
    assert (row["where"], row["failed"]) == ("local", 1)
    assert record["nothing_left"] is True
    assert (
        "Sample upload: the sample was submitted once to the `cape2` sandbox at `10.65.0.40` "
        "(local); 1 of the attempts failed or did not finish, so whether it arrived cannot be "
        "told."
    ) in disclosure_lines(record)
    assert "the sample went only to local addresses" in disclosure_lines(record)[0]


def test_a_sandbox_that_does_not_say_where_it_sends_cannot_be_placed() -> None:
    record = _local(uploads=[upload_record("elsewhere", submitted=True)])

    (row,) = record["uploads"]
    assert (row["where"], row["why"]) == (
        "unknown",
        "the elsewhere provider does not say where it sends the sample",
    )
    assert record["nothing_left"] is False
    assert disclosure_lines(record)[-1].endswith("so where it went cannot be told.")


def test_a_sample_staged_to_a_tool_server_is_an_upload() -> None:
    staged = staging_record(
        "analysis",
        transport="streamable-http",
        url=f"https://user:{PW}@re.example.org/mcp?token=t",
        state=STAGING_DONE,
    )

    record = _local(stagings=[staged])

    (row,) = record["uploads"]
    assert (row["by"], row["source"], row["host"], row["where"], row["failed"]) == (
        "staging",
        "mcp:analysis",
        "re.example.org",
        "remote",
        0,
    )
    assert record["nothing_left"] is False
    assert PW not in json.dumps(record) and "token" not in json.dumps(record)
    assert (
        "Sample upload: the sample was staged once to tool server `analysis` (streamable-http) "
        "at `re.example.org` (outside this machine) through its put_sample tools, for its tools "
        "to read."
    ) in disclosure_lines(record)


@pytest.mark.parametrize("state", [STAGING_ATTEMPTED, STAGING_FAILED])
def test_a_staging_that_did_not_finish_is_said_as_one_that_may_have_arrived(state: str) -> None:
    staged = staging_record("analysis", transport="http", url="http://analysis:8000", state=state)

    record = _local(stagings=[staged])

    (row,) = record["uploads"]
    assert (row["where"], row["failed"]) == ("local", 1)
    assert record["nothing_left"] is True, "a local server, whatever came of the upload"
    assert (
        "Sample upload: the sample was staged once to tool server `analysis` (http) at "
        "`analysis` (taken as local: a service name) through its put_sample tools, for its tools "
        "to read; 1 of the attempts failed or did not finish, so whether it arrived cannot be "
        "told."
    ) in disclosure_lines(record)


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
    assert any(
        "by a tool declared to send it out of the deployment" in line
        for line in disclosure_lines(record)
    )


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


# ---------------------------------------------------------------------------
# The memory store, tracing, a partial record
# ---------------------------------------------------------------------------

BACKENDS = {
    "memory": {"in_process": True, "address_leaf": ""},
    "qdrant": {"in_process": False, "address_leaf": "url"},
    "plugin": {"in_process": False, "address_leaf": ""},
}


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
        ({"memory.backend": "plugin", "memory.plugin.path": "/var/x"}, 1, False),
        ({"memory.backend": "unregistered"}, 1, False),
    ],
)
def test_the_memory_store_is_placed_by_what_its_backend_declares(
    snapshot: dict, rows: int, nothing_left: bool
) -> None:
    record = _local(snapshot=snapshot, backends=BACKENDS)

    assert len(record["stores"]) == rows
    assert record["nothing_left"] is nothing_left


def test_a_backend_that_declares_neither_an_address_nor_the_process_cannot_be_placed() -> None:
    record = _local(snapshot={"memory.backend": "plugin"}, backends=BACKENDS)

    (row,) = record["stores"]
    assert (row["where"], row["why"]) == (
        "unknown",
        "the plugin backend declares neither an address nor that it runs in the process",
    )
    assert (
        "Case memory: the `plugin` case-memory store; the plugin backend declares neither an "
        "address nor that it runs in the process, so where its cases went cannot be told."
    ) in disclosure_lines(record)


def test_the_registered_backends_declare_where_their_store_is() -> None:
    from maljan.memory.store_factory import declared_backends

    held = declared_backends()
    assert held["memory"]["in_process"] is True
    assert held["qdrant"]["address_leaf"] == "url"
    for name, declared in held.items():
        assert declared["in_process"] or declared["address_leaf"], name


@pytest.mark.parametrize("setting", [True, "true", "1", "on"])
def test_tracing_on_in_the_settings_keeps_nothing_from_being_said(setting: object) -> None:
    record = _local(snapshot={"langchain_tracing_v2": setting})

    assert record["tracing"] is True
    assert record["nothing_left"] is False
    assert disclosure_lines(record)[-1] == TRACING_SENTENCE


def test_tracing_on_in_the_process_environment_keeps_nothing_from_being_said() -> None:
    record = _local(snapshot={"langchain_tracing_v2": False}, tracing=True)

    assert record["tracing"] is True
    assert record["nothing_left"] is False


def test_a_record_that_may_miss_a_call_never_says_nothing_left() -> None:
    record = _local(partial_reason=STOPPED_PART_WAY)

    assert record["nothing_left"] is False
    assert disclosure_lines(record)[0].startswith(
        f"This record may be incomplete: {STOPPED_PART_WAY}, "
    )


def test_a_report_enriched_twice_says_every_question_either_run_sent() -> None:
    from maljan.analysis.disclosure import rdap_row, with_enrichment, with_enrichment_asked

    queued = with_enrichment(_local(), [rdap_row()])
    rdap = {"source": "rdap", "host": "rdap.arin.net", "why": ""}
    first = with_enrichment_asked(queued, [{**rdap, "kinds": {"ip": 2}}])
    second = with_enrichment_asked(
        first,
        [{**rdap, "kinds": {"ip": 1}}, {"source": "intel", "host": "", "kinds": {"domain": 1}}],
    )

    assert [(r["source"], r["host"], r["kinds"]) for r in second["enrichment"]["asked"]] == [
        ("intel", "", {"domain": 1}),
        ("rdap", "rdap.arin.net", {"ip": 3}),
    ]
    assert second["nothing_left"] is False
    assert "rdap.arin.net" in second["addressed"]


# ---------------------------------------------------------------------------
# The record itself
# ---------------------------------------------------------------------------


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
    assert first["addressed"] == ["a.example", "b.example", "llm.example.org"]


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
    from maljan.analysis.disclosure import NOT_BUILT_REPORTING_OFF, not_built

    assert disclosure_lines(None) == []
    assert disclosure_lines("not a record") == []
    assert disclosure_lines(not_built(NOT_BUILT_REPORTING_OFF)) == []


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
