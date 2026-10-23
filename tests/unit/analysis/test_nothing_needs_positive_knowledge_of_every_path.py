"""Each path a run can send something out on keeps "nothing left this machine" from printing.

The record says nothing left only with positive knowledge of every path; a
path it cannot place makes the block say what it cannot tell and why. Each
case here once printed "Nothing left this machine" while something left:

* a server run on this machine that declares a lookup forwards every call;
* a sample staged to a tool server before any tool call;
* a hosted model behind a gateway on a local address;
* transition-range addresses that route to a public IPv4 address;
* tracing switched on as text rather than a boolean;
* a memory store, a model endpoint or a tool server address holding
  credentials, which never reach the record;
* a run with no counted call, whose global endpoint still received prompts;
* a failed upload by a tool declared to send the sample out.

Real settings are read through the snapshot the run itself takes
(``core.settings_overrides.public_snapshot``) wherever the case depends on
what the settings hold.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from tests.credential_shapes import password

from maljan.analysis.disclosure import (
    STAGING_DONE,
    addressed_hosts,
    disclosure_lines,
    disclosure_record,
    model_list,
    staging_record,
)
from maljan.core.config import Settings
from maljan.core.settings_overrides import public_snapshot

LOCAL_LLM = {"llm.provider": "openai", "llm.openai.base_url": "http://127.0.0.1:8080/v1"}
RUNTIME = {"http://127.0.0.1:8080": "llama.cpp /props"}
# Built at run time: a credential written down is a secret to a scanner.
PW = password()
KEY = password(10, variant=1)
SECRETS = (PW, KEY)


def _tokens(**per_agent: dict[str, int]) -> dict[str, Any]:
    agents = {a: {"llm_calls": sum(m.values()), "models": dict(m)} for a, m in per_agent.items()}
    return {"llm_calls": sum(r["llm_calls"] for r in agents.values()), "per_agent": agents}


LOCAL_TOKENS = _tokens(static={"openai/q @ http://127.0.0.1:8080": 3})


def _entry(source: str, tool: str, facts: dict | None = None, **over: Any) -> dict[str, Any]:
    row = {
        "id": "ev_0001",
        "tool": tool,
        "args": over.pop("args", {}),
        "ok": True,
        "source": source,
        "server": source.partition(":")[2],
        "facts": facts,
    }
    row.update(over)
    return row


def _snapshot(values: dict[str, Any]) -> dict[str, Any]:
    return public_snapshot(Settings.model_validate(values), ())


def _says_it_cannot_tell(record: dict[str, Any]) -> list[str]:
    lines = disclosure_lines(record)
    assert record["nothing_left"] is False
    assert not any(line.startswith("Nothing left this machine") for line in lines)
    return lines


VT_CALLS = [
    _entry("mcp:virustotal", "get_submission", {"v": 1, "kind": "submission_status"}),
    _entry("mcp:virustotal", "submit_url", {"v": 1}, args={"url": "http://c2.example/x"}),
    _entry("mcp:virustotal", "reanalyze_domain", {"v": 1}, args={"domain": "c2.example"}),
    _entry("mcp:virustotal", "get_analysis", {"v": 1, "kind": "submission_status"}),
]


def test_a_shipped_lookup_server_run_on_this_machine_forwards_every_call() -> None:
    snapshot = _snapshot(
        {
            "llm": {"provider": "openai", "openai": {"base_url": "http://127.0.0.1:8080/v1"}},
            "mcp": {"servers": {"virustotal": {"transport": "stdio", "command": "vt-mcp"}}},
        }
    )

    record = disclosure_record(
        snapshot, entries=VT_CALLS, tokens=LOCAL_TOKENS, agents=["static"], runtimes=RUNTIME
    )

    (row,) = record["servers"]
    assert (row["source"], row["where"], row["calls"]) == ("mcp:virustotal", "unknown", 4)
    assert (
        "Tool calls: tool server `virustotal` (stdio, run on this machine): 4 calls; it is a "
        "local tool server that declares a lookup or a sandbox, so a call through it may go on "
        "to a service the settings do not name, so where they went cannot be told."
    ) in _says_it_cannot_tell(record)


def test_calls_to_a_local_server_whose_block_declares_nothing_are_said_as_undeclared() -> None:
    snapshot = {
        **LOCAL_LLM,
        "mcp.servers.virustotal.transport": "stdio",
        "memory.backend": "memory",
    }

    record = disclosure_record(
        snapshot, entries=VT_CALLS, tokens=LOCAL_TOKENS, agents=["static"], runtimes=RUNTIME
    )

    (row,) = record["undeclared"]
    assert row["calls"] == 2
    assert any(
        line.startswith("Tool calls: 2 calls to tools that declare no effects")
        for line in _says_it_cannot_tell(record)
    )


@pytest.mark.parametrize("called", [False, True])
def test_a_sample_staged_to_a_remote_server_is_said_whether_or_not_a_tool_was_called(
    called: bool,
) -> None:
    snapshot = {
        **LOCAL_LLM,
        "mcp.servers.analysis.transport": "streamable-http",
        "mcp.servers.analysis.url": "https://re.example.org/mcp",
        "memory.backend": "memory",
    }
    staged = staging_record(
        "analysis",
        transport="streamable-http",
        url="https://re.example.org/mcp",
        state=STAGING_DONE,
    )
    entries = [_entry("mcp:analysis", "strings", {"v": 1, "kind": "strings"})] if called else []

    record = disclosure_record(
        snapshot,
        entries=entries,
        stagings=[staged],
        tokens=LOCAL_TOKENS,
        agents=["static"],
        runtimes=RUNTIME,
    )

    lines = _says_it_cannot_tell(record)
    assert any(line.startswith("Sample upload: the sample was staged once") for line in lines)
    assert bool(record["servers"]) is called


def test_a_hosted_model_behind_a_local_gateway_is_not_nothing() -> None:
    record = disclosure_record(
        {"llm.provider": "anthropic", "llm.anthropic.base_url": "http://localhost:4000"},
        tokens=_tokens(judge={"anthropic/claude-haiku-5-5 @ http://localhost:4000": 7}),
        agents=["judge"],
    )

    assert any(
        "a local address that did not answer as a model runtime may forward the prompts" in line
        for line in _says_it_cannot_tell(record)
    )


@pytest.mark.parametrize(
    "host",
    ["[2002:808:808::1]", "[2001:0:4136:e378:8000:63bf:3fff:fdd2]", "[64:ff9b:1::808:808]"],
)
def test_a_transition_address_of_a_public_ipv4_address_is_outside(host: str) -> None:
    record = disclosure_record(
        {"llm.provider": "openai", "llm.openai.base_url": f"http://{host}:8080/v1"},
        tokens=_tokens(static={f"openai/q @ http://{host}:8080": 2}),
        agents=["static"],
        runtimes={f"http://{host}:8080": "llama.cpp /props"},
    )

    (row,) = record["models"]
    assert row["where"] == "remote"
    assert "(outside this machine)" in _says_it_cannot_tell(record)[0]


def test_tracing_switched_on_as_text_is_on() -> None:
    record = disclosure_record(
        {**LOCAL_LLM, "langchain_tracing_v2": "true", "memory.backend": "memory"},
        tokens=LOCAL_TOKENS,
        agents=["static"],
        runtimes=RUNTIME,
    )

    assert record["tracing"] is True
    assert any(line.startswith("Tracing is on") for line in _says_it_cannot_tell(record))


def test_a_remote_store_and_endpoint_holding_credentials_are_named_by_host_alone() -> None:
    record = disclosure_record(
        {
            "llm.provider": "openai",
            "llm.openai.base_url": f"https://user:{PW}@llm.example.org/v1?key={KEY}",
            "memory.backend": "qdrant",
            "memory.qdrant.url": f"https://user:{PW}@q.example.org:6333/?api_key={KEY}",
        },
        tokens=_tokens(static={f"openai/q @ https://user:{PW}@llm.example.org/v1?key={KEY}": 1}),
        agents=["static"],
    )

    text = json.dumps(record)
    assert not any(secret in text for secret in SECRETS)
    (store,) = record["stores"]
    assert (store["host"], store["where"]) == ("q.example.org", "remote")
    assert [row["host"] for row in record["models"]] == ["llm.example.org"]
    lines = _says_it_cannot_tell(record)
    assert not any(secret in line for line in lines for secret in SECRETS)


def test_credentials_in_the_real_settings_never_reach_the_record() -> None:
    snapshot = _snapshot(
        {
            "llm": {
                "provider": "openai",
                "openai": {"base_url": f"https://user:{PW}@llm.example.org/v1?api_key={KEY}"},
            },
            "mcp": {
                "servers": {
                    "remote": {
                        "transport": "streamable-http",
                        "url": f"https://u:{PW}@re.example.org/mcp?token={KEY}",
                        "enabled": True,
                    }
                }
            },
            "memory": {
                "backend": "qdrant",
                "qdrant": {"url": f"https://admin:{PW}@q.example.org:6333"},
            },
        }
    )

    record = disclosure_record(
        snapshot,
        entries=[_entry("mcp:remote", "t", {"v": 1})],
        tokens=_tokens(static={"openai/q @ https://llm.example.org": 1}),
        agents=["static"],
    )

    assert not any(secret in json.dumps(record) for secret in SECRETS)
    assert {"llm.example.org", "re.example.org", "q.example.org"} <= set(record["addressed"])
    lines = _says_it_cannot_tell(record)
    assert not any(secret in line for line in lines for secret in SECRETS)


@pytest.mark.parametrize(
    ("base_url", "where"),
    [("http://127.0.0.1:8080/v1", "local"), ("https://api.example.org/v1", "remote")],
)
def test_a_run_that_counted_no_call_still_names_its_global_endpoint(
    base_url: str, where: str
) -> None:
    record = disclosure_record(
        {"llm.provider": "openai", "llm.openai.base_url": base_url, "memory.backend": "memory"},
        tokens=None,
        agents=[],
    )

    (row,) = record["models"]
    assert (row["where"], row["global"], row["calls"]) == (where, True, 0)
    assert any(
        "is the endpoint of the global model" in line for line in _says_it_cannot_tell(record)
    )


def test_a_failed_upload_by_a_tool_declared_to_send_the_sample_out_is_said() -> None:
    record = disclosure_record(
        {
            **LOCAL_LLM,
            "mcp.servers.sbx.transport": "http",
            "mcp.servers.sbx.url": "https://sbx.example.org/mcp",
            "memory.backend": "memory",
        },
        entries=[
            _entry(
                "mcp:sbx",
                "submit",
                {"v": 1, "kind": "submission", "discloses_sample": True},
                ok=False,
            )
        ],
        tokens=LOCAL_TOKENS,
        agents=["static"],
        runtimes=RUNTIME,
    )

    (row,) = record["uploads"]
    assert (row["by"], row["host"], row["where"], row["failed"]) == (
        "tool",
        "sbx.example.org",
        "remote",
        1,
    )
    assert any(line.startswith("Sample upload:") for line in _says_it_cannot_tell(record))


def test_every_chain_and_address_is_read_from_the_runs_own_snapshot() -> None:
    snapshot = _snapshot(
        {
            "llm": {
                "provider": "openai",
                "openai": {"base_url": "http://127.0.0.1:8080/v1"},
                "agents": {
                    "static": {
                        "provider": "openai",
                        "model": "q",
                        "base_url": "http://127.0.0.1:8080/v1",
                        "fallbacks": [{"provider": "anthropic", "model": "claude-haiku-5-5"}],
                    }
                },
            },
            "mcp": {
                "servers": {
                    "vt": {"transport": "stdio", "command": "vt-mcp"},
                    "remote": {
                        "transport": "streamable-http",
                        "url": f"https://u:{PW}@re.example.org/mcp?token={KEY}",
                    },
                }
            },
            "langchain_tracing_v2": False,
        }
    )

    assert [provider for provider, _endpoint in model_list(snapshot, "static")] == [
        "openai",
        "anthropic",
    ]
    assert model_list(snapshot, "judge") == [("openai", "http://127.0.0.1:8080/v1")]
    hosts = addressed_hosts(snapshot)
    assert {"127.0.0.1", "re.example.org"} <= set(hosts)
    assert not any(secret in host for host in hosts for secret in SECRETS)

    record = disclosure_record(
        snapshot,
        tokens=_tokens(static={"openai/q @ http://127.0.0.1:8080": 2}),
        agents=["static"],
        runtimes=RUNTIME,
    )
    hosted = [row for row in record["models"] if row["where"] == "remote"]
    assert hosted and hosted[0]["configured_for"] == ["static"]
    _says_it_cannot_tell(record)
