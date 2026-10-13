"""An undeclared tool's address argument is read by its name, whatever the tool calls it.

The shared list of address arguments held the platform's own spellings
(``address``, ``addr``, ``ea`` …); a decompiler nobody declared that takes
``name_or_address`` or ``func_addr`` gave no place, so its listing had no root
and its readings stayed unplaced until an admin declared it. For a tool whose
answer is a code listing, a call's argument whose name has a code address's
shape (address words alone, or paired with words for the place of code) is now
read as the place it asks about, after the declared and shared ones; a network
or identity address and a bound, a size or a base never is, and neither is any
argument of a tool whose answer is not code.
"""

from __future__ import annotations

import time

import pytest

from maljan.core.tool_declarations import ToolFacts
from maljan.core.undeclared_tools import (
    ADDRESS_ARGUMENTS,
    address_arguments,
    entry_address_arguments,
    named_as_address,
)


@pytest.mark.parametrize(
    "name",
    [
        "name_or_address",
        "func_addr",
        "funcAddr",
        "targetAddress",
        "function_address",
        "ea",
        "address",
        "rva",
        "entry_rva",
        "instruction_address",
        "insn_addr",
        "code_address",
        "location_address",
        "start_addr",
    ],
)
def test_a_name_for_an_address_is_read_as_one(name: str) -> None:
    assert named_as_address(name)


@pytest.mark.parametrize(
    "name",
    [
        "end_address",
        "base_address",
        "max_addr",
        "address_count",
        "addressSpace",
        "path",
        "name",
        "start",
        "address_range",
        "offset",
        "name_address",
        "addresses",
        "sockaddr",
        # A network or an identity address is not a place in the binary.
        "ip",
        "ip_address",
        "ipAddress",
        "ipv4_address",
        "mac_address",
        "email_address",
        "mail_address",
        "address_family",
        "remote_addr",
        "local_address",
        "src_addr",
        "dst_addr",
        "source_address",
        "destination_address",
        "bind_address",
        "host_address",
        "server_address",
        "url_address",
        "wallet_address",
        "peer_address",
        "physical_address",
        "socket_address",
        "network_address",
        "web_address",
    ],
)
def test_a_bound_a_size_or_another_value_never_is(name: str) -> None:
    assert not named_as_address(name)


def test_the_call_s_own_names_follow_the_declared_and_the_shared_ones() -> None:
    held = address_arguments(None, ["binary_name", "name_or_address"])
    assert held == (*ADDRESS_ARGUMENTS, "name_or_address")
    declared = ToolFacts(arguments={"address": "offset_va"})
    assert address_arguments(declared, ["name_or_address"])[:2] == ("offset_va", "address")
    # Nothing offered, nothing added: the shared list as it was.
    assert address_arguments(None) == ADDRESS_ARGUMENTS


def test_an_entry_s_call_gives_its_own_names() -> None:
    entry = {
        "tool": "decompile_function",
        "source": "mcp:other",
        "facts": {"v": 1},
        "args": {"binary_name": "x.exe", "name_or_address": "0x140001000"},
    }
    assert entry_address_arguments(entry)[-1] == "name_or_address"


def test_a_tool_whose_answer_is_not_code_offers_no_name() -> None:
    entry = {
        "tool": "lookup_host",
        "source": "mcp:other",
        "facts": {"v": 1},
        "args": {"name_or_address": "0x140001000"},
    }
    assert entry_address_arguments(entry) == ADDRESS_ARGUMENTS


def test_a_lookup_s_address_places_no_code_root() -> None:
    from maljan.analysis.evidence_roots import run_roots
    from maljan.schemas.evidence import build_entry

    entry = build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="network",
        tool="resolve_peer",
        args={"bind_address": "1234", "address_family": 2, "ip_address": "16909060"},
        server="other",
        source="mcp:other",
        output='{"peer": "example"}',
    )
    found = run_roots([entry]).entries["ev_0001"]
    assert not found.roots


def _schema_tool(name: str, **fields: type) -> object:
    from pydantic import create_model

    class _Tool:
        pass

    tool = _Tool()
    tool.name = name  # type: ignore[attr-defined]
    tool.args_schema = create_model(f"{name}Args", **{k: (v, ...) for k, v in fields.items()})  # type: ignore[attr-defined,call-overload]
    return tool


def test_the_debate_lists_only_tools_that_read_code_at_an_address() -> None:
    from maljan.pipeline.debate_facts import tools_taking_an_address

    tools = [
        _schema_tool("check_ip_reputation", ip_address=str),
        _schema_tool("resolve", address_family=int, host=str),
        _schema_tool("rename_symbol", name_or_address=str, new_name=str),
        _schema_tool("decompile_function", binary_name=str, name_or_address=str),
        _schema_tool("disassemble_at", func_addr=str),
    ]
    assert tools_taking_an_address(tools) == ["decompile_function", "disassemble_at"]


def test_an_undeclared_decompile_is_placed_by_it() -> None:
    from maljan.analysis.evidence_roots import run_roots
    from maljan.schemas.evidence import build_entry

    entry = build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="reverser",
        tool="decompile_function",
        args={"binary_name": "x.exe", "name_or_address": "0x140001000"},
        server="other",
        source="mcp:other",
        output="int entry(void) { return connect(s, a, n); }",
    )
    found = run_roots([entry]).entries["ev_0001"]
    assert found.roots, found.reason


def test_many_offered_names_are_read_in_linear_time() -> None:
    def _timed(n: int) -> float:
        names = [f"arg_{i}" for i in range(n)] + ["name_or_address"]
        start = time.perf_counter()
        assert address_arguments(None, names)[-1] == "name_or_address"
        return time.perf_counter() - start

    small, large = _timed(2_000), _timed(20_000)
    assert large < max(small * 30, 0.5)
