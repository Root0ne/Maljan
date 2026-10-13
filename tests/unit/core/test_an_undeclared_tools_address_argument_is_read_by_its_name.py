"""An undeclared tool's address argument is read by its name, whatever the tool calls it.

The shared list of address arguments held the platform's own spellings
(``address``, ``addr``, ``ea`` …); a decompiler nobody declared that takes
``name_or_address`` or ``func_addr`` gave no place, so its listing had no root
and its readings stayed unplaced until an admin declared it. A call's argument
whose name has the word ``addr`` or ``address`` is now read as the place it
asks about, after the declared and shared ones; a name that makes it a bound,
a size or a base never is.
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
    ["name_or_address", "func_addr", "targetAddress", "function_address", "ea", "address"],
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
