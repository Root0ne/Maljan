"""The console's call map is derived from the stored ledger alone (T-485).

Each function the run's code reading touched, the functions it calls and the
ones that call it, whether a listing of it is held, and the entries that hold
it. Every address and tool name here is a neutral synthetic value, read by the
tools' declared kinds; the stored-run pin reads a real run where one is on
this machine.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from maljan.reporting.call_map import call_map
from maljan.reporting.follow_up import stored_ledger
from maljan.schemas.evidence import LedgerEntry
from tests.linear_cost import assert_scales
from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import _benchmark

BASE = 0x2470000
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}
_INDEX = {"v": 1, "kind": "function_index", "reader": "function_table"}


def _lifted(entry_id: str, address: int, body: str = "", name: str = "", **kw: Any) -> LedgerEntry:
    listing = f"int {name or f'FUN_{address:x}'}(int a)\n{{\n{body}\n}}\n"
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        agent=kw.pop("agent", "reader_one"),
        args={"address": hex(address)},
        output=listing,
        facts=_DECOMPILE,
        **kw,
    )


def _table(entry_id: str, data: dict[str, Any]) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id, tool="routine_table", args={}, output=json.dumps(data), facts=_INDEX
    )


def _by_address(found: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f["address"]: f for f in found["functions"]}


def test_a_read_routine_its_callee_and_the_entry_that_holds_its_listing() -> None:
    gate, check = BASE + 0x5A10, BASE + 0x5A38
    found = call_map([_lifted("ev_0031", gate, f"  if (FUN_{check:x}(a) == 0) return 0;")])

    rows = _by_address(found)
    assert rows[hex(gate)] == {
        "address": hex(gate),
        "offset": None,
        "names": [],
        "read": True,
        "listed_in": ["ev_0031"],
        "read_by": ["reader_one"],
        "calls": [hex(check)],
        "called_by": [],
    }
    assert rows[hex(check)]["read"] is False
    assert rows[hex(check)]["called_by"] == [hex(gate)]
    assert found["roots"] == [hex(gate)]


def test_the_index_states_calls_and_an_offset_is_spelled_by_its_virtual_address() -> None:
    gate, check, other = 0x5A10, 0x5A38, 0x8100
    index = {
        "image_base": hex(BASE),
        "rows": [
            {
                "function": hex(BASE + other),
                "offset": hex(other),
                "callees": [hex(BASE + check)],
                "callers": [hex(BASE + gate)],
            }
        ],
    }
    # Read by its offset: the same routine as its virtual address.
    found = call_map([_table("ev_0020", index), _lifted("ev_0031", gate, "  return a;")])

    rows = _by_address(found)
    assert found["image_base"] == hex(BASE)
    assert list(rows) == [hex(BASE + gate), hex(BASE + check), hex(BASE + other)]
    assert rows[hex(BASE + gate)]["read"] and rows[hex(BASE + gate)]["offset"] == hex(gate)
    assert rows[hex(BASE + gate)]["calls"] == [hex(BASE + other)]
    assert rows[hex(BASE + other)]["calls"] == [hex(BASE + check)]
    assert not rows[hex(BASE + other)]["read"]
    assert found["roots"] == [hex(BASE + gate)]


def test_a_cycle_is_entered_once_at_its_lowest_address() -> None:
    one, two = BASE + 0x1000, BASE + 0x2000
    found = call_map(
        [
            _lifted("ev_0001", one, f"  FUN_{two:x}(a);"),
            _lifted("ev_0002", two, f"  FUN_{one:x}(a);"),
        ]
    )
    assert found["roots"] == [hex(one)]
    assert _by_address(found)[hex(two)]["calls"] == [hex(one)]


def test_a_given_name_is_kept_and_the_decompiler_s_own_name_is_not() -> None:
    start = BASE + 0x3C7C
    found = call_map([_lifted("ev_0001", start, name="entry")])
    assert _by_address(found)[hex(start)]["names"] == ["entry"]


def test_a_failed_listing_reads_nothing_and_an_empty_ledger_draws_nothing() -> None:
    gate, check = BASE + 0x5A10, BASE + 0x5A38
    assert call_map([_lifted("ev_0031", gate, f"  FUN_{check:x}(a);", ok=False)]) == {
        "image_base": None,
        "functions": [],
        "roots": [],
    }
    assert call_map([])["functions"] == []


def test_the_map_is_the_same_for_the_same_ledger() -> None:
    gate, check = BASE + 0x5A10, BASE + 0x5A38
    ledger = [_lifted("ev_0031", gate, f"  FUN_{check:x}(a);")]
    assert json.dumps(call_map(ledger)) == json.dumps(call_map(list(ledger)))


def test_the_map_is_linear_in_the_ledger() -> None:
    def _ledger(n: int) -> list[LedgerEntry]:
        return [
            _lifted(f"ev_{i:04d}", BASE + 0x100 * i, f"  FUN_{BASE + 0x100 * (i + 1):x}(a);")
            for i in range(1, n + 1)
        ]

    assert len(call_map(_ledger(50))["functions"]) == 51
    assert_scales(_ledger, 300, call_map)


def test_a_stored_run_s_decompiled_listings_draw_its_map() -> None:
    root = _benchmark()
    if root is None or not (root / "haiku7" / "evidence.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    rows = json.loads((root / "haiku7" / "evidence.json").read_text())["items"]
    ledger, unread = stored_ledger(rows)
    found = call_map(ledger)

    assert unread == 0
    functions = _by_address(found)
    assert len(functions) == 150
    assert sum(f["read"] for f in functions.values()) == 64
    assert found["image_base"] == "0x1360bc00000"
    # Every call is drawn from both ends, and every listing cites a stored entry.
    ids = {r["entry_id"] for r in rows}
    for address, function in functions.items():
        assert all(address in functions[c]["called_by"] for c in function["calls"])
        assert set(function["listed_in"]) <= ids
    assert functions["0x1360bc03ce4"]["names"] == ["extra"]
    assert found["roots"][:3] == ["0x1360bc02200", "0x1360bc03c7c", "0x1360bc03ce4"]
