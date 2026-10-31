"""A routine a read routine calls and no entry reads is stated from the ledger (T-404).

The function map's not-visited line ranks functions by their artefacts; a
callee behind a read gate that holds none of its own was on no line, and a
report called a behaviour absent beside it. The callee view reads the calls a
decompiled listing makes by the decompiler's own names and the calls a
function index answer states, and keeps the callees no read routine is. Every
address and tool name here is a neutral synthetic value, read by the tools'
declared kinds.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.agents.function_callees import call_edges, unread_callees
from maljan.schemas.evidence import LedgerEntry
from tests.linear_cost import assert_scales

BASE = 0x2470000
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}
_BATCH = {"v": 1, "kind": "decompile_batch", "reader": "listing"}
_INDEX = {"v": 1, "kind": "function_index", "reader": "function_table"}


def _entry(entry_id: str, tool: str, args: dict[str, Any], output: str, facts: Any, **kw: Any):
    return LedgerEntry(id=entry_id, tool=tool, args=args, output=output, facts=facts, **kw)


def _lifted(entry_id: str, address: int, body: str = "", **kw: Any) -> LedgerEntry:
    listing = f"int FUN_{address:x}(int a)\n{{\n{body}\n}}\n"
    return _entry(entry_id, "lift_routine", {"address": hex(address)}, listing, _DECOMPILE, **kw)


def _table(entry_id: str, data: dict[str, Any], args: dict[str, Any] | None = None) -> LedgerEntry:
    return _entry(entry_id, "routine_table", args or {}, json.dumps(data), _INDEX)


def test_a_callee_of_a_read_listing_nobody_read_is_unread() -> None:
    gate, check = BASE + 0x5A10, BASE + 0x5A38
    found = unread_callees([_lifted("ev_0031", gate, f"  if (FUN_{check:x}(a) == 0) return 0;")])
    assert [(u.address, u.callers, u.read_in) for u in found] == [(check, (gate,), ("ev_0031",))]


def test_a_callee_read_in_any_entry_is_not_unread() -> None:
    gate, check = BASE + 0x5A10, BASE + 0x5A38
    ledger = [
        _lifted("ev_0031", gate, f"  FUN_{check:x}(a);"),
        _lifted("ev_0032", check, "  return a;"),
    ]
    assert unread_callees(ledger) == []


def test_a_name_without_a_call_and_the_own_signature_are_no_call() -> None:
    gate, pointer = BASE + 0x5A10, BASE + 0x6C00
    found = unread_callees([_lifted("ev_0031", gate, f"  void *p = FUN_{pointer:x};")])
    assert found == []


def test_an_offset_and_its_virtual_address_are_one_routine() -> None:
    gate, check = 0x5A10, 0x5A38
    ledger = [
        _table("ev_0020", {"image_base": hex(BASE), "rows": []}),
        _lifted("ev_0031", BASE + gate, f"  FUN_{BASE + check:x}(a);"),
        # Read by its offset: the same routine.
        _lifted("ev_0032", check, "  return a;"),
    ]
    assert unread_callees(ledger) == []


def test_the_index_states_calls_per_row_and_for_the_rest() -> None:
    gate, check, deeper, other = (BASE + o for o in (0x5A10, 0x5A38, 0x7E00, 0x8100))
    index = {
        "image_base": hex(BASE),
        "rows": [
            {
                "function": hex(other),
                "offset": hex(other - BASE),
                "callees": [],
                "callers": [hex(gate)],
            }
        ],
        "other_callees": {hex(gate): [hex(check)], hex(check): [hex(deeper)]},
    }
    ledger = [_table("ev_0020", index), _lifted("ev_0031", gate, "  return a;")]
    found = {u.address: u for u in unread_callees(ledger)}
    # The deeper callee's caller was not read: no fact about it.
    assert set(found) == {check, other}
    assert found[check].stated_in == ("ev_0020",)


def test_an_answer_for_one_address_states_only_its_callees() -> None:
    gate, check, caller = BASE + 0x5A10, BASE + 0x5A38, BASE + 0x9900
    answer = {"image_base": hex(BASE), "callers": [hex(caller)], "callees": [hex(check)]}
    ledger = [
        _table("ev_0020", answer, {"address": hex(gate - BASE)}),
        _lifted("ev_0031", gate, "  return a;"),
    ]
    assert [u.address for u in unread_callees(ledger)] == [check]


def test_an_index_of_a_produced_file_is_not_the_sample_s() -> None:
    gate, check = BASE + 0x5A10, BASE + 0x5A38
    index = {"image_base": hex(BASE), "rows": [], "other_callees": {hex(gate): [hex(check)]}}
    carved = _table("ev_0020", index, {"carved_path": "/work/layer2.bin"})
    assert unread_callees([carved, _lifted("ev_0031", gate, "  return a;")]) == []


def test_a_batch_listing_is_one_routine_per_key_and_an_error_key_reads_nothing() -> None:
    first, second, callee = BASE + 0x1200, BASE + 0x1300, BASE + 0x1400
    output = json.dumps(
        {
            f"{first:x}": f"void FUN_{first:x}(void)\n{{\n  FUN_{callee:x}();\n}}\n",
            f"{second:x}": "Error: no function",
        }
    )
    batch = _entry("ev_0040", "lift_many", {"functions": f"{first:x},{second:x}"}, output, _BATCH)
    edges = call_edges([batch]).calls
    assert edges == {first: {callee: ["ev_0040"]}}
    assert [u.callers for u in unread_callees([batch])] == [(first,)]


def test_a_failed_or_unshown_listing_reads_nothing() -> None:
    gate, check = BASE + 0x5A10, BASE + 0x5A38
    failed = _lifted("ev_0031", gate, f"  FUN_{check:x}(a);", ok=False)
    assert unread_callees([failed]) == []


def test_the_view_is_linear_in_the_ledger() -> None:
    def _ledger(n: int) -> list[LedgerEntry]:
        return [
            _lifted(f"ev_{i:04d}", BASE + 0x100 * i, f"  FUN_{BASE + 0x100 * i + 0x40:x}(a);")
            for i in range(1, n + 1)
        ]

    assert len(unread_callees(_ledger(50))) == 50
    assert_scales(_ledger, 300, unread_callees)


def _asked_at(entry_id: str, asked: int, start: int, body: str) -> LedgerEntry:
    """A decompile asked at ``asked`` whose listing is the function starting at ``start``."""
    listing = f"int FUN_{start:x}(int a)\n{{\n{body}\n}}\n"
    return _entry(entry_id, "lift_routine", {"address": hex(asked)}, listing, _DECOMPILE)


def test_a_listing_s_own_signature_is_no_call_when_asked_inside_the_function() -> None:
    start, check = BASE + 0x5A10, BASE + 0x5A38
    found = unread_callees([_asked_at("ev_0031", start + 0x14, start, f"  FUN_{check:x}(a);")])
    # The function the signature names is the caller, and read; it is no callee.
    assert [(u.address, u.callers) for u in found] == [(check, (start,))]


def test_a_listing_asked_by_its_offset_is_keyed_by_its_signature() -> None:
    start, check = BASE + 0x5A10, BASE + 0x5A38
    ledger = [
        _table("ev_0020", {"image_base": hex(BASE), "rows": []}),
        _asked_at("ev_0031", start - BASE, start, f"  FUN_{check:x}(a);"),
    ]
    assert call_edges(ledger).calls == {start: {check: ["ev_0031"]}}
    assert [(u.address, u.callers) for u in unread_callees(ledger)] == [(check, (start,))]


def test_a_callee_read_by_a_disassembly_is_not_unread() -> None:
    gate, check = BASE + 0x5A10, BASE + 0x5A38
    disassembly = _entry(
        "ev_0033",
        "list_instructions",
        {"address": hex(check)},
        f"{check:x}: push rbp\n{check + 1:x}: ret\n",
        {"v": 1, "kind": "disassembly", "reader": "listing"},
    )
    ledger = [_lifted("ev_0031", gate, f"  FUN_{check:x}(a);"), disassembly]
    assert unread_callees(ledger) == []


def test_a_name_in_a_comment_is_no_call() -> None:
    gate, check, noted = BASE + 0x5A10, BASE + 0x5A38, BASE + 0x6E00
    body = (
        f"  // FUN_{noted:x}(a) was inlined here\n"
        f"  /* see FUN_{noted + 0x10:x}(a)\n     and more */\n"
        f"  FUN_{check:x}(a);"
    )
    assert [u.address for u in unread_callees([_lifted("ev_0031", gate, body)])] == [check]


def test_a_comment_mark_inside_a_string_cuts_nothing_and_an_open_comment_runs_out() -> None:
    from maljan.agents.function_callees import _without_comments

    kept = 'p = "http://x/*y"; c = \'/\'; FUN_1(a); // gone\nq = "a\\"//b"; FUN_2(b);'
    assert _without_comments(kept) == (
        'p = "http://x/*y"; c = \'/\'; FUN_1(a); \nq = "a\\"//b"; FUN_2(b);'
    )
    assert _without_comments("FUN_1(a); /* never closed FUN_2(b);") == "FUN_1(a); "
    gate, check = BASE + 0x5A10, BASE + 0x5A38
    body = f'  log("see http://host/");\n  FUN_{check:x}(a);'
    assert [u.address for u in unread_callees([_lifted("ev_0031", gate, body)])] == [check]


def test_the_comment_scan_is_linear_on_hostile_listings() -> None:
    from maljan.agents.function_callees import _without_comments

    # Unclosed comment marks after a string each, and comment marks inside
    # strings: a backtracking reader is quadratic on both.
    assert_scales(lambda n: 'x = "/*";' * n + "/*" + " /*" * n, 2_000, _without_comments)
    assert_scales(lambda n: 'x = "a//b/*c";\n' * n, 2_000, _without_comments)
    assert_scales(lambda n: "/* x " * n, 2_000, _without_comments)


def test_an_apostrophe_in_prose_opens_no_literal() -> None:
    gate, check, noted = BASE + 0x5A10, BASE + 0x5A38, BASE + 0x6E00
    body = f"  str.It's set; // FUN_{noted:x}(a)\n  c = '\\\\'; FUN_{check:x}(a);"
    assert [u.address for u in unread_callees([_lifted("ev_0031", gate, body)])] == [check]
