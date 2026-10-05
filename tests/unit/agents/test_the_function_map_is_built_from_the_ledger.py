"""The reverser's function map: built by the platform from the ledger, never by the model.

A reverser on a local model re-derived what it had already read from a
transcript that the window kept cutting, and decompiled the same routines
again. The map is its working memory: every function its own calls decompiled
or listed, with the entries that hold the listing, the artefacts the analysis
server tied to it, and the one line its own claims said about it. Everything
in it is read off ledger entries and parsed claims; nothing the model writes
in prose reaches it.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from maljan.agents.function_map import (
    FUNCTION_MAP_HEAD,
    build_function_map,
    function_artefacts,
    function_map_block,
)
from maljan.schemas.evidence import LedgerEntry

BASE = 0x1360BC00000


def _entry(entry_id: str, tool: str, args: dict[str, Any], output: str = "", **extra: Any) -> Any:
    return LedgerEntry(id=entry_id, tool=tool, args=args, output=output, **extra)


def _hashes(entry_id: str = "ev_0020") -> LedgerEntry:
    output = {
        "tool": "resolve_api_hashes",
        "image_base": hex(BASE),
        "hits": [
            {
                "value": "0x1",
                "readings": [{"algorithm": "a", "set": "exports", "name": "OpenThing"}],
                "occurrences": [{"rva": "0x9057", "function": "0x904c"}],
            },
            {
                "value": "0x2",
                "readings": [{"algorithm": "a", "set": "exports", "name": "CloseThing"}],
                "occurrences": [{"rva": "0x9077", "function": "0x904c"}],
            },
            {
                "value": "0x3",
                "readings": [{"algorithm": "a", "set": "modules", "name": "one.dll"}],
                # A start from a list of starts precedes the place; it does not hold it.
                "occurrences": [{"rva": "0x84ec", "after_function_start": "0x84e4"}],
            },
        ],
    }
    return _entry(entry_id, "resolve_api_hashes", {}, json.dumps(output), server="pipeline")


def _blobs(entry_id: str = "ev_0021") -> LedgerEntry:
    output = {
        "tool": "decode_string_blobs",
        "image_base": hex(BASE),
        "results": [
            {
                "text": "first text",
                "references": [
                    {
                        "at": "0x227d",
                        "function": "0x2200",
                        "passed_to": {
                            "call_at": "0x2281",
                            "callee": {"function": "0xae78"},
                            "argument": 1,
                            "register": "rcx",
                            "address_of": "blob",
                        },
                    }
                ],
            },
            {"text": "second text", "references": [{"at": "0x2300", "function": "0x2200"}]},
            {"text": "elsewhere", "references": [{"at": "0x4120", "function": "0x4110"}]},
        ],
    }
    return _entry(entry_id, "decode_string_blobs", {}, json.dumps(output), server="pipeline")


def _floss(entry_id: str = "ev_0019") -> LedgerEntry:
    output = {
        "strings": [
            {"kind": "decoded", "string": "a", "function": hex(BASE + 0xAE78)},
            {"kind": "decoded", "string": "b", "function_rva": "0xae78"},
            {"kind": "stack", "string": "c", "function_rva": "0x9484"},
        ]
    }
    return _entry(entry_id, "floss", {}, json.dumps(output), server="pipeline")


def _decompiled(entry_id: str, address: str, listing: str = "") -> LedgerEntry:
    return _entry(
        entry_id,
        "decompile_function",
        {"address": address, "program": None},
        listing or f"void FUN_{address.removeprefix('0x')}(void)\n{{\n}}\n",
        server="ghidra",
    )


def _claim(text: str, evidence: str = "ev_0031") -> Any:
    return SimpleNamespace(claim=text, evidence_ref=evidence)


class TestWhatTheAnalysisServerTiedToEachFunction:
    def test_names_texts_call_sites_and_decoded_strings_are_kept_per_function(self) -> None:
        found = function_artefacts([_hashes(), _blobs(), _floss()])

        assert found.image_bases == (BASE,)
        by = {address: artefacts for address, artefacts in found.by_function.items()}
        assert [(a.kind, a.value, a.entry) for a in by[0x904C]] == [
            ("name", "OpenThing", "ev_0020"),
            ("name", "CloseThing", "ev_0020"),
        ]
        assert [(a.kind, a.value) for a in by[0x2200]] == [
            ("text", "first text"),
            ("call", "first text"),
            ("text", "second text"),
        ]
        assert [(a.kind, a.value) for a in by[0xAE78]] == [("decoded", "a"), ("decoded", "b")]
        assert [(a.kind, a.value) for a in by[0x9484]] == [("decoded", "c")]

    def test_a_place_after_a_function_start_is_not_put_in_that_function(self) -> None:
        found = function_artefacts([_hashes()])

        assert 0x84E4 not in found.by_function

    def test_an_answer_that_does_not_parse_adds_nothing(self) -> None:
        broken = _entry("ev_0020", "resolve_api_hashes", {}, '{"hits": [', server="pipeline")

        assert function_artefacts([broken]).by_function == {}

    def test_a_failed_call_adds_nothing(self) -> None:
        failed = _hashes()
        failed.ok = False

        assert function_artefacts([failed]).by_function == {}


class TestTheMapOfWhatTheAnalystVisited:
    def test_a_decompiled_function_carries_its_entries_artefacts_and_summary(self) -> None:
        own = [
            _decompiled("ev_0031", "1360bc0904c"),
            _decompiled("ev_0033", "0x1360bc0904c"),
        ]
        claims = [_claim("FUN_1360bc0904c opens the thing and closes it. Then more.")]

        found = build_function_map(
            own, function_artefacts([_hashes(), _blobs()]), claims, image_bases=(BASE,)
        )

        assert len(found.visited) == 1
        entry = found.visited[0]
        assert entry.address == BASE + 0x904C
        assert entry.decompiled == ("ev_0031", "ev_0033")
        assert entry.listed == ()
        assert [a.value for a in entry.artefacts] == ["OpenThing", "CloseThing"]
        assert entry.summary == "FUN_1360bc0904c opens the thing and closes it."

    def test_a_batch_decompile_puts_each_of_its_functions_on_the_map(self) -> None:
        batch = _entry(
            "ev_0040",
            "batch_decompile",
            {"functions": "0x1360bc02200,0x1360bc04110"},
            json.dumps({"0x1360bc02200": "void a(void) {}", "0x1360bc04110": "void b(void) {}"}),
        )

        found = build_function_map([batch], function_artefacts([_blobs()]), [], (BASE,))

        assert [e.address for e in found.visited] == [BASE + 0x2200, BASE + 0x4110]
        assert all(e.decompiled == ("ev_0040",) for e in found.visited)

    def test_a_function_listing_is_marked_listed(self) -> None:
        listed = _entry(
            "ev_0050", "disassemble_function", {"address": "0x1360bc0b344"}, "mov rax, rbx"
        )

        found = build_function_map([listed], None, [], (BASE,))

        assert [(e.address, e.decompiled, e.listed) for e in found.visited] == [
            (BASE + 0xB344, (), ("ev_0050",))
        ]

    def test_a_listing_at_an_address_no_function_is_known_at_is_not_a_function(self) -> None:
        inside = _entry("ev_0051", "disassemble", {"address": "0x1360bc09870"}, "nop")

        assert build_function_map([inside], None, [], (BASE,)).visited == []

    def test_a_listing_at_a_function_the_server_tied_artefacts_to_is_one(self) -> None:
        at_start = _entry("ev_0052", "disassemble", {"address": "0x1360bc0904c"}, "push rbp")

        found = build_function_map([at_start], function_artefacts([_hashes()]), [], (BASE,))

        assert [e.listed for e in found.visited] == [("ev_0052",)]

    def test_a_failed_decompile_is_not_a_visit(self) -> None:
        failed = _decompiled("ev_0060", "0x1360bc09040")
        failed.ok = False

        assert build_function_map([failed], None, [], (BASE,)).visited == []

    def test_the_unvisited_functions_reaching_artefacts_are_kept_apart(self) -> None:
        found = build_function_map(
            [_decompiled("ev_0031", "0x1360bc0904c")],
            function_artefacts([_hashes(), _blobs()]),
            [],
            (BASE,),
        )

        assert [address for address, _ in found.unvisited] == [0x2200, 0x4110]

    def test_prose_the_model_wrote_is_not_read_only_its_parsed_claims(self) -> None:
        own = [_decompiled("ev_0031", "0x1360bc0904c")]

        found = build_function_map(own, None, [], (BASE,))

        assert found.visited[0].summary == ""


class TestTheBlockTheModelReads:
    def _map(self) -> Any:
        return build_function_map(
            [
                _decompiled("ev_0031", "0x1360bc0904c"),
                _entry(
                    "ev_0050", "disassemble_function", {"address": "0x1360bc0b344"}, "mov rax, rbx"
                ),
            ],
            function_artefacts([_hashes(), _blobs(), _floss()]),
            [_claim("FUN_1360bc0904c opens the thing.")],
            (BASE,),
        )

    def test_the_coverage_line_counts_visits_against_functions_reaching_artefacts(self) -> None:
        assert self._map().coverage() == (
            "2 functions visited (1 decompiled, 1 listed); 5 functions reach artefacts "
            "the analysis server tied to them, 1 of them visited"
        )

    def test_each_visited_function_is_one_line_with_its_entries(self) -> None:
        block = function_map_block(self._map())
        lines = block.splitlines()

        assert lines[0] == FUNCTION_MAP_HEAD
        assert lines[1].startswith("coverage: 2 functions visited")
        assert lines[2] == (
            "- 0x1360bc0904c (FUN_1360bc0904c): decompiled in ev_0031; reaches 2 resolved "
            "names (ev_0020); summary: FUN_1360bc0904c opens the thing."
        )
        assert lines[3] == "- 0x1360bc0b344: listed in ev_0050"

    def test_the_unvisited_ones_are_one_line_by_address(self) -> None:
        last = function_map_block(self._map()).splitlines()[-1]

        assert last.startswith("not visited, reaching artefacts: ")
        assert "0x1360bc02200 (2 decoded texts, 1 call-site fact; ev_0021)" in last
        assert "0x1360bc0ae78 (2 strings FLOSS decoded; ev_0019)" in last

    def test_nothing_visited_and_nothing_tied_is_no_block(self) -> None:
        assert function_map_block(build_function_map([], None, [], ())) == ""

    def test_artefacts_with_no_visit_yet_still_make_a_block(self) -> None:
        block = function_map_block(
            build_function_map([], function_artefacts([_hashes()]), [], (BASE,))
        )

        assert block.splitlines()[1] == (
            "coverage: 0 functions visited; 1 function reaches artefacts the analysis server "
            "tied to them, 0 of them visited"
        )

    def test_without_an_image_base_an_unvisited_function_is_said_as_an_offset(self) -> None:
        found = build_function_map([], function_artefacts([_floss()]), [], ())

        assert "offset 0x9484 (1 string FLOSS decoded; ev_0019)" in function_map_block(found)
