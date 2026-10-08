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

BASE = 0x140000000


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
                "occurrences": [{"rva": "0x50b7", "function": "0x50ac"}],
            },
            {
                "value": "0x2",
                "readings": [{"algorithm": "a", "set": "exports", "name": "CloseThing"}],
                "occurrences": [{"rva": "0x50d7", "function": "0x50ac"}],
            },
            {
                "value": "0x3",
                "readings": [{"algorithm": "a", "set": "modules", "name": "one.dll"}],
                # A start from a list of starts precedes the place; it does not hold it.
                "occurrences": [{"rva": "0x44a8", "after_function_start": "0x44a0"}],
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
                        "at": "0x121d",
                        "function": "0x11a0",
                        "passed_to": {
                            "call_at": "0x1221",
                            "callee": {"function": "0x66e0"},
                            "argument": 1,
                            "register": "rcx",
                            "address_of": "blob",
                        },
                    }
                ],
            },
            {"text": "second text", "references": [{"at": "0x12a0", "function": "0x11a0"}]},
            {"text": "elsewhere", "references": [{"at": "0x31b0", "function": "0x31a0"}]},
        ],
    }
    return _entry(entry_id, "decode_string_blobs", {}, json.dumps(output), server="pipeline")


def _floss(entry_id: str = "ev_0019") -> LedgerEntry:
    output = {
        "strings": [
            {"kind": "decoded", "string": "a", "function": hex(BASE + 0x66E0)},
            {"kind": "decoded", "string": "b", "function_rva": "0x66e0"},
            {"kind": "stack", "string": "c", "function_rva": "0x54a0"},
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
        assert [(a.kind, a.value, a.entry) for a in by[0x50AC]] == [
            ("name", "OpenThing", "ev_0020"),
            ("name", "CloseThing", "ev_0020"),
        ]
        assert [(a.kind, a.value) for a in by[0x11A0]] == [
            ("text", "first text"),
            ("call", "first text: argument 1 of the call at 0x1221 to 0x66e0"),
            ("text", "second text"),
        ]
        assert [(a.kind, a.value) for a in by[0x66E0]] == [("decoded", "a"), ("decoded", "b")]
        assert [(a.kind, a.value) for a in by[0x54A0]] == [("decoded", "c")]

    def test_a_place_after_a_function_start_is_not_put_in_that_function(self) -> None:
        found = function_artefacts([_hashes()])

        assert 0x44A0 not in found.by_function

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
            _decompiled("ev_0031", "1400050ac"),
            _decompiled("ev_0033", "0x1400050ac"),
        ]
        claims = [_claim("FUN_1400050ac opens the thing and closes it. Then more.")]

        found = build_function_map(
            own, function_artefacts([_hashes(), _blobs()]), claims, image_bases=(BASE,)
        )

        assert len(found.visited) == 1
        entry = found.visited[0]
        assert entry.address == BASE + 0x50AC
        assert entry.decompiled == ("ev_0031", "ev_0033")
        assert entry.listed == ()
        assert [a.value for a in entry.artefacts] == ["OpenThing", "CloseThing"]
        assert entry.summary == "FUN_1400050ac opens the thing and closes it."

    def test_a_batch_decompile_puts_each_of_its_functions_on_the_map(self) -> None:
        batch = _entry(
            "ev_0040",
            "batch_decompile",
            {"functions": "0x1400011a0,0x1400031a0"},
            json.dumps({"0x1400011a0": "void a(void) {}", "0x1400031a0": "void b(void) {}"}),
        )

        found = build_function_map([batch], function_artefacts([_blobs()]), [], (BASE,))

        assert [e.address for e in found.visited] == [BASE + 0x11A0, BASE + 0x31A0]
        assert all(e.decompiled == ("ev_0040",) for e in found.visited)

    def test_a_function_listing_is_marked_listed(self) -> None:
        listed = _entry(
            "ev_0050", "disassemble_function", {"address": "0x1400073a0"}, "mov rax, rbx"
        )

        found = build_function_map([listed], None, [], (BASE,))

        assert [(e.address, e.decompiled, e.listed) for e in found.visited] == [
            (BASE + 0x73A0, (), ("ev_0050",))
        ]

    def test_a_listing_at_an_address_no_function_is_known_at_is_not_a_function(self) -> None:
        inside = _entry("ev_0051", "disassemble", {"address": "0x1400058a0"}, "nop")

        assert build_function_map([inside], None, [], (BASE,)).visited == []

    def test_a_listing_at_a_function_the_server_tied_artefacts_to_is_one(self) -> None:
        at_start = _entry("ev_0052", "disassemble", {"address": "0x1400050ac"}, "push rbp")

        found = build_function_map([at_start], function_artefacts([_hashes()]), [], (BASE,))

        assert [e.listed for e in found.visited] == [("ev_0052",)]

    def test_a_failed_decompile_is_not_a_visit(self) -> None:
        failed = _decompiled("ev_0060", "0x1400050a0")
        failed.ok = False

        assert build_function_map([failed], None, [], (BASE,)).visited == []

    def test_the_unvisited_functions_reaching_artefacts_are_kept_apart(self) -> None:
        found = build_function_map(
            [_decompiled("ev_0031", "0x1400050ac")],
            function_artefacts([_hashes(), _blobs()]),
            [],
            (BASE,),
        )

        assert [address for address, _ in found.unvisited] == [0x11A0, 0x31A0]

    def test_prose_the_model_wrote_is_not_read_only_its_parsed_claims(self) -> None:
        own = [_decompiled("ev_0031", "0x1400050ac")]

        found = build_function_map(own, None, [], (BASE,))

        assert found.visited[0].summary == ""


class TestTheBlockTheModelReads:
    def _map(self) -> Any:
        return build_function_map(
            [
                _decompiled("ev_0031", "0x1400050ac"),
                _entry(
                    "ev_0050", "disassemble_function", {"address": "0x1400073a0"}, "mov rax, rbx"
                ),
            ],
            function_artefacts([_hashes(), _blobs(), _floss()]),
            [_claim("FUN_1400050ac opens the thing.")],
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
            '- 0x1400050ac ("FUN_1400050ac"): decompiled in ev_0031; reaches 2 resolved '
            "names (ev_0020); summary: FUN_1400050ac opens the thing."
        )
        assert lines[3] == "also visited: 0x1400073a0"

    def test_the_unvisited_ones_are_one_line_by_address(self) -> None:
        last = function_map_block(self._map()).splitlines()[-1]

        assert last.startswith("not visited, reaching artefacts: ")
        assert "0x1400011a0 (2 decoded texts, 1 call-site fact; ev_0021)" in last
        assert "0x1400066e0 (2 strings FLOSS decoded; ev_0019)" in last

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

        assert "offset 0x54a0 (1 string FLOSS decoded; ev_0019)" in function_map_block(found)


class TestCountsAndAddresses:
    def test_a_text_referred_to_twice_from_one_function_is_one_decoded_text(self) -> None:
        output = {
            "image_base": hex(BASE),
            "results": [
                {
                    "text": "same text",
                    "references": [
                        {"function": "0x11a0", "passed_to": {"call_at": "0x1221"}},
                        {"function": "0x11a0", "passed_to": {"call_at": "0x12a1"}},
                    ],
                }
            ],
        }
        blobs = _entry("ev_0021", "decode_string_blobs", {}, json.dumps(output))
        found = build_function_map(
            [_decompiled("ev_0031", "0x1400011a0")], function_artefacts([blobs]), [], (BASE,)
        )

        assert "reaches 1 decoded text (ev_0021), 2 call-site facts (ev_0021)" in (
            function_map_block(found)
        )

    def test_the_same_answer_recorded_twice_is_counted_once_and_cited_twice(self) -> None:
        pack = function_artefacts([_hashes("ev_0020")])
        own = [_decompiled("ev_0031", "0x1400050ac"), _hashes("ev_0040")]

        block = function_map_block(build_function_map(own, pack, [], (BASE,)))

        assert "reaches 2 resolved names (ev_0020, ev_0040)" in block

    def test_an_offset_and_its_virtual_address_are_one_function_through_a_stated_base(
        self,
    ) -> None:
        own = [_decompiled("ev_0031", "0x2a00"), _decompiled("ev_0032", "0x140002a00")]

        found = build_function_map(own, None, [], (BASE,))

        assert [(e.address, e.decompiled) for e in found.visited] == [
            (BASE + 0x2A00, ("ev_0031", "ev_0032"))
        ]

    def test_with_no_base_known_two_spellings_stay_as_written(self) -> None:
        own = [_decompiled("ev_0031", "0x2a00"), _decompiled("ev_0032", "0x140002a00")]

        found = build_function_map(own, None, [], ())

        assert [e.address for e in found.visited] == [0x2A00, BASE + 0x2A00]

    def test_with_no_base_known_a_listing_64_kib_away_is_another_function(self) -> None:
        own = [
            _decompiled("ev_0001", "0x401230"),
            _entry("ev_0002", "disassemble_function", {"address": "0x411230"}, "nop"),
        ]

        found = build_function_map(own, None, [], ())

        assert [(e.address, e.decompiled, e.listed) for e in found.visited] == [
            (0x401230, ("ev_0001",), ()),
            (0x411230, (), ("ev_0002",)),
        ]

    def test_a_floss_virtual_address_with_two_bases_known_is_kept_as_written(self) -> None:
        other = 0x7FF600000000
        hashes = _hashes()
        payload = _entry(
            "ev_0022",
            "resolve_api_hashes",
            {},
            json.dumps({"image_base": hex(other), "hits": []}),
        )
        floss = _entry(
            "ev_0019",
            "floss",
            {},
            json.dumps(
                {"strings": [{"kind": "decoded", "string": "a", "function": hex(other + 0x10)}]}
            ),
        )

        found = function_artefacts([hashes, payload, floss])

        assert other + 0x10 in found.by_function
        assert other + 0x10 in found.virtual

    def test_bare_visits_are_folded_into_one_line(self) -> None:
        own = [_decompiled("ev_0001", "0x140002a00"), _decompiled("ev_0002", "0x140002a80")]

        lines = function_map_block(build_function_map(own, None, [], (BASE,))).splitlines()

        assert lines[2:] == ["also visited: 0x140002a00, 0x140002a80"]


class TestNothingIsGuessed:
    def test_with_no_base_a_claim_about_one_function_is_not_another_s_summary(self) -> None:
        own = [_decompiled("ev_0001", "0x401230"), _decompiled("ev_0002", "0x411230")]
        claim = _claim("0x411230 decrypts the configuration it reads.")

        found = build_function_map(own, None, [claim], ())

        assert [(e.address, e.summary) for e in found.visited] == [
            (0x401230, ""),
            (0x411230, "0x411230 decrypts the configuration it reads."),
        ]

    def test_with_no_base_a_claim_naming_the_decompiler_s_name_is_its_summary(self) -> None:
        own = [_decompiled("ev_0001", "0x411230")]

        found = build_function_map(own, None, [_claim("FUN_00411230 reads a value.")], ())

        assert found.visited[0].summary == "FUN_00411230 reads a value."

    def test_with_a_base_an_offset_in_a_claim_names_its_function(self) -> None:
        own = [_decompiled("ev_0001", "0x1400050ac")]

        found = build_function_map(own, None, [_claim("0x50ac opens the thing.")], (BASE,))

        assert found.visited[0].summary == "0x50ac opens the thing."

    def test_two_virtual_addresses_one_base_apart_are_two_functions(self) -> None:
        own = [_decompiled("ev_0001", "0x401000"), _decompiled("ev_0002", "0x801000")]

        found = build_function_map(own, None, [], (0x400000,))

        assert [e.address for e in found.visited] == [0x401000, 0x801000]

    def test_an_offset_and_its_virtual_address_are_still_one(self) -> None:
        own = [_decompiled("ev_0001", "0x1000"), _decompiled("ev_0002", "0x401000")]

        found = build_function_map(own, None, [], (0x400000,))

        assert [e.address for e in found.visited] == [0x401000]

    def test_a_claim_about_one_of_two_virtual_addresses_a_base_apart_is_its_summary_alone(
        self,
    ) -> None:
        own = [_decompiled("ev_0001", "0x401000"), _decompiled("ev_0002", "0x801000")]
        claim = _claim("0x801000 decrypts the configuration it reads.")

        found = build_function_map(own, None, [claim], (0x400000,))

        assert [(e.address, e.summary) for e in found.visited] == [
            (0x401000, ""),
            (0x801000, "0x801000 decrypts the configuration it reads."),
        ]

    def test_with_a_base_an_offset_in_a_claim_still_names_its_virtual_address(self) -> None:
        own = [_decompiled("ev_0001", "0x401000"), _decompiled("ev_0002", "0x801000")]

        found = build_function_map(own, None, [_claim("0x1000 opens the thing.")], (0x400000,))

        assert [(e.address, e.summary) for e in found.visited] == [
            (0x401000, "0x1000 opens the thing."),
            (0x801000, ""),
        ]

    def test_with_no_base_the_function_s_own_digits_without_0x_name_it(self) -> None:
        own = [_decompiled("ev_0001", "0x401230"), _decompiled("ev_0002", "0x411230")]

        found = build_function_map(own, None, [_claim("401230 reads a value.")], ())

        assert [(e.address, e.summary) for e in found.visited] == [
            (0x401230, "401230 reads a value."),
            (0x411230, ""),
        ]


class TestANameThatIsAWord:
    @staticmethod
    def _entry_map(*claims: str) -> str:
        own = [_decompiled("ev_0001", "0x140002a00", "void entry(void)\n{\n}\n")]
        return (
            build_function_map(own, None, [_claim(c) for c in claims], (BASE,)).visited[0].summary
        )

    def test_the_word_in_a_sentence_names_no_function(self) -> None:
        assert self._entry_map("A Run key entry starts the loader at logon.") == ""

    def test_the_word_beside_a_function_cue_names_it(self) -> None:
        for said in (
            "The entry function writes the Run key.",
            "The exported function entry writes the Run key.",
            "`entry` writes the Run key.",
            "entry() writes the Run key.",
            "The routine 'entry' writes the Run key.",
        ):
            assert self._entry_map(said) == said, said

    def test_the_first_claim_that_names_it_as_a_function_is_taken(self) -> None:
        assert (
            self._entry_map(
                "A Run key entry starts the loader at logon.",
                "The entry export writes the Run key.",
            )
            == "The entry export writes the Run key."
        )

    def test_a_dotted_decompiler_name_s_last_word_takes_the_same_rule(self) -> None:
        for name, said, cued in (
            ("sym.entry", "Persistence via a Run key entry.", "The sym.entry routine runs first."),
            ("fcn.main", "The main payload is decrypted.", "The main function decrypts it."),
            ("sub.start", "At start the loader sleeps.", "`start` sleeps first."),
        ):
            own = [_decompiled("ev_0001", "0x140002a00", f"void {name}(void)\n{{\n}}\n")]
            for claim, summary in ((said, ""), (cued, cued)):
                found = build_function_map(own, None, [_claim(claim)], (BASE,))
                entry = found.visited[0]
                assert name in entry.names, (name, entry.names)
                assert entry.summary == summary, (name, claim)

    def test_a_dotted_name_with_a_distinctive_last_label_names_it_alone(self) -> None:
        own = [_decompiled("ev_0001", "0x140002a00", "void sym.DecryptConfig(void)\n{\n}\n")]
        claim = _claim("DecryptConfig decrypts the configuration.")

        found = build_function_map(own, None, [claim], (BASE,))

        assert found.visited[0].summary == "DecryptConfig decrypts the configuration."

    def test_a_name_that_is_no_word_still_names_it_alone(self) -> None:
        own = [_decompiled("ev_0001", "0x140002a00", "void DecryptConfig(void)\n{\n}\n")]
        claim = _claim("DecryptConfig decrypts the configuration.")

        found = build_function_map(own, None, [claim], (BASE,))

        assert found.visited[0].summary == "DecryptConfig decrypts the configuration."


class TestTheFoldAndTheFacts:
    def test_the_fold_keeps_a_name_that_is_not_a_decompiler_s_generic_one(self) -> None:
        own = [
            _decompiled("ev_0001", "0x140002a00", "void entry(void)\n{\n}\n"),
            _decompiled("ev_0002", "0x140002a40"),
        ]

        lines = function_map_block(build_function_map(own, None, [], (BASE,))).splitlines()

        assert lines[2:] == ['also visited: 0x140002a00 ("entry"), 0x140002a40']

    def test_one_text_passed_to_two_calls_is_two_call_site_facts(self) -> None:
        def _place(call_at: str) -> dict[str, Any]:
            return {
                "function": "0x11a0",
                "passed_to": {"call_at": call_at, "callee": {"function": "0x66e0"}, "argument": 1},
            }

        output = {
            "image_base": hex(BASE),
            "results": [{"text": "one", "references": [_place("0x1221"), _place("0x12a1")]}],
        }
        blobs = _entry("ev_0021", "decode_string_blobs", {}, json.dumps(output))
        again = _entry("ev_0032", "decode_string_blobs", {}, json.dumps(output))

        block = function_map_block(
            build_function_map(
                [_decompiled("ev_0031", "0x1400011a0")],
                function_artefacts([blobs, again]),
                [],
                (BASE,),
            )
        )

        assert (
            "reaches 1 decoded text (ev_0021, ev_0032), 2 call-site facts (ev_0021, ev_0032)"
            in (block)
        )
