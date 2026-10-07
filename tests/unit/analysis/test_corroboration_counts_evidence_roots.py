"""Corroboration counts evidence roots beside layers, and states a single root.

A root is a place in the sample a ledger entry's fact was read from. Two
layers that cite one place are one root; the layer count and the publish
rules stay as they were.
"""

from __future__ import annotations

import time
from typing import Any

from maljan.analysis.corroboration import corroboration_row
from maljan.analysis.evidence_roots import (
    BLOB_UNMATCHED,
    EXPORT_TABLE,
    FILE_UNTOLD,
    IMPORT_TABLE,
    NAMES_NO_ROW,
    NO_CITATION,
    OFFSET_UNPLACED,
    SHARED_COMMAND,
    WHOLE_FILE,
    RootCount,
    layers_and_roots,
    roots_phrase,
    run_roots,
)
from maljan.extractors.capability_matrix import build_capability_matrix, judge_questions
from maljan.reporting.models import TTPMapping
from maljan.reporting.renderers.markdown import _corroborated_words
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, Finding

BASE = 0x180000000
SECTIONS = [
    {
        "name": ".text",
        "virtual_address": "0x00001000",
        "virtual_size": 0x4000,
        "raw_offset": 0x400,
        "raw_size": 0x4000,
    },
    {
        "name": ".data",
        "virtual_address": "0x00005000",
        "virtual_size": 0x1000,
        "raw_offset": 0x4400,
        "raw_size": 0x1000,
    },
]


def _entry(eid: str, tool: str, structured: Any = None, **kwargs: Any) -> LedgerEntry:
    return LedgerEntry(id=eid, tool=tool, structured=structured, **kwargs)


def _ledger() -> list[LedgerEntry]:
    return [
        _entry("ev_0001", "hashes", {"sha256": "a" * 64}),
        _entry(
            "ev_0002",
            "pe_info",
            {
                "sections": SECTIONS,
                "imports": [{"dll": "KERNEL32.dll", "function": "VirtualAlloc"}],
                "exports": ["run"],
            },
        ),
        _entry(
            "ev_0003",
            "decode_string_blobs",
            {
                "image_base": hex(BASE),
                "results": [
                    {
                        "rva": "0x5010",
                        "text": "cmd.exe /c whoami",
                        "floss": {"called_at_rva": "0x1200"},
                    },
                    {"rva": "0x5080", "text": "second", "floss": {}},
                ],
            },
        ),
        _entry(
            "ev_0004",
            "floss",
            {"strings": [{"string": "cmd.exe /c whoami", "called_at_rva": "0x1200"}]},
        ),
        _entry("ev_0005", "decompile_function", args={"address": hex(BASE + 0x1100)}),
        _entry("ev_0006", "get_ip_report", {"data": {}}),
        _entry("ev_0007", "decompile_function", ok=False, args={"address": "0x1100"}),
        _entry("ev_0008", "decompile_function", args={"name": "main"}),
        _entry(
            "ev_0009",
            "sandbox_processes",
            {"processes": [{"pid": 84, "command_line": "rundll32.exe x.dll,#1"}]},
        ),
        _entry(
            "ev_0010",
            "sigma_match_sandbox",
            {
                "matches": [
                    {
                        "tags": ["attack.t1218.011"],
                        "matched_fields": {"CommandLine": "rundll32.exe x.dll,#1"},
                    }
                ]
            },
        ),
        _entry("ev_0011", "sandbox_network", {"tcp": [{"dst": "192.0.2.7", "dport": 443}]}),
        _entry(
            "ev_0012",
            "pcap_summary",
            {"conversations": [{"dst": "192.0.2.7", "dport": 443, "proto": "tcp"}]},
        ),
        _entry(
            "ev_0013", "strings", {"strings": [{"offset": 0x4410, "text": "cmd.exe /c whoami"}]}
        ),
        _entry("ev_0014", "decompile_function", repeated_of="ev_0005"),
        _entry(
            "ev_0015",
            "capa",
            {"capabilities": [{"rule": "hash names", "attck": ["T1027"], "addresses": ["0x1300"]}]},
        ),
    ]


class TestEachEntryStatesItsRoots:
    def test_places_are_offsets_from_the_image_base_with_their_section(self) -> None:
        roots = run_roots(_ledger())
        assert roots.of_entry("ev_0005").roots == ["0x1100 in .text"]
        assert roots.of_entry("ev_0015").roots == ["0x1300 in .text"]
        # A file offset is placed through the section table.
        assert roots.of_entry("ev_0013").roots == ["0x5010 in .data"]

    def test_floss_and_the_blob_decoder_reading_one_blob_are_one_root(self) -> None:
        roots = run_roots(_ledger())
        assert roots.of_entry("ev_0004").roots == ["0x5010 in .data"]
        assert "0x5010 in .data" in roots.of_entry("ev_0003").roots

    def test_tables_processes_flows_and_the_whole_file(self) -> None:
        roots = run_roots(_ledger())
        assert roots.of_entry("ev_0001").roots == [WHOLE_FILE]
        assert IMPORT_TABLE in roots.of_entry("ev_0002").roots
        assert EXPORT_TABLE in roots.of_entry("ev_0002").roots
        assert roots.of_entry("ev_0010").roots == ["sandbox process 84"]
        flow = "network flow tcp to 192.0.2.7:443"
        assert roots.of_entry("ev_0011").roots == [flow]
        assert roots.of_entry("ev_0012").roots == [flow]

    def test_an_entry_with_no_readable_root_says_why(self) -> None:
        roots = run_roots(_ledger())
        assert roots.of_entry("ev_0006").reason.startswith("no: get_ip_report is a reference")
        assert roots.of_entry("ev_0007").reason.startswith("no: the call failed")
        assert roots.of_entry("ev_0008").reason.startswith(
            "no: the call names its function by name"
        )
        assert roots.of_entry("ev_0999").reason.startswith("no: ev_0999 is not an entry")
        for eid in ("ev_0006", "ev_0007", "ev_0008"):
            assert roots.of_entry(eid).roots == []

    def test_a_repeat_has_the_roots_of_the_entry_holding_its_answer(self) -> None:
        assert run_roots(_ledger()).of_entry("ev_0014").roots == ["0x1100 in .text"]


class TestAStatementsRoots:
    def test_an_entry_with_several_places_gives_the_ones_the_statement_names(self) -> None:
        roots = run_roots(_ledger())
        named, unread = roots.of_statement("the blob at 0x5080 decodes", ["ev_0003"])
        assert (named, unread) == (["0x5080 in .data"], [])
        quoted, _ = roots.of_statement('it decodes "cmd.exe /c whoami"', ["ev_0003"])
        assert quoted == ["0x5010 in .data"]
        imports, _ = roots.of_statement("it imports VirtualAlloc", ["ev_0002"])
        assert imports == [IMPORT_TABLE]

    def test_naming_none_of_them_gives_no_root_and_says_so(self) -> None:
        roots = run_roots(_ledger())
        named, unread = roots.of_statement("it decodes strings", ["ev_0003"])
        assert named == []
        assert unread == ["ev_0003: " + NAMES_NO_ROW.format(entry="ev_0003")]
        # Citations naming no row add no root; a named row is its own.
        counted = RootCount()
        counted.add(*roots.of_statement("strings are decoded", ["ev_0003"]))
        counted.add(*roots.of_statement("so says the decoder", ["EV_0003"]))
        counted.add(*roots.of_statement("the blob at 0x5080", ["ev_0003"]))
        assert counted.roots == ["0x5080 in .data"]
        assert len(counted.not_read) == 1

    def test_a_passing_mention_of_a_table_narrows_nothing(self) -> None:
        roots = run_roots(_ledger())
        for said in (
            "the imports and the export table look ordinary",
            "the header says it is a DLL",
            "a resource or an overlay is absent",
        ):
            assert roots.of_statement(said, ["ev_0002"]) == (
                [],
                ["ev_0002: " + NAMES_NO_ROW.format(entry="ev_0002")],
            )
        assert roots.of_statement("exports `run`", ["ev_0002"])[0] == [EXPORT_TABLE]

    def test_a_name_several_rows_hold_narrows_nothing(self) -> None:
        rows = [
            {"offset": hex(0x1000 + 0x40 * k), "imports": [{"name": "CreateFileW"}]}
            for k in range(50)
        ]
        led = [
            _entry("ev_0001", "pe_info", {"sections": SECTIONS}),
            _entry("ev_0002", "function_index", {"rows": rows}),
        ]
        roots = run_roots(led)
        named, unread = roots.of_statement("calls CreateFileW to drop a file", ["ev_0002"])
        assert named == [] and unread == ["ev_0002: " + NAMES_NO_ROW.format(entry="ev_0002")]
        assert roots.of_statement("at 0x1c40 it calls CreateFileW", ["ev_0002"])[0] == [
            "0x1c40 in .text"
        ]
        # 0x1040 is one row's address and, read as a file offset, another's: neither.
        assert roots.of_statement("at 0x1040 it calls CreateFileW", ["ev_0002"])[0] == []

    def test_an_unquoted_mention_beside_a_quoted_one_counts_only_the_quoted(self) -> None:
        led = [
            _entry("ev_0001", "pe_info", {"sections": SECTIONS}),
            _entry(
                "ev_0002",
                "strings",
                {
                    "strings": [
                        {"offset": 0x4500, "text": "http://c2.example/gate"},
                        {"offset": 0x4600, "text": "other"},
                    ]
                },
            ),
            _entry(
                "ev_0003",
                "floss",
                {"strings": [{"string": "http://c2.example/gate", "called_at_rva": "0x5100"}]},
            ),
        ]
        roots = run_roots(led)
        counted = RootCount()
        counted.add(*roots.of_statement("The sample holds a C2 URL [ev_0002]", ["ev_0002"]))
        counted.add(*roots.of_statement('FLOSS shows "http://c2.example/gate"', ["ev_0003"]))
        assert counted.roots == ["0x5100 in .data"]

    def test_a_statement_citing_nothing_says_so(self) -> None:
        assert run_roots(_ledger()).of_statement("no citation", []) == ([], [NO_CITATION])


class TestTwoJobsNeverShareRoots:
    """Entry ids repeat across jobs: each job's roots come from its own ledger."""

    @staticmethod
    def _job(address: int) -> list[LedgerEntry]:
        return [
            _entry("ev_0001", "pe_info", {"sections": SECTIONS}),
            _entry("ev_0002", "decompile_function", args={"address": hex(address)}),
        ]

    def test_either_order_in_one_process(self) -> None:
        first, second = self._job(0x1100), self._job(0x5020)
        for order in ((first, second), (second, first)):
            for job in order:
                expected = "0x1100 in .text" if job is first else "0x5020 in .data"
                assert run_roots(job).of_entry("ev_0002").roots == [expected]


class TestLinear:
    def test_rows_scale_linearly(self) -> None:
        def ledger(n: int) -> list[LedgerEntry]:
            rows = [{"offset": 0x400 + i, "text": f"s{i}"} for i in range(n)]
            return [
                _entry("ev_0001", "pe_info", {"sections": SECTIONS}),
                _entry("ev_0002", "strings", {"strings": rows}),
            ]

        timings = []
        for n in (2_000, 16_000):
            led = ledger(n)
            start = time.perf_counter()
            run_roots(led).of_statement('the string "s5"', ["ev_0002"])
            timings.append(time.perf_counter() - start)
        assert timings[1] < timings[0] * 8 * 4 + 0.5


def _claim(text: str, ref: str, tid: str = "T1059.003") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref, confidence=0.8, technique_id=tid)


def _isrs() -> dict[str, AgentISR]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[_claim("It runs whoami through cmd.exe, the blob at 0x5010.", "[ev_0003]")],
        ),
        "reverser": AgentISR(
            agent_id="reverser",
            domain="reverser",
            claims=[_claim('FLOSS decodes "cmd.exe /c whoami" for a shell command.', "[ev_0004]")],
        ),
    }


class TestTheMatrixStatesRootsBesideLayers:
    def test_two_layers_reading_one_place_are_one_root(self) -> None:
        cells, mappings = build_capability_matrix(
            stix_output=None, isr_reports=_isrs(), ledger=_ledger()
        )
        (mapping,) = mappings
        assert mapping.independent_layers == ["static", "reverser"]
        assert mapping.is_corroborated is True
        assert mapping.evidence_roots == ["0x5010 in .data"]
        assert cells[0].evidence_roots == ["0x5010 in .data"]

    def test_publication_and_layers_do_not_read_the_roots(self) -> None:
        with_roots = build_capability_matrix(
            stix_output=None, isr_reports=_isrs(), ledger=_ledger()
        )
        without = build_capability_matrix(stix_output=None, isr_reports=_isrs())
        strip = {"evidence_roots", "roots_not_read"}
        assert [m.model_dump(exclude=strip) for m in with_roots[1]] == [
            m.model_dump(exclude=strip) for m in without[1]
        ]
        assert without[1][0].evidence_roots == []

    def test_a_finding_cites_its_evidence_ids(self) -> None:
        isrs = {
            "network": AgentISR(
                agent_id="network",
                domain="network",
                findings=[
                    Finding(
                        title="C2",
                        detail="beacons over TLS",
                        technique_ids=["T1071.001"],
                        evidence_ids=["ev_0012"],
                    )
                ],
            )
        }
        cells, _ = build_capability_matrix(stix_output=None, isr_reports=isrs, ledger=_ledger())
        assert cells[0].evidence_roots == ["network flow tcp to 192.0.2.7:443"]


class TestTheCorroborationRecord:
    def test_rows_carry_roots_from_claims_and_asserting_rows(self) -> None:
        from maljan.pipeline.validation import corroboration

        record = corroboration(_isrs(), _ledger())
        assert record["T1059.003"]["evidence_roots"] == ["0x5010 in .data"]
        assert record["T1218.011"]["evidence_roots"] == ["sandbox process 84"]
        assert record["T1027"]["evidence_roots"] == ["0x1300 in .text"]

    def test_the_stored_shape_keeps_them(self) -> None:
        row = corroboration_row(
            {"claimed_by": ["a"], "evidence_roots": ["x"], "roots_not_read": ["y"]}
        )
        assert row["evidence_roots"] == ["x"] and row["roots_not_read"] == ["y"]
        assert "evidence_roots" not in corroboration_row({"claimed_by": ["a"]})


class TestTheWords:
    def test_one_root_says_so_and_several_are_counted(self) -> None:
        assert roots_phrase(["0x1a40 in .text"], []) == "one evidence root (0x1a40 in .text)"
        assert roots_phrase(["a", "b"], ["ev_1: no: x"]) == (
            "2 evidence roots, and 1 citation whose root could not be read"
        )
        assert layers_and_roots(2, ["0x1a40 in .text"], []) == (
            "2 layers, one evidence root (0x1a40 in .text)"
        )
        assert roots_phrase([], []) == ""

    def test_the_report_row_carries_them_inside_its_corroboration_words(self) -> None:
        mapping = TTPMapping(
            technique_id="T1059.003",
            technique_name="Windows Command Shell",
            contributing_layers=["static", "reverser"],
            is_corroborated=True,
            independent_layers=["static", "reverser"],
            evidence_roots=["0x5010 in .data"],
        )
        assert _corroborated_words(mapping, []) == (
            ", corroborated (named by 2 analyst layers, each in a statement of its own; "
            "one evidence root (0x5010 in .data))"
        )

    def test_a_single_layer_row_states_its_root(self) -> None:
        mapping = TTPMapping(
            technique_id="T1082",
            technique_name="System Information Discovery",
            contributing_layers=["static"],
            independent_layers=["static"],
            evidence_roots=["the whole file"],
        )
        assert _corroborated_words(mapping, []) == ", 1 layer, one evidence root (the whole file)"

    def test_a_row_stored_before_roots_says_nothing_new(self) -> None:
        mapping = TTPMapping(
            technique_id="T1082",
            technique_name="System Information Discovery",
            contributing_layers=["static"],
            independent_layers=["static"],
        )
        assert _corroborated_words(mapping, []) == ""


class TestTheJudgeQuestion:
    def test_each_question_states_layers_and_roots_where_its_mentions_are(self) -> None:
        from maljan.agents.judge_agent import QUESTION_ROOTS_LABEL, technique_question_text

        questions, _ = judge_questions({"objects": []}, _isrs(), ledger=_ledger())
        (question,) = questions
        assert question.roots == "2 layers, one evidence root (0x5010 in .data)"
        text = technique_question_text(questions, {}, cards=False)
        assert f"   {QUESTION_ROOTS_LABEL} 2 layers, one evidence root (0x5010 in .data)" in text

    def test_the_line_is_the_report_row_s_fact(self) -> None:
        # Two analysts writing one statement are one independent layer, and an
        # evidence line's quoted value narrows as it does for the matrix.
        same = "It runs whoami through a shell."
        isrs = {
            "static": AgentISR(
                agent_id="static",
                domain="static",
                claims=[_claim(same, '[ev_0003] "cmd.exe /c whoami"')],
            ),
            "reverser": AgentISR(
                agent_id="reverser", domain="reverser", claims=[_claim(same, "[ev_0003]")]
            ),
        }
        questions, _ = judge_questions({"objects": []}, isrs, ledger=_ledger())
        (question,) = questions
        _, mappings = build_capability_matrix(stix_output=None, isr_reports=isrs, ledger=_ledger())
        (mapping,) = mappings
        assert question.roots == layers_and_roots(
            len(mapping.independent_layers), mapping.evidence_roots, mapping.roots_not_read
        )
        assert question.roots.startswith("1 layer, one evidence root (0x5010 in .data)")

    def test_without_the_ledger_no_line_is_added(self) -> None:
        questions, _ = judge_questions({"objects": []}, _isrs())
        assert questions[0].roots == ""


class TestAFunctionHoldsTheAddressesInsideIt:
    """A place inside a function whose range a reader states is that function."""

    RANGES = {"0x1100": [["0x1100", "0x1400"]], "0x2000": [["0x2000", "0x2200"]]}

    @classmethod
    def _ledger(cls, *extra: LedgerEntry, rows: Any = ()) -> list[LedgerEntry]:
        index = {"image_base": hex(BASE), "rows": list(rows)}
        return [
            _entry("ev_0001", "pe_info", {"sections": SECTIONS}),
            _entry("ev_0002", "function_index", index, function_ranges=cls.RANGES),
            *extra,
        ]

    def test_a_capa_match_inside_f_and_a_decompile_of_f_are_one_root(self) -> None:
        led = self._ledger(
            _entry(
                "ev_0003",
                "capa",
                {"capabilities": [{"rule": "r", "attck": ["T1027"], "addresses": ["0x1300"]}]},
            ),
            _entry("ev_0004", "decompile_function", args={"address": hex(BASE + 0x1100)}),
        )
        roots = run_roots(led)
        counted = RootCount()
        counted.add(*roots.of_statement("the routine at 0x1300", ["ev_0003"]))
        counted.add(*roots.of_statement("decompiled", ["ev_0004"]))
        assert counted.roots == ["function 0x1100 in .text"]

    def test_two_matches_in_two_functions_are_two_roots(self) -> None:
        led = self._ledger(
            _entry(
                "ev_0003",
                "capa",
                {
                    "capabilities": [
                        {"rule": "r", "attck": ["T1027"], "addresses": ["0x1300", "0x2100"]}
                    ]
                },
            ),
        )
        assert run_roots(led).of_entry("ev_0003").roots == [
            "function 0x1100 in .text",
            "function 0x2000 in .text",
        ]

    def test_two_addresses_with_no_stated_range_stay_two(self) -> None:
        led = [
            _entry("ev_0001", "pe_info", {"sections": SECTIONS}),
            _entry(
                "ev_0002",
                "capa",
                {"capabilities": [{"rule": "r", "addresses": ["0x1300", "0x1310"]}]},
            ),
        ]
        assert run_roots(led).of_entry("ev_0002").roots == ["0x1300 in .text", "0x1310 in .text"]

    def test_a_disassembler_s_size_and_a_hash_s_size_are_no_ranges(self) -> None:
        listing = "; CALL XREF\n357: fcn.180001100 (int64_t arg1);\n"
        led = [
            _entry("ev_0001", "pe_info", {"sections": SECTIONS}),
            _entry("ev_0002", "hashes", {"image_base": hex(BASE)}),
            _entry(
                "ev_0003",
                "disassemble_function",
                args={"address": hex(BASE + 0x1100)},
                output=listing,
            ),
            _entry(
                "ev_0005",
                "get_function_hash",
                {"address": hex(BASE + 0x1100), "size_bytes": 0x300},
            ),
            _entry("ev_0004", "read_memory", args={"address": hex(BASE + 0x1200)}),
        ]
        assert run_roots(led).of_entry("ev_0004").roots == ["0x1200 in .text"]

    def test_ranges_in_the_answer_itself_are_not_read(self) -> None:
        index = {"image_base": hex(BASE), "rows": [], "function_ranges": self.RANGES}
        led = [
            _entry("ev_0001", "pe_info", {"sections": SECTIONS}),
            _entry("ev_0002", "function_index", index),
            _entry("ev_0003", "read_memory", args={"address": hex(BASE + 0x1200)}),
        ]
        assert run_roots(led).of_entry("ev_0003").roots == ["0x1200 in .text"]

    def test_a_range_holding_another_known_function_start_is_not_used(self) -> None:
        capa = _entry(
            "ev_0003",
            "capa",
            {"capabilities": [{"rule": "r", "addresses": ["0x1150", "0x1300"]}]},
        )
        # A row of the index starts a function at 0x1200, inside 0x1100's range.
        led = self._ledger(capa, rows=[{"offset": "0x1200"}])
        assert run_roots(led).of_entry("ev_0003").roots == ["0x1150 in .text", "0x1300 in .text"]
        # So does a call target the index lists, written as a virtual address.
        index = {
            "image_base": hex(BASE),
            "rows": [],
            "other_callees": {hex(BASE + 0x2000): [hex(BASE + 0x1200)]},
        }
        led = [
            _entry("ev_0001", "pe_info", {"sections": SECTIONS}),
            _entry("ev_0002", "function_index", index, function_ranges=self.RANGES),
            capa,
        ]
        assert run_roots(led).of_entry("ev_0003").roots == ["0x1150 in .text", "0x1300 in .text"]
        # An unrelated start elsewhere changes nothing.
        led = self._ledger(capa, rows=[{"offset": "0x3000"}])
        assert run_roots(led).of_entry("ev_0003").roots == ["function 0x1100 in .text"]


class TestAnAssertionWithNoPlace:
    def test_a_capa_rule_with_no_address_gives_no_root_and_says_why(self) -> None:
        led = [
            _entry("ev_0001", "pe_info", {"sections": SECTIONS}),
            _entry(
                "ev_0002",
                "capa",
                {
                    "capabilities": [
                        {"rule": "a", "attck": ["T1027"], "addresses": []},
                        {"rule": "b", "attck": ["T1055"], "addresses": ["0x1300", "0x1400"]},
                    ]
                },
            ),
        ]
        roots = run_roots(led)
        assert roots.of_assertion("ev_0002", "T1027") == (
            [],
            [
                "ev_0002: no: capa's answer carries no offset, address, section, event or flow to "
                "place"
            ],
        )
        assert roots.of_assertion("ev_0002", "T1055")[0] == ["0x1300 in .text", "0x1400 in .text"]


class TestAStatedRangeIsCheckedAgainstTheImage:
    """A range is read from output a sample can shape, so it is held to the image."""

    @staticmethod
    def _with(*ranges: tuple[int, int, int]) -> Any:
        from maljan.analysis.evidence_roots import Layout, _Section

        sections = tuple(
            _Section(
                name=row["name"],
                rva=int(row["virtual_address"], 16),
                size=row["virtual_size"],
                raw=row["raw_offset"],
                raw_size=row["raw_size"],
            )
            for row in SECTIONS
        )
        return Layout(sections=sections, bases=(BASE,), functions=tuple(ranges))

    def test_a_huge_stated_size_is_not_used(self) -> None:
        layout = self._with((0x1100, 0x1100 + 2**40, 0x1100))
        assert layout.function_at(0x1200) is None
        assert layout.label(0x1200) == "0x1200 in .text"

    def test_a_range_crossing_a_section_boundary_is_not_used(self) -> None:
        layout = self._with((0x4F00, 0x5100, 0x4F00))
        assert layout.function_at(0x4F80) is None

    def test_a_range_holding_another_range_s_function_start_is_not_used(self) -> None:
        layout = self._with((0x1100, 0x1400, 0x1100), (0x1300, 0x1600, 0x1300))
        assert layout.function_at(0x1200) is None
        assert layout.function_at(0x1350) == 0x1300
        assert layout.function_at(0x1500) == 0x1300
        assert layout.function_at(0x1700) is None

    def test_overlapping_ranges_of_two_functions_own_the_overlap_jointly_with_neither(
        self,
    ) -> None:
        # A chained fragment of 0x2000 overlapping 0x1100's range; neither holds
        # the other's start.
        layout = self._with((0x1100, 0x1400, 0x1100), (0x1300, 0x1500, 0x2000))
        assert layout.function_at(0x1200) == 0x1100
        assert layout.function_at(0x1350) is None
        assert layout.function_at(0x1450) == 0x2000

    def test_lookups_do_not_depend_on_how_many_or_how_long_the_ranges_are(self) -> None:
        def timed(n: int) -> float:
            # Nested and overlapping: every range holds the place looked up.
            ranges = [(0x1000 + i % 0x100, 0x5000 - i % 0x100, 0x1000 + i) for i in range(n)]
            start = time.perf_counter()
            layout = self._with(*ranges)
            for rva in range(0x1000, 0x5000, 0x10):
                layout.function_at(rva)
            return time.perf_counter() - start

        small, large = timed(10_000), timed(100_000)
        assert large < small * 10 * 3 + 0.5


class TestHostileScaling:
    """Every per-statement path is dict and set lookups built once per entry."""

    def test_one_entry_of_many_rows_and_many_statements_writing_many_values(self) -> None:
        def timed(rows: int, statements: int) -> float:
            led = [
                _entry("ev_0001", "pe_info", {"sections": SECTIONS}),
                _entry(
                    "ev_0002",
                    "strings",
                    {
                        "strings": [
                            {"offset": 0x400 + i % 0x4000, "text": f"s{i}"} for i in range(rows)
                        ]
                    },
                ),
            ]
            said = " ".join(f'"s{k}" 0x{0x1000 + k:x} Name{k}' for k in range(100))
            start = time.perf_counter()
            roots = run_roots(led)
            counted = RootCount()
            for _ in range(statements):
                counted.add(*roots.of_statement(said, ["ev_0002"]))
            return time.perf_counter() - start

        small, large = timed(10_000, 100), timed(100_000, 1_000)
        assert large < small * 10 * 3 + 0.5

    def test_a_ledger_of_many_entries(self) -> None:
        def timed(n: int) -> float:
            led = [_entry("ev_0001", "pe_info", {"sections": SECTIONS})] + [
                _entry(
                    f"ev_{i + 2:05d}",
                    "decompile_function",
                    args={"address": hex(BASE + 0x1000 + i % 0x3000)},
                )
                for i in range(n)
            ]
            start = time.perf_counter()
            roots = run_roots(led)
            for i in range(0, n, 7):
                roots.of_statement("the function", [f"ev_{i + 2:05d}"])
            return time.perf_counter() - start

        small, large = timed(1_000), timed(10_000)
        assert large < small * 10 * 3 + 0.5


SAMPLE_PE = {
    "image_base": "0x400000",
    "sections": [
        {
            "name": ".text",
            "virtual_address": "0x1000",
            "virtual_size": 0x8000,
            "raw_offset": 0x400,
            "raw_size": 0x8000,
        },
        {
            "name": ".rdata",
            "virtual_address": "0x9000",
            "virtual_size": 0x2000,
            "raw_offset": 0x8400,
            "raw_size": 0x2000,
        },
    ],
}


class TestEachFileHasItsOwnLayout:
    def _carved_pe(self, **args: Any) -> LedgerEntry:
        sections = [
            {
                "name": "UPX0",
                "virtual_address": "0xa000",
                "virtual_size": 0x4000,
                "raw_offset": 0x400,
                "raw_size": 0x4000,
            }
        ]
        return _entry(
            "ev_0002", "pe_info", {"image_base": "0x10000000", "sections": sections}, args=args
        )

    def test_a_carved_file_is_placed_against_its_own_table_and_named(self) -> None:
        led = [
            _entry("ev_0001", "pe_info", SAMPLE_PE, args={"path": "s.exe"}),
            self._carved_pe(carved_path="payload.bin"),
            _entry(
                "ev_0003",
                "strings",
                {"strings": [{"offset": 0x500, "text": "payload-only"}]},
                args={"carved_path": "payload.bin"},
            ),
            _entry(
                "ev_0004",
                "strings",
                {"strings": [{"offset": 0x500, "text": "main-only"}]},
                args={"path": "s.exe"},
            ),
        ]
        roots = run_roots(led)
        assert [s.name for s in roots.layout.sections] == [".text", ".rdata"]
        assert roots.layout.bases == (0x400000,)
        assert roots.of_entry("ev_0003").roots == ['0xa100 in UPX0 of file "payload.bin"']
        assert roots.of_entry("ev_0004").roots == ["0x1100 in .text"]

    def test_a_carved_file_the_carving_states_is_named_by_its_digest(self) -> None:
        digest = "ab" * 32
        carve = _entry(
            "ev_0005",
            "carve_payloads",
            {"payloads": [{"carved_path": "/staged/payload.bin", "sha256": digest}]},
        )
        led = [carve, _entry("ev_0006", "hashes", {}, args={"carved_path": "/staged/payload.bin"})]
        assert run_roots(led).of_entry("ev_0006").roots == [
            f"the whole of file sha256 {digest[:12]}"
        ]

    def test_a_file_that_cannot_be_told_gives_no_root(self) -> None:
        led = [_entry("ev_0001", "strings", {"strings": []}, args={"carved_path": ["a", "b"]})]
        found = run_roots(led).of_entry("ev_0001")
        assert found.roots == [] and found.reason == FILE_UNTOLD


class TestFlossJoinsABlobByCallSiteAndText:
    def _led(self, floss_rows: list[dict[str, Any]]) -> list[LedgerEntry]:
        results = [
            {"rva": hex(0x9100 + 0x100 * k), "text": t, "floss": {"called_at_rva": "0x1200"}}
            for k, t in enumerate(("alpha.example", "bravo.example", "charlie.example"))
        ]
        return [
            _entry("ev_0001", "pe_info", SAMPLE_PE),
            _entry("ev_0010", "decode_string_blobs", {"results": results}),
            _entry("ev_0011", "floss", {"strings": floss_rows}),
        ]

    def test_each_row_joins_the_blob_holding_its_text(self) -> None:
        rows = [
            {"string": t, "called_at_rva": "0x1200"}
            for t in ("alpha.example", "bravo.example", "charlie.example")
        ]
        roots = run_roots(self._led(rows))
        assert roots.of_entry("ev_0011").roots == [
            "0x9100 in .rdata",
            "0x9200 in .rdata",
            "0x9300 in .rdata",
        ]
        both, _ = roots.of_statement('decodes "charlie.example"', ["ev_0011", "ev_0010"])
        assert both == ["0x9300 in .rdata"]
        assert roots.of_statement('"bravo.example"', ["ev_0011"])[0] == ["0x9200 in .rdata"]

    def test_a_call_site_whose_blobs_hold_no_matching_text_gives_no_root(self) -> None:
        rows = [{"string": "delta.example", "called_at_rva": "0x1200"}]
        found = run_roots(self._led(rows)).of_entry("ev_0011")
        assert found.roots == [] and found.reason == BLOB_UNMATCHED


class TestACommandLineBelongsToOneProcess:
    def test_two_processes_sharing_it_give_no_root(self) -> None:
        command = "cmd.exe /c ping 127.0.0.1"
        led = [
            _entry(
                "ev_0030",
                "sandbox_processes",
                {
                    "processes": [
                        {"pid": 100, "command_line": command},
                        {"pid": 200, "command_line": command},
                    ]
                },
            ),
            _entry(
                "ev_0031",
                "sigma_match_sandbox",
                {
                    "matches": [
                        {
                            "matched_fields": {"CommandLine": command},
                            "technique_ids": ["T1059.003"],
                        }
                    ]
                },
            ),
            _entry(
                "ev_0032",
                "lolbin_lookup",
                {"technique_ids": ["T1059.003"]},
                args={"command_lines": [command]},
            ),
        ]
        roots = run_roots(led)
        for eid in ("ev_0031", "ev_0032"):
            assert roots.of_entry(eid).roots == []
            assert roots.of_entry(eid).reason == SHARED_COMMAND
        assert roots.of_assertion("ev_0031", "T1059.003") == ([], [f"ev_0031: {SHARED_COMMAND}"])


class TestACaptureStatesOneFlowForBothDirections:
    def test_the_response_packet_is_the_request_s_flow(self) -> None:
        output = (
            "Packet 1: 10.0.0.5 -> 192.0.2.7 (TCP 49162->443)\n"
            "Packet 2: 192.0.2.7 -> 10.0.0.5 (TCP 443->49162)"
        )
        led = [
            _entry("ev_0050", "read_pcap_summary", output=output),
            _entry(
                "ev_0051",
                "sandbox_network",
                {"tcp": [{"src": "10.0.0.5", "sport": 49162, "dst": "c2.example", "dport": 443}]},
            ),
        ]
        roots = run_roots(led)
        assert roots.of_entry("ev_0050").roots == ["network flow tcp to 192.0.2.7:443"]
        # A host name the sandbox states no resolution for joins no capture address.
        assert roots.of_entry("ev_0051").roots == ["network flow tcp to c2.example:443"]

    def test_a_response_seen_first_elsewhere_keeps_the_label_of_its_connection(self) -> None:
        led = [
            _entry(
                "ev_0001",
                "pcap_summary",
                {"tcp": [{"src": "10.0.0.5", "sport": 49162, "dst": "192.0.2.7", "dport": 443}]},
            ),
            _entry(
                "ev_0002",
                "read_pcap_summary",
                output="Packet 9: 192.0.2.7 -> 10.0.0.5 (TCP 443->49162)",
            ),
        ]
        assert run_roots(led).of_entry("ev_0002").roots == ["network flow tcp to 192.0.2.7:443"]


class TestAFileOffsetWithNoSectionTable:
    def test_it_gives_no_root_where_the_file_states_a_base(self) -> None:
        led = [
            _entry("ev_0043", "function_index", {"image_base": "0x400000", "rows": []}),
            _entry("ev_0040", "strings", {"strings": [{"offset": 0x500, "text": "abc"}]}),
            _entry("ev_0041", "capa", {"capabilities": [{"rule": "r", "addresses": ["0x401100"]}]}),
            _entry("ev_0042", "decompile_function", args={"address": "0x1100"}),
        ]
        roots = run_roots(led)
        assert roots.of_entry("ev_0040").roots == []
        assert roots.of_entry("ev_0040").reason == OFFSET_UNPLACED
        assert roots.of_entry("ev_0041").roots == roots.of_entry("ev_0042").roots == ["0x1100"]

    def test_a_file_with_no_base_and_no_table_keeps_its_offsets(self) -> None:
        led = [_entry("ev_0040", "strings", {"strings": [{"offset": 0x500, "text": "abc"}]})]
        assert run_roots(led).of_entry("ev_0040").roots == ["file offset 0x500"]


class TestTheServedFunctionIndexGivesRoots:
    def test_each_row_line_is_a_root_named_by_address_or_by_a_name_it_alone_quotes(self) -> None:
        table = "\n".join(
            [
                "2 of the 9 functions the run knows hold artefacts of their own (...)",
                '- 0x401100: calls "CreateFileW", "WriteFile" (this answer); called by 1',
                '- 0x401200: calls "WriteFile" (this answer); called by 0',
            ]
        )
        led = [
            _entry("ev_0001", "pe_info", SAMPLE_PE),
            _entry("ev_0002", "function_index", {"image_base": "0x400000", "table": table}),
        ]
        roots = run_roots(led)
        assert roots.of_entry("ev_0002").roots == ["0x1100 in .text", "0x1200 in .text"]
        assert roots.of_statement('it calls "CreateFileW"', ["ev_0002"])[0] == ["0x1100 in .text"]
        assert roots.of_statement("it calls WriteFile", ["ev_0002"])[0] == []
        assert roots.of_statement("the function at 0x401200", ["ev_0002"])[0] == ["0x1200 in .text"]

    def test_an_answer_for_one_address_is_that_function(self) -> None:
        answer = {"image_base": "0x400000", "row": '- 0x401100: calls "CreateFileW" (this answer)'}
        led = [_entry("ev_0001", "pe_info", SAMPLE_PE), _entry("ev_0002", "function_index", answer)]
        assert run_roots(led).of_entry("ev_0002").roots == ["0x1100 in .text"]
        answer = {"image_base": "0x400000", "row": "no: 'zz' is not an address"}
        led = [_entry("ev_0001", "pe_info", SAMPLE_PE), _entry("ev_0002", "function_index", answer)]
        assert run_roots(led).of_entry("ev_0002").reason.startswith("no: ")


class TestManyImageBases:
    def test_reading_scales_linearly_in_the_bases(self) -> None:
        def timed(n: int) -> float:
            led = [
                _entry(
                    f"ev_{k:05d}",
                    "capa",
                    {
                        "image_base": hex(0x10000 * (k + 1)),
                        "capabilities": [
                            {"rule": "r", "addresses": [hex(0x10000 * (k + 1) + 0x1000 + k)]}
                        ],
                    },
                )
                for k in range(n)
            ]
            start = time.perf_counter()
            roots = run_roots(led)
            for k in range(0, n, 10):
                roots.of_statement(f"at {hex(0x10000 * (k + 1) + 0x1000 + k)}", [f"ev_{k:05d}"])
            return time.perf_counter() - start

        small, large = timed(2_000), timed(16_000)
        assert large < small * 8 * 4 + 0.5

    def test_an_address_reads_against_the_nearest_base_below_it(self) -> None:
        from maljan.analysis.evidence_roots import Layout

        layout = Layout(bases=(0x400000, 0x10000000))
        assert layout.rvas_of(0x10001000) == [0x1000, 0x10001000]
        assert layout.rvas_of(0x401000) == [0x1000, 0x401000]
        assert layout.rvas_of(0x1000) == [0x1000]


class TestAnEntryIsAboutTheSampleOnlyWhenItSaysSo:
    def _pe(self) -> LedgerEntry:
        return _entry("ev_0001", "pe_info", SAMPLE_PE, args={"path": "/stage/sample.exe"})

    def test_a_program_of_another_file_keeps_its_base_out_of_the_sample(self) -> None:
        led = [
            self._pe(),
            _entry("ev_0002", "decompile_function", args={"address": "0x401100"}),
            _entry(
                "ev_0003",
                "get_current_program_info",
                {"image_base": "0x10000000", "name": "payload.dll"},
            ),
            _entry("ev_0004", "decompile_function", args={"address": "0x10001100"}),
        ]
        roots = run_roots(led)
        assert roots.layout.bases == (0x400000,)
        assert roots.of_entry("ev_0002").roots == ["0x1100 in .text"]
        assert roots.of_entry("ev_0004").roots == ['0x1100 of file "payload.dll"']

    def test_an_address_outside_the_named_program_gives_no_root(self) -> None:
        from maljan.analysis.evidence_roots import OUTSIDE_PROGRAM

        led = [
            self._pe(),
            _entry(
                "ev_0002",
                "get_current_program_info",
                {"image_base": "0x10000000", "name": "payload.dll"},
            ),
            _entry("ev_0003", "decompile_function", args={"address": "0x10001100"}),
            _entry("ev_0004", "decompile_function", args={"address": "0x401100"}),
        ]
        roots = run_roots(led)
        assert roots.of_entry("ev_0003").roots == ['0x1100 of file "payload.dll"']
        assert roots.of_entry("ev_0004").roots == []
        assert roots.of_entry("ev_0004").reason == OUTSIDE_PROGRAM
        # A stated image size bounds the program from above too.
        sized = {"image_base": "0x10000000", "name": "payload.dll", "size_of_image": 0x2000}
        led[1] = _entry("ev_0002", "get_current_program_info", sized)
        led[3] = _entry("ev_0004", "decompile_function", args={"address": "0x10003000"})
        assert run_roots(led).of_entry("ev_0004").reason == OUTSIDE_PROGRAM

    def test_the_latest_program_is_read_in_the_order_the_calls_were_made(self) -> None:
        opened = _entry(
            "ev_0003",
            "get_current_program_info",
            {"image_base": "0x10000000", "name": "payload.dll"},
            seq=3,
        )
        call = _entry("ev_0002", "decompile_function", args={"address": "0x401100"}, seq=2)
        # Listed after the program statement, made before it.
        roots = run_roots([self._pe(), opened, call])
        assert roots.of_entry("ev_0002").roots == ["0x1100 in .text"]

    def test_a_program_named_as_the_sample_is_the_sample(self) -> None:
        led = [
            self._pe(),
            _entry("ev_0002", "get_current_program_info", {"name": "sample.exe"}),
            _entry("ev_0003", "decompile_function", args={"address": "0x401100"}),
        ]
        assert run_roots(led).of_entry("ev_0003").roots == ["0x1100 in .text"]

    def test_another_path_is_another_file(self) -> None:
        dropped = {
            "sections": [
                {
                    "name": "UPX0",
                    "virtual_address": "0x1000",
                    "virtual_size": 0x9000,
                    "raw_offset": 0x200,
                    "raw_size": 0x9000,
                }
            ]
        }
        led = [
            self._pe(),
            _entry("ev_0002", "pe_info", dropped, args={"path": "/tmp/dropped.exe"}),
            _entry(
                "ev_0003",
                "strings",
                {"strings": [{"offset": 0x300, "text": "dropped-only"}]},
                args={"path": "/tmp/dropped.exe"},
            ),
        ]
        roots = run_roots(led)
        assert [s.name for s in roots.layout.sections] == [".text", ".rdata"]
        assert roots.of_entry("ev_0003").roots == ['0x1100 in UPX0 of file "/tmp/dropped.exe"']

    def test_a_working_copy_named_by_the_sample_s_digest_is_the_sample(self) -> None:
        digest = "cd" * 32
        led = [
            _entry(
                "ev_0001",
                "hashes",
                {"sha256": digest},
                args={"path": f"/stage/{digest}.exe"},
                agent="pipeline",
            ),
            _entry(
                "ev_0002",
                "pe_info",
                SAMPLE_PE,
                args={"path": f"/stage/{digest}.exe"},
                agent="pipeline",
            ),
            _entry("ev_0003", "list_imports", args={"path": f"/work/{digest}.bin"}, output="x"),
        ]
        assert run_roots(led).of_entry("ev_0003").roots == [IMPORT_TABLE]


class TestANumberIsReadInTheRowsCoordinate:
    def test_a_strings_row_is_named_by_its_offset_and_an_ambiguous_number_names_neither(
        self,
    ) -> None:
        rows = [{"offset": 0x8500, "text": "A-string"}, {"offset": 0x7900, "text": "B-string"}]
        led = [
            _entry("ev_0001", "pe_info", SAMPLE_PE),
            _entry("ev_0002", "strings", {"strings": rows}),
        ]
        roots = run_roots(led)
        assert roots.of_entry("ev_0002").roots == ["0x9100 in .rdata", "0x8500 in .text"]
        # 0x8500 is A's offset and, as an address, B's place.
        assert roots.of_statement("the string at offset 0x8500", ["ev_0002"])[0] == []
        assert roots.of_statement("the string at offset 0x7900", ["ev_0002"])[0] == [
            "0x8500 in .text"
        ]


class TestANameNarrowsOnlyWrittenAsOne:
    def test_a_prose_word_never_narrows_and_a_quoted_or_exact_name_does(self) -> None:
        data = {
            **SAMPLE_PE,
            "exports": ["the"],
            "imports": [{"dll": "kernel32.dll", "function": "CreateFileW"}],
        }
        roots = run_roots([_entry("ev_0001", "pe_info", data)])
        said = "the sample reads its header"
        assert roots.of_statement(said, ["ev_0001"])[0] == []
        assert roots.of_statement('it exports "the"', ["ev_0001"])[0] == [EXPORT_TABLE]
        assert roots.of_statement("it calls CreateFileW", ["ev_0001"])[0] == [IMPORT_TABLE]
        assert roots.of_statement("it calls createfilew", ["ev_0001"])[0] == []
