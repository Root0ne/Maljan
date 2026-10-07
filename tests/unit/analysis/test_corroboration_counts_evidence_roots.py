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
    EXPORT_TABLE,
    IMPORT_TABLE,
    NO_CITATION,
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

    def test_naming_none_of_them_is_one_unnamed_row(self) -> None:
        roots = run_roots(_ledger())
        named, unread = roots.of_statement("it decodes strings", ["ev_0003"])
        assert (named, unread) == (["an unnamed row of ev_0003"], [])
        # Two layers citing the entry so are one root; a named row is its own.
        counted = RootCount()
        counted.add(*roots.of_statement("strings are decoded", ["ev_0003"]))
        counted.add(*roots.of_statement("so says the decoder", ["EV_0003"]))
        counted.add(*roots.of_statement("the blob at 0x5080", ["ev_0003"]))
        assert counted.roots == ["an unnamed row of ev_0003", "0x5080 in .data"]

    def test_a_passing_mention_of_a_table_narrows_nothing(self) -> None:
        roots = run_roots(_ledger())
        for said in (
            "the imports and the export table look ordinary",
            "the header says it is a DLL",
            "a resource or an overlay is absent",
        ):
            assert roots.of_statement(said, ["ev_0002"]) == (["an unnamed row of ev_0002"], [])
        assert roots.of_statement("exports `run`", ["ev_0002"])[0] == [EXPORT_TABLE]

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
        assert roots_phrase(["0x4f58 in .text"], []) == "one evidence root (0x4f58 in .text)"
        assert roots_phrase(["a", "b"], ["ev_1: no: x"]) == (
            "2 evidence roots, and 1 citation whose root could not be read"
        )
        assert layers_and_roots(2, ["0x4f58 in .text"], []) == (
            "2 layers, one evidence root (0x4f58 in .text)"
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

    def test_without_the_ledger_no_line_is_added(self) -> None:
        questions, _ = judge_questions({"objects": []}, _isrs())
        assert questions[0].roots == ""


class TestAFunctionHoldsTheAddressesInsideIt:
    """A place inside a function whose range a reader states is that function."""

    @staticmethod
    def _ledger(*extra: LedgerEntry) -> list[LedgerEntry]:
        index = {
            "image_base": hex(BASE),
            "rows": [],
            "function_ranges": {
                hex(BASE + 0x1100): [[hex(BASE + 0x1100), hex(BASE + 0x1400)]],
                hex(BASE + 0x2000): [[hex(BASE + 0x2000), hex(BASE + 0x2200)]],
            },
        }
        return [
            _entry("ev_0001", "pe_info", {"sections": SECTIONS}),
            _entry("ev_0002", "function_index", index),
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

    def test_a_disassembler_s_stated_size_is_a_range(self) -> None:
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
            _entry("ev_0004", "read_memory", args={"address": hex(BASE + 0x1200)}),
        ]
        assert run_roots(led).of_entry("ev_0004").roots == ["function 0x1100 in .text"]


class TestAnAssertionWithNoPlace:
    def test_a_capa_rule_with_no_address_is_one_unnamed_row(self) -> None:
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
        assert roots.of_assertion("ev_0002", "T1027") == (["an unnamed row of ev_0002"], [])
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

    def test_overlapping_ranges_of_two_functions_own_the_overlap_jointly_with_neither(
        self,
    ) -> None:
        layout = self._with((0x1100, 0x1400, 0x1100), (0x1300, 0x1600, 0x1300))
        assert layout.function_at(0x1200) == 0x1100
        assert layout.function_at(0x1350) is None
        assert layout.function_at(0x1500) == 0x1300
        assert layout.function_at(0x1700) is None

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
