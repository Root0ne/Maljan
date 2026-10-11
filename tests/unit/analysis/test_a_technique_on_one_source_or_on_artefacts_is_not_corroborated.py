"""A technique stands on two sayers and two sources; on artefacts alone it is a capability.

Every ledger entry or sandbox item a statement cites is a source of it, rooted
or not, and one entry is one source however many analysts restate it
(``evidence_roots.RunRoots.sources_of_statement``); sources whose roots
overlap (two tools reading one place) count once. Each source is a listing of
code (``schemas.evidence.lists_code``), a run observation (sandbox processes,
flows, DNS queries), a rule match (an asserting tool's row), an artefact of
the file (a place in it, its tables, the file itself), an external
assessment of the whole file (a reputation answer), or a citation that gives
no root. A technique is corroborated with at least two named sources
(analysts or rules) and, read live, at least two independent sources with a
behaviour source among them (``corroboration.corroborated``). One no source of
which is behaviour is published, labelled ``capability`` (every placed source
an artefact of the file) or ``unobserved``; the ATT&CK row, the judge, the
report models and the export say what its sources truly are. A row stored
before sources were read keeps its count.

Every value is synthetic.
"""

from __future__ import annotations

import time
from typing import Any

from maljan.analysis.corroboration import corroborated, corroboration_row, support_sentence
from maljan.analysis.evidence_roots import (
    EXTERNAL_ASSESSMENT,
    READING_ARTEFACT,
    READING_CODE,
    READING_REPORT,
    READING_RULE,
    READING_RUN,
    READING_UNPLACED,
    reading_of,
    run_roots,
    summary_of_sources,
)
from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.pipeline.evidence_summary import summarise
from maljan.pipeline.validation import corroboration, support_of, technique_sources
from maljan.reporting.models import TTPMapping
from maljan.reporting.narrative_agent import support_note
from maljan.reporting.renderers.markdown import _corroborated_words, support_words
from maljan.schemas.evidence import LedgerEntry, lists_code
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

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
        _entry("ev_0001", "pe_info", {"sections": SECTIONS}, agent="pipeline"),
        _entry(
            "ev_0002",
            "decode_string_blobs",
            {
                "image_base": hex(BASE),
                "results": [
                    {"rva": "0x5010", "text": "Autorun", "floss": {"called_at_rva": "0x1200"}},
                    {"rva": "0x5080", "text": "Helper"},
                ],
            },
            agent="pipeline",
        ),
        _entry(
            "ev_0003",
            "sandbox_processes",
            {
                "processes": [
                    {"pid": 84, "command_line": "rundll32.exe x.dll,#1"},
                    {"pid": 90, "command_line": "svchost.exe -k netsvcs"},
                ]
            },
            agent="pipeline",
        ),
        _entry(
            "ev_0004",
            "decompile_function",
            args={"address": hex(BASE + 0x1100)},
            output="void f(void) { RegSetValueExW(); }",
            agent="reverser",
        ),
        _entry(
            "ev_0005",
            "capa",
            {
                "capabilities": [
                    {"rule": "set value", "attck": ["T1112"], "addresses": ["0x1300"]},
                    {"rule": "hash data", "attck": [], "addresses": ["0x1400"]},
                ]
            },
            agent="pipeline",
        ),
        _entry(
            "ev_0006",
            "sandbox_signatures",
            {
                "signatures": [
                    {"name": "autostart", "technique_ids": ["T1547.008"]},
                    {"name": "beacon", "technique_ids": []},
                ]
            },
            agent="pipeline",
        ),
        _entry("ev_0007", "get_file_report", {"detections": 40}, agent="pipeline"),
        _entry(
            "ev_0008",
            "floss",
            {
                "strings": [
                    {"string": "Autorun", "called_at_rva": "0x1200", "function_rva": "0x1180"},
                    {"string": "Zebra", "called_at_rva": "0x1240", "function_rva": "0x1180"},
                ]
            },
            agent="pipeline",
        ),
    ]


def _claim(text: str, ref: str, tid: str = "T1547.001") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref, confidence=0.6, technique_id=tid)


def _isr(name: str, *claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id=name, domain=name, claims=list(claims))


def _restating(n: int, ref: str = "[ev_0002]", tid: str = "T1547.001") -> dict[str, AgentISR]:
    """``n`` analysts restating one cited entry, each in its own words."""
    words = ["holds", "carries", "keeps", "stores", "contains", "lists"]
    return {
        f"a{i}": _isr(
            f"a{i}",
            _claim(
                f'The file {words[i % len(words)]} "Autorun" and "Helper"; analyst {i} '
                "reads them as an autostart.",
                ref,
                tid,
            ),
        )
        for i in range(n)
    }


def _readings(held: dict[str, tuple[str, tuple[str, ...]]]) -> dict[str, str]:
    return {name: reading for name, (reading, _roots) in held.items()}


class TestWhatASourceIs:
    def test_each_kind_is_read_from_the_tool_and_the_roots(self) -> None:
        assert reading_of("decompile_function", ["0x1100 in .text"]) == READING_CODE
        assert reading_of("disassemble_at", []) == READING_CODE
        assert reading_of("sandbox_processes", ["sandbox process 84"]) == READING_RUN
        assert reading_of("pcap_summary", ["network flow tcp to 192.0.2.7:443"]) == READING_RUN
        assert reading_of("decode_string_blobs", ["0x5010 in .data"]) == READING_ARTEFACT
        assert reading_of("any_lookup", [EXTERNAL_ASSESSMENT]) == READING_REPORT
        assert reading_of("decode_string_blobs", []) == READING_UNPLACED

    def test_one_rule_names_a_listing_of_code(self) -> None:
        assert lists_code("Decompile_Function") and lists_code("disassemble")
        assert not lists_code("get_xrefs_to")

    def test_a_reputation_answer_is_an_external_assessment_of_the_whole_file(self) -> None:
        assert run_roots(_ledger()).of_entry("ev_0007").roots == [EXTERNAL_ASSESSMENT]

    def test_every_citation_is_a_source_rooted_or_not(self) -> None:
        roots = run_roots(_ledger())

        held = roots.sources_of_statement(
            'The file holds "Autorun"; no process wrote it [ev_0003] [ev_0099].',
            ["ev_0002", "ev_0003", "ev_0099"],
        )

        assert _readings(held) == {"ev_0002": READING_ARTEFACT, "ev_0003": READING_UNPLACED}

    def test_of_statement_reads_as_it_did(self) -> None:
        roots = run_roots(_ledger())

        assert roots.of_statement('"Autorun" [ev_0002]', ["ev_0002"]) == (["0x5010 in .data"], [])
        assert roots.of_statement("nothing", []) == (
            [],
            ["no: the statement cites no ledger entry"],
        )


class TestTheSourcesOfATechnique:
    def test_five_analysts_restating_one_pack_row_are_one_source(self) -> None:
        held = technique_sources(_restating(5), _ledger())["T1547.001"]

        assert _readings(held) == {"ev_0002": READING_ARTEFACT}
        assert support_of(held) == "capability"

    def test_the_sayers_are_counted_once_per_statement_of_their_own(self) -> None:
        same = "Routine 0x180001100 writes the Run value [ev_0004]."
        isrs = {n: _isr(n, _claim(same, "[ev_0004] [ev_0002]")) for n in ("a", "b")}

        row = corroboration(isrs, _ledger())["T1547.001"]

        assert row["claimed_by"] == ["a", "b"]
        assert row["independent_sayers"] == 1
        assert corroborated(row) is False

    def test_two_tools_reading_one_place_are_one_independent_source(self) -> None:
        isrs = {
            "a": _isr("a", _claim('"Autorun" [ev_0002]', "[ev_0002]")),
            "b": _isr("b", _claim('FLOSS decodes "Autorun" [ev_0008]', "[ev_0008]")),
        }

        summary = summary_of_sources(technique_sources(isrs, _ledger())["T1547.001"])

        assert summary.sources == ("ev_0002", "ev_0008")
        assert summary.independent == 1

    def test_a_code_listing_cited_beside_them_is_behaviour(self) -> None:
        isrs = _restating(2)
        isrs["reverser"] = _isr(
            "reverser", _claim("Routine 0x180001100 writes the Run value [ev_0004].", "[ev_0004]")
        )

        held = technique_sources(isrs, _ledger())["T1547.001"]

        assert _readings(held) == {"ev_0002": READING_ARTEFACT, "ev_0004": READING_CODE}
        assert support_of(held) == ""

    def test_an_asserting_rule_s_row_is_a_rule_match_cited_or_asserting(self) -> None:
        held = technique_sources({}, _ledger())
        assert _readings(held["T1112"]) == {"ev_0005": READING_RULE}
        isrs = {"a": _isr("a", _claim("capa matched at 0x1300 [ev_0005].", "[ev_0005]", "T1112"))}
        assert _readings(technique_sources(isrs, _ledger())["T1112"]) == {"ev_0005": READING_RULE}

    def test_a_run_cited_for_its_absence_supports_nothing(self) -> None:
        said = '"rundll32.exe x.dll,#1" ran, and no write was recorded [ev_0003].'
        held = technique_sources({"a": _isr("a", _claim(said, "[ev_0003]"))}, _ledger())
        assert _readings(held["T1547.001"]) == {"ev_0003": READING_UNPLACED}
        wrote = '"rundll32.exe x.dll,#1" wrote the Run value.'
        held = technique_sources({"b": _isr("b", _claim(wrote, "[ev_0003]"))}, _ledger())
        assert _readings(held["T1547.001"]) == {"ev_0003": READING_RUN}

    def test_a_technique_on_an_external_assessment_alone_is_unobserved(self) -> None:
        held = technique_sources(_restating(3, "[ev_0007]"), _ledger())["T1547.001"]

        assert _readings(held) == {"ev_0007": READING_REPORT}
        assert support_of(held) == "unobserved"

    def test_no_ledger_traces_nothing(self) -> None:
        assert technique_sources(_restating(2), []) == {}
        assert support_of({}) == ""

    def test_many_claims_are_read_in_linear_time(self) -> None:
        timings = []
        for n in (200, 2000):
            isrs = {
                "a": _isr("a", *[_claim(f'"Autorun" {i} [ev_0002]', "[ev_0002]") for i in range(n)])
            }
            start = time.perf_counter()
            technique_sources(isrs, _ledger())
            timings.append(time.perf_counter() - start)
        assert timings[1] < timings[0] * 10 * 4 + 0.5

    def test_many_sources_are_joined_in_linear_time(self) -> None:
        timings = []
        for n in (2000, 20000):
            held = {f"ev_{i}": ("artefact", (f"root {i}", f"root {i + 1}")) for i in range(n)}
            start = time.perf_counter()
            summary_of_sources(held)
            timings.append(time.perf_counter() - start)
        assert timings[1] < timings[0] * 10 * 4 + 0.5


class TestWhatARuleCitationIs:
    def test_a_cited_rule_whose_rows_do_not_name_the_technique_is_placed_nowhere(self) -> None:
        said = "The sample hides a value; capa ran over it [ev_0005]."
        held = technique_sources({"a": _isr("a", _claim(said, "[ev_0005]"))}, _ledger())

        assert _readings(held["T1547.001"]) == {"ev_0005": READING_UNPLACED}

    def test_a_statement_placing_a_rule_row_reads_it_as_a_rule_match(self) -> None:
        said = "capa matched at 0x1300 [ev_0005]."
        held = technique_sources({"a": _isr("a", _claim(said, "[ev_0005]"))}, _ledger())

        assert _readings(held["T1547.001"]) == {"ev_0005": READING_RULE}

    def test_a_rule_cited_for_what_it_does_not_hold_is_placed_nowhere(self) -> None:
        said = "capa has no rule for it [ev_0005]."
        held = technique_sources({"a": _isr("a", _claim(said, "[ev_0005]", "T1112"))}, _ledger())

        assert _readings(held["T1112"]) == {"ev_0005": READING_RULE}  # its rows name T1112
        said = "capa matched at 0x1300 [ev_0005]. Nothing else was seen."
        held = technique_sources({"a": _isr("a", _claim(said, "[ev_0005]"))}, _ledger())
        assert _readings(held["T1547.001"]) == {"ev_0005": READING_RULE}
        said = "capa has no autostart rule at 0x1300 [ev_0005]."
        held = technique_sources({"a": _isr("a", _claim(said, "[ev_0005]"))}, _ledger())
        assert _readings(held["T1547.001"]) == {"ev_0005": READING_UNPLACED}

    def test_two_unplaced_rule_citations_are_not_corroborated(self) -> None:
        said = "Two rules fired [ev_0005] [ev_0006]."
        isrs = {n: _isr(n, _claim(f"{said} {n}", "[ev_0005] [ev_0006]")) for n in ("a", "b")}

        row = corroboration(isrs, _ledger())["T1547.001"]

        assert row["source_kinds"] == {"unplaced": 2}
        assert corroborated(row) is False

    def test_a_signature_named_by_the_statement_is_placed_by_its_name(self) -> None:
        said = 'The sandbox raised "autostart" [ev_0006].'
        held = technique_sources({"a": _isr("a", _claim(said, "[ev_0006]"))}, _ledger())

        assert _readings(held["T1547.001"]) == {"ev_0006": READING_RULE}

    def test_a_rule_row_and_an_index_row_on_one_function_are_two_sources(self) -> None:
        summary = summary_of_sources(
            {
                "ev_0005": ("rule", ("function 0x1300 in .text",)),
                "ev_0009": ("artefact", ("function 0x1300 in .text",)),
            }
        )

        assert summary.independent == 2

    def test_an_external_assessment_adds_no_independent_source(self) -> None:
        summary = summary_of_sources(
            {"ev_0005": ("rule", ("x",)), "ev_0007": ("report", (EXTERNAL_ASSESSMENT,))}
        )

        assert summary.independent == 1


class TestTheWholeAnswer:
    def test_a_statement_writing_what_the_answer_states_places_it(self) -> None:
        said = "Emulation recovers its strings with the routine at 0x1180 [ev_0008]."
        held = technique_sources({"a": _isr("a", _claim(said, "[ev_0008]"))}, _ledger())

        reading, roots = held["T1547.001"]["ev_0008"]
        assert reading == READING_ARTEFACT
        assert roots == ("the whole answer of ev_0008",)

    def test_the_facts_are_counts_identifiers_and_values_every_row_holds(self) -> None:
        from maljan.analysis.evidence_roots import answer_facts

        facts = answer_facts(
            {
                "total": 3,
                "schemes": ["xor8_rolling", "base64"],
                "readable_test": "a long sentence of prose",
                "rows": [
                    {"routine": "0x4000", "text": "a"},
                    {"routine": "0x4000", "text": "b"},
                ],
            }
        )

        assert facts.numbers == {3}
        assert "xor8_rolling" in facts.tokens and "base64" in facts.tokens
        assert facts.addresses == {0x4000}

    def test_many_rows_are_read_in_linear_time(self) -> None:
        from maljan.analysis.evidence_roots import answer_facts

        timings = []
        for n in (2000, 20000):
            rows = [{"routine": "0x4000", "text": str(i)} for i in range(n)]
            start = time.perf_counter()
            answer_facts({"rows": rows, "total": n})
            timings.append(time.perf_counter() - start)
        assert timings[1] < timings[0] * 10 * 4 + 0.5


class TestTheCorroborationRow:
    def test_six_analysts_restating_one_signature_are_not_corroborated(self) -> None:
        row = corroboration(_restating(6, "[ev_0006]", "T1547.008"), _ledger())["T1547.008"]

        assert row["sources"] == ["ev_0006"]
        assert row["independent_sources"] == 1
        assert len(row["claimed_by"]) == 6
        assert corroborated(row) is False

    def test_a_signature_and_a_citation_placed_nowhere_are_one_independent_source(self) -> None:
        isrs = _restating(6, "[ev_0006] and the strings [ev_0002]", "T1547.008")
        for isr in isrs.values():
            isr.claims[0].claim = "A sandbox signature names an autostart; see the strings."

        row = corroboration(isrs, _ledger())["T1547.008"]

        assert row["sources"] == ["ev_0002", "ev_0006"]
        assert row["source_kinds"] == {"rule": 1, "unplaced": 1}
        assert row["independent_sources"] == 1
        assert corroborated(row) is False

    def test_statements_citing_nothing_have_no_source_and_are_not_corroborated(self) -> None:
        row = corroboration(_restating(4, "the strings"), _ledger())["T1547.001"]

        assert row["sources"] == []
        assert corroborated(row) is False

    def test_one_analyst_citing_two_sources_is_not_corroborated(self) -> None:
        said = "Routine 0x180001100 writes the Run value [ev_0004], capa at 0x1300 [ev_0005]."
        row = corroboration({"r": _isr("r", _claim(said, "[ev_0004] [ev_0005]"))}, _ledger())[
            "T1547.001"
        ]

        assert row["independent_sources"] == 2
        assert corroborated(row) is False

    def test_two_sayers_and_two_sources_with_code_are_corroborated(self) -> None:
        isrs = _restating(1)
        isrs["reverser"] = _isr(
            "reverser", _claim("Routine 0x180001100 writes the Run value [ev_0004].", "[ev_0004]")
        )

        row = corroboration(isrs, _ledger())["T1547.001"]

        assert row["sources"] == ["ev_0002", "ev_0004"]
        assert "support" not in row
        assert corroborated(row) is True

    def test_capability_is_never_corroborated(self) -> None:
        row = corroboration(_restating(5), _ledger())["T1547.001"]

        assert row["support"] == "capability"
        assert corroborated(row) is False

    def test_a_row_stored_before_sources_keeps_its_count(self) -> None:
        assert corroborated({"asserted_by": [], "claimed_by": ["a", "b"]}) is True
        assert corroborated(["a"]) is False

    def test_the_row_shape_carries_the_sources(self) -> None:
        row = corroboration_row(
            {
                "asserted_by": [],
                "claimed_by": ["a"],
                "sources": [],
                "source_kinds": {"report": 1},
                "support": "unobserved",
            }
        )

        assert row["sources"] == []
        assert row["independent_sources"] == 0
        assert row["source_kinds"] == {"report": 1}
        assert row["support"] == "unobserved"


class TestTheMatrixAndTheReport:
    def test_a_capability_is_published_and_not_corroborated(self) -> None:
        cells, mappings = build_capability_matrix(
            stix_output=None, isr_reports=_restating(3), ledger=_ledger()
        )

        (mapping,) = mappings
        assert mapping.technique_id == "T1547.001"
        assert len(mapping.independent_layers) == 3
        assert mapping.sources == ["ev_0002"]
        assert mapping.support == "capability"
        assert mapping.is_corroborated is False
        assert cells[0].support == "capability"
        assert cells[0].is_corroborated is False

    def test_the_matrix_and_the_judge_decide_alike(self) -> None:
        isrs = _restating(1)
        isrs["reverser"] = _isr(
            "reverser", _claim("Routine 0x180001100 writes the Run value [ev_0004].", "[ev_0004]")
        )

        _cells, (mapping,) = build_capability_matrix(
            stix_output=None, isr_reports=isrs, ledger=_ledger()
        )

        assert mapping.is_corroborated is corroborated(corroboration(isrs, _ledger())["T1547.001"])

    def test_the_status_says_capability_not_observed(self) -> None:
        mapping = TTPMapping(
            technique_id="T1547.001",
            technique_name="Registry Run Keys / Startup Folder",
            contributing_layers=["a", "b", "judge"],
            independent_layers=["a", "b"],
            sources=["ev_0002", "ev_0003"],
            source_kinds={"artefact": 2},
            support="capability",
            evidence_roots=["0x5010 in .data"],
        )

        words = _corroborated_words(mapping, [])

        assert words.startswith(
            " as a capability, not observed (2 sources: 2 artefacts of the file"
        )
        assert "named by 2 analyst layers" in words
        assert words.endswith("; one evidence root (0x5010 in .data))")
        assert "corroborated" not in words

    def test_an_external_assessment_is_named_as_what_it_is(self) -> None:
        said = support_words("unobserved", {"report": 1}, 1, 3)

        assert said.startswith("as not observed (1 source: 1 external assessment of the whole file")
        assert "artefact" not in said

    def test_a_row_stored_before_the_support_renders_as_it_did(self) -> None:
        mapping = TTPMapping(
            technique_id="T1055",
            technique_name="Process Injection",
            contributing_layers=["a", "b"],
            independent_layers=["a", "b"],
            is_corroborated=True,
        )

        assert _corroborated_words(mapping, []) == (
            ", corroborated (named by 2 analyst layers, each in a statement of its own)"
        )

    def test_a_row_one_source_stands_behind_says_so(self) -> None:
        mapping = TTPMapping(
            technique_id="T1027.005",
            technique_name="Indicator Removal from Tools",
            contributing_layers=["a", "b"],
            independent_layers=["a", "b"],
            sources=["ev_0005"],
            independent_sources=1,
            is_corroborated=False,
        )

        assert _corroborated_words(mapping, []) == (
            ", not corroborated (2 analyst layers name it; 2 of them in a statement of its own; "
            "they cite 1 independent source, each counted once)"
        )

    def test_the_export_marks_this_run_s_uses_edge_and_not_the_pattern(self) -> None:
        from maljan.reporting.models import MalwareReport
        from maljan.reporting.renderers.stix_renderer import (
            _attack_patterns_for,
            _support_by_pattern,
            _with_record_evidence,
        )

        report = MalwareReport.model_construct(
            ttp_mappings=[
                TTPMapping(
                    technique_id="T1547.001",
                    technique_name="Run Keys",
                    sources=["ev_0002"],
                    source_kinds={"artefact": 1},
                    support="capability",
                ),
                TTPMapping(technique_id="T1027", technique_name="Obfuscated"),
            ]
        )
        pairs = _attack_patterns_for(report, "malware--1")
        objects = [obj for pair in pairs for obj in pair if obj is not None]

        marked = _with_record_evidence(
            objects, "malware--1", {}, {}, support=_support_by_pattern(report)
        )

        patterns = [o.model_dump() for o in marked if o.type == "attack-pattern"]
        edges = {o.target_ref: o.model_dump() for o in marked if o.type == "relationship"}
        assert all("x_maljan_support" not in p for p in patterns)
        capability = edges[pairs[0][0].id]
        assert capability["relationship_type"] == "uses"
        assert capability["x_maljan_support"] == "capability"
        assert capability["x_maljan_support_note"] == support_sentence(
            "capability", {"artefact": 1}, 1
        )
        assert "x_maljan_support" not in edges[pairs[1][0].id]


class TestTheModelsAreTold:
    def test_the_judge_is_told_the_sources_and_what_they_are(self) -> None:
        isrs = _restating(2)
        traced = corroboration(isrs, _ledger())

        block = summarise(isrs, _ledger(), traced)

        line = next(x for x in block.splitlines() if "T1547.001" in x)
        assert "[traced to 1 cited source(s), each counted once: ev_0002" in line
        assert support_sentence("capability", {"artefact": 1}, 1) in line

    def test_without_the_rows_the_block_is_as_it_was(self) -> None:
        assert "traced to" not in summarise(_restating(2), _ledger())

    def test_the_report_models_are_told_what_the_sources_are(self) -> None:
        from maljan.reporting.composer import _published_techniques
        from maljan.reporting.models import MalwareReport

        capability = TTPMapping(
            technique_id="T1547.001",
            technique_name="Run Keys",
            sources=["ev_0002"],
            source_kinds={"artefact": 1},
            support="capability",
        )
        report = MalwareReport.model_construct(
            ttp_mappings=[
                capability,
                TTPMapping(technique_id="T1027", technique_name="Obfuscated"),
            ],
            run_summary={},
            rule_match_strings={},
        )

        said = _published_techniques(report)

        assert f"- T1547.001 Run Keys — {support_note(capability)}" in said
        assert support_note(capability).startswith(
            "published as capability, not observed: 1 source"
        )
        assert "- T1027 Obfuscated\n" in said + "\n"
