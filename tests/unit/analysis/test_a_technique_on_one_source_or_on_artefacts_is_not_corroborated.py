"""A technique stands on its sources, counted once each, and on artefacts alone it is a capability.

A source of a statement is a cited ledger entry or sandbox item that gives the
statement a root (``evidence_roots.RunRoots.sources_of_statement``): one pack
row is one source however many analysts restate it. Each source is a listing
of code (a tool whose name says it decompiles or disassembles), a run
observation (its roots are sandbox processes, flows or DNS queries), a rule
match (an asserting tool's own row) or an artefact of the file (names,
strings, tables, index rows). A technique every source of which is an artefact
is published as a capability, not observed: it is not corroborated however
many layers name it, the report's status says so, and the judge and the report
models are told. A technique with no source read keeps the rule it had.

Every value is synthetic.
"""

from __future__ import annotations

import time
from typing import Any

from maljan.analysis.corroboration import corroborated, corroboration_row
from maljan.analysis.evidence_roots import (
    READING_ARTEFACT,
    READING_CODE,
    READING_RULE,
    READING_RUN,
    reading_of,
    run_roots,
)
from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.pipeline.evidence_summary import CAPABILITY_FACT, summarise
from maljan.pipeline.validation import (
    CAPABILITY_SUPPORT,
    corroboration,
    support_of,
    technique_sources,
)
from maljan.reporting.models import TTPMapping
from maljan.reporting.narrative_agent import CAPABILITY_NOTE
from maljan.reporting.renderers.markdown import (
    CAPABILITY_STATUS,
    _corroborated_words,
    capability_words,
)
from maljan.schemas.evidence import LedgerEntry
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
                    {"rva": "0x5010", "text": "Autorun"},
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
            {"capabilities": [{"rule": "set value", "attck": ["T1112"], "addresses": ["0x1300"]}]},
            agent="pipeline",
        ),
    ]


def _claim(text: str, ref: str, tid: str = "T1547.001") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref, confidence=0.6, technique_id=tid)


def _isr(name: str, *claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id=name, domain=name, claims=list(claims))


def _restating(n: int) -> dict[str, AgentISR]:
    """``n`` analysts restating the pack's two decoded strings, each in its own words."""
    words = ["holds", "carries", "keeps", "stores", "contains", "lists"]
    return {
        f"a{i}": _isr(
            f"a{i}",
            _claim(
                f'The file {words[i % len(words)]} "Autorun" and "Helper"; analyst {i} '
                "reads them as an autostart.",
                "[ev_0002]",
            ),
        )
        for i in range(n)
    }


class TestWhatASourceIs:
    def test_a_listing_of_code_a_run_and_an_artefact(self) -> None:
        assert reading_of("decompile_function", ["0x1100 in .text"]) == READING_CODE
        assert reading_of("disassemble_at", []) == READING_CODE
        assert reading_of("sandbox_processes", ["sandbox process 84"]) == READING_RUN
        assert reading_of("pcap_summary", ["network flow tcp to 192.0.2.7:443"]) == READING_RUN
        assert reading_of("decode_string_blobs", ["0x5010 in .data"]) == READING_ARTEFACT

    def test_an_entry_the_statement_names_no_row_of_is_no_source(self) -> None:
        roots = run_roots(_ledger())

        held = roots.sources_of_statement(
            'The file holds "Autorun"; no process wrote it [ev_0003].', ["ev_0002", "ev_0003"]
        )

        assert held == {"ev_0002": READING_ARTEFACT}

    def test_a_run_cited_to_say_it_was_not_seen_supports_nothing(self) -> None:
        isrs = {
            "a": _isr(
                "a",
                _claim(
                    '"Autorun" is held; "rundll32.exe x.dll,#1" ran, no write observed [ev_0003].',
                    "[ev_0002]",
                ),
            ),
            "b": _isr("b", _claim('"rundll32.exe x.dll,#1" wrote the Run value.', "[ev_0003]")),
        }

        held = technique_sources({"a": isrs["a"]}, _ledger())["T1547.001"]
        assert held == {"ev_0002": READING_ARTEFACT}
        held = technique_sources(isrs, _ledger())["T1547.001"]
        assert held == {"ev_0002": READING_ARTEFACT, "ev_0003": READING_RUN}

    def test_of_statement_reads_as_it_did(self) -> None:
        roots = run_roots(_ledger())

        assert roots.of_statement('"Autorun" [ev_0002]', ["ev_0002"]) == (["0x5010 in .data"], [])
        assert roots.of_statement("nothing", []) == (
            [],
            ["no: the statement cites no ledger entry"],
        )


class TestTheSourcesOfATechnique:
    def test_five_analysts_restating_one_pack_row_are_one_source(self) -> None:
        held = technique_sources(_restating(5), _ledger())

        assert held["T1547.001"] == {"ev_0002": READING_ARTEFACT}
        assert support_of(held["T1547.001"]) == CAPABILITY_SUPPORT

    def test_a_code_listing_cited_beside_them_is_not_a_capability(self) -> None:
        isrs = _restating(2)
        isrs["reverser"] = _isr(
            "reverser", _claim("Routine 0x180001100 writes the Run value [ev_0004].", "[ev_0004]")
        )

        held = technique_sources(isrs, _ledger())["T1547.001"]

        assert held == {"ev_0002": READING_ARTEFACT, "ev_0004": READING_CODE}
        assert support_of(held) == ""

    def test_an_asserting_rule_s_row_is_a_rule_match(self) -> None:
        held = technique_sources({}, _ledger())

        assert held["T1112"] == {"ev_0005": READING_RULE}

    def test_a_statement_citing_a_rule_s_row_reads_it_as_a_rule_match(self) -> None:
        isrs = {"a": _isr("a", _claim("capa matched at 0x1300 [ev_0005].", "[ev_0005]", "T1112"))}

        assert technique_sources(isrs, _ledger())["T1112"] == {"ev_0005": READING_RULE}

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


class TestTheCorroborationRow:
    def test_the_row_states_its_sources_and_its_support(self) -> None:
        rows = corroboration(_restating(5), _ledger())

        row = rows["T1547.001"]
        assert row["sources"] == ["ev_0002"]
        assert row["support"] == CAPABILITY_SUPPORT
        assert len(row["claimed_by"]) == 5
        assert corroborated(row) is False

    def test_two_sources_one_of_them_code_are_corroborated(self) -> None:
        isrs = _restating(1)
        isrs["reverser"] = _isr(
            "reverser", _claim("Routine 0x180001100 writes the Run value [ev_0004].", "[ev_0004]")
        )

        row = corroboration(isrs, _ledger())["T1547.001"]

        assert row["sources"] == ["ev_0002", "ev_0004"]
        assert "support" not in row
        assert corroborated(row) is True

    def test_one_source_is_not_corroborated_however_many_name_it(self) -> None:
        row = {"asserted_by": ["capa"], "claimed_by": ["a", "b"], "sources": ["ev_0005"]}

        assert corroborated(row) is False

    def test_a_row_stored_before_sources_keeps_its_count(self) -> None:
        assert corroborated({"asserted_by": [], "claimed_by": ["a", "b"]}) is True
        assert corroborated(["a"]) is False

    def test_the_row_shape_carries_both(self) -> None:
        row = corroboration_row(
            {"asserted_by": [], "claimed_by": ["a"], "sources": ["ev_1"], "support": "capability"}
        )

        assert row["sources"] == ["ev_1"]
        assert row["support"] == "capability"


class TestTheMatrixAndTheReport:
    def test_a_capability_is_published_and_not_corroborated(self) -> None:
        cells, mappings = build_capability_matrix(
            stix_output=None, isr_reports=_restating(3), ledger=_ledger()
        )

        (mapping,) = mappings
        assert mapping.technique_id == "T1547.001"
        assert len(mapping.independent_layers) == 3
        assert mapping.sources == ["ev_0002"]
        assert mapping.support == CAPABILITY_SUPPORT
        assert mapping.is_corroborated is False
        assert cells[0].support == CAPABILITY_SUPPORT

    def test_the_status_says_capability_not_observed(self) -> None:
        mapping = TTPMapping(
            technique_id="T1547.001",
            technique_name="Registry Run Keys / Startup Folder",
            contributing_layers=["a", "b", "judge"],
            independent_layers=["a", "b"],
            sources=["ev_0002", "ev_0003"],
            support="capability",
            evidence_roots=["0x5010 in .data"],
        )

        words = _corroborated_words(mapping, [])

        assert words.startswith(f" {CAPABILITY_STATUS} (2 sources, all artefacts of the file")
        assert "named by 2 analyst layers" in words
        assert words.endswith("; one evidence root (0x5010 in .data))")
        assert "corroborated" not in words

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

    def test_one_source_is_counted_in_the_singular(self) -> None:
        assert capability_words(1, 0).startswith(f"{CAPABILITY_STATUS} (1 source, all")

    def test_a_row_one_source_stands_behind_says_so(self) -> None:
        mapping = TTPMapping(
            technique_id="T1027.005",
            technique_name="Indicator Removal from Tools",
            contributing_layers=["a", "b"],
            independent_layers=["a", "b"],
            sources=["ev_0005"],
            is_corroborated=False,
        )

        assert _corroborated_words(mapping, []) == (
            ", not corroborated (2 analyst layers name it; 2 of them in a statement of its own; "
            "they cite 1 source, each counted once)"
        )


class TestTheModelsAreTold:
    def test_the_judge_is_told_the_sources_and_the_capability(self) -> None:
        isrs = _restating(2)
        traced = corroboration(isrs, _ledger())

        block = summarise(isrs, _ledger(), traced)

        line = next(x for x in block.splitlines() if "T1547.001" in x)
        assert "[traced to 1 cited source(s), each counted once: ev_0002" in line
        assert CAPABILITY_FACT in line

    def test_without_the_rows_the_block_is_as_it_was(self) -> None:
        isrs = _restating(2)

        assert "traced to" not in summarise(isrs, _ledger())

    def test_the_report_models_are_told_a_capability(self) -> None:
        from maljan.reporting.composer import _published_techniques
        from maljan.reporting.models import MalwareReport

        report = MalwareReport.model_construct(
            ttp_mappings=[
                TTPMapping(
                    technique_id="T1547.001", technique_name="Run Keys", support="capability"
                ),
                TTPMapping(technique_id="T1027", technique_name="Obfuscated"),
            ],
            run_summary={},
            rule_match_strings={},
        )

        said = _published_techniques(report)

        assert f"- T1547.001 Run Keys — {CAPABILITY_NOTE}" in said
        assert "- T1027 Obfuscated\n" in said + "\n"
