"""Fields that existed in the schema and appeared in no report.

The audit that produced this file asked a simple question — "does any of the new
static-analysis work actually reach a reader?" — and the answer for most of it
was no. `api_capabilities`, `packer_matches`, `api_technique_hits` and
`tool_artifact_matches` were all populated (one of them was not even that) and
none of them were rendered anywhere.

That is a specific kind of failure worth a test: the pipeline gets measurably
better, every unit test passes, and the person reading the report sees exactly
what they saw before. `api_technique_hits` was the extreme case — declared on
the model, never written by anything, never read by anything. A field that
exists only in the schema is indistinguishable from a field that does not exist.

Carved payloads had a milder version of the same problem: they rendered, as
`- carved:PE (51200 bytes)`, which loses the offset and the hash — the two
things a reader needs in order to go and look at the payload.
"""

from __future__ import annotations

from maljan.reporting.models import (
    FamilyAttribution,
    FileHashes,
    MalwareReport,
    PESection,
    SampleIdentity,
    StaticAnalysis,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer


def _report(static: StaticAnalysis | None = None, **attr: object) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_name="s.exe"),
        static=static,
        attribution=FamilyAttribution(**attr),  # type: ignore[arg-type]
    )


def _render(static: StaticAnalysis | None = None, **attr: object) -> str:
    return MarkdownRenderer().render(_report(static, **attr))


class TestTheImportDerivedTechniquesAreVisible:
    def test_the_audit_trail_is_rendered(self) -> None:
        md = _render(
            StaticAnalysis(
                api_technique_hits=[
                    {
                        "technique_id": "T1056.001",
                        "name": "Input Capture: Keylogging",
                        "confidence": 0.55,
                        "matched_apis": ["GetAsyncKeyState", "SetWindowsHookExW"],
                    }
                ]
            )
        )
        assert "T1056.001" in md
        assert "GetAsyncKeyState" in md, "the reasoning must be checkable"
        assert "SetWindowsHookExW" in md

    def test_it_says_the_evidence_needed_no_sandbox(self) -> None:
        """The whole point of the deterministic layer is that it works when
        CAPE does not. A reader cannot tell unless the report says so."""
        md = _render(
            StaticAnalysis(
                api_technique_hits=[
                    {"technique_id": "T1057", "name": "x", "confidence": 0.5, "matched_apis": ["a"]}
                ]
            )
        )
        assert "no sandbox" in md.lower()

    def test_the_capability_profile_is_rendered(self) -> None:
        md = _render(StaticAnalysis(api_capabilities={"process_injection": 7, "network": 3}))
        assert "process_injection" in md
        assert "×7" in md or "x7" in md


class TestPackerEvidenceReplacesABareString:
    def test_the_ranked_matches_are_rendered_with_confidence(self) -> None:
        md = _render(
            StaticAnalysis(
                packer_hint="UPX (packer)",
                packer_matches=[
                    {
                        "name": "UPX",
                        "kind": "packer",
                        "confidence": 0.85,
                        "method": "section+entry_point",
                        "evidence": ["UPX0", "UPX1"],
                    }
                ],
            )
        )
        assert "UPX" in md
        assert "0.85" in md, "a reader needs to know how sure the detector was"
        assert "section+entry_point" in md, "and on what basis"

    def test_the_bare_hint_still_renders_without_a_catalog(self) -> None:
        md = _render(StaticAnalysis(packer_hint="high-entropy sections (possibly packed)"))
        assert "high-entropy sections" in md


class TestCarvedPayloadsAreLocatable:
    def test_offset_and_hash_survive_into_the_report(self) -> None:
        md = _render(
            StaticAnalysis(
                embedded_resources=[
                    {
                        "type": "carved:PE",
                        "id": "overlay+0x1a400",
                        "size": 51200,
                        "offset": 107520,
                        "source": "overlay",
                        "sha256": "b" * 64,
                        "entropy": 7.21,
                        "carved": True,
                    }
                ]
            )
        )
        assert "carved:PE" in md
        assert "overlay+0x1a400" in md, "without the offset nobody can go and look"
        assert "bbbb" in md, "nor without the hash"
        assert "7.21" in md

    def test_ordinary_resources_still_render_as_before(self) -> None:
        md = _render(
            StaticAnalysis(embedded_resources=[{"type": "RT_ICON", "id": 1, "size": 1024}])
        )
        assert "RT_ICON" in md

    def test_the_two_kinds_are_not_conflated(self) -> None:
        """A nested executable and an icon are different findings."""
        md = _render(
            StaticAnalysis(
                embedded_resources=[
                    {"type": "RT_ICON", "id": 1, "size": 1024},
                    {"type": "carved:PE", "id": "overlay+0x100", "size": 9999, "carved": True},
                ]
            )
        )
        assert "Carved payloads" in md


class TestTheFamilyEvidenceIsShown:
    def test_tool_artifact_markers_are_rendered(self) -> None:
        """Without them the reader sees a family name and nothing to check."""
        md = _render(
            None,
            family="CobaltStrike",
            family_confidence=0.75,
            tool_artifact_matches=[
                {
                    "tool": "Cobalt Strike",
                    "family": "CobaltStrike",
                    "kind": "c2_framework",
                    "confidence": 0.75,
                    "markers": ["beacon.x64.dll", "ReflectiveLoader"],
                }
            ],
        )
        assert "Cobalt Strike" in md
        assert "beacon.x64.dll" in md
        assert "ReflectiveLoader" in md

    def test_no_artifacts_means_no_empty_table(self) -> None:
        md = _render(None, family="Emotet", family_confidence=0.8)
        assert "Offensive-tool artifacts" not in md


class TestASectionCanBeFoundInTheFile:
    """``PESection.raw_offset`` is PointerToRawData. It was extracted, stored
    on the model and declared in the TypeScript interface, and printed by
    neither renderer — a field with a producer and no consumer, which is the
    same shape as the dead ``api_technique_hits`` the audit found.

    It matters here specifically: the carved-payload table reports a file
    offset, and the section table was the only thing that could say which
    section that offset falls in. Without the column the two tables sat next to
    each other and could not be joined.
    """

    def test_the_section_table_carries_the_file_offset(self) -> None:
        md = _render(
            StaticAnalysis(
                sections=[
                    PESection(
                        name=".text",
                        virtual_address="0x1000",
                        virtual_size=8192,
                        raw_size=8192,
                        raw_offset=1024,
                        entropy=6.1,
                    )
                ]
            )
        )
        assert "Raw offset" in md, "the column header"
        assert "0x400" in md, "1024 as hex, so it can be pasted into a hex editor"

    def test_a_section_without_one_does_not_break_the_row(self) -> None:
        """Reports written before the field existed deserialise with None."""
        md = _render(
            StaticAnalysis(
                sections=[
                    PESection(
                        name=".rdata",
                        virtual_address="0x3000",
                        virtual_size=512,
                        raw_size=512,
                        entropy=4.2,
                    )
                ]
            )
        )
        assert ".rdata" in md
        assert "Raw offset" in md


class TestTheFamilyNameShowsItsWorking:
    """``tool_artifact_matches`` had three siblings on ``FamilyAttribution``
    and all three were dead in the same way: produced by the judge, carried
    through ``AnalysisState``, stored on the model, printed by no renderer.

    The effect was a report that named a family and withheld every
    deterministic reason for it — the exact position the grounding flag exists
    to warn about, reached silently.
    """

    def test_function_hash_matches_are_rendered(self) -> None:
        md = _render(
            None,
            family="AgentTesla",
            family_confidence=0.8,
            function_hash_matches=[
                {
                    "family": "AgentTesla",
                    "confidence": 0.83,
                    "shared_functions": 12,
                    "example_functions": ["sub_401A20"],
                }
            ],
        )
        assert "Function-hash matches" in md
        assert "sub_401A20" in md, "an unnamed match cannot be checked"
        assert "0.83" in md

    def test_family_rag_candidates_are_rendered(self) -> None:
        md = _render(
            None,
            family_rag_candidates=[
                {"family": "FormBook", "similarity": 0.612, "malware_category": "stealer"}
            ],
        )
        assert "Family-feature RAG candidates" in md
        assert "FormBook" in md
        assert "0.612" in md

    def test_attck_case_priors_are_labelled_advisory(self) -> None:
        """They describe prior runs, not this sample. Rendering them beside
        real evidence without saying so would be the more harmful bug."""
        md = _render(
            None,
            attck_case_candidates=[{"technique_id": "T1055", "support": 7, "similarity": 0.548}],
        )
        assert "ATT&CK case priors" in md
        assert "T1055" in md
        assert "Advisory only" in md

    def test_nothing_is_printed_when_there_is_no_evidence(self) -> None:
        md = _render(None)
        assert "Function-hash matches" not in md
        assert "Family-feature RAG candidates" not in md
        assert "ATT&CK case priors" not in md


class TestComputedSignalsThatWereNeverPrinted:
    """Three more producer-without-consumer fields, found by sweeping every
    field on every report model for a reader rather than by noticing one.

    ``dga_score``, ``is_punycode`` and ``homograph_target`` are all written by
    ``network_extractor`` and were read by no renderer and no UI. The homograph
    one is the worst of them: the extractor works out that a punycode label
    renders as a familiar brand, which is the entire reason such a domain gets
    registered, and the report printed the raw FQDN with no note.
    """

    def test_a_homograph_domain_names_what_it_imitates(self) -> None:
        from maljan.reporting.models import NetworkDomain, NetworkIOCs

        report = _report()
        report.network = NetworkIOCs(
            domains=[
                NetworkDomain(
                    fqdn="xn--pple-43d.com",
                    is_suspicious=True,
                    is_punycode=True,
                    homograph_target="apple.com",
                )
            ]
        )
        md = MarkdownRenderer().render(report)
        assert "xn--pple-43d.com" in md
        assert "apple.com" in md, "the imitated brand is the finding"
        assert "punycode" in md

    def test_a_dga_score_reaches_the_reader(self) -> None:
        from maljan.reporting.models import NetworkDomain, NetworkIOCs

        report = _report()
        report.network = NetworkIOCs(
            domains=[NetworkDomain(fqdn="kqxvbnzp.info", is_suspicious=True, dga_score=0.87)]
        )
        md = MarkdownRenderer().render(report)
        assert "0.87" in md

    def test_an_ordinary_domain_gains_no_noise(self) -> None:
        """The reason column is shared, so a clean domain must stay clean."""
        from maljan.reporting.models import NetworkDomain, NetworkIOCs

        report = _report()
        report.network = NetworkIOCs(domains=[NetworkDomain(fqdn="example.com")])
        md = MarkdownRenderer().render(report)
        assert "example.com" in md
        assert "DGA score" not in md
        assert "punycode" not in md

    def test_magic_bytes_let_a_reader_disagree_with_the_file_type(self) -> None:
        from maljan.reporting.models import FileHashes, SampleIdentity

        report = _report()
        report.identity = SampleIdentity(
            hashes=FileHashes(sha256="a" * 64),
            file_name="invoice.doc",
            file_type="Microsoft Word",
            magic_bytes="4d5a90000300000004000000",
        )
        md = MarkdownRenderer().render(report)
        assert "4d5a90000300000004000000" in md, "a .doc starting MZ is the whole finding"


class TestTheComposedSectionsReachTheReport:
    """``composer_enabled`` defaults to True and the composer spends an LLM
    call per prose section, with a 120 s timeout each. Until 2026-07-28 no
    renderer read a single field it wrote — not markdown, not HTML, not PDF,
    not the API, not the UI. Every one of those calls was billed and discarded.

    This is the most expensive instance of the producer-without-consumer bug in
    the repo, and the least visible: a run with the composer on and a run with
    it off produced byte-identical reports.
    """

    def test_the_prose_sections_and_their_evidence_refs_render(self) -> None:
        from maljan.reporting.models import TechnicalAnalysis, TechnicalSubsection

        report = _report()
        report.technical_analysis = TechnicalAnalysis(
            packing_obfuscation=TechnicalSubsection(
                title="Packing & Obfuscation",
                body="The sample is UPX-packed with a modified header.",
                evidence_refs=["static:sections", "yara:UPX_mod"],
            )
        )
        md = MarkdownRenderer().render(report)
        assert "## Technical Analysis" in md
        assert "UPX-packed with a modified header" in md
        assert "static:sections" in md, "prose without refs is indistinguishable from invention"

    def test_the_spared_processes_are_shown_not_just_the_killed_ones(self) -> None:
        """The exclusions are often the more identifying half of the list."""
        from maljan.reporting.models import ServiceProcessKill, TechnicalAnalysis

        report = _report()
        report.technical_analysis = TechnicalAnalysis(
            service_process_kill=ServiceProcessKill(
                kill_list=["sqlservr.exe"], white_list=["explorer.exe"], mechanism="taskkill"
            )
        )
        md = MarkdownRenderer().render(report)
        assert "sqlservr.exe" in md
        assert "explorer.exe" in md

    def test_c2_channels_render(self) -> None:
        from maljan.reporting.models import C2Channel

        report = _report()
        report.c2_channels = [
            C2Channel(name="primary", protocol="HTTPS", encryption="RC4", beacon_format="JSON")
        ]
        md = MarkdownRenderer().render(report)
        assert "## C2 Channels" in md
        assert "RC4" in md

    def test_the_conclusion_and_its_sophistication_rating_render(self) -> None:
        from maljan.reporting.models import Conclusion

        report = _report()
        report.conclusion = Conclusion(text="A commodity loader.", sophistication_rating="low")
        md = MarkdownRenderer().render(report)
        assert "## Conclusion" in md
        assert "commodity loader" in md
        assert "low" in md

    def test_a_run_without_the_composer_is_unchanged(self) -> None:
        """The sections must vanish entirely rather than render as empty
        headings, so disabling the composer produces the report it always did.
        """
        md = MarkdownRenderer().render(_report())
        assert "## Technical Analysis" not in md
        assert "## C2 Channels" not in md
        assert "## Conclusion" not in md
        assert "## Introduction & Background" not in md

    def test_the_html_export_inherits_the_fix(self) -> None:
        """HtmlRenderer builds from MarkdownRenderer and PdfRenderer from that,
        so all three formats were losing the composer output together and all
        three are fixed by one change. Worth pinning: if HTML ever grows its own
        section list, this is what notices."""
        from maljan.reporting.models import Conclusion
        from maljan.reporting.renderers.html import HtmlRenderer

        report = _report()
        report.conclusion = Conclusion(text="A commodity loader.", sophistication_rating="low")
        html = HtmlRenderer().render(report, embed_figures=False)
        assert "commodity loader" in html

    def test_composed_prose_is_marked_as_unverified(self) -> None:
        """The first report rendered after the composer output became visible
        asserted the sample was a .NET executable calling `_CorExeMain` from
        `mscoree.dll`. The same report's identity section said Microsoft Visual
        C++ and its import table contained no `mscoree`.

        The prose is written from evidence bundles and never cross-checked
        against the report it lands in, and it reads exactly like the
        deterministic sections above it. Marking it is the same concession the
        "(unverified)" family badge makes.
        """
        from maljan.reporting.models import Conclusion, TechnicalAnalysis, TechnicalSubsection

        report = _report()
        report.intro_background = "Background prose."
        report.conclusion = Conclusion(text="A commodity loader.")
        report.technical_analysis = TechnicalAnalysis(
            discovery=TechnicalSubsection(title="Discovery", body="It enumerates files.")
        )
        md = MarkdownRenderer().render(report)
        assert md.count("Composed by the report LLM") == 3, "every composed section must say so"
        assert "verify" in md.lower()

    def test_the_note_alone_does_not_create_a_section(self) -> None:
        """Adding the note must not turn an empty TechnicalAnalysis into a
        rendered heading — the emptiness check compares against the note too."""
        from maljan.reporting.models import TechnicalAnalysis

        report = _report()
        report.technical_analysis = TechnicalAnalysis()
        md = MarkdownRenderer().render(report)
        assert "## Technical Analysis" not in md
