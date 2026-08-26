"""Phase 5: deterministic SVG figures from report data."""

from __future__ import annotations

import xml.dom.minidom as _minidom

from maljan.reporting.figures import (
    build_attack_matrix,
    build_code_listings,
    build_entropy_chart,
    build_figures,
    build_infection_chain,
    build_network_graph,
    build_process_tree,
)
from maljan.reporting.models import (
    DynamicBehavior,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    PESection,
    ProcessNode,
    SampleIdentity,
    StaticAnalysis,
    TTPMapping,
)


def _report(**over: object) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        **over,  # type: ignore[arg-type]
    )


def _well_formed(svg: str) -> bool:
    _minidom.parseString(svg)  # raises on malformed XML
    return True


class TestFigureOmission:
    def test_all_none_on_empty_report(self) -> None:
        r = _report()
        assert build_process_tree(r) is None
        assert build_attack_matrix(r) is None
        assert build_entropy_chart(r) is None
        assert build_network_graph(r) is None
        assert build_infection_chain(r) is None
        assert build_code_listings(r) == []
        assert build_figures(r) == []


class TestFigureGeneration:
    def test_process_tree_svg(self) -> None:
        r = _report(
            dynamic=DynamicBehavior(
                process_tree=[
                    ProcessNode(
                        pid=100,
                        name="parent.exe",
                        children=[ProcessNode(pid=200, ppid=100, name="child.exe")],
                    )
                ]
            )
        )
        fig = build_process_tree(r)
        assert fig is not None and fig.kind == "process_tree"
        assert _well_formed(fig.content)
        assert "parent.exe" in fig.content

    def test_attack_matrix_svg(self) -> None:
        r = _report(
            ttp_mappings=[
                TTPMapping(technique_id="T1071", technique_name="App Layer", tactic="TA0011"),
                TTPMapping(technique_id="T1055", technique_name="Injection", tactic="TA0005"),
            ]
        )
        fig = build_attack_matrix(r)
        assert fig is not None and _well_formed(fig.content)
        assert "T1071" in fig.content

    def test_entropy_chart_flags_high(self) -> None:
        r = _report(
            static=StaticAnalysis(
                sections=[
                    PESection(name=".text", virtual_address="0x1000", entropy=7.8),
                    PESection(name=".data", virtual_address="0x5000", entropy=3.1),
                ]
            )
        )
        fig = build_entropy_chart(r)
        assert fig is not None and _well_formed(fig.content)
        assert "#cf222e" in fig.content  # danger colour for the high-entropy section

    def test_network_graph_defangs(self) -> None:
        r = _report(network=NetworkIOCs(domains=[NetworkDomain(fqdn="evil.com")]))
        fig = build_network_graph(r)
        assert fig is not None and _well_formed(fig.content)
        assert "evil[.]com" in fig.content

    def test_infection_chain_needs_two_tactics(self) -> None:
        one = _report(
            ttp_mappings=[
                TTPMapping(technique_id="T1055", technique_name="Injection", tactic="TA0005")
            ]
        )
        assert build_infection_chain(one) is None
        two = _report(
            ttp_mappings=[
                TTPMapping(technique_id="T1204", technique_name="Exec", tactic="TA0002"),
                TTPMapping(technique_id="T1486", technique_name="Encrypt", tactic="TA0040"),
            ]
        )
        fig = build_infection_chain(two)
        assert fig is not None and _well_formed(fig.content)

    def test_code_listing_from_evidence(self) -> None:
        r = _report(
            technical_evidence={
                "static": [
                    {
                        "tool_name": "decompile_function",
                        "symbol": "FUN_00401310",
                        "output": "void FUN_00401310(void) { connect(...); }",
                    }
                ]
            }
        )
        figs = build_code_listings(r)
        assert len(figs) == 1
        assert figs[0].kind == "code_listing"
        assert "FUN_00401310" in figs[0].content
        assert "&lt;" not in figs[0].caption

    def test_build_figures_assembles_multiple(self) -> None:
        r = _report(
            static=StaticAnalysis(
                sections=[PESection(name=".text", virtual_address="0x1000", entropy=7.5)]
            ),
            network=NetworkIOCs(domains=[NetworkDomain(fqdn="c2.evil")]),
            ttp_mappings=[
                TTPMapping(technique_id="T1204", technique_name="Exec", tactic="TA0002"),
                TTPMapping(technique_id="T1486", technique_name="Encrypt", tactic="TA0040"),
            ],
        )
        figs = build_figures(r)
        kinds = {f.kind for f in figs}
        assert "entropy_chart" in kinds
        assert "network_graph" in kinds
        assert "attack_matrix" in kinds
        assert "infection_chain" in kinds
        for f in figs:
            assert _well_formed(f.content) if f.kind != "code_listing" else True
