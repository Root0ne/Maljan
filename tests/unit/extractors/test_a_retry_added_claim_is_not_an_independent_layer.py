"""A claim a tool-less retry added is no independent layer in the ATT&CK table.

After a revision that wrote no claim, the claims its validation retry wrote
are added beside the answer in force, marked with the round. The retry is a
turn with no tools. The capability matrix reads the same answers
corroboration reads: such a claim that cites nothing its own analyst's tool
calls filed is still collected (its analyst named the technique), but it is
not a layer with a statement of its own, and a technique only such claims
name carries the note. An unmarked claim reads as it always did. Every value
is synthetic.
"""

from __future__ import annotations

from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, retry_added_marker

LEDGER = [
    LedgerEntry(id="ev_0001", agent="static", tool="pe_info", output="Run key"),
    LedgerEntry(id="ev_0002", agent="dynamic", tool="procs", output="reg set Run key"),
]
MARKER = retry_added_marker(2)


def _claim(text: str, ev: str, technique: str, *, retry: bool = False) -> ClaimEvidence:
    claim = ClaimEvidence(claim=text, evidence_ref=ev, confidence=0.7, technique_id=technique)
    if retry:
        claim.added_by_retry_in_round = 2
    return claim


def _answers(*, retry: bool, dynamic_ev: str = "[ev_0001]") -> dict[str, AgentISR]:
    static = _claim("Persists through the Run key [ev_0001]", "[ev_0001]", "T1547.001")
    dynamic = _claim(
        f"Writes the Run key value at startup {dynamic_ev}", dynamic_ev, "T1547.001", retry=retry
    )
    return {
        "static": AgentISR(agent_id="static", domain="static", claims=[static]),
        "dynamic": AgentISR(agent_id="dynamic", domain="dynamic", claims=[dynamic]),
    }


def _row(isrs: dict[str, AgentISR], tid: str) -> tuple[object, object]:
    cells, maps = build_capability_matrix(stix_output=None, isr_reports=isrs, ledger=LEDGER)
    cell = next(c for c in cells if c.technique_id == tid)
    mapping = next(m for m in maps if m.technique_id == tid)
    return cell, mapping


def _markdown(isrs: dict[str, AgentISR]) -> str:
    cells, maps = build_capability_matrix(stix_output=None, isr_reports=isrs, ledger=LEDGER)
    report = MalwareReport(
        verdict="Malware",
        identity=SampleIdentity(hashes=FileHashes(sha256="f" * 64)),
        capability_matrix=cells,
        ttp_mappings=maps,
    )
    return MarkdownRenderer().render(report)


class TestTheLayers:
    def test_an_unbacked_retry_claim_is_not_a_second_independent_layer(self) -> None:
        _plain_cell, plain = _row(_answers(retry=False), "T1547.001")
        _cell, marked = _row(_answers(retry=True), "T1547.001")

        assert plain.independent_layers == ["static", "dynamic"]
        assert marked.contributing_layers == ["static", "dynamic"]
        assert marked.independent_layers == ["static"]
        assert marked.is_corroborated is False

    def test_a_retry_claim_on_its_own_analyst_s_entry_counts(self) -> None:
        _cell, mapping = _row(_answers(retry=True, dynamic_ev="[ev_0002]"), "T1547.001")

        assert mapping.independent_layers == ["static", "dynamic"]

    def test_the_markdown_counts_one_layer_of_its_own(self) -> None:
        plain = _markdown(_answers(retry=False))
        marked = _markdown(_answers(retry=True))

        assert "named by 2 analyst layers" in plain
        assert "named by 1 analyst layer," in marked
        assert "named by 2 analyst layers" not in marked
        assert MARKER not in marked.split("Registry Run Keys")[1].splitlines()[0]

    def test_the_mapping_names_the_layer_that_named_it_only_so(self) -> None:
        _cell, plain = _row(_answers(retry=False), "T1547.001")
        _cell, marked = _row(_answers(retry=True), "T1547.001")

        assert marked.retry_only_layers == ["dynamic"]
        assert plain.retry_only_layers == []
        # Left out of the stored row when empty, so an unmarked row is stored
        # as it always was.
        assert "retry_only_layers" not in plain.model_dump()

    def test_the_statement_is_listed_with_its_note(self) -> None:
        cell, _mapping = _row(_answers(retry=True), "T1547.001")

        assert cell.statements[-1].endswith(f"({MARKER})")
        assert cell.statements[-1].startswith("dynamic: ")


class TestTheNote:
    def _only_retry(self) -> dict[str, AgentISR]:
        claim = _claim("Uses a scheduled task [ev_0001]", "[ev_0001]", "T1053.005", retry=True)
        return {"dynamic": AgentISR(agent_id="dynamic", domain="dynamic", claims=[claim])}

    def test_a_technique_only_unbacked_retry_claims_name_carries_the_note(self) -> None:
        cell, mapping = _row(self._only_retry(), "T1053.005")

        assert MARKER in cell.note
        assert mapping.independent_layers == []

    def test_the_markdown_prints_the_note(self) -> None:
        assert MARKER in _markdown(self._only_retry())

    def test_an_unmarked_claim_carries_no_note(self) -> None:
        cell, _mapping = _row(_answers(retry=False), "T1547.001")

        assert MARKER not in cell.note
