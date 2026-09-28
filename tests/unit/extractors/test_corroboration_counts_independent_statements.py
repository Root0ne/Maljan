"""Corroboration counts what the analysts said independently, not how many said it.

A local run printed a contradicted technique "corroborated (named by 6
analyst layers)": four analysts had written the same sentence word for word,
one of them twice, and a fifth layer was counted for its summary title, which
it listed under five techniques. Statements with the same normalised text now
count once, the report says how many were identical, and a finding's title is
not a statement.
"""

from __future__ import annotations

from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.reporting.renderers.markdown import _corroborated_words
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, Finding

COPIED = "The sample persists by writing a shortcut into the Startup folder."


def _claim(text: str, tid: str = "T1547.001") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref="[ev_0001]", confidence=0.9, technique_id=tid)


def _isr(domain: str, *claims: ClaimEvidence, findings: list[Finding] | None = None) -> AgentISR:
    return AgentISR(agent_id=domain, domain=domain, claims=list(claims), findings=findings or [])


def _mapping(isrs: dict[str, AgentISR], tid: str = "T1547.001"):
    cells, mappings = build_capability_matrix(stix_output=None, isr_reports=isrs)
    cell = next(c for c in cells if c.technique_id == tid)
    mapping = next((m for m in mappings if m.technique_id == tid), None)
    return cell, mapping


def test_the_same_sentence_from_three_layers_is_one_independent_statement() -> None:
    isrs = {
        "static": _isr("static", _claim(COPIED)),
        "dynamic": _isr("dynamic", _claim(COPIED.upper())),
        "network": _isr("network", _claim(f"  {COPIED}  "), _claim(COPIED)),
    }

    cell, mapping = _mapping(isrs)

    assert mapping is not None
    assert mapping.independent_layers == ["static"]
    assert mapping.identical_statements == 3
    assert mapping.is_corroborated is False
    assert cell.identical_statements == 3


def test_two_layers_in_their_own_words_corroborate() -> None:
    isrs = {
        "static": _isr("static", _claim(COPIED)),
        "dynamic": _isr("dynamic", _claim("A .lnk file is written under the Startup folder.")),
        "network": _isr("network", _claim(COPIED)),
    }

    _cell, mapping = _mapping(isrs)

    assert mapping is not None
    assert mapping.independent_layers == ["static", "dynamic"]
    assert mapping.identical_statements == 1
    assert mapping.is_corroborated is True


def test_a_findings_title_is_not_a_statement() -> None:
    title = "Example Loader with Reconnaissance and Exfiltration"
    isrs = {
        "static": _isr("static", _claim(COPIED)),
        "network": _isr(
            "network", findings=[Finding(title=title, technique_ids=["T1547.001"], confidence=0.9)]
        ),
    }

    cell, mapping = _mapping(isrs)

    assert not any(title in statement for statement in cell.statements)
    assert mapping is not None
    assert mapping.independent_layers == ["static"]
    assert mapping.is_corroborated is False


def test_a_findings_detail_is_a_statement() -> None:
    isrs = {
        "static": _isr("static", _claim(COPIED)),
        "network": _isr(
            "network",
            findings=[
                Finding(
                    title="Persistence",
                    detail="It adds a shortcut to the user's Startup folder at install.",
                    technique_ids=["T1547.001"],
                )
            ],
        ),
    }

    cell, mapping = _mapping(isrs)

    assert mapping is not None
    assert mapping.independent_layers == ["static", "network"]
    assert any("It adds a shortcut" in statement for statement in cell.statements)


def test_the_row_says_how_many_statements_were_identical() -> None:
    isrs = {
        "static": _isr("static", _claim(COPIED)),
        "dynamic": _isr("dynamic", _claim("A .lnk file is written under the Startup folder.")),
        "network": _isr("network", _claim(COPIED)),
    }
    _cell, mapping = _mapping(isrs)

    said = _corroborated_words(mapping, [])

    assert said.startswith(", corroborated")
    assert "2 analyst layers in independent statements" in said
    assert "1 statement identical to another and counted once" in said


def test_a_copied_row_says_it_is_not_corroborated_and_why() -> None:
    isrs = {
        "static": _isr("static", _claim(COPIED)),
        "dynamic": _isr("dynamic", _claim(COPIED)),
    }
    _cell, mapping = _mapping(isrs)

    said = _corroborated_words(mapping, [])

    assert not said.startswith(", corroborated")
    assert "not corroborated" in said
    assert "2 analyst layers name it in 1 independent statement" in said
    assert "1 statement identical to another and counted once" in said
