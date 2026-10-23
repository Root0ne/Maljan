"""The mediator reads each analyst's claims once.

An analyst's first answer reaches the mediation as its ISR summary, and the
mediation used to append every ISR summary again under the structured-claims
heading: in a first round each claim was sent twice. A summary that is already
one of the reports word for word is now left out of that block; a revised
report, which is the analyst's own words beside the claims in force, keeps both.
"""

from __future__ import annotations

import time

from maljan.agents.judge_agent import mediation_reports_text
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

ISR_HEADING = "=== STRUCTURED CLAIMS (ISR) ==="


def _isr(agent: str, *claims: str, revision_round: int = 0) -> AgentISR:
    return AgentISR(
        agent_id=agent,
        domain=agent,
        revision_round=revision_round,
        claims=[
            ClaimEvidence(claim=text, evidence_ref=f"[ev_{i + 1:04d}]", confidence=0.8)
            for i, text in enumerate(claims)
        ],
    )


def test_a_first_round_sends_each_summary_once() -> None:
    isrs = {
        "static": _isr("static", "The file is a DLL.", "It imports five names."),
        "dynamic": _isr("dynamic", "It contacts two hosts."),
    }
    reports = {name: isr.to_text_summary() for name, isr in isrs.items()}

    text = mediation_reports_text(reports, isrs)

    assert ISR_HEADING not in text
    for name, isr in isrs.items():
        assert text.count(isr.to_text_summary()) == 1
        assert f"--- {name.upper()} ANALYST ---" in text
    assert text.count("Claim 1: The file is a DLL. | Evidence: [ev_0001] | Confidence: 0.80") == 1


def test_a_revised_report_keeps_the_claims_in_force_beside_it() -> None:
    first = _isr("static", "The file is a DLL.")
    revised = _isr("static", "The file is a DLL.", "It is not packed.", revision_round=1)
    unchanged = _isr("network", "It contacts two hosts.")
    reports = {
        "static": "CLAIM 1: The file is a DLL.\nCLAIM 2: It is not packed.",
        "network": unchanged.to_text_summary(),
    }

    text = mediation_reports_text(reports, {"static": revised, "network": unchanged})

    assert ISR_HEADING in text
    block = text.split(ISR_HEADING, 1)[1]
    assert revised.to_text_summary() in block
    assert unchanged.to_text_summary() not in block
    assert text.count(unchanged.to_text_summary()) == 1
    assert first.to_text_summary() not in block


def test_the_text_is_as_before_where_no_summary_repeats_a_report() -> None:
    isr = _isr("static", "The file is a DLL.")
    reports = {"static": "prose of its own"}

    assert mediation_reports_text(reports, {"static": isr}) == (
        f"--- STATIC ANALYST ---\nprose of its own\n\n{ISR_HEADING}\n[ISR] {isr.to_text_summary()}"
    )
    assert mediation_reports_text(reports, None) == "--- STATIC ANALYST ---\nprose of its own"
    assert mediation_reports_text(reports, {"static": AgentISR(agent_id="s", domain="s")}) == (
        "--- STATIC ANALYST ---\nprose of its own"
    )


def test_the_assembly_is_linear_in_the_number_of_analysts() -> None:
    def build(n: int) -> float:
        isrs = {f"a{i}": _isr(f"a{i}", *(f"claim {j} of {i}" for j in range(20))) for i in range(n)}
        reports = {name: isr.to_text_summary() for name, isr in isrs.items()}
        started = time.perf_counter()
        mediation_reports_text(reports, isrs)
        return time.perf_counter() - started

    small, large = build(50), build(500)
    assert large < small * 40
