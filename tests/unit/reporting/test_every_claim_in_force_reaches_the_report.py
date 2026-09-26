"""Every analyst claim in force reaches the report: cited, named, or listed.

The report models are handed the claims; what they leave out of the body was
gone with nothing saying so. After the body is composed a deterministic check
reads it claim by claim, and the report lists every claim in force the body
does not cite by its label and whose code locations or API names the body does
not all name, with the names it lacks; a claim that names none is read by its
words.

The fixture is one run's claims in force and the body its report models wrote
over them.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from maljan.reporting.claim_coverage import (
    body_text,
    claim_label,
    claims_in_force,
    claims_not_discussed,
)
from maljan.reporting.composer import ANALYST_CLAIMS_HEADING, _bundle_text
from maljan.reporting.evidence_bundles import bundle_for
from maljan.reporting.models import (
    ClaimNotDiscussed,
    FileHashes,
    KeyFinding,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
    TTPMapping,
)
from maljan.reporting.narrative_agent import CLAIMS_IN_FORCE_HEADING, build_prompt_text
from maljan.reporting.renderers.markdown import CLAIMS_NOT_DISCUSSED_TITLE, MarkdownRenderer

RUN: dict[str, Any] = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "fixtures"
        / "claims"
        / "claims_in_force_and_composed_body.json"
    ).read_text(encoding="utf-8")
)


def _isrs(claims: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    return {
        agent: SimpleNamespace(agent_id=agent, claims=[SimpleNamespace(**row) for row in rows])
        for agent, rows in claims.items()
    }


_IDENTITY = SampleIdentity(hashes=FileHashes(sha256="a" * 64))


def _run_report() -> MalwareReport:
    return _report(**{k: v for k, v in RUN["body"].items() if v is not None})


def _report(**body: Any) -> MalwareReport:
    return MalwareReport(identity=_IDENTITY, **body)


def _claim(text: str, evidence: str = "[ev_0001]") -> dict[str, Any]:
    return {"claim": text, "evidence_ref": evidence, "confidence": 0.8}


class TestTheRunsClaimsAgainstItsBody:
    def test_the_claims_the_body_does_not_carry_are_listed_by_analyst_and_number(self) -> None:
        rows = claims_not_discussed(_run_report(), _isrs(RUN["claims"]))
        listed = [claim_label(row.agent, row.claim_number) for row in rows]

        assert sum(len(v) for v in RUN["claims"].values()) == 87
        for label in ("triage claim 13", "static claim 13", "dynamic claim 4"):
            assert label in listed
        # A gating claim whose other checks the body carries: the one clause it
        # dropped shows through the function names only that clause names.
        assert "static claim 15" in listed
        assert len(listed) == 23

    def test_each_row_carries_the_claim_whole_and_the_count_found(self) -> None:
        rows = claims_not_discussed(_run_report(), _isrs(RUN["claims"]))
        by_label = {claim_label(r.agent, r.claim_number): r for r in rows}

        row = by_label["static claim 13"]
        assert row.claim == RUN["claims"]["static"][12]["claim"]
        assert row.evidence_ref == RUN["claims"]["static"][12]["evidence_ref"]
        assert "VirtualAllocEx" in row.missing
        gating = by_label["static claim 15"]
        assert "FUN_0x68e8" in gating.missing
        assert gating.counted == "names"

    def test_the_report_prints_them_in_their_own_section(self) -> None:
        report = _run_report()
        report.claims_not_discussed = claims_not_discussed(report, _isrs(RUN["claims"]))

        markdown = MarkdownRenderer().render(report)
        section = markdown[markdown.index(CLAIMS_NOT_DISCUSSED_TITLE) :]

        assert f"### 13.1 {CLAIMS_NOT_DISCUSSED_TITLE}" in markdown
        assert "**static claim 15** (confidence 0.85; the body never names " in section
        assert "FUN_0x68e8" in section
        assert section.count("\n- **") == 23


class TestTheRule:
    def test_a_claim_cited_by_its_label_is_covered(self) -> None:
        report = _report(executive_summary="As static claim 2 says, the table is read at start.")
        isrs = _isrs({"static": [_claim("First."), _claim("FUN_0x4a10 calls ReadTable.")]})

        listed = [r.claim_number for r in claims_not_discussed(report, isrs)]

        assert listed == [1]

    def test_an_address_plus_an_image_base_is_the_same_place(self) -> None:
        report = _report(
            technical_analysis=TechnicalAnalysis(
                evasion_antiforensics=TechnicalSubsection(
                    title="t", body="FUN_0x68e8 checks the adapter length through GetTableInfo."
                )
            )
        )
        isrs = _isrs({"static": [_claim("FUN_1400068e8 calls GetTableInfo to check lengths.")]})

        assert claims_not_discussed(report, isrs) == []

    def test_one_missing_name_lists_the_claim_whatever_the_body_carries(self) -> None:
        body = "FUN_0x4010 calls OpenTable and CloseTable, and FUN_0x4020 reads 0x100 bytes."
        report = _report(key_findings=[KeyFinding(text=body)])
        isrs = _isrs(
            {
                "dynamic": [
                    _claim(
                        "FUN_0x4010 and FUN_0x4020 call OpenTable, CloseTable and ReadTable; "
                        "FUN_0x4030 checks a flag of 0x8664."
                    )
                ]
            }
        )

        (row,) = claims_not_discussed(report, isrs)

        # A bare 0x value in a claim is not a code location: 0x8664 is not asked for.
        assert row.missing == ["FUN_0x4030", "ReadTable"]

    def test_an_address_matches_exactly_not_by_any_shared_ending(self) -> None:
        report = _report(executive_summary="The routine at 0x1000 sets it up; so does 0x20000.")
        isrs = _isrs(
            {
                "static": [
                    _claim("FUN_0x11000 sets it up."),
                    _claim("FUN_0x10000 sets it up too."),
                    _claim("FUN_0x401000 sets it up as well."),
                ]
            }
        )

        listed = [r.claim_number for r in claims_not_discussed(report, isrs)]

        # 0x11000 only ends in 1000; 0x10000 has as many digits as 0x20000; 0x401000
        # is 0x1000 plus a 64 KiB-aligned base.
        assert listed == [1, 2]

    def test_a_claim_that_names_no_identifier_is_read_by_its_words(self) -> None:
        body = "The loader waits before its first contact and then repeats on a schedule."
        report = _report(executive_summary=body)
        isrs = _isrs(
            {
                "network": [
                    _claim("The loader waits before first contact, then repeats."),
                    _claim("Nothing about accounts, printers or scanners appears anywhere."),
                ]
            }
        )

        rows = claims_not_discussed(report, isrs)

        assert [(r.claim_number, r.counted) for r in rows] == [(2, "words")]

    def test_the_attack_table_s_quotes_are_not_the_body(self) -> None:
        text = "FUN_0x4a10 reads the table through ReadTable."
        report = _report(
            ttp_mappings=[
                TTPMapping(technique_id="T0001", technique_name="n", evidence_quotes=[text])
            ]
        )
        isrs = _isrs({"static": [_claim(text)]})

        assert text not in body_text(report)

        assert [r.claim_number for r in claims_not_discussed(report, isrs)] == [1]


class TestTheReportModelsAreHandedEveryClaimUnderItsLabel:
    def test_every_section_bundle_shows_each_claim_under_its_label(self) -> None:
        isrs = _isrs(RUN["claims"])
        text = _bundle_text("execution_flow", bundle_for("execution_flow", _report(), None, isrs))

        assert ANALYST_CLAIMS_HEADING in text
        for claim in claims_in_force(isrs):
            assert f"[{claim.label}] " in text

    def test_the_narrative_round_is_handed_every_claim_in_force_whole(self) -> None:
        isrs = _isrs(RUN["claims"])
        text = build_prompt_text(_report(), isrs)

        assert CLAIMS_IN_FORCE_HEADING in text
        for claim in claims_in_force(isrs):
            assert f"[{claim.label}] {claim.claim}" in text

    def test_without_claims_the_narrative_prompt_has_no_claims_block(self) -> None:
        assert CLAIMS_IN_FORCE_HEADING not in build_prompt_text(_report())


def test_a_stored_report_without_the_field_renders_no_section() -> None:
    report = _report()
    assert report.claims_not_discussed == []
    assert CLAIMS_NOT_DISCUSSED_TITLE not in MarkdownRenderer().render(report)


def test_the_row_model_round_trips() -> None:
    row = ClaimNotDiscussed(agent="a", claim_number=1, claim="c", carried=1, named=3)
    assert ClaimNotDiscussed.model_validate(row.model_dump()) == row
