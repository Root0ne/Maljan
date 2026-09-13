"""The capability matrix is a projection, and a projection adjusts nothing.

Two properties. A technique with no confidence, no evidence and no source is
not emitted at all — it would render as a "verified" capability and seed
fabricated prose. And everything that is emitted carries the number its source
put on it: the cap this module used to apply to an obfuscation or injection
claim whose static evidence it could not find is gone, because a matrix builder
discounting an analyst's confidence is the analyst's finding rewritten by
something that read none of the evidence.
"""

from __future__ import annotations

from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _bundle(*, techniques: list[str], relationships: list[dict] | None = None) -> dict:
    objects: list[dict] = [
        {
            "type": "attack-pattern",
            "id": f"attack-pattern--{tid}",
            "name": tid,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
        }
        for tid in techniques
    ]
    objects.extend(relationships or [])
    return {"type": "bundle", "objects": objects}


def _isr(agent_id: str, *claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id=agent_id, domain=agent_id, claims=list(claims))


def _claim(technique_id: str, confidence: float = 0.8, claim: str = "it does the thing"):
    return ClaimEvidence(
        claim=claim, evidence_ref="ref", confidence=confidence, technique_id=technique_id
    )


class TestSignalQuality:
    def test_a_technique_only_the_judge_named_is_kept_and_credited_to_it(self) -> None:
        """The judge putting a technique in the verdict is itself the source.
        Dropping the row would leave the verdict naming a technique the report
        it is printed in does not carry."""
        cells, mappings = build_capability_matrix(
            stix_output=_bundle(techniques=["T1000"]), isr_reports=None
        )

        assert [c.technique_id for c in cells] == ["T1000"]
        assert cells[0].contributing_layers == ["judge"]
        # The judge read the analysts, not the sample, so it corroborates
        # nothing on its own.
        assert mappings[0].is_corroborated is False

    def test_a_technique_nothing_asserted_is_dropped(self) -> None:
        cells, mappings = build_capability_matrix(stix_output=None, isr_reports=None)

        assert cells == [] and mappings == []

    def test_a_technique_with_evidence_but_no_confidence_is_kept(self) -> None:
        cells, _ = build_capability_matrix(
            stix_output=None,
            isr_reports={"static": _isr("static", _claim("T1059", confidence=0.0))},
        )

        assert {c.technique_id for c in cells} == {"T1059"}


class TestItProjectsTheJudgeAndTheAnalysts:
    def test_the_judges_relationship_confidence_is_carried_through(self) -> None:
        bundle = _bundle(
            techniques=["T1055"],
            relationships=[
                {
                    "type": "relationship",
                    "x_maljan_technique_id": "T1055",
                    "x_maljan_confidence": 0.77,
                    "x_maljan_contributing_agents": ["static", "dynamic"],
                }
            ],
        )

        cells, mappings = build_capability_matrix(stix_output=bundle, isr_reports=None)

        assert [c.confidence for c in cells] == [0.77]
        assert cells[0].contributing_layers == ["judge", "static", "dynamic"]
        assert mappings[0].is_corroborated is True

    def test_an_analyst_claim_adds_its_own_evidence_quote(self) -> None:
        cells, _ = build_capability_matrix(
            stix_output=_bundle(techniques=["T1055"]),
            isr_reports={"static": _isr("static", _claim("T1055", 0.6, "writes into a peer"))},
        )

        assert cells[0].evidence == ["writes into a peer"]
        assert cells[0].contributing_layers == ["judge", "static"]

    def test_an_obfuscation_claim_keeps_the_confidence_the_analyst_gave_it(self) -> None:
        """The cap used to pull this to 0.40 whenever no packer was detected."""
        cells, _ = build_capability_matrix(
            stix_output=None,
            isr_reports={"static": _isr("static", _claim("T1027", 0.85))},
        )

        assert [c.confidence for c in cells] == [0.85]

    def test_an_injection_claim_is_not_discounted_either(self) -> None:
        cells, _ = build_capability_matrix(
            stix_output=None,
            isr_reports={"static": _isr("static", _claim("T1055", 0.80))},
        )

        assert [c.confidence for c in cells] == [0.80]

    def test_a_claim_whose_technique_id_failed_validation_is_kept_and_marked(self) -> None:
        """Dropping it would delete the analyst's answer from the one surface a
        reader looks at, which is the behaviour this phase replaced."""
        isr = _isr("static", _claim("T1055", 0.9))
        isr.claims[0].technique_id_valid = False

        cells, mappings = build_capability_matrix(stix_output=None, isr_reports={"static": isr})

        assert [c.technique_id for c in cells] == ["T1055"]
        assert [c.technique_id_valid for c in cells] == [False]
        assert [m.technique_id_valid for m in mappings] == [False]

    def test_one_source_flagging_an_id_marks_the_row(self) -> None:
        """Two analysts, one of which kept an id it was told does not resolve."""
        good = _isr("dynamic", _claim("T1055", 0.5))
        bad = _isr("static", _claim("T1055", 0.9))
        bad.claims[0].technique_id_valid = False

        cells, _ = build_capability_matrix(
            stix_output=None, isr_reports={"static": bad, "dynamic": good}
        )

        assert [c.technique_id_valid for c in cells] == [False]

    def test_a_row_no_source_flagged_stays_valid(self) -> None:
        cells, _ = build_capability_matrix(
            stix_output=None, isr_reports={"static": _isr("static", _claim("T1055"))}
        )

        assert [c.technique_id_valid for c in cells] == [True]


class TestAJudgeIdIsCheckedLikeAnAnalystClaim:
    """The judge has no later loop to be told in, so its ids are checked here.

    Before this, an analyst that kept ``T0000`` was labelled in the report and
    a judge that emitted the same id was not — one rule for the model that had
    the last word.
    """

    @staticmethod
    def _catalogue(monkeypatch, known: set[str]) -> None:
        """Point the matrix's catalogue check at a stub, not at MITRE."""
        import maljan.tools.knowledge as knowledge

        def _validate(ids: list[str]) -> dict[str, object]:
            return {"invalid": [{"id": t} for t in ids if t not in known], "checked": len(ids)}

        monkeypatch.setattr(knowledge, "attck_validate", _validate, raising=False)

    def test_a_curated_placeholder_reaches_the_report_marked(self, monkeypatch) -> None:
        self._catalogue(monkeypatch, {"T1055"})

        cells, mappings = build_capability_matrix(
            stix_output=_bundle(techniques=["T0000"]),
            isr_reports={"static": _isr("static", _claim("T0000", 0.5))},
        )

        assert [c.technique_id for c in cells] == ["T0000"]
        assert [c.technique_id_valid for c in cells] == [False]
        assert [m.technique_id_valid for m in mappings] == [False]

    def test_a_plausible_but_unknown_judge_id_is_marked(self, monkeypatch) -> None:
        self._catalogue(monkeypatch, {"T1055"})
        bundle = _bundle(
            techniques=["T7777"],
            relationships=[
                {
                    "type": "relationship",
                    "x_maljan_technique_id": "T7777",
                    "x_maljan_confidence": 0.9,
                    "x_maljan_contributing_agents": ["static"],
                }
            ],
        )

        cells, _ = build_capability_matrix(stix_output=bundle, isr_reports=None)

        assert [(c.technique_id, c.technique_id_valid) for c in cells] == [("T7777", False)]
        # The judge's own number survives the marking untouched.
        assert cells[0].confidence == 0.9

    def test_a_misshapen_judge_id_is_marked(self, monkeypatch) -> None:
        self._catalogue(monkeypatch, {"T1055"})

        cells, _ = build_capability_matrix(
            stix_output=_bundle(techniques=["T123"]), isr_reports=None
        )

        assert [(c.technique_id, c.technique_id_valid) for c in cells] == [("T123", False)]

    def test_a_catalogued_judge_id_is_left_alone(self, monkeypatch) -> None:
        self._catalogue(monkeypatch, {"T1055"})

        cells, _ = build_capability_matrix(
            stix_output=_bundle(techniques=["T1055"]),
            isr_reports={"static": _isr("static", _claim("T1055"))},
        )

        assert [(c.technique_id, c.technique_id_valid) for c in cells] == [("T1055", True)]

    def test_an_unreachable_catalogue_marks_nothing(self, monkeypatch) -> None:
        """Marking every id as invented because MITRE is unreachable would be a
        worse failure than marking none."""
        import maljan.tools.knowledge as knowledge

        def _explode(ids: list[str]) -> dict[str, object]:
            raise RuntimeError("the catalogue is not readable")

        monkeypatch.setattr(knowledge, "attck_validate", _explode, raising=False)

        cells, _ = build_capability_matrix(
            stix_output=_bundle(techniques=["T7777"]),
            isr_reports={"static": _isr("static", _claim("T7777"))},
        )

        assert [c.technique_id_valid for c in cells] == [True]


class TestTheJudgeIsNotCountedAsCorroboration:
    def test_one_analyst_plus_the_judge_is_still_one_source(self) -> None:
        """The judge read the analysts rather than the sample. Counting it
        would turn one analyst's claim into two agreeing sources."""
        bundle = _bundle(
            techniques=["T1055"],
            relationships=[
                {
                    "type": "relationship",
                    "x_maljan_technique_id": "T1055",
                    "x_maljan_confidence": 0.8,
                    "x_maljan_contributing_agents": ["static"],
                }
            ],
        )

        _cells, mappings = build_capability_matrix(stix_output=bundle, isr_reports=None)

        assert mappings[0].contributing_layers == ["judge", "static"]
        assert mappings[0].is_corroborated is False
