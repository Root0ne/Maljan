"""A capability word in the report is grounded by what the run found, and by nothing else.

A benign control report carried three over-claims that were neither asked about
nor marked:

- "Despite this attribution, the binary implements defense evasion and
  anti-forensics capabilities." — no term covered anti-forensics, and the id
  that would have (T1070, Indicator Removal) was published from a claim that
  said "does not contain any obvious defense evasion mechanisms";
- "We assess that the sample likely uses these registry APIs to establish
  persistence" — grounded by T1547, published from an absence claim, by that
  claim's own words, and by the API catalogue's row "CreateMutexA |
  persistence", which says what a catalogue lists an API under;
- "the presence of these capabilities suggests it may be used for
  reconnaissance or credential harvesting" — grounded by T1555, published
  from an absence claim, and by the sample's own settings path
  "/SSH/Auth/Credentials".

Each ground is closed where it is wrong, with the capability check's own
negation reader: a claim of absence grounds nothing, a matrix row the run did
not publish grounds nothing, a reference table grounds nothing, the sample's
own strings ground nothing by their words, and a word in the evidence grounds
only where it is said rather than denied.
"""

from __future__ import annotations

from maljan.pipeline.validation import (
    UNGROUNDED_CAPABILITY_CODE,
    CapabilityGrounding,
    ungrounded_capabilities,
)
from maljan.reporting.models import (
    CapabilityCell,
    EvidenceSection,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TTPMapping,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

ANTI_FORENSICS = (
    "Despite this attribution, the binary implements defense evasion and anti-forensics "
    "capabilities."
)
PERSISTENCE = (
    "We assess that the sample likely uses these registry APIs to establish persistence, but "
    "the specific keys or values are not present in the static artifacts."
)
CREDENTIALS = (
    "While the sample is signed and presents as a legitimate tool, the presence of these "
    "capabilities suggests it may be used for reconnaissance or credential harvesting [ev_0003]."
)


def _absent(text: str, technique_id: str | None) -> ClaimEvidence:
    claim = ClaimEvidence(
        claim=text, evidence_ref="[ev_0006] strings", confidence=0.9, technique_id=technique_id
    )
    claim.states_absence = technique_id is not None
    return claim


def _benign_run(*extra_claims: ClaimEvidence) -> tuple[MalwareReport, dict[str, AgentISR]]:
    """The benign run's evidence, as the report after the absence claims were asked."""
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_type="pe"),
        ttp_mappings=[TTPMapping(technique_id="T1027", technique_name="Obfuscated Files")],
        capability_matrix=[
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id=tid,
                technique_name=name,
                not_published="the only claims that name it say the behaviour is absent",
            )
            for tid, name in (
                ("T1070", "Indicator Removal"),
                ("T1547", "Boot or Logon Autostart Execution"),
                ("T1555", "Credentials from Password Stores"),
            )
        ],
        sections=[
            EvidenceSection(
                key="tool_api_capability_capabilities",
                title="Api capability: capabilities",
                kind="table",
                columns=["api", "category", "behaviours"],
                rows=[
                    ["CreateMutexA", "persistence", "persistence"],
                    ["CreateFileMappingA", "process_injection", "process_injection"],
                ],
                source="tool:api_capability",
            ),
            EvidenceSection(
                key="iocs",
                title="Indicators recovered from the sample",
                kind="table",
                columns=["Kind", "Value"],
                rows=[["path", "/SSH/Auth/Credentials"]],
                source="tool:iocs_from_file",
            ),
            EvidenceSection(
                key="capa_capabilities",
                title="capa capabilities",
                kind="table",
                columns=["Namespace", "Rule"],
                rows=[["data-manipulation/encoding/xor", "encode data using XOR"]],
                source="tool:capa",
            ),
        ],
    )
    isr = AgentISR(
        agent_id="static",
        domain="static",
        claims=[
            _absent(
                "The binary does not contain any obvious defense evasion mechanisms in its "
                "static analysis.",
                "T1070",
            ),
            _absent(
                "The binary does not contain any obvious persistence mechanisms in its static "
                "analysis.",
                "T1547",
            ),
            _absent(
                "The binary does not contain any obvious credential access mechanisms in its "
                "static analysis.",
                "T1555",
            ),
            # No id, so nothing to ask: its words still say the behaviour is absent.
            _absent(
                "The binary does not exhibit obvious persistence mechanisms in its static "
                "imports or strings.",
                None,
            ),
            *extra_claims,
        ],
    )
    return report, {"static": isr}


def _paths(text: str, report: MalwareReport, isrs: dict[str, AgentISR]) -> set[str]:
    grounding = CapabilityGrounding.from_report(report, isrs)
    found = ungrounded_capabilities(text, grounding)
    assert {v.code for v in found} <= {UNGROUNDED_CAPABILITY_CODE}
    return {v.path for v in found}


class TestTheBenignRunsOverClaims:
    def test_anti_forensics_is_asked_about(self) -> None:
        assert "anti-forensics" in _paths(ANTI_FORENSICS, *_benign_run())

    def test_persistence_is_asked_about(self) -> None:
        assert _paths(PERSISTENCE, *_benign_run()) == {"persistence"}

    def test_credential_harvesting_is_asked_about(self) -> None:
        assert _paths(CREDENTIALS, *_benign_run()) == {"credential_theft"}

    def test_the_sentence_is_quoted_for_its_mark(self) -> None:
        report, isrs = _benign_run()
        (violation,) = ungrounded_capabilities(
            PERSISTENCE, CapabilityGrounding.from_report(report, isrs)
        )

        assert violation.quoted == (PERSISTENCE,)


class TestWhatStillGrounds:
    def test_an_analyst_claim_that_says_it_grounds_the_word(self) -> None:
        positive = ClaimEvidence(
            claim="The sample writes a Run key so that it persists across reboots.",
            evidence_ref="[ev_0007] registry write",
            confidence=0.8,
            technique_id=None,
        )

        assert _paths(PERSISTENCE, *_benign_run(positive)) == set()

    def test_a_published_technique_grounds_the_word(self) -> None:
        report, isrs = _benign_run()
        report.ttp_mappings.append(
            TTPMapping(technique_id="T1555", technique_name="Credentials from Password Stores")
        )

        assert _paths(CREDENTIALS, report, isrs) == set()

    def test_a_tool_that_observed_the_behaviour_grounds_the_word(self) -> None:
        report, isrs = _benign_run()
        report.sections.append(
            EvidenceSection(
                key="dynamic_notes",
                title="Sandbox",
                kind="text",
                text="The sample cleared the Security event log after it ran.",
                source="tool:sandbox_report",
            )
        )

        assert "anti-forensics" not in _paths(ANTI_FORENSICS, report, isrs)

    def test_a_negated_mention_in_one_cell_does_not_reach_the_next(self) -> None:
        report, isrs = _benign_run()
        report.sections.append(
            EvidenceSection(
                key="notes",
                title="Notes",
                kind="table",
                rows=[["no"], ["persistence via a Run key observed"]],
                source="tool:sandbox_report",
            )
        )

        assert _paths(PERSISTENCE, report, isrs) == set()
