"""The capability check marks what a report claims, never a value and never an absence.

A benign control's report printed four marks and none of them was right:

- two on the host-identifier row ``/SSH/Auth/Credentials`` — the client's own
  configuration panel path, a value the sample holds, and the purpose written
  beside it, which restates the value's words;
- two on sentences saying persistence is absent: "the specific APIs required
  for persistence are absent" (the term ends the subject of "are absent") and
  "It does not import the registry APIs required for persistence" (the term
  ends the object of a negated verb).

And its four real over-claims — keylogging, evading detection and debuggers,
anti-debugging, "a repacked legitimate binary" — were not marked: capa's rule
names ("log keystrokes via polling", "check for time delay via GetTickCount")
grounded the first three, and no term read evasion or packing.
"""

from __future__ import annotations

from maljan.pipeline.validation import (
    CapabilityGrounding,
    behaviour_pattern,
    masked_values,
    section_capability_violations,
    states_absence,
    ungrounded_capabilities,
)
from maljan.reporting.models import EvidenceSection, FileHashes, MalwareReport, SampleIdentity
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

KEYLOGGING = "The sample performs keylogging and captures clipboard data [ev_0008, ev_0009]."
EVADES = "The sample attempts to evade detection and debuggers [ev_0008, ev_0009]."
ANTI_DEBUGGING = "The sample employs anti-debugging and evasion techniques to hinder analysis."
REPACKED = (
    "The presence of a valid signature does not preclude malicious functionality, which may "
    "indicate a repacked legitimate binary."
)
NEGATED_OBJECT = (
    "It does not import the registry APIs required for persistence (e.g., RegCreateKeyEx, "
    "RegSetValueEx) and does not contain strings associated with common persistence locations "
    "such as Run keys or scheduled tasks."
)
ABSENT_SUBJECT = (
    "While the sample imports advapi32.dll, the specific APIs required for persistence are absent."
)


def _benign_run() -> tuple[MalwareReport, dict[str, AgentISR]]:
    """A signed client's run: capa and YARA matched rules, and the analyst claimed no technique."""
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="b" * 64), file_type="pe"),
        sections=[
            EvidenceSection(
                key="capa_capabilities",
                title="capa capabilities",
                kind="table",
                columns=["Namespace", "Rule", "MBC"],
                rows=[
                    ["collection/keylog", "log keystrokes via polling", "Keylogging::Polling"],
                    [
                        "anti-analysis/anti-debugging/debugger-detection",
                        "check for time delay via GetTickCount",
                        "Anti-Behavioral Analysis::Debugger Detection",
                    ],
                    ["", "delay execution", "Dynamic Analysis Evasion::Delayed Execution"],
                    ["communication/c2/shell", "create reverse shell", ""],
                ],
                source="tool:capa",
            ),
            EvidenceSection(
                key="yara_matches",
                title="YARA rule matches",
                kind="table",
                columns=["Rule", "Tags", "Where"],
                rows=[["keylogger_apis", "", "offset=12"]],
                source="tool:yara_scan",
            ),
            EvidenceSection(
                key="pe_header",
                title="PE header",
                kind="table",
                columns=["Field", "Value"],
                rows=[["machine", "AMD64"]],
                source="tool:pe_info",
            ),
        ],
    )
    isr = AgentISR(
        agent_id="static",
        domain="static",
        claims=[
            ClaimEvidence(
                claim="The binary is a legitimate, digitally signed terminal client.",
                evidence_ref="[ev_0003] signature",
                confidence=1.0,
                technique_id=None,
            )
        ],
    )
    return report, {"static": isr}


def _grounding() -> CapabilityGrounding:
    return CapabilityGrounding.from_report(*_benign_run())


def _paths(text: str) -> set[str]:
    return {v.path for v in ungrounded_capabilities(text, _grounding())}


class TestTheRealOverClaimsAreMarked:
    def test_keylogging_on_a_capa_rule_name_is_asked(self) -> None:
        assert _paths(KEYLOGGING) == {"keylogging"}

    def test_evading_detection_and_debuggers_is_asked(self) -> None:
        assert _paths(EVADES) == {"anti-analysis"}

    def test_anti_debugging_and_evasion_techniques_are_asked(self) -> None:
        assert _paths(ANTI_DEBUGGING) == {"anti-analysis"}

    def test_a_repacked_binary_is_asked(self) -> None:
        assert _paths(REPACKED) == {"anti-analysis"}

    def test_a_published_technique_still_grounds_the_word(self) -> None:
        report, isrs = _benign_run()
        isrs["static"].claims.append(
            ClaimEvidence(
                claim="It records keystrokes with a polling loop.",
                evidence_ref="[ev_0008] capa",
                confidence=0.8,
                technique_id="T1056.001",
            )
        )

        grounding = CapabilityGrounding.from_report(report, isrs)

        assert ungrounded_capabilities(KEYLOGGING, grounding) == []


class TestARuleMatchIsSaidNotClaimed:
    def test_a_sentence_that_says_capa_matched_is_not_a_claim(self) -> None:
        text = "capa matched its rule 'log keystrokes via polling' in the input handling code."

        assert _paths(text) == set()

    def test_a_rule_name_grounds_nothing(self) -> None:
        grounding = _grounding()

        assert "keystroke" not in grounding.evidence_text
        assert "debugger" not in grounding.evidence_text
        assert "capa_capabilities" in grounding.evidence_keys


class TestAValueIsNotAClaim:
    def test_a_configuration_path_row_is_not_marked(self) -> None:
        payload = {
            "identifiers": [
                {
                    "kind": "Path",
                    "value": "/SSH/Auth/Credentials",
                    "purpose": "Configuration path for SSH authentication credentials",
                    "evidence_refs": ["ev_0006"],
                }
            ]
        }

        assert section_capability_violations(payload, _grounding()) == []

    def test_a_purpose_that_claims_more_than_its_value_is_still_marked(self) -> None:
        payload = {
            "identifiers": [
                {
                    "kind": "Path",
                    "value": "/SSH/Auth/Credentials",
                    "purpose": "Used to harvest stored browser passwords for a stealer",
                    "evidence_refs": ["ev_0006"],
                }
            ]
        }

        paths = {v.path for v in section_capability_violations(payload, _grounding())}

        assert paths == {"credential_theft"}

    def test_a_path_a_key_a_quote_and_a_code_span_are_not_read(self) -> None:
        text = (
            "The strings include /SSH/Auth/Credentials, "
            "HKCU\\Software\\Keylogger\\Settings, the name `persist.dll` and the label "
            '"backdoor account".'
        )

        assert _paths(text) == set()

    def test_the_mask_keeps_every_position(self) -> None:
        text = "It holds `a b` and /x/y/z here."

        masked = masked_values(text)

        assert len(masked) == len(text)
        assert masked.index("here") == text.index("here")

    def test_a_heading_is_not_a_claim(self) -> None:
        payload = {"title": "Persistence", "body": "No autostart entry was read.", "refs": []}

        assert section_capability_violations(payload, _grounding()) == []


class TestAnAbsenceIsNotMarked:
    def test_the_object_of_a_negated_verb(self) -> None:
        assert _paths(NEGATED_OBJECT) == set()

    def test_the_end_of_the_subject_of_are_absent(self) -> None:
        assert _paths(ABSENT_SUBJECT) == set()

    def test_the_subject_of_is_not_supported(self) -> None:
        text = "The presence of persistence capabilities is not supported by the evidence."

        assert _paths(text) == set()

    def test_rather_than_sets_the_term_aside(self) -> None:
        text = "Its imports are standard for a client application rather than a C2 agent."

        assert _paths(text) == set()

    def test_a_claim_after_the_negated_object_is_still_marked(self) -> None:
        text = "It does not import the APIs required for persistence and it logs keystrokes."

        assert _paths(text) == {"keylogging"}

    def test_the_absence_question_reads_the_same_subject(self) -> None:
        """One reading: the sentence the mark now spares is one the absence question asks."""
        pattern = behaviour_pattern("T1547")

        assert states_absence(ABSENT_SUBJECT, pattern)
        assert states_absence(NEGATED_OBJECT, pattern)
        assert not states_absence("It writes a Run key for persistence.", pattern)
