"""A technique only a rule match stands behind is said to be one, and grounds no capability.

A run published five techniques from the project's own YARA rules, each
matching a single string in a large file, with no analyst claiming any of them;
one of them then let "credential theft" through the ungrounded-capability
check. The publish rule is unchanged — the judge named them and a rule matched
— but the ATT&CK table now says how much matched, and such a technique grounds
no capability word.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from maljan.analysis.corroboration import rule_match_only
from maljan.pipeline.evidence_summary import yara_rule_strings
from maljan.pipeline.validation import CapabilityGrounding, narrative_capability_violations
from maljan.reporting.models import (
    EvidenceSection,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TTPMapping,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer

RULE = "example_credential_rule"


def _yara_entry() -> Any:
    return SimpleNamespace(
        id="ev_0007",
        tool="yara_scan",
        structured={
            "matches": [
                {
                    "rule": RULE,
                    "meta": {"technique_id": "T1003"},
                    "strings": [
                        {"identifier": "$0", "offset": 10},
                        {"identifier": "$0", "offset": 90},
                    ],
                }
            ]
        },
    )


def _report(claimed_by: list[str]) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        ttp_mappings=[
            TTPMapping(
                technique_id="T1003",
                technique_name="OS Credential Dumping",
                tactic="TA0006",
                tactic_name="Credential Access",
                confidence=0.8,
                contributing_layers=["judge"],
            )
        ],
        run_summary={
            "corroboration": {"T1003": {"asserted_by": ["yara"], "claimed_by": claimed_by}}
        },
        rule_match_strings=yara_rule_strings([_yara_entry()]),
        sections=[
            EvidenceSection(
                key="yara_matches",
                title="YARA matches",
                kind="table",
                columns=["Rule", "Tags", "Where"],
                rows=[[RULE, "", "offset=10, identifier=$0"]],
            )
        ],
    )


SUMMARY = {"executive_summary": "The sample is built for credential theft."}


class TestTheCount:
    def test_distinct_strings_are_counted_not_offsets(self) -> None:
        assert yara_rule_strings([_yara_entry()]) == {
            "T1003": [{"rule": RULE, "strings": 1, "source": "yara"}]
        }


class TestEachRowIsReadWithTheLayerThatMatchedIt:
    """A row is shown under the layer that matched it, by its declared label, never by a name."""

    def test_an_operator_signature_tool_names_its_own_rules(self) -> None:
        from maljan.core.declared_reading import shipped_by_name, stored_record

        # Declared as the shipped signature-rule tool is, under a label of its own.
        facts = shipped_by_name()["yara_scan"].model_copy(update={"source": "sigs"})
        entry = SimpleNamespace(
            id="ev_0003",
            tool="sigscan__match",
            source="mcp:sigscan",
            facts=stored_record(facts),
            structured=_yara_entry().structured,
        )
        strings = yara_rule_strings([entry])
        assert strings == {"T1003": [{"rule": RULE, "strings": 1, "source": "sigs"}]}
        report = _report([]).model_copy(
            update={
                "rule_match_strings": strings,
                "run_summary": {
                    "corroboration": {"T1003": {"asserted_by": ["sigs"], "claimed_by": []}}
                },
            }
        )
        assert rule_match_only(report) == {
            "T1003": f"rule match only (sigs `{RULE}`, 1 string), no analyst claim"
        }

    def test_a_row_of_one_layer_is_never_shown_under_another(self) -> None:
        report = _report([]).model_copy(
            update={
                "run_summary": {
                    "corroboration": {"T1003": {"asserted_by": ["sigs"], "claimed_by": []}}
                }
            }
        )
        assert rule_match_only(report) == {"T1003": "rule match only (sigs), no analyst claim"}

    def test_a_stored_row_without_its_layer_is_the_shipped_signature_tools(self) -> None:
        stored = {"T1003": [{"rule": RULE, "strings": 1}]}
        report = _report([]).model_copy(update={"rule_match_strings": stored})
        assert rule_match_only(report) == {
            "T1003": f"rule match only (yara `{RULE}`, 1 string), no analyst claim"
        }


class TestTheNote:
    def test_a_rule_alone_is_named_with_how_much_matched(self) -> None:
        assert rule_match_only(_report([])) == {
            "T1003": f"rule match only (yara `{RULE}`, 1 string), no analyst claim"
        }

    def test_an_analyst_claim_removes_the_note(self) -> None:
        assert rule_match_only(_report(["static"])) == {}

    def test_the_attack_table_prints_it(self) -> None:
        text = MarkdownRenderer().render(_report([]))

        assert f"rule match only (yara `{RULE}`, 1 string), no analyst claim" in text


class TestTheGrounding:
    def test_a_rule_alone_grounds_no_capability_word(self) -> None:
        report = _report([])
        grounding = CapabilityGrounding.from_report(report)

        paths = [v.path for v in narrative_capability_violations(SUMMARY, grounding)]

        assert paths == ["credential_theft"]

    def test_a_claimed_technique_still_grounds_it(self) -> None:
        report = _report(["static"])
        grounding = CapabilityGrounding.from_report(report)

        assert narrative_capability_violations(SUMMARY, grounding) == []
