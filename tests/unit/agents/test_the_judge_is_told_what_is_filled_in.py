"""The judge is asked only for what it decides, and told what the checks ask.

Measured over the stored runs: the retry the judge gets was spent in ten runs
on ``attck.missing_id`` — an attack-pattern with no technique id — which the
prompt itself invited with *"Omit technique ID if unsure"*, while the check
asks for the id or for the object to go. A rule the model cannot satisfy both
ways is a turn spent on the prompt, not on the sample. And about two fifths of
what the judge writes for its objects is ids and ``created`` / ``modified`` /
``spec_version`` stamps: the ids are minted after it answers and the stamps
overwritten, so every character of them is output the model is made to
produce for nothing — output a small reply budget runs out on, which is how a
run at an 8,192-token window ended on the no-confidence fallback. The agents a
relationship credits were free text with no names given; the check that now
asks about them reads the names the evidence summary uses.
"""

from __future__ import annotations

from maljan.agents.judge_agent import JUDGE_VERDICT_SYSTEM
from maljan.agents.judge_postprocess import postprocess_judge_bundle
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.stix_models import Bundle, Indicator


class TestThePromptAgreesWithTheChecks:
    def test_it_no_longer_invites_an_attack_pattern_with_no_id(self) -> None:
        assert "Omit technique ID if unsure" not in JUDGE_VERDICT_SYSTEM
        assert "not an AttackPattern" in JUDGE_VERDICT_SYSTEM
        assert '"external_id": "T####" or "T####.###"' in JUDGE_VERDICT_SYSTEM

    def test_it_names_where_a_credit_comes_from(self) -> None:
        assert "by the names the EVIDENCE SUMMARY gives them" in JUDGE_VERDICT_SYSTEM

    def test_it_names_the_relationship_types_stix_defines(self) -> None:
        assert "malware uses attack-pattern" in JUDGE_VERDICT_SYSTEM
        assert "indicator indicates malware" in JUDGE_VERDICT_SYSTEM


class TestWhatIsFilledInIsNotAsked:
    def test_the_prompt_says_the_stamps_are_filled_in(self) -> None:
        assert (
            "Leave out created, modified, spec_version and valid_from: they are stamped "
            "after you answer." in " ".join(JUDGE_VERDICT_SYSTEM.split())
        )

    def test_a_bundle_without_them_is_a_whole_bundle(self) -> None:
        answer = {
            "type": "bundle",
            "objects": [
                {"type": "malware", "id": "malware--1", "name": "sample", "is_family": False},
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "pattern": "[ipv4-addr:value = '82.157.13.47']",
                    "pattern_type": "stix",
                    "indicator_types": ["malicious-activity"],
                },
                {
                    "type": "relationship",
                    "id": "relationship--1",
                    "relationship_type": "indicates",
                    "source_ref": "indicator--1",
                    "target_ref": "malware--1",
                },
            ],
        }
        bundle = Bundle.model_validate(postprocess_judge_bundle(answer))
        report = MalwareReportBuilder(
            file_hash="c" * 64,
            file_name="sample.elf",
            sample_path=None,
            sandbox_report={},
            reports={},
            isr_reports={},
            stix_output={"objects": []},
            run_summary={},
            discussion_history=[],
            final_decision="Malware",
            overall_confidence=0.9,
            judge_assessment=None,
            malware_category="reverse_shell",
            evidence_ledger=[],
        ).build_deterministic()
        # A sandbox reached the address: the second source the one publish rule
        # asks of the judge's value.
        from maljan.reporting.models import NetworkIOCs, NetworkIP

        report.network = NetworkIOCs(ips=[NetworkIP(address="82.157.13.47", source="sandbox")])

        exported = ExtendedSTIXRenderer().render(report, bundle).model_dump(mode="json")

        (indicator,) = [
            o
            for o in exported["objects"]
            if o["type"] == "indicator" and "82.157.13.47" in o["pattern"]
        ]
        assert isinstance(bundle.objects[1], Indicator)
        assert indicator["spec_version"] == "2.1"
        for stamp in ("created", "modified", "valid_from"):
            assert indicator[stamp], stamp
