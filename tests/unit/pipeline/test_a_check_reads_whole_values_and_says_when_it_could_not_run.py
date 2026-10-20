"""The deterministic checks match whole values, credit no sibling and say when they could not run.

Each class is one way a check used to answer a question it was not asked:

- an indicator was grounded by any run of characters inside a longer value,
  so ``ample.com`` was "in the evidence" because ``example.com`` was;
- a credit for a sub-technique stood on a source that named a sibling;
- a tool's echo of its own name and input counted as values it held, so a
  true "no matches" was challenged;
- a check that raised left no trace, and the answer read as validated;
- the run's strings section grounded every encryption claim, and a technique
  the report declined was grounded again by the claim it came from;
- a value in prose was located by its first substring, inside a longer value,
  and a value written twice was weighed once.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.agents._indicator_denylists import whole_value_in, whole_value_starts
from maljan.pipeline.validation import (
    CHECK_FAILED_CODE,
    ENTRY_CONTENTS_MISSTATED_CODE,
    KEPT_WITH_A_FINDING,
    CapabilityGrounding,
    EntryTexts,
    Haystack,
    Violation,
    _call_echoes,
    _held_values,
    _indicator_problem,
    _unstated_values,
    misstated_entry_contents,
    retry_with_feedback_sync,
    unconfirmed_credits,
    ungrounded_capabilities,
    validation_metrics,
)
from maljan.reporting.models import (
    CapabilityCell,
    EvidenceSection,
    FileHashes,
    MalwareReport,
    SampleIdentity,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.judgement import JudgeAssessment
from maljan.schemas.stix_models import (
    AttackPattern,
    Bundle,
    ConfidenceAnnotatedRelationship,
    Malware,
)

EVIDENCE = '{"hosts": ["example.com"], "ips": ["11.2.3.45"], "mutexes": ["global\\\\abcmutex123"]}'


def _problem(pattern: str) -> str:
    return _indicator_problem(pattern, Haystack([EVIDENCE.lower()]), set())


class TestAnIndicatorIsGroundedByAWholeValue:
    @pytest.mark.parametrize(
        "pattern",
        [
            "[domain-name:value = 'ample.com']",
            "[domain-name:value = 'example.co']",
            "[ipv4-addr:value = '1.2.3.4']",
            "[ipv4-addr:value = '11.2.3.4']",
            "[mutex:name = 'cmutex1']",
            "[url:value = 'http://ample.com']",
        ],
    )
    def test_a_slice_of_a_recorded_value_is_not_grounded(self, pattern: str) -> None:
        assert _problem(pattern) != ""

    @pytest.mark.parametrize(
        "pattern",
        [
            "[domain-name:value = 'example.com']",
            "[ipv4-addr:value = '11.2.3.45']",
            "[mutex:name = 'Global\\\\abcmutex123']",
        ],
    )
    def test_the_recorded_value_itself_is_grounded(self, pattern: str) -> None:
        assert _problem(pattern) == ""

    def test_a_like_shape_is_still_asked_for_its_fixed_text(self) -> None:
        assert _problem("[domain-name:value LIKE '%xample.co%']") == ""

    def test_the_spellings_are_found_as_whole_values(self) -> None:
        haystack = Haystack(['{"path": "c:\\\\temp\\\\evil.exe"}'])

        assert haystack.holds_value("c:\\temp\\evil.exe")
        assert not haystack.holds_value("emp\\evil.exe")
        assert haystack.holds_text("emp\\evil.exe")

    def test_every_whole_occurrence_is_found_and_no_slice(self) -> None:
        text = "sub.evil.example then evil.example and evil.example."

        assert list(whole_value_starts("evil.example", text)) == [22, 39]
        assert whole_value_in("evil.example", text)
        assert not whole_value_in("vil.example", text)

    @pytest.mark.parametrize(
        ("pattern", "evidence"),
        [
            ("[domain-name:value = 'evil.com']", '{"from": "bot@evil.com"}'),
            ("[domain-name:value = 'evil.com']", '{"url": "http://user:pw@evil.com/x"}'),
            ("[mutex:name = 'abcmutex123']", "mutex Global\\abcmutex123 created"),
            ("[mutex:name = 'abcmutex123']", '{"m": "Global\\\\abcmutex123"}'),
        ],
    )
    def test_a_whole_value_after_an_at_or_a_lone_backslash_is_grounded(
        self, pattern: str, evidence: str
    ) -> None:
        assert _indicator_problem(pattern, Haystack([evidence.lower()]), set()) == ""

    @pytest.mark.parametrize(
        ("pattern", "evidence"),
        [
            ("[domain-name:value = 'evil.com']", '{"q": "api.evil.com"}'),
            ("[domain-name:value = 'evil.com']", "user@api.evil.com"),
            ("[domain-name:value = 'evil.com']", "bot@evil.com_x"),
            ("[ipv4-addr:value = '1.2.3.4']", "x\\11.2.3.45"),
            ("[mutex:name = 'cmutex1']", "mutex Global\\abcmutex123 created"),
            ("[mutex:name = 'tmp']", "c:\\tmp\\evil.exe"),
            ("[url:value = 'http://evil.com/gate']", "see http://evil.com/gate.php"),
        ],
    )
    def test_those_readings_still_ground_no_slice(self, pattern: str, evidence: str) -> None:
        assert _indicator_problem(pattern, Haystack([evidence.lower()]), set()) != ""


def _credit(tid: str, agents: list[str]) -> Bundle:
    malware = Malware(name="sample")
    pattern = AttackPattern(
        name=tid, external_references=[{"source_name": "mitre-attack", "external_id": tid}]
    )
    edge = ConfidenceAnnotatedRelationship(
        relationship_type="uses",
        source_ref=malware.id,
        target_ref=pattern.id,
        x_maljan_confidence=0.9,
        x_maljan_evidence_basis="static",
        x_maljan_contributing_agents=agents,
    )
    return Bundle(
        objects=[malware, pattern, edge],
        x_maljan_assessment=JudgeAssessment(verdict="Malware", confidence=0.9),
    )


class TestACreditStandsOnTheSourcesThatNamedIt:
    def test_a_sibling_sub_technique_is_not_a_source(self) -> None:
        (row,) = unconfirmed_credits(_credit("T1055.012", ["static"]), {"T1055.001": ["static"]})

        assert row.uncredited == ("static",)

    def test_a_parent_named_stands_behind_its_sub_technique(self) -> None:
        assert unconfirmed_credits(_credit("T1055.012", ["static"]), {"T1055": ["static"]}) == []

    def test_a_sub_technique_named_stands_behind_its_parent(self) -> None:
        assert unconfirmed_credits(_credit("T1055", ["static"]), {"T1055.001": ["static"]}) == []

    def test_the_id_itself_stands_behind_itself(self) -> None:
        sources = {"T1055.012": ["static"]}

        assert unconfirmed_credits(_credit("T1055.012", ["static"]), sources) == []


def _entries(text: str, args: dict[str, Any] | None = None) -> EntryTexts:
    return EntryTexts(
        texts={"ev_0003": text.lower()},
        tools={"ev_0003": "yara_scan"},
        words={"ev_0003": frozenset({"yara"})},
        entries={
            "ev_0003": LedgerEntry(
                id="ev_0003", tool="yara_scan", args=args or {"file": "/work/in/sample.exe"}
            )
        },
    )


NO_ENTRIES = {"body": "The yara output contains no entries [ev_0003]."}


class TestAnEchoIsNotAValueHeld:
    def test_a_tool_s_name_and_input_beside_an_empty_list_hold_nothing(self) -> None:
        text = '{"tool": "yara_scan", "file": "sample.exe", "matches": []}'
        entries = _entries(text)

        assert _held_values(text, _call_echoes(entries, "ev_0003")) == 0
        assert misstated_entry_contents(NO_ENTRIES, entries) == []

    def test_an_empty_section_echoing_its_argument_holds_nothing(self) -> None:
        text = '{"section": "ttp_tags", "rows": [], "total": 0}'

        assert _held_values(text, ["ttp_tags"]) == 0

    def test_a_one_line_value_the_call_did_not_pass_is_held(self) -> None:
        text = '{"c2": "http://evil.com/gate.php", "errors": []}'

        assert _held_values(text, ["config_extract", "sample.exe"]) == 1
        (row,) = misstated_entry_contents(NO_ENTRIES, _entries(text))
        assert row.code == ENTRY_CONTENTS_MISSTATED_CODE

    def test_an_item_in_a_list_is_still_held(self) -> None:
        text = '{"tool": "yara_scan", "file": "sample.exe", "matches": ["rule_a"]}'

        (row,) = misstated_entry_contents(NO_ENTRIES, _entries(text))

        assert row.code == ENTRY_CONTENTS_MISSTATED_CODE
        assert _held_values(text, ["yara_scan", "sample.exe"]) == 1

    def test_a_count_and_a_text_of_lines_are_held(self) -> None:
        assert _held_values('{"section": "flows", "rows": [], "packets": 120}', ["flows"]) == 1
        assert _held_values('{"command": "run", "stdout": "a\\nb\\nc", "argv": []}', ["run"]) == 3

    def test_with_no_echo_named_every_line_is_held(self) -> None:
        assert _held_values('{"name": "a.exe", "format": "PE"}') == 2
        assert _held_values("first\nsecond") == 2


class TestACheckThatRaisedIsRecorded:
    @staticmethod
    def _broken(_parsed: Any) -> list[Violation]:
        raise RecursionError("deep pattern")

    def test_the_row_names_the_check_and_asks_nothing(self) -> None:
        calls: list[int] = []

        def run(_turns: list[Any]) -> str:
            calls.append(1)
            return "answer"

        _parsed, violations, retries = retry_with_feedback_sync(
            run, [{"role": "user", "content": "q"}], [self._broken], parse=lambda a: a
        )

        (row,) = violations
        assert row.code == CHECK_FAILED_CODE
        assert row.advisory and not row.asked
        assert "RecursionError" in row.message
        assert "deep pattern" not in row.message
        assert retries == 0 and calls == [1]

    def test_the_check_is_named_among_those_that_did_not_run(self) -> None:
        _parsed, violations, _retries = retry_with_feedback_sync(
            lambda _turns: "answer", [], [self._broken], parse=lambda a: a
        )

        metrics = validation_metrics(0, [("judge", v) for v in violations], not_run=["x"])

        assert metrics["not_run"] == sorted(["x", violations[0].subject])
        assert "_broken" in violations[0].subject

    def test_a_report_round_keeps_its_answer_beside_the_row(self) -> None:
        assert CHECK_FAILED_CODE in KEPT_WITH_A_FINDING


ENCRYPTION = "The sample encrypts its configuration with a hard-coded key."


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), **over)


class TestWhatGroundsACapabilityWord:
    def test_a_strings_section_grounds_no_encryption(self) -> None:
        report = _report(
            sections=[
                EvidenceSection(
                    key="strings",
                    title="Strings",
                    kind="table",
                    columns=["Value"],
                    rows=[["kernel32.dll"]],
                    source="tool:strings",
                )
            ]
        )

        found = ungrounded_capabilities(ENCRYPTION, CapabilityGrounding.from_report(report))

        assert {v.path for v in found} == {"encryption"}

    def test_a_declined_technique_is_not_grounded_by_its_claim(self) -> None:
        report = _report(
            capability_matrix=[
                CapabilityCell(
                    tactic="TA0005",
                    tactic_name="Defense Evasion",
                    technique_id="T1027",
                    technique_name="Obfuscated Files or Information",
                    not_published="not published: the judge dropped it",
                )
            ]
        )
        isr = AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="A packed section.",
                    evidence_ref="[ev_0001]",
                    confidence=0.8,
                    technique_id="T1027",
                )
            ],
        )

        grounding = CapabilityGrounding.from_report(report, {"static": isr})

        assert "T1027" not in grounding.technique_ids

    def test_an_invalid_id_is_not_grounded_by_its_claim(self) -> None:
        claim = ClaimEvidence(
            claim="A packed section.",
            evidence_ref="[ev_0001]",
            confidence=0.8,
            technique_id="T1027",
        )
        claim.technique_id_valid = False
        isr = AgentISR(agent_id="static", domain="static", claims=[claim])

        assert (
            "T1027" not in CapabilityGrounding.from_report(_report(), {"static": isr}).technique_ids
        )

    def test_a_claim_nothing_declined_still_grounds(self) -> None:
        claim = ClaimEvidence(
            claim="A packed section.",
            evidence_ref="[ev_0001]",
            confidence=0.8,
            technique_id="T1027",
        )
        isr = AgentISR(agent_id="static", domain="static", claims=[claim])

        assert "T1027" in CapabilityGrounding.from_report(_report(), {"static": isr}).technique_ids


def _packed() -> ClaimEvidence:
    return ClaimEvidence(
        claim="A packed section.", evidence_ref="[ev_0001]", confidence=0.8, technique_id="T1027"
    )


def _refused(_kind: str, _value: str) -> str:
    return "no: not published"


class TestAValueInProseIsWeighedWhereverItIsWritten:
    def test_a_parent_domain_is_not_located_inside_its_subdomain(self) -> None:
        sentence = "It reaches sub.evil-host.net (no: not published) and evil-host.net."

        found = {value for _kind, value, _state in _unstated_values(sentence, _refused)}

        assert found == {"evil-host.net"}

    def test_a_value_written_twice_is_weighed_at_each_place(self) -> None:
        sentence = "It reaches evil-host.net (no: not published), then evil-host.net again."

        found = [value for _kind, value, _state in _unstated_values(sentence, _refused)]

        assert found == ["evil-host.net"]

    def test_a_value_with_its_state_at_every_place_raises_nothing(self) -> None:
        sentence = "It reaches evil-host.net (no: not published) and nothing else."

        assert _unstated_values(sentence, _refused) == []
