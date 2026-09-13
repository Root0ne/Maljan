"""The validation loop: what it finds, what it says back, and what it keeps.

The point of every case here is that nothing is corrected in place. A bad
technique id comes back as a violation with suggestions, not as a different id;
an ungrounded indicator comes back as feedback, and only after the model has
had its turn is the object dropped — and then recorded.
"""

from __future__ import annotations

import pytest

from maljan.pipeline.validation import (
    FEEDBACK_PREAMBLE,
    Violation,
    corroboration,
    drop_ungrounded_indicators,
    feedback_text,
    mark_invalid_technique_ids,
    retry_with_feedback,
    retry_with_feedback_sync,
    validate_isr,
    validate_verdict_bundle,
    validation_metrics,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.judgement import FamilyVerdict, JudgeAssessment, SeverityVerdict
from maljan.schemas.stix_models import AttackPattern, Bundle, Indicator


class _Attck:
    """A stand-in for ``tools.knowledge`` that never loads the real bundle."""

    known = {"T1055", "T1071"}

    def attck_validate(self, ids: list[str]) -> dict[str, object]:
        return {"invalid": [{"id": t} for t in ids if t not in self.known], "checked": len(ids)}

    def resolve_technique(self, text: str, k: int = 5) -> dict[str, object]:
        return {"candidates": [{"technique_id": tid} for tid in sorted(self.known)][:k]}


def _isr(claims: list[ClaimEvidence], agent_id: str = "static") -> AgentISR:
    return AgentISR(agent_id=agent_id, domain="static", claims=claims)


def _attack_pattern_bundle(external_id: str) -> Bundle:
    return Bundle(
        objects=[  # type: ignore[list-item]
            AttackPattern(
                name="Process Injection",
                external_references=[{"source_name": "mitre-attack", "external_id": external_id}],
            )
        ]
    )


def _claim(**kwargs: object) -> ClaimEvidence:
    payload: dict[str, object] = {
        "claim": "the sample allocates memory in another process",
        "evidence_ref": "API call: VirtualAllocEx @ 0x401234",
        "confidence": 0.8,
    }
    payload.update(kwargs)
    return ClaimEvidence.model_construct(**payload)


class TestValidateISR:
    def test_an_id_outside_the_catalogue_is_reported_with_suggestions(self):
        violations = validate_isr(_isr([_claim(technique_id="T9999")]), attck=_Attck())

        assert [v.code for v in violations] == ["attck.unknown_id"]
        assert "T9999" in violations[0].message
        assert "T1055" in violations[0].message
        assert violations[0].path == "static.claims[0]"

    def test_no_more_than_three_suggestions_are_offered(self):
        class _Many(_Attck):
            def resolve_technique(self, text: str, k: int = 5) -> dict[str, object]:
                return {"candidates": [{"technique_id": f"T10{n:02d}"} for n in range(10)][:k]}

        violations = validate_isr(_isr([_claim(technique_id="T9999")]), attck=_Many())

        assert violations[0].message.count("T10") == 3

    def test_a_catalogued_id_passes(self):
        assert validate_isr(_isr([_claim(technique_id="T1055")]), attck=_Attck()) == []

    def test_confidence_outside_the_unit_interval_is_reported(self):
        violations = validate_isr(_isr([_claim(confidence=1.4)]), attck=_Attck())

        assert [v.code for v in violations] == ["isr.confidence_range"]

    def test_a_claim_with_no_evidence_text_is_reported(self):
        violations = validate_isr(_isr([_claim(evidence_ref="   ")]), attck=_Attck())

        assert [v.code for v in violations] == ["isr.empty_evidence"]

    def test_without_a_catalogue_the_technique_check_is_skipped(self):
        assert validate_isr(_isr([_claim(technique_id="T9999")]), attck=None) == []

    def test_a_knowledge_backend_that_raises_produces_no_violation(self):
        class _Broken:
            def attck_validate(self, ids: list[str]) -> dict[str, object]:
                raise RuntimeError("the catalogue is not readable")

        assert validate_isr(_isr([_claim(technique_id="T9999")]), attck=_Broken()) == []

    def test_marking_leaves_the_id_alone_and_only_sets_the_flag(self):
        isr = _isr([_claim(technique_id="T9999")])
        violations = validate_isr(isr, attck=_Attck())

        mark_invalid_technique_ids(isr, violations)

        assert isr.claims[0].technique_id == "T9999"
        assert isr.claims[0].technique_id_valid is False


class TestValidateVerdictBundle:
    def test_an_indicator_naming_a_value_no_tool_saw_is_reported(self):
        bundle = Bundle(
            objects=[Indicator(pattern="[domain-name:value = 'evil.example']")]  # type: ignore[list-item]
        )

        violations = validate_verdict_bundle(bundle, {"real.example"})

        assert [v.code for v in violations] == ["stix.ungrounded_indicator"]
        assert "evil.example" in violations[0].message

    def test_an_indicator_the_corpus_contains_is_accepted(self):
        bundle = Bundle(
            objects=[Indicator(pattern="[domain-name:value = 'real.example']")]  # type: ignore[list-item]
        )

        assert validate_verdict_bundle(bundle, {"saw real.example once"}) == []

    def test_a_misshapen_technique_id_is_reported_without_a_catalogue(self):
        bundle = _attack_pattern_bundle("TX")

        violations = validate_verdict_bundle(bundle)

        assert [v.code for v in violations] == ["stix.unknown_technique"]
        assert "not shaped like" in violations[0].message

    def test_a_plausible_but_imaginary_id_is_reported_against_the_catalogue(self):
        """``T7777`` passes the regex and does not exist. This is the case the
        violation is for, and it was unreachable while a filter upstream
        dropped the object before the validator ever saw it."""
        bundle = _attack_pattern_bundle("T7777")

        violations = validate_verdict_bundle(bundle, attck=_Attck())

        assert [v.code for v in violations] == ["stix.unknown_technique"]
        assert "no entry for in any domain" in violations[0].message

    def test_a_catalogued_id_passes(self):
        assert validate_verdict_bundle(_attack_pattern_bundle("T1055"), attck=_Attck()) == []

    def test_without_a_catalogue_a_plausible_id_is_not_questioned(self):
        assert validate_verdict_bundle(_attack_pattern_bundle("T7777")) == []

    def test_a_sigma_reference_is_not_read_as_an_attck_id(self):
        """An attack-pattern may carry a Sigma rule id first. Holding the judge
        to the ATT&CK vocabulary for one of those would burn the single retry
        on nothing."""
        bundle = Bundle(
            objects=[  # type: ignore[list-item]
                AttackPattern(
                    name="Process Injection",
                    external_references=[
                        {"source_name": "sigma", "external_id": "5f1c6b0d-1e1a-4f5e-9d31-000000"},
                        {"source_name": "mitre-attack", "external_id": "T1055"},
                    ],
                )
            ]
        )

        assert validate_verdict_bundle(bundle, attck=_Attck()) == []

    def test_an_attack_pattern_with_no_mitre_reference_at_all_is_not_questioned(self):
        bundle = Bundle(
            objects=[  # type: ignore[list-item]
                AttackPattern(
                    name="Custom detection",
                    external_references=[{"source_name": "sigma", "external_id": "abc-123"}],
                )
            ]
        )

        assert validate_verdict_bundle(bundle, attck=_Attck()) == []

    def test_a_severity_outside_the_enum_is_reported(self):
        bundle = Bundle()
        bundle.x_maljan_assessment = JudgeAssessment(
            severity=SeverityVerdict.model_construct(rating="Catastrophic", rationale="")
        )

        assert [v.code for v in validate_verdict_bundle(bundle)] == ["verdict.severity_enum"]

    def test_a_family_with_no_evidence_ids_is_reported(self):
        bundle = Bundle()
        bundle.x_maljan_assessment = JudgeAssessment(family=FamilyVerdict(name="AsyncRAT"))

        assert [v.code for v in validate_verdict_bundle(bundle)] == [
            "attribution.ungrounded_family"
        ]

    def test_a_family_that_cites_evidence_passes(self):
        bundle = Bundle()
        bundle.x_maljan_assessment = JudgeAssessment(
            family=FamilyVerdict(name="AsyncRAT", evidence_ids=["ev_0004"])
        )

        assert validate_verdict_bundle(bundle) == []


class TestIndicatorAdmission:
    """The rules the post-processor used to apply silently, said out loud.

    Each case was a real false positive in a shipped bundle. What changed is
    what happens to it: the judge is told which value is not evidence and why,
    and the drop only happens if it insists.
    """

    def _violation(self, pattern: str, corpus: set[str]) -> Violation | None:
        bundle = Bundle(objects=[Indicator(pattern=pattern)])  # type: ignore[list-item]
        found = validate_verdict_bundle(bundle, corpus)
        return found[0] if found else None

    def test_a_path_with_a_real_extension_is_admitted(self):
        assert self._violation("[file:name = '/data/local/tmp/payload.so']", {"payload.so"}) is None

    def test_a_path_under_a_known_os_prefix_is_admitted(self):
        assert self._violation("[file:name = '/sdcard/Download/dropper']", {"dropper"}) is None

    def test_a_toolchain_build_path_is_reported_as_an_artefact(self):
        ndk = "/buildbot/src/android/ndk-r25-release/toolchain/llvm-project/libcxx/include/string"
        violation = self._violation(f"[file:name = '{ndk}']", {ndk.lower()})

        assert violation is not None
        assert "compiler or toolchain artefact" in violation.message

    def test_a_bytecode_class_reference_is_reported_as_such(self):
        violation = self._violation(
            "[file:name = '/lang/ClassCastException']", {"/lang/classcastexception"}
        )

        assert violation is not None
        assert "class reference" in violation.message

    def test_a_random_short_string_is_not_a_path(self):
        violation = self._violation("[file:name = '/I FyD']", {"/i fyd"})

        assert violation is not None
        assert "no filesystem anchor" in violation.message

    def test_a_vendor_documentation_url_is_reported(self):
        violation = self._violation(
            "[url:value = 'https://android.googlesource.com/toolchain/llvm-project']",
            {"https://android.googlesource.com/toolchain/llvm-project"},
        )

        assert violation is not None
        assert "documentation or vendor infrastructure" in violation.message

    def test_an_arbitrary_c2_url_the_corpus_saw_is_admitted(self):
        assert (
            self._violation(
                "[url:value = 'http://evil.example.com/beacon']",
                {"http://evil.example.com/beacon"},
            )
            is None
        )

    def test_a_hash_the_corpus_saw_is_admitted(self):
        digest = "95236ef71738807ce60ef7d042699decb7156931931682cf46e6ad" + "0" * 10
        assert self._violation(f"[file:hashes.'SHA-256' = '{digest}']", {digest}) is None

    def test_an_empty_pattern_is_reported(self):
        violation = self._violation("", set())

        assert violation is not None
        assert "empty pattern" in violation.message


class TestDropUngroundedIndicators:
    def test_the_named_indicator_goes_and_the_rest_stay(self):
        bundle = Bundle(
            objects=[  # type: ignore[list-item]
                Indicator(pattern="[domain-name:value = 'real.example']"),
                Indicator(pattern="[domain-name:value = 'evil.example']"),
            ]
        )
        violations = validate_verdict_bundle(bundle, {"real.example"})

        dropped = drop_ungrounded_indicators(bundle, violations)

        assert dropped == 1
        assert len(bundle.objects) == 1
        assert "real.example" in bundle.objects[0].pattern  # type: ignore[union-attr]


class TestRetryWithFeedback:
    @pytest.mark.asyncio
    async def test_a_bad_answer_earns_one_feedback_turn_and_is_then_accepted(self):
        seen: list[list[object]] = []
        answers = ["T9999", "T1055"]

        async def run(messages: list[object]) -> str:
            seen.append(list(messages))
            return answers[len(seen) - 1]

        def validator(value: str) -> list[Violation]:
            return [] if value == "T1055" else [Violation("attck.unknown_id", "no such id")]

        result, violations, retries = await retry_with_feedback(
            run, ["ask"], [validator], parse=lambda answer: str(answer)
        )

        assert (result, violations, retries) == ("T1055", [], 1)
        assert len(seen) == 2
        assert FEEDBACK_PREAMBLE in str(seen[1][-1].content)

    @pytest.mark.asyncio
    async def test_what_is_still_wrong_after_the_retry_is_returned_not_raised(self):
        async def run(messages: list[object]) -> str:
            return "T9999"

        def validator(value: str) -> list[Violation]:
            return [Violation("attck.unknown_id", "no such id", "claims[0]")]

        result, violations, retries = await retry_with_feedback(
            run, ["ask"], [validator], parse=lambda answer: str(answer)
        )

        assert result == "T9999"
        assert [v.code for v in violations] == ["attck.unknown_id"]
        assert retries == 1

    @pytest.mark.asyncio
    async def test_a_good_first_answer_costs_no_retry(self):
        calls = 0

        async def run(messages: list[object]) -> str:
            nonlocal calls
            calls += 1
            return "fine"

        _, violations, retries = await retry_with_feedback(
            run, ["ask"], [lambda _v: []], parse=lambda answer: str(answer)
        )

        assert (calls, violations, retries) == (1, [], 0)

    def test_the_synchronous_sibling_behaves_the_same(self):
        answers = ["bad", "good"]
        calls = 0

        def run(messages: list[object]) -> str:
            nonlocal calls
            calls += 1
            return answers[calls - 1]

        def validator(value: str) -> list[Violation]:
            return [] if value == "good" else [Violation("x", "wrong")]

        result, violations, retries = retry_with_feedback_sync(
            run, ["ask"], [validator], parse=lambda answer: str(answer)
        )

        assert (result, violations, retries) == ("good", [], 1)

    def test_a_validator_that_raises_does_not_fail_the_run(self):
        def broken(_value: str) -> list[Violation]:
            raise RuntimeError("bad validator")

        result, violations, retries = retry_with_feedback_sync(
            lambda _m: "answer", ["ask"], [broken], parse=lambda answer: str(answer)
        )

        assert (result, violations, retries) == ("answer", [], 0)


class TestFeedbackText:
    def test_it_names_every_code_and_asks_for_the_same_format(self):
        text = feedback_text(
            [Violation("attck.unknown_id", "no such id", "static.claims[0]"), Violation("b", "m")]
        )

        assert text.startswith(FEEDBACK_PREAMBLE)
        assert "attck.unknown_id" in text
        assert "static.claims[0]" in text
        assert text.rstrip().endswith("answer again in the same format.")


class TestMetrics:
    def test_the_validation_block_counts_codes_and_keeps_the_leftovers(self):
        metrics = validation_metrics(
            2,
            [
                ("static", Violation("attck.unknown_id", "no such id")),
                ("network", Violation("attck.unknown_id", "no such id")),
                ("judge", Violation("stix.ungrounded_indicator", "never seen")),
            ],
        )

        assert metrics["retries"] == 2
        assert metrics["by_code"] == {"attck.unknown_id": 2, "stix.ungrounded_indicator": 1}
        assert metrics["unresolved"][0] == {
            "agent": "static",
            "code": "attck.unknown_id",
            "message": "no such id",
        }

    def test_corroboration_lists_sources_and_computes_no_number(self):
        isrs = {
            "static": _isr([_claim(technique_id="T1055")], agent_id="static"),
            "dynamic": _isr([_claim(technique_id="T1055")], agent_id="dynamic"),
        }
        ledger = [
            LedgerEntry(
                id="ev_0001",
                tool="capa",
                structured={"capabilities": [{"attck": "T1055"}, {"attck": "T1071"}]},
            )
        ]

        assert corroboration(isrs, ledger) == {
            "T1055": ["capa", "dynamic", "static"],
            "T1071": ["capa"],
        }

    def test_a_claim_whose_id_failed_validation_does_not_corroborate(self):
        isr = _isr([_claim(technique_id="T9999")])
        isr.claims[0].technique_id_valid = False

        assert corroboration({"static": isr}, []) == {}
