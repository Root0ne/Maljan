"""The technique ids are read in the shapes the tools write them."""

from __future__ import annotations

from maljan.analysis.technique_ids import (
    api_capability_hits,
    sigma_technique_ids,
    technique_ids_in,
)


class TestTechniqueIdsIn:
    def test_capa_s_decorated_strings(self) -> None:
        attck = [
            "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]",
            "Defense Evasion::Process Injection [T1055]",
        ]
        assert technique_ids_in(attck) == ["T1027.002", "T1055"]

    def test_a_bare_id_and_a_lower_case_one(self) -> None:
        assert technique_ids_in("T1218.011") == ["T1218.011"]
        assert technique_ids_in("t1218.011") == ["T1218.011"]

    def test_duplicates_collapse_and_order_is_kept(self) -> None:
        assert technique_ids_in(["x [T1055]", "T1027", "T1055"]) == ["T1055", "T1027"]

    def test_nothing_else_names_a_technique(self) -> None:
        assert technique_ids_in(None) == []
        assert technique_ids_in(42) == []
        assert technique_ids_in({"technique_id": "T1055"}) == []
        assert technique_ids_in("TA0005 is a tactic, T105 is not an id") == []


class TestSigmaTechniqueIds:
    def test_the_tags_sigma_match_emits(self) -> None:
        row = {"tags": ["attack.persistence", "attack.t1547.001", "attack.T1055.012"]}
        assert sigma_technique_ids(row) == ["T1547.001", "T1055.012"]

    def test_a_tactic_tag_is_not_a_technique(self) -> None:
        assert sigma_technique_ids({"tags": ["attack.defense-evasion", "cve.2021.1234"]}) == []

    def test_a_hand_written_row_is_read_too(self) -> None:
        assert sigma_technique_ids({"meta": {"technique_ids": ["T1547.001"]}}) == ["T1547.001"]
        assert sigma_technique_ids({"technique_ids": ["T1053.005"]}) == ["T1053.005"]

    def test_not_a_row(self) -> None:
        assert sigma_technique_ids(None) == []


class TestApiCapabilityHits:
    def _payload(self, matched: list[str], min_apis: int = 2) -> dict:
        rule = {
            "technique_id": "T1055",
            "name": "Process Injection",
            "matched": matched,
            "min_apis": min_apis,
        }
        return {"capabilities": [{"api": api, "techniques": [rule]} for api in matched]}

    def test_a_rule_the_set_cleared_is_one_row_with_the_pooled_apis(self) -> None:
        hits = api_capability_hits(self._payload(["WriteProcessMemory", "CreateRemoteThread"]))
        assert hits == [
            {
                "technique_id": "T1055",
                "name": "Process Injection",
                "rule": "",
                "matched_apis": ["WriteProcessMemory", "CreateRemoteThread"],
            }
        ]

    def test_a_rule_under_its_floor_is_not_a_hit(self) -> None:
        assert api_capability_hits(self._payload(["WriteProcessMemory"], min_apis=2)) == []

    def test_not_a_payload(self) -> None:
        assert api_capability_hits(None) == []
        assert api_capability_hits({"capabilities": "nope"}) == []


class TestTheRateTravelsWithTheRow:
    """A deterministic association reaches the report with the share of
    ordinary software the same rule fires on, or it says it was not measured.

    The rate is copied down here rather than looked up again later, because the
    report has to show what the catalogue said when the tool was asked.
    """

    @staticmethod
    def _payload(measured: dict | None, corpus: str = "2730 binaries from 25 vendors") -> dict:
        rule: dict = {
            "technique_id": "T1113",
            "name": "Screen Capture",
            "rule": "pulling the pixels back out",
            "matched": ["GetDIBits", "PrintWindow"],
            "min_apis": 2,
        }
        if measured is not None:
            rule["measured"] = measured
        return {
            "capabilities": [{"api": api, "techniques": [rule]} for api in rule["matched"]],
            "corpora": {"benign": corpus},
        }

    def test_the_share_and_the_count_behind_it_are_both_on_the_row(self) -> None:
        """The sentence says what the rule did before it says a number, and it
        names the corpus the number is a share of. The value is persisted and
        read on its own, so the words that stop it reading as a probability
        that this sample is benign have to be inside the string."""
        (hit,) = api_capability_hits(
            self._payload({"seen_on_benign_percent": 0.3, "seen_on_benign_files": 8})
        )
        assert hit["benign_rate"] == (
            "fires on 0.3% of benign software (8 of 2730 binaries from 25 vendors)"
        )

    def test_how_thin_the_support_is_travels_with_how_common_the_rule_is(self) -> None:
        """A rule at 1.0% of ordinary software reads well until a reader learns
        it has fired on no malware the combination was not chosen on. The two
        halves of the measurement are read together or not at all, and the
        report and the console read only this string."""
        (hit,) = api_capability_hits(
            self._payload(
                {
                    "seen_on_benign_percent": 1.0,
                    "seen_on_benign_files": 26,
                    "held_out_malware_profiles": 0,
                }
            )
        )
        assert hit["benign_rate"].endswith("; 0 held-out malware profiles support it")
        (one,) = api_capability_hits(
            self._payload(
                {
                    "seen_on_benign_percent": 0.3,
                    "seen_on_benign_files": 8,
                    "held_out_malware_profiles": 1,
                }
            )
        )
        assert one["benign_rate"].endswith("; 1 held-out malware profile supports it")

    def test_a_platform_with_no_malware_corpus_says_nothing_rather_than_zero(self) -> None:
        (hit,) = api_capability_hits(
            self._payload({"seen_on_benign_percent": 0.2, "seen_on_benign_files": 3})
        )
        assert "held-out" not in hit["benign_rate"]

    def test_a_rate_that_rounds_to_zero_still_says_how_many_files(self) -> None:
        """One file in three thousand is 0.0% to one decimal place, and a
        reader who saw only that would read it as a rule that never fires."""
        (hit,) = api_capability_hits(
            self._payload({"seen_on_benign_percent": 0.0, "seen_on_benign_files": 1})
        )
        assert "(1 of 2730" in hit["benign_rate"]

    def test_an_unmeasured_rule_carries_no_rate_rather_than_a_zero(self) -> None:
        (hit,) = api_capability_hits(self._payload(None))
        assert "benign_rate" not in hit
        (hit,) = api_capability_hits(self._payload({"seen_on_benign_percent": 0.3}))
        assert "benign_rate" not in hit


class TestTwoRulesForOneTechniqueStayTwoRows:
    """The catalogue's name is on both, so the name cannot tell them apart.

    Keyed by technique and name alone the two pooled their matched APIs, and
    the floor of whichever was seen first was applied to the pool — so a
    technique could be asserted on a combination no single rule ever cleared.
    """

    @staticmethod
    def _payload(*rules: dict) -> dict:
        capabilities = []
        for rule in rules:
            for api in rule["matched"]:
                capabilities.append({"api": api, "techniques": [rule]})
        return {"capabilities": capabilities}

    def _rule(self, label: str, matched: list[str], min_apis: int = 2) -> dict:
        return {
            "technique_id": "T1685",
            "name": "Disable or Modify Tools",
            "rule": label,
            "matched": matched,
            "min_apis": min_apis,
        }

    def test_each_rule_is_its_own_row(self) -> None:
        hits = api_capability_hits(
            self._payload(
                self._rule(
                    "scanning and tracing provider calls", ["AmsiScanBuffer", "EtwEventWrite"]
                ),
                self._rule("tracing provider registration", ["EtwEventRegister", "EventWrite"]),
            )
        )

        assert len(hits) == 2
        assert {hit["rule"] for hit in hits} == {
            "scanning and tracing provider calls",
            "tracing provider registration",
        }
        assert all(hit["technique_id"] == "T1685" for hit in hits)

    def test_neither_rule_clears_its_floor_on_the_others_apis(self) -> None:
        """One API each: pooled they would be two, and one row would fire."""
        hits = api_capability_hits(
            self._payload(
                self._rule("scanning and tracing provider calls", ["AmsiScanBuffer"]),
                self._rule("tracing provider registration", ["EtwEventRegister"]),
            )
        )

        assert hits == []

    def test_a_rule_repeated_under_every_api_is_still_one_row(self) -> None:
        hits = api_capability_hits(
            self._payload(
                self._rule(
                    "scanning and tracing provider calls", ["AmsiScanBuffer", "AmsiOpenSession"]
                )
            )
        )

        assert len(hits) == 1
        assert hits[0]["matched_apis"] == ["AmsiScanBuffer", "AmsiOpenSession"]
