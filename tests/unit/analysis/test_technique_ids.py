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
